"""Crypto-function classifier (Pramana_Ledger_Spec.md §5.1).

Takes observations and returns UsageContexts. Never takes an asset and returns
"the function of that asset", because assets do not have one -- that was the
red-team finding (§5). A certificate observed in a handshake yields TWO
contexts from ONE observation: the key establishment that carried the session,
and the signature that authenticated it. They land on different clocks.

Three hard edges, all from §5.1:

* Observed means seen on the traffic path or in the artefact. Offered-but-not-
  negotiated suites and keyUsage bits are capability, so INFERRED.
* Package presence yields NO context at all -- not an UNKNOWN one. A library
  on disk is not a usage, and emitting a row for it would put an invented
  surface into the ledger.
* Anything unmatched is UNKNOWN. There is no default and no fallthrough guess.
"""
from __future__ import annotations

from datetime import date

from pydantic import BaseModel, ConfigDict, field_validator

from ecdat.data.crypto_families import canonical_family, is_hybrid_group
from ecdat.model.epistemic import EpistemicState
from ecdat.model.field_value import FieldValue
from ecdat.model.usage_context import CryptoFunction, UsageContext

# Rule ids, registered in rules/registry.py against §5.1.
R_KEX = "FUNC-TLS-KEX-001"
R_KEYTRANSPORT = "FUNC-TLS-KEYTRANSPORT-001"
R_HYBRID = "FUNC-TLS-HYBRID-001"
R_CERT_AUTH = "FUNC-CERT-AUTH-001"
R_OFFERED = "FUNC-TLS-OFFERED-001"
R_KEYUSAGE = "FUNC-KEYUSAGE-001"
R_SRC_KEYTRANSPORT = "FUNC-SRC-KEYTRANSPORT-001"
R_SRC_SIGNATURE = "FUNC-SRC-SIGNATURE-001"
R_SRC_KEX = "FUNC-SRC-KEX-001"


# --- observations ----------------------------------------------------------


class NegotiatedHandshake(BaseModel):
    """What a surface actually negotiated, from one vantage. The only TLS
    observation that produces KNOWN contexts."""

    model_config = ConfigDict(frozen=True)

    surface_id: str
    vantage: str
    observed_at: date
    cipher_suite: str
    negotiated_group: str | None = None
    kex_asset_id: str
    cert_asset_id: str | None = None
    evidence_id: str

    @field_validator("surface_id", "vantage", "cipher_suite", "kex_asset_id", "evidence_id")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be blank")
        return value


class OfferedSuite(BaseModel):
    """A suite the endpoint offered but did not negotiate (§5.1 -> INFERRED)."""

    model_config = ConfigDict(frozen=True)

    surface_id: str
    cipher_suite: str
    asset_id: str
    evidence_id: str


class CertificateKeyUsage(BaseModel):
    """keyUsage / extendedKeyUsage bits (§5.1 -> INFERRED capability)."""

    model_config = ConfigDict(frozen=True)

    surface_id: str
    asset_id: str
    evidence_id: str
    key_usage: tuple[str, ...] = ()


class SourceCallSite(BaseModel):
    """A call site found by our own rules (§5.1 source bullet).

    `transformation` is None when the rule matched a non-literal argument --
    `Cipher.getInstance(props.getTransformation())`. The function is still
    observed; the algorithm is not. That split is the PAY-001 case.
    """

    model_config = ConfigDict(frozen=True)

    surface_id: str
    asset_id: str
    api_class: str
    location: str
    evidence_id: str
    transformation: str | None = None
    wrap_mode: bool = False


class PackagePresence(BaseModel):
    """A crypto library on disk. Produces no context, by design."""

    model_config = ConfigDict(frozen=True)

    surface_id: str
    asset_id: str
    package: str
    evidence_id: str


# --- helpers ---------------------------------------------------------------


def _fn(
    value: CryptoFunction | None,
    state: EpistemicState,
    rule_id: str | None,
    evidence_id: str | None = None,
) -> FieldValue[CryptoFunction]:
    return FieldValue[CryptoFunction](
        value=value,
        state=state,
        evidence_refs=(evidence_id,) if evidence_id else (),
        rule_id=rule_id,
    )


def _alg(
    value: str | None, state: EpistemicState, evidence_id: str | None = None
) -> FieldValue[str]:
    return FieldValue[str](
        value=value, state=state, evidence_refs=(evidence_id,) if evidence_id else ()
    )


def _unknown_context(
    uid: str, asset_id: str, surface_id: str, protocol_context: str
) -> UsageContext:
    return UsageContext(
        usage_context_id=uid,
        asset_id=asset_id,
        surface_id=surface_id,
        protocol_context=protocol_context,
        function=_fn(None, EpistemicState.UNKNOWN, None),
    )


def _suite_kex_token(cipher_suite: str) -> str | None:
    """The key-exchange token of a TLS 1.2-style suite name, or None for a
    TLS 1.3 suite (which encodes no key exchange -- the group does)."""
    parts = cipher_suite.upper().split("_")
    if not parts or parts[0] != "TLS":
        return None
    rest = parts[1:]
    if "WITH" not in rest:
        return None
    return "_".join(rest[: rest.index("WITH")])


def _kex_function_from_token(token: str | None) -> CryptoFunction | None:
    if token is None:
        return None
    if token == "RSA":
        return CryptoFunction.KEY_TRANSPORT
    if "ECDHE" in token or "DHE" in token:
        return CryptoFunction.KEY_ESTABLISHMENT
    return None


# --- classification --------------------------------------------------------


def classify_handshake(obs: NegotiatedHandshake) -> tuple[UsageContext, ...]:
    """§5.1 first bullet. One handshake -> the confidentiality context, plus
    the certificate's authentication context when a certificate was seen."""
    contexts: list[UsageContext] = []
    kex_token = _suite_kex_token(obs.cipher_suite)
    group = canonical_family(obs.negotiated_group)
    base_uid = f"{obs.surface_id}|{obs.vantage}|{obs.observed_at.isoformat()}"

    function = _kex_function_from_token(kex_token)
    if is_hybrid_group(obs.negotiated_group):
        function, rule_id, family = CryptoFunction.HYBRID_KEX, R_HYBRID, obs.negotiated_group
    elif function == CryptoFunction.KEY_TRANSPORT:
        rule_id, family = R_KEYTRANSPORT, "RSA"
    elif function == CryptoFunction.KEY_ESTABLISHMENT:
        rule_id, family = R_KEX, group
    elif kex_token is None and obs.negotiated_group is not None:
        # TLS 1.3: the suite names no key exchange, the negotiated group is it.
        function, rule_id, family = CryptoFunction.KEY_ESTABLISHMENT, R_KEX, group
    else:
        function, rule_id, family = None, None, None

    if function is None:
        contexts.append(
            _unknown_context(
                f"{base_uid}|kex", obs.kex_asset_id, obs.surface_id, obs.cipher_suite
            )
        )
    else:
        contexts.append(
            UsageContext(
                usage_context_id=f"{base_uid}|kex",
                asset_id=obs.kex_asset_id,
                surface_id=obs.surface_id,
                protocol_context=obs.cipher_suite,
                function=_fn(function, EpistemicState.KNOWN, rule_id, obs.evidence_id),
                algorithm=(
                    _alg(family, EpistemicState.KNOWN, obs.evidence_id)
                    if family
                    else _alg(None, EpistemicState.UNKNOWN)
                ),
            )
        )

    if obs.cert_asset_id:
        contexts.append(
            UsageContext(
                usage_context_id=f"{base_uid}|auth",
                asset_id=obs.cert_asset_id,
                surface_id=obs.surface_id,
                protocol_context=f"{obs.cipher_suite} server certificate",
                function=_fn(
                    CryptoFunction.SIGNATURE_AUTH,
                    EpistemicState.KNOWN,
                    R_CERT_AUTH,
                    obs.evidence_id,
                ),
            )
        )

    return tuple(contexts)


def classify_offered_suite(obs: OfferedSuite) -> tuple[UsageContext, ...]:
    """§5.1: offered-but-not-negotiated -> INFERRED capability context."""
    uid = f"{obs.surface_id}|offered|{obs.cipher_suite}"
    function = _kex_function_from_token(_suite_kex_token(obs.cipher_suite))
    if function is None:
        return (
            _unknown_context(
                uid, obs.asset_id, obs.surface_id, f"offered: {obs.cipher_suite}"
            ),
        )
    family = "RSA" if function == CryptoFunction.KEY_TRANSPORT else None
    return (
        UsageContext(
            usage_context_id=uid,
            asset_id=obs.asset_id,
            surface_id=obs.surface_id,
            protocol_context=f"offered, not negotiated: {obs.cipher_suite}",
            function=_fn(function, EpistemicState.INFERRED, R_OFFERED, obs.evidence_id),
            algorithm=(
                _alg(family, EpistemicState.INFERRED, obs.evidence_id)
                if family
                else _alg(None, EpistemicState.UNKNOWN)
            ),
        ),
    )


#: keyUsage bit -> the capability it permits (§5.1). Bit names are X.509 field
#: names, not a risk judgement.
_KEY_USAGE_FUNCTION: dict[str, CryptoFunction] = {
    "digitalSignature": CryptoFunction.SIGNATURE_AUTH,
    "keyCertSign": CryptoFunction.SIGNATURE_AUTH,
    "keyEncipherment": CryptoFunction.KEY_TRANSPORT,
    "keyAgreement": CryptoFunction.KEY_ESTABLISHMENT,
}


def classify_key_usage(obs: CertificateKeyUsage) -> tuple[UsageContext, ...]:
    """§5.1: keyUsage/EKU -> INFERRED capability contexts, one per bit."""
    contexts: list[UsageContext] = []
    for bit in obs.key_usage:
        function = _KEY_USAGE_FUNCTION.get(bit)
        if function is None:
            continue
        contexts.append(
            UsageContext(
                usage_context_id=f"{obs.surface_id}|keyUsage|{bit}",
                asset_id=obs.asset_id,
                surface_id=obs.surface_id,
                protocol_context=f"keyUsage: {bit}",
                function=_fn(function, EpistemicState.INFERRED, R_KEYUSAGE, obs.evidence_id),
            )
        )
    return tuple(contexts)


def classify_call_site(obs: SourceCallSite) -> tuple[UsageContext, ...]:
    """§5.1 source bullet. The function comes from the API class and the call
    shape; the algorithm comes from the transformation string only when that
    string is a literal."""
    api = obs.api_class.rsplit(".", 1)[-1]
    transformation = (obs.transformation or "").upper()
    uid = f"{obs.surface_id}|{obs.location}"

    if api == "Signature":
        function, rule_id = CryptoFunction.SIGNATURE_AUTH, R_SRC_SIGNATURE
    elif api == "KeyAgreement":
        function, rule_id = CryptoFunction.KEY_ESTABLISHMENT, R_SRC_KEX
    elif api == "Cipher" and (obs.wrap_mode or transformation.startswith("RSA")):
        function, rule_id = CryptoFunction.KEY_TRANSPORT, R_SRC_KEYTRANSPORT
    else:
        return (
            _unknown_context(
                uid, obs.asset_id, obs.surface_id, f"{obs.api_class} at {obs.location}"
            ),
        )

    return (
        UsageContext(
            usage_context_id=uid,
            asset_id=obs.asset_id,
            surface_id=obs.surface_id,
            protocol_context=f"{obs.api_class} at {obs.location}",
            function=_fn(function, EpistemicState.KNOWN, rule_id, obs.evidence_id),
            algorithm=(
                _alg(obs.transformation, EpistemicState.KNOWN, obs.evidence_id)
                if obs.transformation
                else _alg(None, EpistemicState.UNKNOWN)
            ),
        ),
    )


def classify_package(obs: PackagePresence) -> tuple[UsageContext, ...]:
    """§5.1: "Package presence -> no context." Not an UNKNOWN context: none."""
    return ()

"""PQC / hybrid recommendation (Final Architecture Part 8).

Keyed on PURPOSE, never on algorithm name. Part 8 puts the reason as the
judge's question: *"Why not just map RSA to ML-KEM?"* -> "Because RSA does
three different jobs. Which one this instance is doing determines the answer,
and when we can't determine it, we say so instead of guessing."

That makes this module a consumer of the same UsageContext the ledgers eat,
and it inherits the same refusal: a context whose function is UNKNOWN gets
"insufficient evidence to recommend -- purpose undetermined" and is routed to
the coverage report (Part 8, Caveats). It does not get a plausible default.

Two asymmetries carried through from Part 8 rather than re-derived here:

* **Hybrid for key exchange, not for signatures.** Recorded traffic can be
  decrypted later, so confidentiality needs protecting today. A signature is
  verified in real time -- nothing to harvest -- so the only risk is future
  forgery, and hybrid signatures double an already large size.
* **Long-lived signing is a different row from general signing.** Firmware and
  roots get SLH-DSA or LMS/XMSS; a session signature does not need either, and
  SLH-DSA's signature is up to 49 KB.

Every option, parameter set, byte count and the breakage figure comes from
data/pqc_options.yaml with a citation. Nothing is computed here except which
cited rows apply.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict

from ecdat.model.epistemic import EpistemicState
from ecdat.model.usage_context import CryptoFunction, UsageContext
from ecdat.risk.run import LedgerSubject

_FILENAME = "pqc_options.yaml"

#: Part 8, Caveats. The literal sentence, because a paraphrase drifts.
INSUFFICIENT_EVIDENCE = "insufficient evidence to recommend — purpose undetermined"


class NoCitedOptionError(LookupError):
    """No usable row covers this purpose or profile."""


def _path() -> Path:
    # src/ecdat/recommend/engine.py -> repository root -> data/
    return Path(__file__).resolve().parents[3] / "data" / _FILENAME


@lru_cache(maxsize=1)
def _data() -> dict[str, Any]:
    document = yaml.safe_load(_path().read_text(encoding="utf-8"))
    if not isinstance(document, dict) or "options" not in document:
        raise ValueError(f"malformed PQC option registry at {_path()}")
    return document


def _usable(section: str) -> tuple[dict[str, Any], ...]:
    return tuple(row for row in (_data().get(section) or ()) if row.get("usable") is True)


class Profile(BaseModel):
    """A policy profile: which parameter sets this deployment is required to
    use. Part 8: "Make the policy a configurable profile, not a hardcoded
    constant."
    """

    model_config = ConfigDict(frozen=True)

    key: str
    label: str
    parameter_sets: dict[str, str]
    citation: str
    firmware_signing: str | None = None

    @classmethod
    def load(cls, key: str) -> "Profile":
        for row in _usable("profiles"):
            if row["key"] == key:
                return cls(
                    key=row["key"],
                    label=row["label"],
                    parameter_sets=dict(row["parameter_sets"]),
                    firmware_signing=row.get("firmware_signing"),
                    citation=row["citation"],
                )
        raise NoCitedOptionError(f"no usable profile {key!r} in {_FILENAME}")

    @classmethod
    def default(cls) -> "Profile":
        for row in _usable("profiles"):
            if row.get("default") is True:
                return cls.load(row["key"])
        raise NoCitedOptionError(f"no row in {_FILENAME} is marked default")

    @classmethod
    def load_all(cls) -> tuple["Profile", ...]:
        return tuple(cls.load(row["key"]) for row in _usable("profiles"))


class Cost(BaseModel):
    """Sizes for one algorithm + parameter set, straight from Part 8's lookup
    table. `approximate` is carried from the source: where Part 8 writes a
    tilde or a range, we print a range."""

    model_config = ConfigDict(frozen=True)

    key: str
    citation: str
    approximate: bool = False
    public_key_bytes: int | None = None
    signature_bytes: int | None = None
    signature_bytes_low: int | None = None
    signature_bytes_high: int | None = None
    ciphertext_bytes: int | None = None
    client_key_share_bytes: int | None = None
    baseline_key_share_bytes: int | None = None
    note: str | None = None

    @classmethod
    def load(cls, key: str) -> "Cost | None":
        for row in _usable("costs"):
            if row["key"] == key:
                return cls(**{k: v for k, v in row.items() if k != "usable" and k != "quote"})
        return None


class Option(BaseModel):
    """One acceptable replacement. Several may apply; Part 8 lists more than
    one answer for some purposes and states no tie-break, so none is invented
    here."""

    model_config = ConfigDict(frozen=True)

    algorithm: str
    standard: str
    hybrid: bool
    citation: str
    parameter_set: str | None = None
    cost: Cost | None = None
    note: str | None = None
    caveat: str | None = None


class Recommendation(BaseModel):
    """What to move this usage context to, or why we will not say.

    `options` is empty exactly when `insufficient_evidence` is true or the
    purpose is one Part 8 does not cover. An empty option set is never a
    silent one -- `reason` always says which.
    """

    model_config = ConfigDict(frozen=True)

    usage_context_id: str
    asset_id: str
    surface_id: str
    function: str
    function_status: str
    current_algorithm: str | None
    profile: str
    options: tuple[Option, ...] = ()
    reason: str = ""
    insufficient_evidence: bool = False

    @property
    def route_to_coverage(self) -> bool:
        """Part 8, Caveats: an insufficient-evidence result is routed to the
        coverage report rather than shown as a recommendation."""
        return self.insufficient_evidence


def _hybrid_caveat() -> str | None:
    for row in _usable("breakage"):
        if row["key"] == "pq_key_share_handshake_failure":
            rate = row["measured_failure_rate"]
            return (
                f"Known breakage precedent: ~{rate * 100:.2f}% of scanned origins "
                "failed the TLS handshake when sent a post-quantum key share "
                "first (ossified middleboxes assuming a one-packet ClientHello). "
                f"Source: {row['citation']}"
            )
    return None


def _plain(quote: str) -> str:
    """Drop the source document's markdown emphasis markers.

    The quote is stored verbatim in data/pqc_options.yaml, asterisks and all,
    so it can be diffed against Part 8. Those asterisks are the Markdown the
    sentence is written IN, not part of the sentence, and rendering them in a
    UI reads as a bug. Nothing else about the text is altered.
    """
    return " ".join(quote.replace("**", "").replace("*", "").split())


def hybrid_rationale() -> dict[str, str]:
    """Part 8's reason for hybrid on the confidentiality clock and not on the
    authentication one, quoted once for the view rather than pasted onto every
    row it explains."""
    for row in _usable("hybrid_rationale"):
        if row["key"] == "why_hybrid_kex_not_signatures":
            return {"quote": _plain(row["quote"]), "citation": row["citation"]}
    return {}


def _options_for(option_key: str, profile: Profile) -> tuple[Option, ...]:
    built: list[Option] = []
    for row in _usable("options"):
        if row["key"] != option_key:
            continue
        algorithm = row["algorithm"]
        parameter_set = profile.parameter_sets.get(algorithm)
        built.append(
            Option(
                algorithm=algorithm,
                standard=row["standard"],
                hybrid=bool(row["hybrid"]),
                citation=row["citation"],
                parameter_set=parameter_set,
                cost=Cost.load(parameter_set or algorithm),
                note=row.get("note"),
                caveat=_hybrid_caveat() if row["hybrid"] else None,
            )
        )
    return tuple(built)


def recommend(
    subject: LedgerSubject | UsageContext, *, profile: Profile | None = None
) -> Recommendation:
    """One usage context in, one recommendation (or one honest refusal) out."""
    context = subject.usage_context if isinstance(subject, LedgerSubject) else subject
    binding_key = subject.binding_key if isinstance(subject, LedgerSubject) else None
    profile = profile or Profile.default()
    function = context.function.value

    base = dict(
        usage_context_id=context.usage_context_id,
        asset_id=context.asset_id,
        surface_id=context.surface_id,
        function=function.value if function else "UNKNOWN",
        function_status=context.function.state.value,
        current_algorithm=context.algorithm.value if context.algorithm else None,
        profile=profile.key,
    )

    if context.function.state == EpistemicState.UNKNOWN or function is None:
        return Recommendation(
            **base,
            insufficient_evidence=True,
            reason=(
                f"{INSUFFICIENT_EVIDENCE}. Part 8: never emit a confident "
                "recommendation from an undetermined purpose; this is routed "
                "to the coverage report instead."
            ),
        )

    if function == CryptoFunction.HYBRID_KEX:
        return Recommendation(
            **base,
            reason=(
                "already negotiating a hybrid key exchange. Nothing to "
                "recommend: confirm classical is refused (§5.7) rather than "
                "changing the algorithm."
            ),
        )

    if function == CryptoFunction.ENCRYPTION:
        return Recommendation(
            **base,
            reason=(
                "symmetric encryption is a Grover key-size question, not an "
                "algorithm replacement. Part 8's table names no option set for "
                "it, so none is offered here."
            ),
        )

    if function == CryptoFunction.SIGNATURE_AUTH:
        # Part 8 splits general signing from long-lived, low-frequency
        # signing. The evidence that distinguishes them is already on the
        # subject: an authenticity lifetime of zero is a session signature.
        long_lived = binding_key is not None and _has_nonzero_authenticity(binding_key)
        options = _options_for("SIGNATURE_AUTH", profile)
        if long_lived:
            options = options + _options_for("SIGNATURE_AUTH_LONG_LIVED", profile)
            if profile.firmware_signing:
                options = tuple(
                    o.model_copy(
                        update={
                            "note": (
                                f"{o.note + ' ' if o.note else ''}"
                                f"{profile.label} mandates {profile.firmware_signing} "
                                "for firmware signing."
                            )
                        }
                    )
                    if o.algorithm == "LMS/XMSS"
                    else o
                    for o in options
                )
        return Recommendation(
            **base,
            options=options,
            reason=(
                "Signature over an artefact that must stay trustworthy after "
                "the session, so Part 8's long-lived signing row applies as "
                "well as the general one. No hybrid option: a signature is "
                "verified in real time, so there is nothing to harvest."
                if long_lived
                else "Session signature. No hybrid option: a signature is "
                "verified in real time, so there is nothing to harvest."
            ),
        )

    options = _options_for(function.value, profile)
    if not options:
        return Recommendation(
            **base,
            reason=f"Part 8's table names no option set for {function.value}.",
        )
    return Recommendation(
        **base,
        options=options,
        reason=(
            "Recorded traffic is the threat here, so a hybrid transition "
            "option is offered alongside the pure post-quantum one."
        ),
    )


def _has_nonzero_authenticity(binding_key: str) -> bool:
    """True when the bound data class states an authenticity lifetime greater
    than zero -- Part 8's "long-lived, low-frequency signing" case.

    Reads the cited lifetime row rather than a threshold: A == 0 is a session
    signature and A > 0 is an artefact that must stay trustworthy afterwards.
    That distinction is structural (§5.6), not a number chosen here.
    """
    from ecdat.risk.scenarios import NoCitedLifetimeError, lifetime_row

    try:
        row = lifetime_row(binding_key)
    except NoCitedLifetimeError:
        return False
    authenticity = row.get("authenticity_lifetime_A")
    if not authenticity:
        return False
    return bool(authenticity.get("years") or authenticity.get("days"))

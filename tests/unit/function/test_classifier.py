"""Pramana_Ledger_Spec.md §5.1 -- the six function cases, plus multi-function.

Acceptance for phase 2 (§7.2): "6 function cases + multi-function".
"""
from datetime import date

from ecdat.function.classifier import (
    CertificateKeyUsage,
    NegotiatedHandshake,
    OfferedSuite,
    PackagePresence,
    SourceCallSite,
    classify_call_site,
    classify_handshake,
    classify_key_usage,
    classify_offered_suite,
    classify_package,
)
from ecdat.model.epistemic import EpistemicState
from ecdat.model.usage_context import CryptoFunction

OBSERVED = EpistemicState.KNOWN
OBS_AT = date(2026, 6, 1)


def _hs(**kw):
    kw.setdefault("surface_id", "tls:pay:443")
    kw.setdefault("vantage", "dmz-probe-1")
    kw.setdefault("observed_at", OBS_AT)
    kw.setdefault("kex_asset_id", "PAY-KEX")
    kw.setdefault("evidence_id", "E-probe")
    return NegotiatedHandshake(**kw)


def _by_function(contexts):
    return {c.function.value: c for c in contexts}


# --- case 1: ECDHE negotiated ----------------------------------------------


def test_negotiated_ecdhe_is_observed_key_establishment():
    (ctx,) = classify_handshake(
        _hs(cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", negotiated_group="X25519")
    )
    assert ctx.function.value == CryptoFunction.KEY_ESTABLISHMENT
    assert ctx.function.state == OBSERVED
    assert ctx.function.rule_id == "FUNC-TLS-KEX-001"
    assert ctx.algorithm.value == "X25519"


# --- case 2: TLS_RSA_* negotiated ------------------------------------------


def test_negotiated_tls_rsa_is_observed_key_transport():
    (ctx,) = classify_handshake(cipher_suite_obs := _hs(cipher_suite="TLS_RSA_WITH_AES_128_CBC_SHA"))
    assert cipher_suite_obs.negotiated_group is None
    assert ctx.function.value == CryptoFunction.KEY_TRANSPORT
    assert ctx.function.state == OBSERVED
    assert ctx.algorithm.value == "RSA"


# --- case 3: hybrid negotiated ---------------------------------------------


def test_negotiated_hybrid_group_is_hybrid_kex():
    (ctx,) = classify_handshake(
        _hs(cipher_suite="TLS_AES_256_GCM_SHA384", negotiated_group="X25519MLKEM768")
    )
    assert ctx.function.value == CryptoFunction.HYBRID_KEX
    assert ctx.function.rule_id == "FUNC-TLS-HYBRID-001"


def test_tls13_suite_without_hybrid_group_is_key_establishment():
    """A TLS 1.3 suite name encodes no key exchange; the group does."""
    (ctx,) = classify_handshake(
        _hs(cipher_suite="TLS_AES_128_GCM_SHA256", negotiated_group="secp256r1")
    )
    assert ctx.function.value == CryptoFunction.KEY_ESTABLISHMENT
    assert ctx.algorithm.value == "P-256", "registry spelling, resolved by alias"


# --- case 4: the certificate on the same handshake -------------------------


def test_handshake_with_certificate_yields_two_contexts_on_two_clocks():
    """§6 row 1: 'RSA cert, TLS auth only (ECDHE negotiated) -> no
    confidentiality row for the key; auth: ROTATE_BEFORE_Z'."""
    contexts = classify_handshake(
        _hs(
            cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            negotiated_group="X25519",
            cert_asset_id="PAY-005",
        )
    )
    by_fn = _by_function(contexts)
    assert set(by_fn) == {CryptoFunction.KEY_ESTABLISHMENT, CryptoFunction.SIGNATURE_AUTH}
    kex, auth = by_fn[CryptoFunction.KEY_ESTABLISHMENT], by_fn[CryptoFunction.SIGNATURE_AUTH]
    assert kex.asset_id == "PAY-KEX" and auth.asset_id == "PAY-005"
    assert auth.function.rule_id == "FUNC-CERT-AUTH-001"
    assert auth.is_authentication and not auth.is_confidentiality


# --- case 5: offered but not negotiated ------------------------------------


def test_offered_suite_is_inferred_not_observed():
    (ctx,) = classify_offered_suite(
        OfferedSuite(
            surface_id="tls:pay:443",
            cipher_suite="TLS_RSA_WITH_AES_128_CBC_SHA",
            asset_id="PAY-005",
            evidence_id="E-offer",
        )
    )
    assert ctx.function.value == CryptoFunction.KEY_TRANSPORT
    assert ctx.function.state == EpistemicState.INFERRED
    assert ctx.function.rule_id == "FUNC-TLS-OFFERED-001"


def test_key_usage_bits_are_inferred_capability():
    contexts = classify_key_usage(
        CertificateKeyUsage(
            surface_id="certdir:pki",
            asset_id="PAY-005",
            key_usage=("digitalSignature", "keyEncipherment", "cRLSign"),
            evidence_id="E-cert",
        )
    )
    by_fn = _by_function(contexts)
    assert set(by_fn) == {CryptoFunction.SIGNATURE_AUTH, CryptoFunction.KEY_TRANSPORT}
    assert all(c.function.state == EpistemicState.INFERRED for c in contexts)
    assert "cRLSign" not in {c.protocol_context for c in contexts}, "unmapped bit invents nothing"


# --- case 6: source call sites ---------------------------------------------


def test_signature_call_site_is_signature_auth():
    (ctx,) = classify_call_site(
        SourceCallSite(
            surface_id="src:payments",
            asset_id="PAY-002",
            api_class="java.security.Signature",
            location="WebhookSigner.java:41",
            transformation="SHA256withRSA",
            evidence_id="E-sg",
        )
    )
    assert ctx.function.value == CryptoFunction.SIGNATURE_AUTH
    assert ctx.function.state == OBSERVED


def test_key_agreement_call_site_is_key_establishment():
    (ctx,) = classify_call_site(
        SourceCallSite(
            surface_id="src:payments",
            asset_id="PAY-012",
            api_class="javax.crypto.KeyAgreement",
            location="Handshake.java:88",
            evidence_id="E-ka",
        )
    )
    assert ctx.function.value == CryptoFunction.KEY_ESTABLISHMENT


def test_wrap_mode_cipher_is_key_transport_with_unknown_algorithm():
    """PAY-001: the transformation comes from a properties file, so the
    function is observed and the algorithm is not (§5.1)."""
    (ctx,) = classify_call_site(
        SourceCallSite(
            surface_id="src:payments",
            asset_id="PAY-001",
            api_class="javax.crypto.Cipher",
            location="KeyWrapService.java:27",
            wrap_mode=True,
            transformation=None,
            evidence_id="E-kw",
        )
    )
    assert ctx.function.value == CryptoFunction.KEY_TRANSPORT
    assert ctx.function.state == OBSERVED
    assert ctx.algorithm.state == EpistemicState.UNKNOWN
    assert ctx.algorithm.value is None


def test_rsa_transformation_cipher_is_key_transport():
    (ctx,) = classify_call_site(
        SourceCallSite(
            surface_id="src:payments",
            asset_id="PAY-001",
            api_class="javax.crypto.Cipher",
            location="KeyWrapService.java:31",
            transformation="RSA/ECB/OAEPWithSHA-256AndMGF1Padding",
            evidence_id="E-rsa",
        )
    )
    assert ctx.function.value == CryptoFunction.KEY_TRANSPORT
    assert ctx.algorithm.value.startswith("RSA/")


def test_symmetric_cipher_call_site_is_unknown_not_encryption():
    """AES/GCM is bulk encryption, not a ledger function; §5.1 gives it no
    rule, so it must fall to UNKNOWN rather than be guessed into ENCRYPTION."""
    (ctx,) = classify_call_site(
        SourceCallSite(
            surface_id="src:payments",
            asset_id="PAY-003",
            api_class="javax.crypto.Cipher",
            location="TokenVault.java:19",
            transformation="AES/GCM/NoPadding",
            evidence_id="E-aes",
        )
    )
    assert ctx.function.state == EpistemicState.UNKNOWN
    assert ctx.function.value is None


# --- the no-context case ---------------------------------------------------


def test_package_presence_yields_no_context_at_all():
    """§5.1: 'Package presence -> no context.' Not an UNKNOWN row."""
    assert (
        classify_package(
            PackagePresence(
                surface_id="pkg:image",
                asset_id="PAY-008",
                package="bcprov-jdk18on",
                evidence_id="E-pkg",
            )
        )
        == ()
    )


def test_unrecognised_suite_is_unknown_with_no_default():
    (ctx,) = classify_handshake(_hs(cipher_suite="TLS_SRP_SHA_WITH_AES_128_CBC_SHA"))
    assert ctx.function.state == EpistemicState.UNKNOWN
    assert ctx.function.value is None
    assert ctx.function.rule_id is None


# --- multi-function on one asset -------------------------------------------


def test_one_certificate_carries_key_transport_and_signature_contexts():
    """§6: 'RSA cert: TLS_RSA_* offered (Inf) + ECDHE negotiated (Obs) ->
    two contexts'."""
    observed = classify_handshake(
        _hs(
            cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            negotiated_group="X25519",
            cert_asset_id="PAY-005",
        )
    )
    inferred = classify_offered_suite(
        OfferedSuite(
            surface_id="tls:pay:443",
            cipher_suite="TLS_RSA_WITH_AES_128_CBC_SHA",
            asset_id="PAY-005",
            evidence_id="E-offer",
        )
    )
    on_pay005 = [c for c in observed + inferred if c.asset_id == "PAY-005"]
    assert len(on_pay005) == 2
    states = {c.function.value: c.function.state for c in on_pay005}
    assert states[CryptoFunction.SIGNATURE_AUTH] == OBSERVED
    assert states[CryptoFunction.KEY_TRANSPORT] == EpistemicState.INFERRED

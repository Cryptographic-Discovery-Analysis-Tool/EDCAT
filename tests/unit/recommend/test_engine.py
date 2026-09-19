"""PQC / hybrid recommendation (Final Architecture Part 8).

Part 8's judge question is the spec for this module: "Why not just map RSA to
ML-KEM? -> Because RSA does three different jobs."
"""
from datetime import date

import pytest

from ecdat.api.app import DEFAULT_SUBJECTS, load_subjects
from ecdat.model.epistemic import EpistemicState
from ecdat.model.field_value import FieldValue
from ecdat.model.temporal import TemporalEvidence
from ecdat.model.usage_context import CryptoFunction, UsageContext
from ecdat.recommend.engine import (
    INSUFFICIENT_EVIDENCE,
    NoCitedOptionError,
    Profile,
    recommend,
)
from ecdat.risk.run import LedgerSubject

OBSERVED = EpistemicState.KNOWN


def context(function, algorithm=None, *, state=OBSERVED, uid="UC-1"):
    return UsageContext(
        usage_context_id=uid,
        asset_id="asset-1",
        surface_id="tls:host:443",
        protocol_context="observed handshake",
        function=FieldValue[CryptoFunction](
            value=function,
            state=state,
            evidence_refs=("E-probe",) if state == OBSERVED else (),
            rule_id="FUNC-TLS-KEX-001" if function is not None else None,
        ),
        algorithm=(
            FieldValue[str](value=algorithm, state=OBSERVED, evidence_refs=("E-probe",))
            if algorithm
            else None
        ),
    )


def subject(function, algorithm=None, *, binding_key=None, state=OBSERVED):
    return LedgerSubject(
        usage_context=context(function, algorithm, state=state),
        temporal=TemporalEvidence(surface_id="tls:host:443", observation_ts=date(2026, 9, 18)),
        binding_key=binding_key,
    )


def algorithms(rec):
    return [o.algorithm for o in rec.options]


# --- the judge's question ---------------------------------------------------


def test_one_algorithm_three_jobs_three_different_answers():
    """Part 8: 'RSA does three different jobs. Which one this instance is
    doing determines the answer.'"""
    transport = recommend(subject(CryptoFunction.KEY_TRANSPORT, "RSA"))
    signing = recommend(subject(CryptoFunction.SIGNATURE_AUTH, "RSA"))
    unknown = recommend(subject(None, "RSA", state=EpistemicState.UNKNOWN))

    assert "ML-KEM" in algorithms(transport)
    assert "ML-DSA" in algorithms(signing)
    assert unknown.options == ()
    assert algorithms(transport) != algorithms(signing)


def test_unknown_purpose_refuses_rather_than_defaults():
    """Part 8, Caveats: 'Never emit a confident recommendation from a
    purpose: unknown finding.'"""
    rec = recommend(subject(None, "RSA", state=EpistemicState.UNKNOWN))
    assert rec.insufficient_evidence is True
    assert rec.route_to_coverage is True
    assert INSUFFICIENT_EVIDENCE in rec.reason
    assert rec.options == ()


# --- hybrid on one clock only -----------------------------------------------


def test_key_exchange_gets_a_hybrid_option():
    rec = recommend(subject(CryptoFunction.KEY_ESTABLISHMENT, "X25519"))
    hybrids = [o for o in rec.options if o.hybrid]
    assert [o.algorithm for o in hybrids] == ["X25519MLKEM768"]


def test_signatures_never_get_a_hybrid_option():
    """Part 8: 'A signature is verified in real time; there is nothing to
    harvest ... and hybrid signatures double an already large size cost.'"""
    rec = recommend(subject(CryptoFunction.SIGNATURE_AUTH, "RSA"))
    assert all(o.hybrid is False for o in rec.options)
    assert "nothing to harvest" in rec.reason


def test_the_hybrid_option_carries_its_breakage_precedent():
    """Part 8: 'Migration breakage risk belongs here.' A recommendation
    without it is advice with no warning label."""
    rec = recommend(subject(CryptoFunction.KEY_ESTABLISHMENT, "X25519"))
    (hybrid,) = [o for o in rec.options if o.hybrid]
    assert "0.34%" in hybrid.caveat
    assert "ClientHello" in hybrid.caveat
    assert all(o.caveat is None for o in rec.options if not o.hybrid)


# --- long-lived signing is a separate row -----------------------------------


def test_session_signature_gets_only_the_general_signing_option():
    rec = recommend(subject(CryptoFunction.SIGNATURE_AUTH, binding_key="TEST.A_SESSION"))
    assert algorithms(rec) == ["ML-DSA"]


def test_artefact_that_outlives_the_session_also_gets_the_long_lived_options():
    """Part 8 splits 'general digital signature' from 'long-lived,
    low-frequency signing (firmware, roots)'. A == 0 vs A > 0 is the
    structural distinction, not a threshold chosen here."""
    rec = recommend(subject(CryptoFunction.SIGNATURE_AUTH, binding_key="TEST.A_15Y"))
    assert algorithms(rec) == ["ML-DSA", "SLH-DSA", "LMS/XMSS"]


# --- profiles ----------------------------------------------------------------


def test_default_profile_is_nist_level_3():
    """Part 8: 'the internet defaults to NIST Level 3 (ML-KEM-768,
    ML-DSA-65)'."""
    assert Profile.default().key == "NIST_L3"
    rec = recommend(subject(CryptoFunction.KEY_ESTABLISHMENT, "X25519"))
    assert rec.options[0].parameter_set == "ML-KEM-768"


def test_cnsa_profile_moves_every_parameter_set_to_level_5():
    """Part 8: 'NSA CNSA 2.0 mandates Level 5 only (ML-KEM-1024,
    ML-DSA-87)'."""
    profile = Profile.load("CNSA_2_0")
    kex = recommend(subject(CryptoFunction.KEY_ESTABLISHMENT, "X25519"), profile=profile)
    sig = recommend(subject(CryptoFunction.SIGNATURE_AUTH, "RSA"), profile=profile)
    assert kex.options[0].parameter_set == "ML-KEM-1024"
    assert sig.options[0].parameter_set == "ML-DSA-87"


def test_cnsa_names_its_firmware_signing_mandate():
    profile = Profile.load("CNSA_2_0")
    rec = recommend(
        subject(CryptoFunction.SIGNATURE_AUTH, binding_key="TEST.A_15Y"), profile=profile
    )
    (stateful,) = [o for o in rec.options if o.algorithm == "LMS/XMSS"]
    assert "LMS/XMSS for firmware signing" in stateful.note


def test_an_uncited_profile_is_not_invented():
    with pytest.raises(NoCitedOptionError):
        Profile.load("CNSA_3_0")


# --- cost model --------------------------------------------------------------


def test_costs_come_from_the_cited_lookup_table():
    rec = recommend(subject(CryptoFunction.KEY_ESTABLISHMENT, "X25519"))
    kem = rec.options[0]
    assert kem.cost.public_key_bytes == 1184
    assert kem.cost.ciphertext_bytes == 1088
    assert kem.cost.citation.startswith("docs/architecture/")


def test_an_approximate_source_value_stays_a_range():
    """Part 8 writes SLH-DSA as '~7.8 KB – 49 KB'. Collapsing that to one
    number would invent precision the source does not have."""
    rec = recommend(subject(CryptoFunction.SIGNATURE_AUTH, binding_key="TEST.A_15Y"))
    (slh,) = [o for o in rec.options if o.algorithm == "SLH-DSA"]
    assert slh.cost.approximate is True
    assert slh.cost.signature_bytes is None
    assert slh.cost.signature_bytes_low and slh.cost.signature_bytes_high


# --- purposes Part 8 does not cover ------------------------------------------


def test_symmetric_encryption_gets_no_option_set_and_says_why():
    rec = recommend(subject(CryptoFunction.ENCRYPTION, "AES/GCM/NoPadding"))
    assert rec.options == ()
    assert "Grover" in rec.reason
    assert rec.insufficient_evidence is False, "we know the purpose; Part 8 just has no row"


def test_an_already_hybrid_context_is_told_to_confirm_not_to_migrate():
    rec = recommend(subject(CryptoFunction.HYBRID_KEX, "X25519MLKEM768"))
    assert rec.options == ()
    assert "classical is refused" in rec.reason


# --- over the shipped fixture -------------------------------------------------


def test_every_fixture_subject_gets_an_answer_or_an_honest_refusal():
    for s in load_subjects(DEFAULT_SUBJECTS):
        rec = recommend(s)
        assert rec.options or rec.reason, s.usage_context.usage_context_id
        if rec.insufficient_evidence:
            assert rec.options == ()


def test_draft_standards_are_never_recommended():
    """FIPS 206 is still draft and HQC's standard is in development; both are
    recorded in data/pqc_options.yaml as unusable."""
    offered = {
        o.algorithm
        for s in load_subjects(DEFAULT_SUBJECTS)
        for o in recommend(s).options
    }
    assert "FN-DSA" not in offered
    assert "HQC" not in offered

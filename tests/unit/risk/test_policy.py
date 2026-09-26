"""Policy deadlines over ledger rows (build-plan.md P22).

Built on the frozen §6 helpers, so every record here is a real ledger
evaluation; the overlay only reads what the ledger already decided.
"""
from datetime import date

from ecdat.model.usage_context import CryptoFunction
from ecdat.risk import confidentiality_ledger
from ecdat.risk.policy import PolicyStatus, annotate, load_policies

from .test_exposure_ledger import AS_OF, classical_at, context, inputs, stop_at, temporal, x


def _record(algorithm, migrations=()):
    return confidentiality_ledger.evaluate(
        inputs(
            usage_context=context(CryptoFunction.KEY_ESTABLISHMENT, algorithm),
            temporal=temporal(confirmed=date(2021, 1, 1)),
            binding=x("TEST.X_25Y"),
            migrations=migrations,
        )
    )


def _by(annotations, policy, milestone):
    (a,) = [a for a in annotations if a.policy_key == policy and a.milestone_key == milestone]
    return a


def test_only_usable_cited_policies_load():
    keys = {p.key for p in load_policies()}
    assert keys == {
        "IN_DST_CII",
        "IN_DST_ENTERPRISE",
        "NIST_IR_8547_IPD",
        "EU_HIGH_RISK",
        "EU_MEDIUM_RISK",
        "US_EO14412_HVA",
        "CA_CCCS_ITSM40001",
        "DE_BSI_TR02102_KEY_AGREEMENT",
        "DE_BSI_TR02102_SIGNATURES",
    }


def test_india_cii_dates_are_the_roadmaps_own():
    (cii,) = [p for p in load_policies() if p.key == "IN_DST_CII"]
    assert [m.date for m in cii.milestones] == [
        date(2026, 12, 31),
        date(2027, 12, 31),
        date(2028, 12, 31),
        date(2029, 12, 31),
    ]


def test_india_testing_labs_milestone_is_programme_scope_and_not_laid_over_a_row():
    """"by December 2026" (DST roadmap printed p. 36) is national testing-lab
    infrastructure, not something a single CII row meets -- same reasoning
    as `foundations` below."""
    annotations = annotate(_record("X25519"))
    assert not [a for a in annotations if a.milestone_key == "testing_labs"]


def test_us_eo14412_hva_dates_are_the_orders_own():
    (policy,) = [p for p in load_policies() if p.key == "US_EO14412_HVA"]
    assert [(m.key, m.date) for m in policy.milestones] == [
        ("key_establishment", date(2030, 12, 31)),
        ("digital_signatures", date(2031, 12, 31)),
    ]


def test_us_eo14412_hva_open_for_a_quantum_vulnerable_unmigrated_row():
    annotations = annotate(_record("X25519"))
    key_est = _by(annotations, "US_EO14412_HVA", "key_establishment")
    sigs = _by(annotations, "US_EO14412_HVA", "digital_signatures")
    assert key_est.status == PolicyStatus.OPEN
    assert key_est.deadline == date(2030, 12, 31)
    assert sigs.status == PolicyStatus.OPEN
    assert sigs.deadline == date(2031, 12, 31)


def test_us_eo14412_hva_met_when_observed_stop_precedes_the_deadline():
    record = _record("X25519", migrations=(stop_at(date(2026, 6, 1)),))
    assert _by(annotate(record), "US_EO14412_HVA", "key_establishment").status == PolicyStatus.MET


def test_quantum_vulnerable_unmigrated_row_is_open_with_days_remaining():
    annotations = annotate(_record("X25519"))
    full = _by(annotations, "IN_DST_CII", "full_migration")
    assert full.status == PolicyStatus.OPEN
    assert full.days_remaining == (date(2029, 12, 31) - AS_OF).days


def test_observed_stop_before_the_deadline_is_met():
    record = _record("X25519", migrations=(stop_at(date(2026, 6, 1)),))
    assert record.M == date(2026, 6, 1)
    assert _by(annotate(record), "IN_DST_CII", "full_migration").status == PolicyStatus.MET


def test_a_reopened_row_is_not_met():
    record = _record(
        "X25519", migrations=(stop_at(date(2024, 1, 1)), classical_at(date(2025, 1, 1)))
    )
    assert _by(annotate(record), "IN_DST_CII", "full_migration").status == PolicyStatus.OPEN


def test_pq_family_is_not_applicable():
    assert all(a.status == PolicyStatus.NOT_APPLICABLE for a in annotate(_record("ML-KEM")))


def test_unknown_or_uncited_family_is_undetermined_never_guessed():
    assert all(a.status == PolicyStatus.UNDETERMINED for a in annotate(_record(None)))
    assert all(a.status == PolicyStatus.UNDETERMINED for a in annotate(_record("SM2")))


def test_dh_is_now_cited_and_therefore_open():
    """NIST IR 8547 ipd Table 4 (vendored 2026-09-23) resolves DH."""
    assert _by(annotate(_record("DH")), "NIST_IR_8547_IPD", "disallowed").status == PolicyStatus.OPEN


def test_the_overlay_never_changes_the_band():
    record = _record("X25519")
    before = record.band
    annotate(record)
    assert record.band == before


def test_programme_milestones_are_never_laid_over_a_row():
    """India's "Building the foundations" is inventory and CBOM requests --
    an organisation meets it, a key does not."""
    annotations = annotate(_record("X25519"))
    assert not [a for a in annotations if a.milestone_key == "foundations"]
    assert _by(annotations, "IN_DST_CII", "high_priority").status == PolicyStatus.OPEN


def test_nist_112_bit_deprecation_does_not_bind_a_128_bit_curve():
    """X25519 is 128-bit (SP 800-186 Table 1): only "Disallowed after 2035" binds."""
    annotations = annotate(_record("X25519"))
    assert _by(annotations, "NIST_IR_8547_IPD", "deprecated_112").status == PolicyStatus.NOT_APPLICABLE
    assert _by(annotations, "NIST_IR_8547_IPD", "disallowed").status == PolicyStatus.OPEN


def test_nist_112_bit_deprecation_binds_p224():
    """P-224 is 112-bit (SP 800-186 Table 1)."""
    assert _by(annotate(_record("P-224")), "NIST_IR_8547_IPD", "deprecated_112").status == PolicyStatus.OPEN


def test_rsa_without_a_key_size_is_undetermined_for_the_112_bit_rule():
    """RSA's strength depends on its key size (SP 800-57 Table 2), which no row
    carries yet -- so the 2030 rule cannot be decided, and is not guessed."""
    annotations = annotate(_record("RSA"))
    assert _by(annotations, "NIST_IR_8547_IPD", "deprecated_112").status == PolicyStatus.UNDETERMINED
    assert _by(annotations, "NIST_IR_8547_IPD", "disallowed").status == PolicyStatus.OPEN


def test_eu_high_and_medium_risk_deadlines():
    annotations = annotate(_record("X25519"))
    assert _by(annotations, "EU_HIGH_RISK", "no_standalone_classical").deadline == date(2030, 12, 31)
    assert _by(annotations, "EU_MEDIUM_RISK", "no_standalone_classical").deadline == date(2035, 12, 31)
    assert _by(annotations, "EU_HIGH_RISK", "no_standalone_classical").status == PolicyStatus.OPEN


def test_ca_cccs_itsm40001_dates_are_the_roadmaps_own():
    (policy,) = [p for p in load_policies() if p.key == "CA_CCCS_ITSM40001"]
    assert [(m.key, m.date) for m in policy.milestones] == [
        ("initial_departmental_plan", date(2026, 4, 30)),
        ("annual_progress_reporting", date(2026, 4, 30)),
        ("high_priority", date(2031, 12, 31)),
        ("full_migration", date(2035, 12, 31)),
    ]


def test_ca_cccs_itsm40001_programme_milestones_are_never_laid_over_a_row():
    annotations = annotate(_record("X25519"))
    assert not [a for a in annotations if a.milestone_key == "initial_departmental_plan"]
    assert not [a for a in annotations if a.milestone_key == "annual_progress_reporting"]
    assert _by(annotations, "CA_CCCS_ITSM40001", "high_priority").status == PolicyStatus.OPEN
    assert _by(annotations, "CA_CCCS_ITSM40001", "full_migration").deadline == date(2035, 12, 31)


def test_de_bsi_tr02102_key_agreement_and_signature_deadlines():
    annotations = annotate(_record("X25519"))
    key_agreement = _by(annotations, "DE_BSI_TR02102_KEY_AGREEMENT", "no_classical_only_key_agreement")
    signatures = _by(annotations, "DE_BSI_TR02102_SIGNATURES", "no_classical_only_signatures")
    assert key_agreement.deadline == date(2031, 12, 31)
    assert key_agreement.status == PolicyStatus.OPEN
    assert signatures.deadline == date(2035, 12, 31)
    assert signatures.status == PolicyStatus.OPEN


def test_de_bsi_tr02102_met_when_observed_stop_precedes_the_deadline():
    record = _record("X25519", migrations=(stop_at(date(2026, 6, 1)),))
    assert (
        _by(annotate(record), "DE_BSI_TR02102_KEY_AGREEMENT", "no_classical_only_key_agreement").status
        == PolicyStatus.MET
    )

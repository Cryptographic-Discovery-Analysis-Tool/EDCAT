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
    assert keys == {"IN_DST_CII", "IN_DST_ENTERPRISE", "NIST_IR_8547_IPD"}
    assert "EU_COORDINATED_ROADMAP_2025" not in keys, "EU roadmap is not vendored yet"
    assert "NIST_IR_8547_IPD_DEPRECATE_112" not in keys, "needs a key strength no row carries"


def test_india_cii_dates_are_the_roadmaps_own():
    (cii,) = [p for p in load_policies() if p.key == "IN_DST_CII"]
    assert [m.date for m in cii.milestones] == [date(2027, 12, 31), date(2028, 12, 31), date(2029, 12, 31)]


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

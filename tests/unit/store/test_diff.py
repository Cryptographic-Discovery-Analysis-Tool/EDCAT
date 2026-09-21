"""Run-to-run diff (build-plan.md P13; Pramana_Ledger_Spec.md SS5.7).

Reuses the frozen-set helpers from test_exposure_ledger.py so every fixture
here is a real, cited ledger evaluation -- nothing invented to match the
diff logic.
"""
from datetime import date, datetime, timezone

from ecdat.risk import confidentiality_ledger
from ecdat.risk.record import ExposureBand
from ecdat.store.diff import DiffClass, diff_runs
from ecdat.store.repository import Run

from ..risk.test_exposure_ledger import (
    Z_AGGR,
    Z_CENTRAL,
    classical_at,
    context,
    inputs,
    stop_at,
    temporal,
    x,
)
from ecdat.model.usage_context import CryptoFunction

RECORDED_AT = datetime(2026, 9, 21, tzinfo=timezone.utc)


def _record(*, scenario=Z_CENTRAL, migrations=(), uid="UC-1"):
    return confidentiality_ledger.evaluate(
        inputs(
            scenario=scenario,
            usage_context=context(CryptoFunction.KEY_TRANSPORT, "RSA", uid=uid),
            temporal=temporal(confirmed=date(2021, 1, 1)),
            binding=x("TEST.X_7Y"),
            migrations=migrations,
        )
    )


def _run(run_id, records):
    return Run(
        run_id=run_id,
        target_id="pay-1",
        scenario_id="Z_central",
        as_of=date(2026, 9, 18),
        recorded_at=RECORDED_AT,
        records=tuple(records),
    )


def test_migrated_when_a_stop_is_newly_observed():
    old = _run("run-1", [_record(migrations=())])
    new = _run("run-2", [_record(migrations=(stop_at(date(2026, 6, 1)),))])

    result = diff_runs(old, new)
    assert len(result.rows) == 1
    row = result.rows[0]
    assert row.diff_class == DiffClass.MIGRATED
    assert row.old_record_id and row.new_record_id


def test_regressed_when_classical_reobserved_after_a_stop():
    stopped = (stop_at(date(2024, 1, 1)),)
    reopened = (stop_at(date(2024, 1, 1)), classical_at(date(2025, 1, 1)))

    old = _run("run-1", [_record(migrations=stopped)])
    new = _run("run-2", [_record(migrations=reopened)])

    result = diff_runs(old, new)
    assert result.rows[0].diff_class == DiffClass.REGRESSED


def test_changed_when_band_moves_without_a_migration_event():
    old = _run("run-1", [_record(scenario=Z_AGGR)])
    new = _run("run-2", [_record(scenario=Z_CENTRAL)])

    result = diff_runs(old, new)
    row = result.rows[0]
    assert row.diff_class == DiffClass.CHANGED
    assert row.old_band == ExposureBand.BLEEDING
    assert row.new_band == ExposureBand.SAVABLE


def test_unchanged_when_nothing_moves():
    old = _run("run-1", [_record()])
    new = _run("run-2", [_record()])

    result = diff_runs(old, new)
    assert result.rows[0].diff_class == DiffClass.UNCHANGED


def test_new_and_removed_rows_are_named_not_dropped():
    old = _run("run-1", [_record(uid="UC-old")])
    new = _run("run-2", [_record(uid="UC-new")])

    result = diff_runs(old, new)
    classes = {row.usage_context_id: row.diff_class for row in result.rows}
    assert classes == {"UC-old": DiffClass.REMOVED, "UC-new": DiffClass.NEW}


def test_a_configuration_only_claim_does_not_migrate_the_row():
    """SS5.7's red-team fix, persisted across runs: an unobserved (INFERRED)
    migration claim must not move a row to MIGRATED, exactly as it does not
    stop the clock within one run."""
    from ecdat.model.epistemic import EpistemicState

    claimed_not_observed = stop_at(date(2026, 6, 1)).model_copy(
        update={"status": EpistemicState.INFERRED}
    )
    old = _run("run-1", [_record(migrations=())])
    new = _run("run-2", [_record(migrations=(claimed_not_observed,))])

    result = diff_runs(old, new)
    assert result.rows[0].diff_class != DiffClass.MIGRATED


def test_rows_are_ordered_migrated_and_new_before_removed_and_unchanged():
    old = _run(
        "run-1",
        [_record(uid="UC-unchanged"), _record(uid="UC-gone"), _record(uid="UC-migrated")],
    )
    new = _run(
        "run-2",
        [
            _record(uid="UC-unchanged"),
            _record(uid="UC-migrated", migrations=(stop_at(date(2026, 6, 1)),)),
            _record(uid="UC-fresh"),
        ],
    )

    result = diff_runs(old, new)
    classes_in_order = [row.diff_class for row in result.rows]
    assert classes_in_order.index(DiffClass.MIGRATED) < classes_in_order.index(
        DiffClass.UNCHANGED
    )
    assert classes_in_order.index(DiffClass.NEW) < classes_in_order.index(DiffClass.UNCHANGED)
    assert classes_in_order.index(DiffClass.REMOVED) < classes_in_order.index(
        DiffClass.UNCHANGED
    )

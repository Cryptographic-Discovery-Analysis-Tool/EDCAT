"""The run store itself (build-plan.md P13)."""
from datetime import date, datetime, timezone

import pytest

from ecdat.risk import confidentiality_ledger
from ecdat.store.repository import (
    InvalidRunIdError,
    JsonlRunStore,
    NoSuchRunError,
    Run,
    new_run_id,
)

from ..risk.test_exposure_ledger import context, inputs, temporal, x
from ecdat.model.usage_context import CryptoFunction

RECORDED_AT = datetime(2026, 9, 21, tzinfo=timezone.utc)


def _record(uid="UC-1"):
    return confidentiality_ledger.evaluate(
        inputs(
            usage_context=context(CryptoFunction.KEY_TRANSPORT, "RSA", uid=uid),
            temporal=temporal(confirmed=date(2021, 1, 1)),
            binding=x("TEST.X_7Y"),
        )
    )


def _run(run_id="run-1", target_id="pay-1"):
    return Run(
        run_id=run_id,
        target_id=target_id,
        scenario_id="Z_central",
        as_of=date(2026, 9, 18),
        recorded_at=RECORDED_AT,
        records=(_record(),),
    )


def test_new_run_id_is_unique_and_valid():
    ids = {new_run_id() for _ in range(50)}
    assert len(ids) == 50


def test_save_then_load_round_trips(tmp_path):
    store = JsonlRunStore(tmp_path)
    run = _run()
    store.save(run)

    loaded = store.load(run.run_id)
    assert loaded.run_id == run.run_id
    assert loaded.records[0].band == run.records[0].band
    assert loaded.records[0].inputs_sha256 == run.records[0].inputs_sha256


def test_save_refuses_to_overwrite_an_existing_run(tmp_path):
    store = JsonlRunStore(tmp_path)
    run = _run()
    store.save(run)
    with pytest.raises(ValueError):
        store.save(run)


def test_load_missing_run_raises(tmp_path):
    store = JsonlRunStore(tmp_path)
    with pytest.raises(NoSuchRunError):
        store.load("run-does-not-exist")


def test_list_runs_orders_by_recorded_at(tmp_path):
    store = JsonlRunStore(tmp_path)
    early = _run("run-early")
    late = Run(
        run_id="run-late",
        target_id="pay-1",
        scenario_id="Z_central",
        as_of=date(2026, 9, 19),
        recorded_at=datetime(2026, 9, 22, tzinfo=timezone.utc),
        records=(_record(),),
    )
    store.save(late)
    store.save(early)

    summaries = store.list_runs()
    assert [s.run_id for s in summaries] == ["run-early", "run-late"]
    assert summaries[0].row_count == 1


def test_list_runs_filters_by_target(tmp_path):
    store = JsonlRunStore(tmp_path)
    store.save(_run("run-a", target_id="pay-1"))
    store.save(_run("run-b", target_id="pay-2"))

    assert [s.run_id for s in store.list_runs(target_id="pay-2")] == ["run-b"]


@pytest.mark.parametrize("bad_id", ["", "../etc", "a/b", "a b", "..", "-leading-dash"])
def test_invalid_run_ids_are_rejected(tmp_path, bad_id):
    store = JsonlRunStore(tmp_path)
    with pytest.raises((InvalidRunIdError, Exception)):
        store.load(bad_id)

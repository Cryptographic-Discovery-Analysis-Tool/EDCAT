"""Evidence Closure Engine (Pramana_Ledger_Spec.md §5.8).

Phase 5 acceptance (§7.2): "each UNBOUNDED case -> exactly one minimum task;
impact sets correct".

Builders are local rather than shared with tests/unit/risk: that file encodes
the frozen §6 expectations and is deliberately self-contained, so a change
made for this file's convenience cannot quietly move a frozen expectation.
"""
from datetime import date

import pytest

from ecdat.closure.engine import ClosureTask, closure_queue, tasks_for
from ecdat.context.binding import Lifetime
from ecdat.model.epistemic import EpistemicState
from ecdat.model.field_value import FieldValue
from ecdat.model.temporal import MigrationEvidence, TemporalEvidence
from ecdat.model.usage_context import CryptoFunction, UsageContext
from ecdat.risk import authentication_ledger, confidentiality_ledger
from ecdat.risk.record import ExposureBand, LedgerInputs
from ecdat.risk.scenarios import (
    CaptureAssumption,
    CaptureMode,
    Policy,
    Scenario,
    binding_for,
)

AS_OF = date(2026, 9, 18)
OBSERVED = EpistemicState.KNOWN
Z_CENTRAL = Scenario.load("Z_central")


def policy(mode=CaptureMode.SINCE_CONFIRMED, since=None, **kw):
    return Policy(
        capture_assumption=CaptureAssumption(mode=mode, since=since),
        rollout_Y_default=Lifetime(years=1),
        **kw,
    )


def context(function, algorithm=None, *, state=OBSERVED, algorithm_state=None, uid="UC-1"):
    algorithm_state = algorithm_state or state
    return UsageContext(
        usage_context_id=uid,
        asset_id="PAY-001",
        surface_id="tls:pay:443",
        protocol_context="observed handshake",
        function=FieldValue[CryptoFunction](
            value=function,
            state=state,
            evidence_refs=("E-probe",) if state == OBSERVED else (),
            rule_id="FUNC-TLS-KEX-001" if function is not None else None,
        ),
        algorithm=(
            FieldValue[str](
                value=algorithm,
                state=algorithm_state,
                evidence_refs=("E-probe",) if algorithm_state == OBSERVED else (),
            )
            if algorithm
            else None
        ),
    )


def temporal(confirmed=None, not_before=None):
    return TemporalEvidence(
        surface_id="tls:pay:443",
        observation_ts=AS_OF,
        first_observed=(
            FieldValue[date](value=confirmed, state=OBSERVED, evidence_refs=("E-probe",))
            if confirmed
            else None
        ),
        not_before=(
            FieldValue[date](value=not_before, state=OBSERVED, evidence_refs=("E-cert",))
            if not_before
            else None
        ),
    )


def inputs(**kw):
    kw.setdefault("as_of", AS_OF)
    kw.setdefault("scenario", Z_CENTRAL)
    kw.setdefault("policy", policy())
    return LedgerInputs(**kw)


def x(key):
    return binding_for(target_id="PAY-001", key=key, source_ref="operator declaration")


def conf(**kw):
    return confidentiality_ledger.evaluate(inputs(**kw))


# --- one missing input, one task -------------------------------------------


def test_missing_go_live_yields_exactly_one_task_naming_the_minimum_evidence():
    """§6: 'Missing go-live, only notBefore | UNBOUNDED; task "declare go-live
    or take first observation"'."""
    record = conf(
        usage_context=context(CryptoFunction.KEY_ESTABLISHMENT, "X25519"),
        temporal=temporal(not_before=date(2019, 3, 1)),
        binding=x("TEST.X_25Y"),
    )
    (task,) = tasks_for(record)
    assert task.key == "start_confirmed"
    assert "go-live" in task.collect
    assert task.rows == ("UC-1",)


def test_missing_binding_yields_the_data_class_task_not_the_start_task():
    """The row is missing X *and* a confirmed start. Only the first blocking
    input gets a task: telling an operator to collect two things when the
    first one might make the second irrelevant is not a minimum task."""
    record = conf(
        usage_context=context(CryptoFunction.KEY_ESTABLISHMENT, "X25519"),
        temporal=temporal(not_before=date(2019, 3, 1)),
    )
    (task,) = tasks_for(record)
    assert task.key == "data_class_binding"


def test_unknown_function_task_promises_no_band():
    """§6: 'Unknown KEX | UNBOUNDED, no conditional'. The task still exists --
    what it cannot do is say what the answer will be."""
    record = conf(
        usage_context=context(None, state=EpistemicState.UNKNOWN),
        temporal=temporal(confirmed=date(2021, 1, 1)),
        binding=x("TEST.X_25Y"),
    )
    (task,) = tasks_for(record)
    assert task.key == "function"
    assert task.reachable_bands == ()
    assert task.narrowed is False
    assert task.worst_reachable is None


def test_a_bounded_row_generates_no_task():
    record = conf(
        usage_context=context(CryptoFunction.KEY_ESTABLISHMENT, "X25519"),
        temporal=temporal(confirmed=date(2021, 1, 1)),
        binding=x("TEST.X_25Y"),
    )
    assert record.band == ExposureBand.BLEEDING
    assert tasks_for(record) == ()


# --- decision impact is computed, not asserted -----------------------------


def test_unresolvable_family_task_reaches_both_safe_and_bleeding():
    """Collecting the family moves the row between the two ends. That is the
    impact set, computed by re-running the ledger over cited families."""
    record = conf(
        usage_context=context(CryptoFunction.KEY_ESTABLISHMENT, "SM2"),
        temporal=temporal(confirmed=date(2021, 1, 1)),
        binding=x("TEST.X_25Y"),
    )
    (task,) = tasks_for(record)
    assert task.key == "algorithm_family"
    assert set(task.reachable_bands) == {ExposureBand.BLEEDING, ExposureBand.SAFE}
    assert task.worst_reachable == ExposureBand.BLEEDING
    assert task.longest_reachable_window_days > 0


def test_missing_data_class_task_brackets_the_reachable_bands():
    record = conf(
        usage_context=context(CryptoFunction.KEY_ESTABLISHMENT, "X25519"),
        temporal=temporal(confirmed=date(2021, 1, 1)),
    )
    (task,) = tasks_for(record)
    assert task.key == "data_class_binding"
    assert set(task.reachable_bands) == {ExposureBand.BLEEDING, ExposureBand.SAVABLE}


def test_inferred_input_task_reaches_the_conditional_band():
    """§6: 'Inferred configuration (PAY-001) | UNBOUNDED + conditional
    BLEEDING'. The task's reachable set must agree with the row's conditional
    band -- they are two views of the same computation."""
    record = conf(
        usage_context=context(
            CryptoFunction.KEY_TRANSPORT,
            "RSA",
            algorithm_state=EpistemicState.INFERRED,
        ),
        temporal=temporal(confirmed=date(2021, 1, 1)),
        binding=x("TEST.X_25Y"),
    )
    (task,) = tasks_for(record)
    assert task.key == "inferred_algorithm"
    assert task.reachable_bands == (record.conditional_band,)


def test_start_task_brackets_the_window_between_possible_and_now():
    record = conf(
        usage_context=context(CryptoFunction.KEY_ESTABLISHMENT, "X25519"),
        temporal=temporal(not_before=date(2019, 3, 1)),
        binding=x("TEST.X_25Y"),
    )
    (task,) = tasks_for(record)
    assert task.reachable_bands == (ExposureBand.BLEEDING,)
    assert task.longest_reachable_window_days == (AS_OF - date(2019, 3, 1)).days


# --- §6 row 6: a bounded row can still be waiting on evidence --------------


def test_config_only_hybrid_generates_a_probe_task_on_a_bleeding_row():
    """§6: 'Hybrid configured, not observed | M=inf -> BLEEDING; closure task
    "probe negotiated group from vantage"'."""
    configured = MigrationEvidence(
        surface_id="tls:pay:443",
        vantage="config-file",
        observed_at=date(2026, 6, 1),
        negotiated_group="X25519MLKEM768",
        classical_still_accepted=False,
        status=EpistemicState.INFERRED,
    )
    record = conf(
        usage_context=context(CryptoFunction.KEY_ESTABLISHMENT, "X25519"),
        temporal=temporal(confirmed=date(2021, 1, 1)),
        binding=x("TEST.X_25Y"),
        migrations=(configured,),
    )
    assert record.band == ExposureBand.BLEEDING
    (task,) = tasks_for(record)
    assert task.key == "migration_observation"
    assert "probe" in task.collect.lower()
    assert set(task.reachable_bands) == {ExposureBand.UNSAVABLE, ExposureBand.BLEEDING}


# --- the authentication ledger ---------------------------------------------


def test_missing_authenticity_lifetime_task_separates_rotate_from_resign():
    record = authentication_ledger.evaluate(
        inputs(
            usage_context=context(CryptoFunction.SIGNATURE_AUTH, uid="UC-auth"),
            temporal=temporal(confirmed=date(2026, 1, 1)),
        )
    )
    assert record.band == ExposureBand.UNBOUNDED
    (task,) = tasks_for(record)
    assert task.key == "authenticity_lifetime"
    assert set(task.reachable_bands) == {
        ExposureBand.ROTATE_BEFORE_Z,
        ExposureBand.RESIGN_BEFORE_Z,
    }


# --- the queue --------------------------------------------------------------


def test_queue_merges_one_task_across_the_rows_it_would_bound():
    rows = [
        conf(
            usage_context=context(CryptoFunction.KEY_ESTABLISHMENT, "X25519", uid=uid),
            temporal=temporal(not_before=date(2019, 3, 1)),
            binding=x("TEST.X_25Y"),
        )
        for uid in ("UC-a", "UC-b", "UC-c")
    ]
    (task,) = closure_queue(rows)
    assert task.key == "start_confirmed"
    assert task.rows == ("UC-a", "UC-b", "UC-c")


def test_queue_ranks_worst_reachable_band_first_then_rows_affected():
    """§5.8: 'rank tasks lexicographically (worst reachable band, rows
    affected, longest reachable window)'."""
    bleeding_reachable = conf(
        usage_context=context(CryptoFunction.KEY_ESTABLISHMENT, "SM2", uid="UC-dh"),
        temporal=temporal(confirmed=date(2021, 1, 1)),
        binding=x("TEST.X_25Y"),
    )
    unknown_function = conf(
        usage_context=context(None, state=EpistemicState.UNKNOWN, uid="UC-unk"),
        temporal=temporal(confirmed=date(2021, 1, 1)),
        binding=x("TEST.X_25Y"),
    )
    queue = closure_queue([unknown_function, bleeding_reachable])
    assert [task.key for task in queue] == ["algorithm_family", "function"]


def test_more_rows_outranks_fewer_at_the_same_band():
    def row(uid, family):
        return conf(
            usage_context=context(CryptoFunction.KEY_ESTABLISHMENT, family, uid=uid),
            temporal=temporal(confirmed=date(2021, 1, 1)),
            binding=x("TEST.X_25Y"),
        )

    many = [row(f"UC-{i}", "SM2") for i in range(3)]
    one = conf(
        usage_context=context(
            CryptoFunction.KEY_TRANSPORT,
            "RSA",
            algorithm_state=EpistemicState.INFERRED,
            uid="UC-inf",
        ),
        temporal=temporal(confirmed=date(2021, 1, 1)),
        binding=x("TEST.X_25Y"),
    )
    queue = closure_queue([one, *many])
    by_key = {task.key: task for task in queue}
    assert by_key["algorithm_family"].worst_reachable == ExposureBand.BLEEDING
    assert by_key["inferred_algorithm"].worst_reachable == ExposureBand.BLEEDING
    assert queue.index(by_key["algorithm_family"]) < queue.index(by_key["inferred_algorithm"])


# --- the catalogue is the only source of task text -------------------------


def test_every_task_carries_its_citation_and_its_reason():
    record = conf(
        usage_context=context(CryptoFunction.KEY_ESTABLISHMENT, "X25519"),
        temporal=temporal(not_before=date(2019, 3, 1)),
        binding=x("TEST.X_25Y"),
    )
    (task,) = tasks_for(record)
    assert task.citation.startswith("docs/architecture/")
    assert len(task.bounds) > 40, "a task must say why it bounds the row"
    assert isinstance(task, ClosureTask)


def test_closure_impact_never_mutates_the_record_it_was_computed_from():
    record = conf(
        usage_context=context(CryptoFunction.KEY_ESTABLISHMENT, "SM2"),
        temporal=temporal(confirmed=date(2021, 1, 1)),
        binding=x("TEST.X_25Y"),
    )
    before = record.model_dump_json()
    tasks_for(record)
    assert record.model_dump_json() == before

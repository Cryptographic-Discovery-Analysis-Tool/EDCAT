"""Pramana_Ledger_Spec.md §5.2 / §5.7 -- two dates, never one."""
from datetime import date

import pytest
from pydantic import ValidationError

from ecdat.model.epistemic import EpistemicState
from ecdat.model.field_value import FieldValue
from ecdat.model.temporal import MigrationEvidence, TemporalEvidence

AS_OF = date(2026, 9, 18)


def _d(value, state, refs=()):
    return FieldValue[date](value=value, state=state, evidence_refs=refs)


def _te(**kw):
    return TemporalEvidence(surface_id="tls:pay:443", observation_ts=AS_OF, **kw)


def test_not_before_alone_never_confirms():
    """§5.2: 'notBefore alone never confirms.'"""
    te = _te(not_before=_d(date(2019, 3, 1), EpistemicState.KNOWN, ("E-cert",)))
    assert te.possible_since.value == date(2019, 3, 1)
    assert te.confirmed_since(accept_declared_go_live=True) is None


def test_snapshot_presence_never_confirms():
    te = _te(first_snapshot_containing=_d(date(2022, 1, 1), EpistemicState.KNOWN, ("E-s",)))
    assert te.possible_since.value == date(2022, 1, 1)
    assert te.confirmed_since(accept_declared_go_live=True) is None


def test_notbefore_2019_first_observed_2024_gives_both_dates():
    """§6: 'notBefore 2019, first_observed 2024, no go-live ->
    possible 2019 / confirmed 2024'."""
    te = _te(
        not_before=_d(date(2019, 3, 1), EpistemicState.KNOWN, ("E-cert",)),
        first_observed=_d(date(2024, 7, 9), EpistemicState.KNOWN, ("E-probe",)),
    )
    assert te.possible_since.value == date(2019, 3, 1)
    assert te.confirmed_since(accept_declared_go_live=False).value == date(2024, 7, 9)


def test_confirmed_is_never_earlier_than_possible():
    for kwargs in (
        dict(not_before=_d(date(2019, 1, 1), EpistemicState.KNOWN, ("E1",))),
        dict(
            declared_go_live=_d(date(2020, 1, 1), EpistemicState.DECLARED),
            first_observed=_d(date(2024, 1, 1), EpistemicState.KNOWN, ("E2",)),
        ),
        dict(first_observed=_d(date(2021, 5, 5), EpistemicState.KNOWN, ("E3",))),
    ):
        te = _te(**kwargs)
        confirmed = te.confirmed_since(accept_declared_go_live=True)
        if confirmed is not None:
            assert confirmed.value >= te.possible_since.value


def test_declared_go_live_confirms_only_when_policy_allows():
    te = _te(declared_go_live=_d(date(2020, 6, 1), EpistemicState.DECLARED))
    assert te.confirmed_since(accept_declared_go_live=False) is None
    assert te.confirmed_since(accept_declared_go_live=True).value == date(2020, 6, 1)


def test_selection_preserves_the_winning_input_state_and_evidence():
    """A min() makes no new claim, so it must not weaken one (module
    docstring; CFG-001 would otherwise cap KNOWN -> INFERRED)."""
    te = _te(first_observed=_d(date(2021, 1, 1), EpistemicState.KNOWN, ("E-probe",)))
    confirmed = te.confirmed_since(accept_declared_go_live=False)
    assert confirmed.state == EpistemicState.KNOWN
    assert confirmed.evidence_refs == ("E-probe",)


def test_status_per_field_reports_absence_as_not_observed():
    te = _te(not_before=_d(date(2019, 1, 1), EpistemicState.KNOWN, ("E1",)))
    status = te.status_per_field
    assert status["not_before"] == EpistemicState.KNOWN
    assert status["first_observed"] == EpistemicState.NOT_OBSERVED


def test_no_evidence_at_all_yields_no_dates():
    te = _te()
    assert te.possible_since is None
    assert te.confirmed_since(accept_declared_go_live=True) is None


# --- §5.7 hybrid clock -----------------------------------------------------


def _me(**kw):
    kw.setdefault("surface_id", "tls:pay:443")
    kw.setdefault("vantage", "dmz-probe-1")
    kw.setdefault("observed_at", date(2026, 6, 1))
    return MigrationEvidence(**kw)


def test_observed_migration_requires_evidence():
    with pytest.raises(ValidationError, match="fake M"):
        _me(status=EpistemicState.KNOWN, classical_still_accepted=False)


def test_observed_negotiation_with_classical_off_stops_the_clock():
    assert _me(
        status=EpistemicState.KNOWN,
        classical_still_accepted=False,
        negotiated_group="X25519MLKEM768",
        evidence_refs=("E-probe",),
    ).stops_the_clock


def test_config_only_hybrid_never_stops_the_clock():
    """§5.7 / §6 'Hybrid configured, not observed'."""
    assert not _me(
        status=EpistemicState.INFERRED,
        classical_still_accepted=False,
        negotiated_group="X25519MLKEM768",
    ).stops_the_clock


def test_observed_hybrid_with_classical_still_accepted_does_not_stop():
    assert not _me(
        status=EpistemicState.KNOWN,
        classical_still_accepted=True,
        negotiated_group="X25519MLKEM768",
        evidence_refs=("E-probe",),
    ).stops_the_clock

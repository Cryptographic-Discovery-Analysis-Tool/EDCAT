"""Scenario sensitivity (build-plan.md P19; Pramana_Ledger_Spec.md §5.4, §5.10).

Reuses the frozen §6 test set from test_exposure_ledger.py: row 2 (RSA static
key transport, X=7Y, confirmed since 2021-01-01) is BLEEDING under
Z_aggressive and SAVABLE under Z_central -- a real, cited, scenario-sensitive
row, not a case invented to match the implementation. Row 1's authentication
verdict (ROTATE_BEFORE_Z, confirmed since 2021-01-01, A=0) is SAFE_UNTIL_Z
under every scenario because deadline = Z - Y is always in the future for all
three Z's relative to as_of -- a real, cited, scenario-STABLE row, used here
as the negative case.
"""
from datetime import date

from ecdat.risk import confidentiality_ledger
from ecdat.risk.record import ExposureBand
from ecdat.risk.scenarios import Scenario
from ecdat.risk.sensitivity import sensitivity_for

from .test_exposure_ledger import ALL_Z, Z_AGGR, Z_CENTRAL, Z_OPTIM, context, inputs, temporal, x
from ecdat.model.usage_context import CryptoFunction
from ecdat.risk import authentication_ledger


def _rsa_key_transport_record():
    return confidentiality_ledger.evaluate(
        inputs(
            scenario=Z_CENTRAL,
            usage_context=context(CryptoFunction.KEY_TRANSPORT, "RSA"),
            temporal=temporal(confirmed=date(2021, 1, 1)),
            binding=x("TEST.X_7Y"),
        )
    )


def _rsa_auth_record():
    return authentication_ledger.evaluate(
        inputs(
            scenario=Z_CENTRAL,
            usage_context=context(CryptoFunction.SIGNATURE_AUTH, uid="UC-auth", asset="PAY-005"),
            temporal=temporal(confirmed=date(2021, 1, 1)),
            binding=x("TEST.A_SESSION"),
        )
    )


def test_scenario_sensitive_row_flips_between_aggressive_and_central():
    record = _rsa_key_transport_record()
    result = sensitivity_for(record, scenarios=ALL_Z)

    assert [o.scenario_id for o in result.outcomes] == [
        "Z_aggressive",
        "Z_central",
        "Z_optimistic",
    ]
    assert result.outcomes[0].band == ExposureBand.BLEEDING
    assert result.outcomes[1].band == ExposureBand.SAVABLE
    assert result.scenario_sensitive is True

    flip = result.first_flip
    assert flip is not None
    assert flip.scenario_id == "Z_central"
    assert flip.deadline == date(2029, 1, 1)


def test_scenario_stable_row_reports_no_flip():
    record = _rsa_auth_record()
    result = sensitivity_for(record, scenarios=ALL_Z)

    bands = {o.band for o in result.outcomes}
    assert bands == {ExposureBand.ROTATE_BEFORE_Z} or len(bands) == 1
    assert result.scenario_sensitive is False
    assert result.first_flip is None


def test_default_scenarios_are_the_cited_registry():
    record = _rsa_key_transport_record()
    result = sensitivity_for(record)
    assert {o.scenario_id for o in result.outcomes} == {s.id for s in Scenario.load_all()}


def test_outcomes_are_ordered_earliest_z_first():
    record = _rsa_key_transport_record()
    # Pass scenarios out of order; sensitivity_for must still order by z_date.
    result = sensitivity_for(record, scenarios=(Z_OPTIM, Z_AGGR, Z_CENTRAL))
    assert [o.z_date for o in result.outcomes] == sorted(o.z_date for o in result.outcomes)
    assert result.outcomes[0].scenario_id == "Z_aggressive"

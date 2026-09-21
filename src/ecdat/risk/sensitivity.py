"""Scenario sensitivity: print the date the ranking flips (build-plan.md P19;
Pramana_Ledger_Spec.md §5.4, §5.10).

The deck's weakest-sounding admission is "we do not know when Z is." This
module is what turns that into an output instead of an apology: every row is
re-run under all three cited Z dates (data/scenarios.yaml), and the row says
plainly whether its band depends on which one turns out to be right.

Nothing here is interpolated or invented. Each date shown is `evaluate()`'s
own output for a cited scenario -- the same machinery `replay()` already uses
to re-derive a record for its stored scenario, pointed at the scenario axis
instead of the evidence axis. There is no probabilistic Z (§5.12) and no
attempt to compute a continuous crossing date between two cited scenarios:
that would require interpolating between two assumptions the operator picked,
which is exactly the weighted-score-through-the-side-door failure §5.12
rejects. What is reported instead is the plain fact three cited runs can
prove: which named scenario is the first, in Z order, whose band differs from
the earliest scenario's.
"""
from __future__ import annotations

from datetime import date

from pydantic import BaseModel, ConfigDict

from ecdat.risk import authentication_ledger, confidentiality_ledger
from ecdat.risk.record import CalculationRecord, ExposureBand
from ecdat.risk.scenarios import Scenario


class ScenarioOutcome(BaseModel):
    """One cited scenario's band and deadline for one row."""

    model_config = ConfigDict(frozen=True)

    scenario_id: str
    label: str
    z_date: date
    band: ExposureBand
    deadline: date | None


class ScenarioSensitivity(BaseModel):
    """§5.10's ranking, re-run under every cited Z. `outcomes` is ordered by
    `z_date`, earliest first, so `outcomes[0]` is always the baseline a flip
    is measured against."""

    model_config = ConfigDict(frozen=True)

    record_id: str
    usage_context_id: str
    outcomes: tuple[ScenarioOutcome, ...]

    @property
    def scenario_sensitive(self) -> bool:
        """True when this row's band is not the same under every cited Z --
        the plain, computed answer to "does this depend on which scenario is
        right", with no threshold or weight involved."""
        return len({outcome.band for outcome in self.outcomes}) > 1

    @property
    def first_flip(self) -> ScenarioOutcome | None:
        """The earliest-Z scenario, after the baseline, whose band differs
        from the baseline's. None when the row is not scenario-sensitive, or
        when fewer than two scenarios were evaluated."""
        if len(self.outcomes) < 2:
            return None
        baseline_band = self.outcomes[0].band
        for outcome in self.outcomes[1:]:
            if outcome.band != baseline_band:
                return outcome
        return None


def _evaluate(inputs, *, is_auth: bool, record_id: str) -> CalculationRecord | None:
    ledger = authentication_ledger if is_auth else confidentiality_ledger
    try:
        return ledger.evaluate(inputs, record_id=record_id)
    except (confidentiality_ledger.LedgerNotApplicable, ValueError):
        # A candidate scenario this row's inputs cannot be evaluated under
        # (e.g. a policy/evidence combination the ledger refuses) contributes
        # no outcome rather than a fabricated one.
        return None


def sensitivity_for(
    record: CalculationRecord, *, scenarios: tuple[Scenario, ...] | None = None
) -> ScenarioSensitivity:
    """Re-run `record`'s own ledger under every cited scenario, band and
    deadline reported side by side, ordered earliest-Z first."""
    is_auth = record.rule_version == authentication_ledger.RULE_ID
    if scenarios is None:
        scenarios = Scenario.load_all()
    ordered = sorted(scenarios, key=lambda scenario: scenario.z_date)

    outcomes: list[ScenarioOutcome] = []
    for scenario in ordered:
        candidate_inputs = record.inputs.model_copy(update={"scenario": scenario})
        outcome = _evaluate(candidate_inputs, is_auth=is_auth, record_id=record.record_id)
        if outcome is None:
            continue
        outcomes.append(
            ScenarioOutcome(
                scenario_id=scenario.id,
                label=scenario.label,
                z_date=scenario.z_date,
                band=outcome.band,
                deadline=outcome.deadline,
            )
        )

    return ScenarioSensitivity(
        record_id=record.record_id,
        usage_context_id=record.usage_context_id,
        outcomes=tuple(outcomes),
    )

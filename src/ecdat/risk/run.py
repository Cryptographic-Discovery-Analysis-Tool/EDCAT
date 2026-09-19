"""Routing evidence to the right ledger (Pramana_Ledger_Spec.md §5.5, §5.6).

A `LedgerSubject` is everything we have collected about one usage context,
with NO scenario and NO policy attached. That separation is the point: the
same subject is evaluated against all three Z dates and against whatever
capture assumption the operator picks, and the answers differ. Baking a
scenario into the evidence would make the assumption invisible again, which is
the failure the two-ledger design exists to prevent.

Routing is by crypto function and nothing else:

* signatures      -> the authentication ledger (§5.6)
* KEX / key transport / hybrid -> the confidentiality ledger (§5.5)
* symmetric encryption -> NEITHER. §5.5: "Grover cases go to policy flags, not
  the ledger." A Grover case is a key-size question, not a deadline, and
  giving it a band would imply a clock it does not have.
* unknown function -> the confidentiality ledger, which produces UNBOUNDED and
  a closure task. It goes there rather than nowhere because a row that vanishes
  is a row nobody chases.
"""
from __future__ import annotations

from datetime import date

from pydantic import BaseModel, ConfigDict

from ecdat.model.temporal import MigrationEvidence, TemporalEvidence
from ecdat.model.usage_context import (
    AUTHENTICATION_FUNCTIONS,
    CONFIDENTIALITY_FUNCTIONS,
    CryptoFunction,
    UsageContext,
)
from ecdat.risk import authentication_ledger, confidentiality_ledger
from ecdat.risk.record import CalculationRecord, LedgerInputs
from ecdat.risk.scenarios import NoCitedLifetimeError, Policy, Scenario, binding_for


class LedgerSubject(BaseModel):
    """One usage context and every piece of evidence bearing on it.

    `binding_key` names a row in data/data_lifetime.yaml rather than carrying
    a lifetime directly, so the citation travels with the subject and a
    subject can never assert a lifetime no cited row supports.
    """

    model_config = ConfigDict(frozen=True)

    usage_context: UsageContext
    temporal: TemporalEvidence
    binding_key: str | None = None
    binding_source_ref: str = "operator declaration"
    migrations: tuple[MigrationEvidence, ...] = ()
    signed_at: date | None = None


class GroverFlag(BaseModel):
    """A symmetric-encryption context, recorded and shown, but never banded.

    §5.5 sends these to a policy flag. They are surfaced so an operator can
    see them -- silently dropping them would be the same "silence reads as
    clean" failure the undetermined bucket exists to prevent -- but they carry
    no window and no deadline, because Grover does not create one.
    """

    model_config = ConfigDict(frozen=True)

    usage_context_id: str
    asset_id: str
    surface_id: str
    algorithm: str | None
    note: str = (
        "symmetric encryption: a key-size question under Grover, not a "
        "harvest-now deadline. Reported, not banded (§5.5)."
    )


class RunResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    scenario_id: str
    as_of: date
    records: tuple[CalculationRecord, ...]
    grover_flags: tuple[GroverFlag, ...] = ()
    skipped: tuple[str, ...] = ()


def inputs_for(
    subject: LedgerSubject, *, scenario: Scenario, policy: Policy, as_of: date
) -> LedgerInputs:
    binding = None
    if subject.binding_key is not None:
        binding = binding_for(
            target_id=subject.usage_context.asset_id,
            key=subject.binding_key,
            source_ref=subject.binding_source_ref,
        )
    return LedgerInputs(
        as_of=as_of,
        scenario=scenario,
        policy=policy,
        usage_context=subject.usage_context,
        temporal=subject.temporal,
        binding=binding,
        migrations=subject.migrations,
        signed_at=subject.signed_at,
    )


def evaluate_subject(
    subject: LedgerSubject, *, scenario: Scenario, policy: Policy, as_of: date
) -> CalculationRecord | GroverFlag:
    """Route one subject to its ledger. Returns a GroverFlag for the one case
    that belongs to neither."""
    function = subject.usage_context.function.value
    context = subject.usage_context

    if function == CryptoFunction.ENCRYPTION:
        return GroverFlag(
            usage_context_id=context.usage_context_id,
            asset_id=context.asset_id,
            surface_id=context.surface_id,
            algorithm=context.algorithm.value if context.algorithm else None,
        )

    inputs = inputs_for(subject, scenario=scenario, policy=policy, as_of=as_of)
    if function in AUTHENTICATION_FUNCTIONS:
        return authentication_ledger.evaluate(inputs)
    if function in CONFIDENTIALITY_FUNCTIONS or function is None:
        return confidentiality_ledger.evaluate(inputs)
    raise confidentiality_ledger.LedgerNotApplicable(
        f"no ledger routes {function.value}"
    )


def evaluate_run(
    subjects: list[LedgerSubject],
    *,
    scenario: Scenario,
    policy: Policy,
    as_of: date,
) -> RunResult:
    """Evaluate every subject under one scenario.

    A subject whose lifetime row is missing is recorded in `skipped` with its
    reason rather than dropped. Nothing disappears quietly from a run.
    """
    records: list[CalculationRecord] = []
    flags: list[GroverFlag] = []
    skipped: list[str] = []

    for subject in subjects:
        try:
            outcome = evaluate_subject(
                subject, scenario=scenario, policy=policy, as_of=as_of
            )
        except NoCitedLifetimeError as error:
            skipped.append(f"{subject.usage_context.usage_context_id}: {error}")
            continue
        if isinstance(outcome, GroverFlag):
            flags.append(outcome)
        else:
            records.append(outcome)

    return RunResult(
        scenario_id=scenario.id,
        as_of=as_of,
        records=tuple(records),
        grover_flags=tuple(flags),
        skipped=tuple(skipped),
    )

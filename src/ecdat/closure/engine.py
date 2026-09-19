"""Evidence Closure Engine (Pramana_Ledger_Spec.md §5.8).

An UNBOUNDED row is not a shrug. It is the statement "one named input is
missing, here is the cheapest thing that would supply it, and here is what the
answer could turn out to be". Producing that is what separates this from a
scanner that prints UNKNOWN and stops.

Three things make a task real rather than decorative:

1. It names the MINIMUM evidence (data/closure_catalog.yaml), not a project.
   "Probe the negotiated group for this surface from a recorded vantage" is a
   task. "Do a TLS audit" is a wish.
2. Its decision impact is computed, not asserted: the ledger is re-run over
   the ADMISSIBLE VALUES of the missing input and the reachable bands are
   reported. An operator can see that collecting X moves a row between
   SAFE and BLEEDING, or that it moves nothing.
3. It is ranked by what it could reveal (worst reachable band, then rows
   affected, then longest reachable window) -- lexicographic on categorical
   fields, same as §5.10. No weights.

Where the substitution uses a concrete value, that value comes from a cited
row in data/, never from a number chosen here.
"""
from __future__ import annotations

from datetime import date
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Iterable

import yaml
from pydantic import BaseModel, ConfigDict

from ecdat.model.epistemic import EpistemicState
from ecdat.model.field_value import FieldValue
from ecdat.model.usage_context import CryptoFunction
from ecdat.risk import authentication_ledger, confidentiality_ledger
from ecdat.risk.record import (
    CalculationRecord,
    ExposureBand,
    LedgerInputs,
    band_rank,
)
from ecdat.risk.scenarios import (
    CaptureAssumption,
    CaptureMode,
    NoCitedLifetimeError,
    binding_for,
)

_CATALOG_FILE = "closure_catalog.yaml"


class NoCitedTaskError(LookupError):
    """No usable catalogue row describes how to close this input."""


def _catalog_path() -> Path:
    # src/ecdat/closure/engine.py -> repository root -> data/
    return Path(__file__).resolve().parents[3] / "data" / _CATALOG_FILE


@lru_cache(maxsize=1)
def _catalog() -> dict[str, dict[str, Any]]:
    document = yaml.safe_load(_catalog_path().read_text(encoding="utf-8"))
    return {
        row["key"]: row
        for row in (document.get("tasks") or ())
        if row.get("usable") is True
    }


class ClosureTask(BaseModel):
    """§5.8: "what to collect, why it bounds the row, rows touched, reachable
    outcomes"."""

    model_config = ConfigDict(frozen=True)

    key: str
    collect: str
    method: str
    bounds: str
    citation: str
    rows: tuple[str, ...]
    reachable_bands: tuple[ExposureBand, ...] = ()
    longest_reachable_window_days: int = 0

    @property
    def narrowed(self) -> bool:
        """False when the missing input admits any outcome at all -- §6's
        'Unknown KEX | UNBOUNDED, no conditional'. The task still stands; what
        it cannot do is promise what the answer will be."""
        return bool(self.reachable_bands)

    @property
    def worst_reachable(self) -> ExposureBand | None:
        if not self.reachable_bands:
            return None
        return min(self.reachable_bands, key=band_rank)

    def merged_with(self, other: "ClosureTask") -> "ClosureTask":
        return self.model_copy(
            update={
                "rows": tuple(dict.fromkeys(self.rows + other.rows)),
                "reachable_bands": tuple(
                    dict.fromkeys(self.reachable_bands + other.reachable_bands)
                ),
                "longest_reachable_window_days": max(
                    self.longest_reachable_window_days,
                    other.longest_reachable_window_days,
                ),
            }
        )


# --- admissible-value substitution -----------------------------------------
#
# Each entry returns the LedgerInputs that would result from the missing input
# taking one of its admissible values. Re-running the ledger over them IS the
# decision-impact computation; nothing here predicts a band.

def _with(inputs: LedgerInputs, **update: Any) -> LedgerInputs:
    return inputs.model_copy(update=update)


def _swap_algorithm(inputs: LedgerInputs, family: str) -> LedgerInputs:
    context = inputs.usage_context
    return _with(
        inputs,
        usage_context=context.model_copy(
            update={
                "algorithm": FieldValue[str](
                    value=family,
                    state=EpistemicState.KNOWN,
                    evidence_refs=("E-hypothetical",),
                )
            }
        ),
    )


def _algorithm_candidates(inputs: LedgerInputs) -> tuple[LedgerInputs, ...]:
    """The family is either Shor-broken or it is not; both are cited rows."""
    return (_swap_algorithm(inputs, "RSA"), _swap_algorithm(inputs, "ML-KEM"))


def _binding_candidates(inputs: LedgerInputs) -> tuple[LedgerInputs, ...]:
    """The shortest and longest cited lifetimes bracket every band the row
    could reach once a data class is declared."""
    candidates = []
    for key in ("TEST.X_1Y", "TEST.X_25Y"):
        try:
            binding = binding_for(
                target_id=inputs.usage_context.asset_id,
                key=key,
                source_ref="hypothetical, for closure impact only",
            )
        except NoCitedLifetimeError:
            continue
        candidates.append(_with(inputs, binding=binding))
    return tuple(candidates)


def _start_candidates(inputs: LedgerInputs) -> tuple[LedgerInputs, ...]:
    """The admissible start runs from the earliest date anything makes
    possible to `as_of`. Both ends are evaluated; everything between is
    bracketed by them."""
    possible = inputs.temporal.possible_since
    ends: list[date] = [inputs.as_of]
    if possible is not None and possible.value is not None:
        ends.insert(0, possible.value)
    return tuple(
        _with(
            inputs,
            policy=inputs.policy.model_copy(
                update={
                    "capture_assumption": CaptureAssumption(
                        mode=CaptureMode.SINCE_DATE, since=day
                    )
                }
            ),
        )
        for day in ends
    )


def _accept_inferred_candidates(inputs: LedgerInputs) -> tuple[LedgerInputs, ...]:
    """Confirming an inferred input promotes it. (Refuting it removes the row
    entirely, which is an outcome with no band -- reported as the absence of a
    worse one rather than as a band.)"""
    return (
        _with(
            inputs,
            policy=inputs.policy.model_copy(update={"accept_inferred_inputs": True}),
        ),
    )


def _migration_candidates(inputs: LedgerInputs) -> tuple[LedgerInputs, ...]:
    """Probing either confirms the claimed migration (it stops the clock from
    the date observed) or does not (the clock never stopped)."""
    observed = tuple(
        migration.model_copy(
            update={
                "status": EpistemicState.KNOWN,
                "evidence_refs": ("E-hypothetical",),
            }
        )
        for migration in inputs.migrations
        if migration.status != EpistemicState.KNOWN and not migration.classical_still_accepted
    )
    if not observed:
        return ()
    return (_with(inputs, migrations=observed), _with(inputs, migrations=()))


def _signed_at_candidates(inputs: LedgerInputs) -> tuple[LedgerInputs, ...]:
    possible = inputs.temporal.possible_since
    days = [inputs.as_of] + (
        [possible.value] if possible is not None and possible.value is not None else []
    )
    return tuple(_with(inputs, signed_at=day) for day in days)


def _authenticity_candidates(inputs: LedgerInputs) -> tuple[LedgerInputs, ...]:
    candidates = []
    for key in ("TEST.A_SESSION", "TEST.A_15Y"):
        try:
            binding = binding_for(
                target_id=inputs.usage_context.asset_id,
                key=key,
                source_ref="hypothetical, for closure impact only",
            )
        except NoCitedLifetimeError:
            continue
        candidates.append(_with(inputs, binding=binding, signed_at=inputs.signed_at or inputs.as_of))
    return tuple(candidates)


_CANDIDATES: dict[str, Callable[[LedgerInputs], tuple[LedgerInputs, ...]]] = {
    "function": lambda inputs: (),
    "algorithm_family": _algorithm_candidates,
    "inferred_algorithm": _accept_inferred_candidates,
    "inferred_function": _accept_inferred_candidates,
    "data_class_binding": _binding_candidates,
    "start_confirmed": _start_candidates,
    "start_possible": _start_candidates,
    "migration_observation": _migration_candidates,
    "signed_at": _signed_at_candidates,
    "authenticity_lifetime": _authenticity_candidates,
}


# --- diagnosis -------------------------------------------------------------


def _missing_inputs(record: CalculationRecord) -> tuple[str, ...]:
    """Which catalogue keys this row is waiting on.

    Read off the inputs, not off the reason string: a diagnosis that parses
    prose breaks the first time the prose is improved.
    """
    inputs = record.inputs
    context = inputs.usage_context
    is_auth = record.rule_version == authentication_ledger.RULE_ID
    keys: list[str] = []

    if record.band == ExposureBand.UNBOUNDED:
        if context.function.state == EpistemicState.UNKNOWN:
            keys.append("function")
        elif is_auth:
            if inputs.binding is None or inputs.binding.authenticity_lifetime_A is None:
                keys.append("authenticity_lifetime")
            elif inputs.signed_at is None:
                keys.append("signed_at")
            if context.function.state == EpistemicState.INFERRED:
                keys.append("inferred_function")
        else:
            if inputs.binding is None:
                keys.append("data_class_binding")
            elif record.assumes_capture_since is None:
                keys.append(
                    "start_possible"
                    if inputs.policy.capture_assumption.mode == CaptureMode.SINCE_POSSIBLE
                    else "start_confirmed"
                )
            else:
                if context.function.state == EpistemicState.INFERRED:
                    keys.append("inferred_function")
                if (
                    context.algorithm is not None
                    and context.algorithm.state == EpistemicState.INFERRED
                ):
                    keys.append("inferred_algorithm")
                if not keys:
                    keys.append("algorithm_family")

    # §6: 'Hybrid configured, not observed | M=inf -> BLEEDING; closure task
    # "probe negotiated group from vantage"'. A bounded row can still be
    # waiting on evidence -- the band is right, and one probe could change it.
    if any(
        migration.status != EpistemicState.KNOWN and not migration.classical_still_accepted
        for migration in inputs.migrations
    ):
        keys.append("migration_observation")

    return tuple(dict.fromkeys(keys))


def _evaluate(inputs: LedgerInputs, is_auth: bool) -> CalculationRecord | None:
    ledger = authentication_ledger if is_auth else confidentiality_ledger
    try:
        return ledger.evaluate(inputs, record_id="closure-impact")
    except (confidentiality_ledger.LedgerNotApplicable, ValueError):
        return None


def tasks_for(record: CalculationRecord) -> tuple[ClosureTask, ...]:
    """§5.8, one row. Every task carries its computed reachable bands."""
    is_auth = record.rule_version == authentication_ledger.RULE_ID
    tasks: list[ClosureTask] = []
    for key in _missing_inputs(record):
        row = _catalog().get(key)
        if row is None:
            raise NoCitedTaskError(
                f"{key!r} has no usable row in {_CATALOG_FILE}; a missing input "
                "with no catalogued way to collect it is a gap in the "
                "catalogue, not a task to invent here"
            )
        reachable: list[ExposureBand] = []
        longest = 0
        for candidate in _CANDIDATES[key](record.inputs):
            outcome = _evaluate(candidate, is_auth)
            if outcome is None or outcome.band == ExposureBand.UNBOUNDED:
                continue
            reachable.append(outcome.band)
            longest = max(longest, *(w.days for w in outcome.windows), 0)
        tasks.append(
            ClosureTask(
                key=key,
                collect=row["collect"],
                method=" ".join(row["method"].split()),
                bounds=" ".join(row["bounds"].split()),
                citation=row["citation"],
                rows=(record.usage_context_id,),
                reachable_bands=tuple(dict.fromkeys(reachable)),
                longest_reachable_window_days=longest,
            )
        )
    return tuple(tasks)


def closure_queue(records: Iterable[CalculationRecord]) -> tuple[ClosureTask, ...]:
    """§5.8: one queue over many rows, tasks merged by key and ranked
    lexicographically -- worst reachable band, rows affected, longest
    reachable window. A task that would bound forty rows outranks one that
    would bound one, and neither is multiplied by anything.
    """
    merged: dict[str, ClosureTask] = {}
    for record in records:
        for task in tasks_for(record):
            merged[task.key] = (
                merged[task.key].merged_with(task) if task.key in merged else task
            )

    def rank(task: ClosureTask) -> tuple[int, int, int]:
        worst = task.worst_reachable
        # A task that narrows nothing cannot promise a band; it sorts after
        # tasks that can reach a known-bad one, and before nothing else.
        worst_rank = band_rank(worst) if worst is not None else band_rank(ExposureBand.UNBOUNDED)
        return (worst_rank, -len(task.rows), -task.longest_reachable_window_days)

    return tuple(sorted(merged.values(), key=rank))

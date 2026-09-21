"""Run-to-run diff (build-plan.md P13; Pramana_Ledger_Spec.md SS5.7).

MIGRATED and REGRESSED introduce no new judgement -- they are
`_Timeline.first_stop` / `_Timeline.reopened` (confidentiality_ledger.py),
already tested there, persisted across two runs instead of computed inside
one. A row becomes MIGRATED only on a KNOWN migration observation with
`classical_still_accepted` False in the newer run; a configuration file
claiming an upgrade moves nothing, because `_Timeline` already enforces that
rule and this module changes none of it -- it only re-asks the same question
twice and reports whether the answer changed.
"""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict

from ecdat.model.epistemic import EpistemicState
from ecdat.risk import authentication_ledger
from ecdat.risk.confidentiality_ledger import _Timeline
from ecdat.risk.record import CalculationRecord, ExposureBand
from ecdat.store.repository import Run


class DiffClass(str, Enum):
    """Closed set, matching build-plan.md P13 exactly."""

    NEW = "NEW"
    CHANGED = "CHANGED"
    REMOVED = "REMOVED"
    MIGRATED = "MIGRATED"
    REGRESSED = "REGRESSED"
    UNCHANGED = "UNCHANGED"


class RowDiff(BaseModel):
    """One usage_context_id's story between two runs."""

    model_config = ConfigDict(frozen=True)

    usage_context_id: str
    diff_class: DiffClass
    old_band: ExposureBand | None
    new_band: ExposureBand | None
    old_record_id: str | None = None
    new_record_id: str | None = None

    @property
    def reason(self) -> str:
        """A one-line, non-invented explanation -- states what changed
        between the two runs, not a guess at why."""
        if self.diff_class == DiffClass.NEW:
            return f"first seen this run, band {self.new_band.value if self.new_band else '?'}"
        if self.diff_class == DiffClass.REMOVED:
            return (
                f"no longer present ({self.old_band.value if self.old_band else '?'} "
                "in the previous run); a removed row is not a closed one -- it may "
                "mean the surface disappeared or that this run's scan did not cover it"
            )
        if self.diff_class == DiffClass.MIGRATED:
            return "an observed migration with classical disabled stopped the clock"
        if self.diff_class == DiffClass.REGRESSED:
            return "a classical negotiation was observed again after a stop -- reopened"
        if self.diff_class == DiffClass.CHANGED:
            return f"{self.old_band.value if self.old_band else '?'} -> {self.new_band.value if self.new_band else '?'}"
        return "band unchanged"


class RunDiff(BaseModel):
    """The full comparison of two runs, ordered NEW/MIGRATED/REGRESSED/
    CHANGED before REMOVED/UNCHANGED -- the classes a reader needs to see
    first, without any weight attached to that ordering."""

    model_config = ConfigDict(frozen=True)

    from_run_id: str
    to_run_id: str
    rows: tuple[RowDiff, ...]

    def by_class(self, diff_class: DiffClass) -> tuple[RowDiff, ...]:
        return tuple(row for row in self.rows if row.diff_class == diff_class)


_ORDER = {
    DiffClass.MIGRATED: 0,
    DiffClass.NEW: 1,
    DiffClass.REGRESSED: 2,
    DiffClass.CHANGED: 3,
    DiffClass.REMOVED: 4,
    DiffClass.UNCHANGED: 5,
}


def _is_confidentiality(record: CalculationRecord) -> bool:
    return record.rule_version != authentication_ledger.RULE_ID


def _currently_stopped(record: CalculationRecord) -> bool:
    """§5.7's stop/reopen concept belongs to the confidentiality clock only
    (module docstring of confidentiality_ledger.py: nothing already signed is
    'lost'). Authentication rows never classify as MIGRATED/REGRESSED."""
    if not _is_confidentiality(record):
        return False
    known_migrations = tuple(
        m for m in record.inputs.migrations if m.status == EpistemicState.KNOWN
    )
    if not known_migrations:
        return False
    # `start`/`as_of` only affect exposure_intervals(), not first_stop/reopened.
    timeline = _Timeline(known_migrations, start=record.inputs.as_of, as_of=record.inputs.as_of)
    return timeline.currently_stopped


def _classify(
    old: CalculationRecord | None, new: CalculationRecord | None
) -> DiffClass:
    if old is None and new is not None:
        return DiffClass.NEW
    if old is not None and new is None:
        return DiffClass.REMOVED
    assert old is not None and new is not None

    old_stopped = _currently_stopped(old)
    new_stopped = _currently_stopped(new)
    if not old_stopped and new_stopped:
        return DiffClass.MIGRATED
    if old_stopped and not new_stopped:
        return DiffClass.REGRESSED
    return DiffClass.UNCHANGED if old.band == new.band else DiffClass.CHANGED


def diff_runs(old: Run, new: Run) -> RunDiff:
    """Compare two runs by `usage_context_id`. A row missing its lifetime
    binding and therefore absent from one run's records is REMOVED or NEW,
    not silently ignored -- nothing about a row disappears without being
    named (`skipped` on `RunResult` already names the reason; this module
    does not re-derive it)."""
    old_by_id = {r.usage_context_id: r for r in old.records}
    new_by_id = {r.usage_context_id: r for r in new.records}
    all_ids = sorted(set(old_by_id) | set(new_by_id))

    rows: list[RowDiff] = []
    for usage_context_id in all_ids:
        old_record = old_by_id.get(usage_context_id)
        new_record = new_by_id.get(usage_context_id)
        diff_class = _classify(old_record, new_record)
        rows.append(
            RowDiff(
                usage_context_id=usage_context_id,
                diff_class=diff_class,
                old_band=old_record.band if old_record else None,
                new_band=new_record.band if new_record else None,
                old_record_id=old_record.record_id if old_record else None,
                new_record_id=new_record.record_id if new_record else None,
            )
        )

    rows.sort(key=lambda row: (_ORDER[row.diff_class], row.usage_context_id))
    return RunDiff(from_run_id=old.run_id, to_run_id=new.run_id, rows=tuple(rows))

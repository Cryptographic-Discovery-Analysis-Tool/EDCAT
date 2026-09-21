"""The run store (build-plan.md P13). See `store.repository` and
`store.diff` for the real content; this module only re-exports the public
surface so callers write `from ecdat.store import Run, RunStore, diff_runs`.
"""
from ecdat.store.diff import DiffClass, RowDiff, RunDiff, diff_runs
from ecdat.store.repository import (
    InvalidRunIdError,
    JsonlRunStore,
    NoSuchRunError,
    Run,
    RunStore,
    RunSummary,
    new_run_id,
)

__all__ = [
    "DiffClass",
    "InvalidRunIdError",
    "JsonlRunStore",
    "NoSuchRunError",
    "Run",
    "RunDiff",
    "RunStore",
    "RunSummary",
    "RowDiff",
    "diff_runs",
    "new_run_id",
]

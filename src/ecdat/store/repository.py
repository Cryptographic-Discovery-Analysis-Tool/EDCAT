"""The run store (build-plan.md P13; Lock SS5 row 9; SS5.7's migration timeline).

Nothing about the ledger changes here. This module answers exactly one
question the ledger cannot answer by itself: what did a *previous* run say,
so two runs can be compared. Everything a `RunDiff` reports is read off two
already-computed, already-replayable `RunResult`s -- this module persists and
retrieves, it does not re-derive a band or invent a judgement.

Lock SS5 row 9 leaves the table layout open; a run is an append-only document
either way. `RunStore` is that document contract. `JsonlRunStore` is the
concrete backing shipped today: one JSON document per run, one line per file,
under a directory -- no new service to stand up, works in CI and offline, and
satisfies "append-only document" literally. A `PostgresRunStore` implementing
the same `RunStore` protocol is the natural next adapter behind this
interface; nothing above `RunStore` needs to change when it lands. Until it
does, `store/` claims exactly what it is: a real, working, tested repository
with a file-backed default, not a database.
"""
from __future__ import annotations

import json
import re
import uuid
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, ConfigDict, field_validator

from ecdat.risk.record import CalculationRecord
from ecdat.risk.run import GroverFlag, RunResult

_RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class InvalidRunIdError(ValueError):
    """A run_id that is empty, too long, or contains characters that would
    make it unsafe as a filename (path traversal, separators)."""


class NoSuchRunError(LookupError):
    """No run with this id exists in the store."""


def _validate_run_id(run_id: str) -> str:
    if not _RUN_ID_RE.match(run_id):
        raise InvalidRunIdError(
            f"{run_id!r} is not a valid run_id: must be 1-128 characters, "
            "alphanumeric plus '.', '_', '-', and must not start with one "
            "of those (no path traversal, no empty component)"
        )
    return run_id


def new_run_id(*, prefix: str = "run") -> str:
    """A fresh run identity. Not content-derived on purpose: two runs with
    byte-identical records are still two runs -- run identity is about *when*
    a scan happened, and that is exactly the fact the diff needs to compare
    across, so it cannot be folded into a hash of the content itself."""
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


class Run(BaseModel):
    """One append-only document: a `RunResult` plus its identity and when it
    was recorded. Frozen -- a run, once stored, does not change; a re-scan is
    a new run, never an edit to an old one."""

    model_config = ConfigDict(frozen=True)

    run_id: str
    target_id: str
    scenario_id: str
    as_of: date
    recorded_at: datetime
    records: tuple[CalculationRecord, ...]
    grover_flags: tuple[GroverFlag, ...] = ()
    skipped: tuple[str, ...] = ()

    @field_validator("run_id")
    @classmethod
    def _valid_run_id(cls, value: str) -> str:
        return _validate_run_id(value)

    @classmethod
    def from_result(
        cls,
        result: RunResult,
        *,
        target_id: str,
        run_id: str | None = None,
        recorded_at: datetime | None = None,
    ) -> "Run":
        return cls(
            run_id=run_id or new_run_id(),
            target_id=target_id,
            scenario_id=result.scenario_id,
            as_of=result.as_of,
            recorded_at=recorded_at or datetime.now(timezone.utc),
            records=result.records,
            grover_flags=result.grover_flags,
            skipped=result.skipped,
        )


class RunSummary(BaseModel):
    """The header of a run, without its rows -- what `list_runs()` returns,
    so listing a store with a thousand runs does not mean reading a
    thousand documents' worth of ledger rows."""

    model_config = ConfigDict(frozen=True)

    run_id: str
    target_id: str
    scenario_id: str
    as_of: date
    recorded_at: datetime
    row_count: int


class RunStore(Protocol):
    """The document contract SS5 row 9 leaves open. Any backing that
    satisfies this is a valid run store; the ledger and the diff logic never
    see the backing itself."""

    def save(self, run: Run) -> None: ...

    def load(self, run_id: str) -> Run: ...

    def list_runs(self, *, target_id: str | None = None) -> tuple[RunSummary, ...]: ...


class JsonlRunStore:
    """File-backed `RunStore`: one JSON document per run, one file per run,
    under `directory`. Concurrent-safe for the case that matters here --
    scans append new runs; nothing ever edits an existing run's file."""

    def __init__(self, directory: Path | str):
        self._dir = Path(directory)
        self._dir.mkdir(parents=True, exist_ok=True)

    def _path(self, run_id: str) -> Path:
        return self._dir / f"{_validate_run_id(run_id)}.json"

    def save(self, run: Run) -> None:
        path = self._path(run.run_id)
        if path.exists():
            raise ValueError(
                f"run {run.run_id!r} already exists at {path} -- a run store "
                "is append-only; re-scanning produces a new run_id, never an "
                "overwrite of an old one"
            )
        path.write_text(run.model_dump_json(indent=2), encoding="utf-8")

    def load(self, run_id: str) -> Run:
        path = self._path(run_id)
        if not path.exists():
            raise NoSuchRunError(f"no run {run_id!r} in {self._dir}")
        return Run.model_validate_json(path.read_text(encoding="utf-8"))

    def list_runs(self, *, target_id: str | None = None) -> tuple[RunSummary, ...]:
        summaries: list[RunSummary] = []
        for path in sorted(self._dir.glob("*.json")):
            document = json.loads(path.read_text(encoding="utf-8"))
            if target_id is not None and document.get("target_id") != target_id:
                continue
            summaries.append(
                RunSummary(
                    run_id=document["run_id"],
                    target_id=document["target_id"],
                    scenario_id=document["scenario_id"],
                    as_of=document["as_of"],
                    recorded_at=document["recorded_at"],
                    row_count=len(document.get("records") or ()),
                )
            )
        summaries.sort(key=lambda s: s.recorded_at)
        return tuple(summaries)

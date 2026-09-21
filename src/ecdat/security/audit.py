"""Append-only audit log (build-plan.md P17): who read or exported what.

The fourth deck control's other half, alongside `security/auth.py`. A
`Principal` is never named by a raw token (see that module for why); an
`AuditEntry` carries the same fingerprint an auth failure would carry, so a
log entry and a 401 in the API's own logs can be tied to the same caller
without either one holding a secret.

`Verb` is a closed set matching what P17 actually asks for: *"an append-only
log of who read or exported what. Export is the sensitive verb here, not
scanning."* Every authenticated request is READ or EXPORT; there is nothing
a third verb would need to distinguish yet.

Backing is `JsonlAuditLog`, the same one-line-per-record, append-only shape
`store/repository.py::JsonlRunStore` already uses for run documents -- a log
is a document store with an even simpler write pattern (append, never
overwrite a line), so this file is a smaller sibling of that one rather than
a new design.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, ConfigDict

from ecdat.security.auth import Principal


class Verb(str, Enum):
    """Closed set: every authenticated request is a READ or an EXPORT."""

    READ = "READ"
    EXPORT = "EXPORT"


class AuditEntry(BaseModel):
    """One authenticated request, after the fact. `outcome` is `"allowed"`
    or the auth-error class name (`"InsufficientRoleError"`, etc.) -- a
    denied request is logged too, because "who tried and was refused" is
    part of "who read or exported what", not a fact this log gets to drop."""

    model_config = ConfigDict(frozen=True)

    ts: datetime
    principal_fingerprint: str
    role: str
    verb: Verb
    path: str
    outcome: str


class AuditLog(Protocol):
    def record(self, entry: AuditEntry) -> None: ...

    def entries(self) -> tuple[AuditEntry, ...]: ...


class JsonlAuditLog:
    """File-backed `AuditLog`: one JSON object per line, appended, never
    rewritten. `entries()` reads the whole file back -- fine at the scale an
    audit log of one dashboard's API traffic actually reaches; a real
    deployment's log shipping is out of scope for build-plan.md P17's
    "minimum honest scope"."""

    def __init__(self, path: Path | str):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if not self._path.exists():
            self._path.touch()

    def record(self, entry: AuditEntry) -> None:
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(entry.model_dump_json() + "\n")

    def entries(self) -> tuple[AuditEntry, ...]:
        if not self._path.exists():
            return ()
        lines = [
            line for line in self._path.read_text(encoding="utf-8").splitlines() if line.strip()
        ]
        return tuple(AuditEntry.model_validate_json(line) for line in lines)


class InMemoryAuditLog:
    """Same contract, no disk -- the default for `create_app()` when no path
    is configured, and for tests that want to assert on entries without a
    temp file."""

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []

    def record(self, entry: AuditEntry) -> None:
        self._entries.append(entry)

    def entries(self) -> tuple[AuditEntry, ...]:
        return tuple(self._entries)


def entry_for(
    principal: Principal | None, *, verb: Verb, path: str, outcome: str
) -> AuditEntry:
    """`principal` is None for a request that never authenticated at all
    (no token / an invalid one) -- still logged, with a fingerprint of the
    raw token that was tried, computed by the caller (this function does not
    see raw tokens either)."""
    return AuditEntry(
        ts=datetime.now(timezone.utc),
        principal_fingerprint=principal.fingerprint if principal else "(unauthenticated)",
        role=principal.role.value if principal else "(none)",
        verb=verb,
        path=path,
        outcome=outcome,
    )

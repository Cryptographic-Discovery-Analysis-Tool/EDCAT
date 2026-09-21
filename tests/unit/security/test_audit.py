"""Append-only audit log (build-plan.md P17)."""
from __future__ import annotations

from ecdat.security.audit import InMemoryAuditLog, JsonlAuditLog, Verb, entry_for
from ecdat.security.auth import Principal, Role


def test_in_memory_log_records_in_order():
    log = InMemoryAuditLog()
    log.record(entry_for(Principal(fingerprint="a", role=Role.VIEWER), verb=Verb.READ, path="/api/ledger", outcome="allowed"))
    log.record(entry_for(Principal(fingerprint="b", role=Role.EXPORTER), verb=Verb.EXPORT, path="/api/export", outcome="allowed"))

    entries = log.entries()
    assert len(entries) == 2
    assert entries[0].verb == Verb.READ
    assert entries[1].verb == Verb.EXPORT


def test_a_denied_request_is_logged_with_no_principal():
    log = InMemoryAuditLog()
    log.record(entry_for(None, verb=Verb.READ, path="/api/ledger", outcome="MissingTokenError"))

    (entry,) = log.entries()
    assert entry.principal_fingerprint == "(unauthenticated)"
    assert entry.role == "(none)"
    assert entry.outcome == "MissingTokenError"


def test_jsonl_log_persists_across_instances(tmp_path):
    path = tmp_path / "audit.jsonl"
    first = JsonlAuditLog(path)
    first.record(entry_for(Principal(fingerprint="a", role=Role.VIEWER), verb=Verb.READ, path="/api/closure", outcome="allowed"))

    second = JsonlAuditLog(path)
    entries = second.entries()
    assert len(entries) == 1
    assert entries[0].path == "/api/closure"


def test_jsonl_log_is_append_only_one_line_per_entry(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = JsonlAuditLog(path)
    for i in range(3):
        log.record(
            entry_for(
                Principal(fingerprint=f"p{i}", role=Role.VIEWER),
                verb=Verb.READ,
                path=f"/api/ledger?n={i}",
                outcome="allowed",
            )
        )
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3
    assert log.entries()[2].path == "/api/ledger?n=2"


def test_jsonl_log_creates_its_file_and_parent_directory(tmp_path):
    path = tmp_path / "nested" / "audit.jsonl"
    log = JsonlAuditLog(path)
    assert path.exists()
    assert log.entries() == ()


def test_entry_never_carries_a_raw_token_only_a_fingerprint():
    entry = entry_for(Principal(fingerprint="abc123", role=Role.VIEWER), verb=Verb.READ, path="/api/ledger", outcome="allowed")
    dumped = entry.model_dump_json()
    assert "abc123" in dumped
    assert entry.principal_fingerprint == "abc123"

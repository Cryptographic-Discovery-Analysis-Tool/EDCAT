"""`ecdat ledger-run` / `ecdat runs` / `ecdat diff` (build-plan.md P13).

Drives `main()` with real argv against the same fixture the dashboard opens
with (tests/fixtures/ledger/subjects.json), so the whole path -- reading a
subjects file, evaluate_run(), saving a Run, listing runs, diffing two of
them -- is exercised the way a real invocation would be.
"""
from __future__ import annotations

import json
from pathlib import Path

from ecdat.cli import main

SUBJECTS = str(
    Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "ledger" / "subjects.json"
)


def _ledger_run(store_dir: Path, scenario: str) -> None:
    code = main(
        [
            "ledger-run",
            "--subjects",
            SUBJECTS,
            "--target-id",
            "pay-1",
            "--scenario",
            scenario,
            "--rollout-y-days",
            "365",
            "--as-of",
            "2026-09-18",
            "--store-dir",
            str(store_dir),
        ]
    )
    assert code == 0


def test_ledger_run_saves_a_run(tmp_path, capsys):
    _ledger_run(tmp_path, "Z_central")
    out = capsys.readouterr().out
    assert "row(s)" in out
    files = list(tmp_path.glob("*.json"))
    assert len(files) == 1


def test_runs_lists_saved_runs(tmp_path, capsys):
    _ledger_run(tmp_path, "Z_central")
    capsys.readouterr()

    code = main(["runs", "--store-dir", str(tmp_path), "--json"])
    assert code == 0
    rows = json.loads(capsys.readouterr().out)
    assert len(rows) == 1
    assert rows[0]["target_id"] == "pay-1"
    assert rows[0]["scenario_id"] == "Z_central"


def test_diff_between_two_scenarios_finds_the_row_that_moves(tmp_path, capsys):
    _ledger_run(tmp_path, "Z_aggressive")
    capsys.readouterr()
    _ledger_run(tmp_path, "Z_central")
    capsys.readouterr()

    from ecdat.store import JsonlRunStore

    store = JsonlRunStore(tmp_path)
    summaries = store.list_runs()
    assert len(summaries) == 2
    old_id, new_id = summaries[0].run_id, summaries[1].run_id

    code = main(
        [
            "diff",
            "--store-dir",
            str(tmp_path),
            "--from",
            old_id,
            "--to",
            new_id,
            "--json",
        ]
    )
    assert code == 0
    document = json.loads(capsys.readouterr().out)
    assert document["from_run_id"] == old_id
    assert document["to_run_id"] == new_id
    changed = [r for r in document["rows"] if r["diff_class"] == "CHANGED"]
    assert changed, "expected at least one row to move between Z_aggressive and Z_central"
    assert any(r["old_band"] == "BLEEDING" and r["new_band"] == "SAVABLE" for r in changed)


def test_diff_of_a_run_against_itself_is_all_unchanged(tmp_path, capsys):
    _ledger_run(tmp_path, "Z_central")
    capsys.readouterr()

    from ecdat.store import JsonlRunStore

    run_id = JsonlRunStore(tmp_path).list_runs()[0].run_id

    code = main(
        [
            "diff",
            "--store-dir",
            str(tmp_path),
            "--from",
            run_id,
            "--to",
            run_id,
            "--json",
        ]
    )
    assert code == 0
    document = json.loads(capsys.readouterr().out)
    assert all(r["diff_class"] == "UNCHANGED" for r in document["rows"])


def test_diff_unknown_run_id_fails_cleanly(tmp_path, capsys):
    code = main(
        [
            "diff",
            "--store-dir",
            str(tmp_path),
            "--from",
            "run-does-not-exist",
            "--to",
            "run-also-missing",
        ]
    )
    assert code == 2
    assert "no run" in capsys.readouterr().err

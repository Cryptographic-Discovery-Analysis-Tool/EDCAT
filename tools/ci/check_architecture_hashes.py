#!/usr/bin/env python3
"""Fail CI if docs/architecture/*.md changed without a new ADR in the same diff.

Not domain code — CI tooling only. See CLAUDE.md hard rule: canonical architecture
docs are READ-ONLY; any change must go through Section 8 change control, which is
recorded as an ADR under docs/decisions/.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ARCH_DIR = REPO_ROOT / "docs" / "architecture"
LOCK_FILE = ARCH_DIR / "HASHES.lock"
DECISIONS_DIR = REPO_ROOT / "docs" / "decisions"


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def current_hashes() -> dict[str, str]:
    hashes = {}
    for path in sorted(ARCH_DIR.glob("*.md")):
        hashes[path.name] = sha256_of(path)
    return hashes


def load_lock() -> dict[str, str]:
    if not LOCK_FILE.exists():
        return {}
    return json.loads(LOCK_FILE.read_text())


def git_diff_base() -> str | None:
    base_ref = os.environ.get("GITHUB_BASE_REF")
    if base_ref:
        candidate = f"origin/{base_ref}"
        try:
            subprocess.run(
                ["git", "rev-parse", "--verify", candidate],
                cwd=REPO_ROOT, check=True, capture_output=True,
            )
            return candidate
        except subprocess.CalledProcessError:
            pass
    try:
        subprocess.run(
            ["git", "rev-parse", "--verify", "HEAD~1"],
            cwd=REPO_ROOT, check=True, capture_output=True,
        )
        return "HEAD~1"
    except subprocess.CalledProcessError:
        return None


def changed_files_since(base: str) -> list[str]:
    result = subprocess.run(
        ["git", "diff", "--name-status", f"{base}...HEAD"],
        cwd=REPO_ROOT, check=True, capture_output=True, text=True,
    )
    return result.stdout.strip().splitlines()


def has_new_adr(diff_lines: list[str]) -> bool:
    for line in diff_lines:
        parts = line.split("\t")
        if not parts:
            continue
        status = parts[0]
        for path in parts[1:]:
            if status.startswith("A") and path.startswith("docs/decisions/ADR-") and path.endswith(".md"):
                return True
    return False


def main() -> int:
    recorded = load_lock()
    current = current_hashes()

    changed = {
        name
        for name in set(recorded) | set(current)
        if recorded.get(name) != current.get(name)
    }

    if not changed:
        print("check_architecture_hashes: no change to docs/architecture/*.md — OK")
        return 0

    base = git_diff_base()
    if base is None:
        print(
            "check_architecture_hashes: architecture doc(s) changed "
            f"({', '.join(sorted(changed))}) but no git history to diff against "
            "(first commit) — cannot verify an ADR was added. Failing closed.",
            file=sys.stderr,
        )
        return 1

    diff_lines = changed_files_since(base)
    if has_new_adr(diff_lines):
        print(
            "check_architecture_hashes: architecture doc(s) changed "
            f"({', '.join(sorted(changed))}) and a new docs/decisions/ADR-*.md is "
            "present in this diff — OK. Remember to update docs/architecture/HASHES.lock."
        )
        return 0

    print(
        "check_architecture_hashes: FAIL — docs/architecture/*.md changed "
        f"({', '.join(sorted(changed))}) without a new docs/decisions/ADR-NNN-*.md "
        "in this diff. Per CLAUDE.md, canonical architecture docs are READ-ONLY; "
        "changes require Section 8 change control recorded as an ADR.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

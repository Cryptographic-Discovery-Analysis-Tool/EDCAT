#!/usr/bin/env python3
"""Fail CI if harness identifiers leak into src/ or rules/.

Not domain code — CI tooling only. See CLAUDE.md hard rule: "No harness identifiers
(meridian, harness paths, hostnames) anywhere in src/ or rules/", and harness doc
Section 8.6: "fail the build if scanner code/rules contain `meridian`,
`ecdat-harness`, any `targets/` path segment, or harness hostnames."
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCAN_DIRS = [REPO_ROOT / "src", REPO_ROOT / "rules"]

# Patterns taken verbatim from harness doc Section 8.6 / CLAUDE.md hard rules.
# Hostname list intentionally not extended beyond this: no harness PKI/hostnames
# have been generated yet (harness/build/pki-lock.generated.json does not exist),
# so a concrete hostname pattern would be guessed, not verified. See OI-001-adjacent
# note below — extend this list only from real generated harness output.
FORBIDDEN_PATTERNS = [
    re.compile(r"meridian", re.IGNORECASE),
    re.compile(r"ecdat-harness", re.IGNORECASE),
    re.compile(r"(?:^|[/\\])targets[/\\]"),
]

TEXT_SUFFIXES = {
    ".py", ".yar", ".yara", ".yml", ".yaml", ".json", ".toml", ".cfg", ".ini",
    ".txt", ".md", ".sh",
}


def iter_files() -> list[Path]:
    files = []
    for base in SCAN_DIRS:
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if path.is_file() and path.suffix in TEXT_SUFFIXES:
                files.append(path)
    return files


def main() -> int:
    violations: list[tuple[Path, int, str, str]] = []

    for path in iter_files():
        try:
            lines = path.read_text(encoding="utf-8", errors="strict").splitlines()
        except UnicodeDecodeError:
            continue
        for lineno, line in enumerate(lines, start=1):
            for pattern in FORBIDDEN_PATTERNS:
                if pattern.search(line):
                    violations.append((path, lineno, pattern.pattern, line.strip()))

    if not violations:
        print("check_no_harness_identifiers: no harness identifiers in src/ or rules/ — OK")
        return 0

    print("check_no_harness_identifiers: FAIL — harness identifiers found:", file=sys.stderr)
    for path, lineno, pattern, line in violations:
        rel = path.relative_to(REPO_ROOT)
        print(f"  {rel}:{lineno}: matched /{pattern}/ — {line}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

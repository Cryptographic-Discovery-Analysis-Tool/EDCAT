"""CI guard: no uncited constant in data/.

Phase 3 acceptance (Pramana_Ledger_Spec.md §7.2): "CI grep: no uncited
constant in `data/`". Every row in every data registry that is marked
`usable: true` must carry a `citation` whose leading token is a path to a
non-empty file in this repo, and a `quote` reproducing the sentence that
states the value.

A row marked `usable: false` is exempt: that is the honest-absence pattern
(data/base_confidence.yaml) where we record what we looked for and why what we
found is not adoptable. It must still say why, via `why_not_usable`.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = REPO_ROOT / "data"


def _rows(node: Any) -> list[dict[str, Any]]:
    """Every dict in the document that looks like a registry row."""
    found: list[dict[str, Any]] = []
    if isinstance(node, dict):
        if "usable" in node:
            found.append(node)
        for value in node.values():
            found.extend(_rows(value))
    elif isinstance(node, list):
        for value in node:
            found.extend(_rows(value))
    return found


def _citation_target(citation: str) -> Path | None:
    """The in-repo path a citation points at, if it names one."""
    head = citation.strip().split()[0].rstrip(",;")
    if "/" not in head:
        return None
    candidate = REPO_ROOT / head
    if not candidate.exists() and head.startswith("ecdat-harness/"):
        # Sibling repository, cited by design (CLAUDE.md canonical sources).
        candidate = REPO_ROOT.parent / head
    return candidate


def main() -> int:
    problems: list[str] = []
    for path in sorted(DATA_DIR.glob("*.yaml")):
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        for row in _rows(document):
            key = row.get("key") or row.get("id") or "<unkeyed row>"
            where = f"{path.name}#{key}"

            if row.get("usable") is not True:
                if not str(row.get("why_not_usable", "")).strip():
                    problems.append(f"{where}: usable:false with no why_not_usable")
                continue

            citation = str(row.get("citation", "")).strip()
            if not citation:
                problems.append(f"{where}: usable:true with no citation")
                continue
            if not str(row.get("quote", "")).strip():
                problems.append(
                    f"{where}: usable:true with no quote -- a citation without "
                    "the sentence it cites cannot be checked"
                )
            target = _citation_target(citation)
            if target is None:
                problems.append(f"{where}: citation names no file path: {citation!r}")
            elif not target.exists():
                problems.append(f"{where}: citation points at a missing file: {target}")
            elif target.stat().st_size == 0:
                problems.append(f"{where}: citation points at an EMPTY file: {target}")

    if problems:
        print("check_data_citations: uncited or unverifiable constants in data/")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print("check_data_citations: every usable row in data/ is cited and quoted -- OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())

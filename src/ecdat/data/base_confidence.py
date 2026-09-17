"""Loader for `data/base_confidence.yaml` (Lock §5 row 3; OI-004, ADR-002).

There is no hardcoded confidence value anywhere in `src/`. `lookup()` returns
a number only for a row the registry marks `usable: true`, which today is no
row at all — Final Architecture Part 3, where the table would live, is empty
(OI-001). Callers must handle `NoCitedConfidenceError` rather than falling back
to a default: a silent default is exactly the invented number this registry
exists to prevent.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

_REGISTRY_FILENAME = "base_confidence.yaml"


class NoCitedConfidenceError(LookupError):
    """No row in the registry cites a usable confidence for this key."""


def _registry_path() -> Path:
    # src/ecdat/data/base_confidence.py -> repository root -> data/
    return Path(__file__).resolve().parents[3] / "data" / _REGISTRY_FILENAME


@lru_cache(maxsize=1)
def load() -> dict[str, Any]:
    data = yaml.safe_load(_registry_path().read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "rows" not in data:
        raise ValueError(f"malformed confidence registry at {_registry_path()}")
    return data


def rows() -> tuple[dict[str, Any], ...]:
    return tuple(load().get("rows") or ())


def usable_keys() -> frozenset[str]:
    return frozenset(r["key"] for r in rows() if r.get("usable") is True)


def lookup(key: str) -> float:
    """Return the cited base confidence for `key`.

    Raises NoCitedConfidenceError when the key is absent, or present but not
    marked usable (i.e. recorded, with its reason, but not adoptable).
    """
    for row in rows():
        if row.get("key") != key:
            continue
        if row.get("usable") is not True:
            raise NoCitedConfidenceError(
                f"{key!r} is recorded in the registry but not usable: "
                f"{row.get('why_not_usable', 'no reason recorded')}"
            )
        return float(row["value"])
    raise NoCitedConfidenceError(f"{key!r} has no row in the base-confidence registry")

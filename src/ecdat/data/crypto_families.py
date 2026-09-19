"""Loader for `data/crypto_families.yaml` (Pramana_Ledger_Spec.md §5.5).

No family classification is hardcoded in `src/`, and there is no
name-pattern fallback: a family with no usable row is UNKNOWN to the ledger,
which produces an UNBOUNDED band and a closure task, not a guess. That is the
whole point -- guessing "anything with EC in the name is broken" is how a
scanner invents certainty it does not have.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

_FILENAME = "crypto_families.yaml"


class NoCitedFamilyError(LookupError):
    """No usable row classifies this family."""


def _path() -> Path:
    # src/ecdat/data/crypto_families.py -> repository root -> data/
    return Path(__file__).resolve().parents[3] / "data" / _FILENAME


@lru_cache(maxsize=1)
def load() -> dict[str, Any]:
    data = yaml.safe_load(_path().read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "families" not in data:
        raise ValueError(f"malformed crypto-family registry at {_path()}")
    return data


def families() -> tuple[dict[str, Any], ...]:
    return tuple(load().get("families") or ())


def hybrid_groups() -> frozenset[str]:
    return frozenset(
        row["key"] for row in (load().get("hybrid_groups") or ()) if row.get("usable") is True
    )


def is_hybrid_group(group: str | None) -> bool:
    return group is not None and group in hybrid_groups()


def is_shor_broken(family: str) -> bool:
    """True/False only for a cited, usable row. Raises otherwise."""
    for row in families():
        if row.get("key") != family:
            continue
        if row.get("usable") is not True:
            raise NoCitedFamilyError(
                f"{family!r} is recorded but not usable: "
                f"{row.get('why_not_usable', 'no reason recorded')}"
            )
        return bool(row["shor_broken"])
    raise NoCitedFamilyError(f"{family!r} has no row in the crypto-family registry")


def canonical_family(name: str | None) -> str | None:
    """Resolve a wire/tool spelling to the family spelling the registry uses.

    Naming identity only (`basis: NAMING_IDENTITY` rows). An unlisted spelling
    is returned unchanged, so it misses `is_shor_broken` and becomes a closure
    task rather than a guess.
    """
    if name is None:
        return None
    for row in load().get("family_aliases") or ():
        if row.get("usable") is True and row.get("key") == name:
            return str(row["family"])
    return name

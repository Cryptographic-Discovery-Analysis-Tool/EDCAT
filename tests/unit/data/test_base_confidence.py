"""The base-confidence registry must never hand out an uncited number.

OI-004 / ADR-002: the table the Lock refers to (§5 row 3) would live in
ECDAT_Final_Architecture.md Part 3, which is empty in this repo. These tests
keep the registry honest about that rather than letting a plausible default
creep in.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from ecdat.data import base_confidence

REPO_ROOT = Path(__file__).resolve().parents[3]


def test_no_usable_row_exists_while_part3_is_missing():
    assert base_confidence.usable_keys() == frozenset()
    assert base_confidence.load()["usable_row_count"] == len(base_confidence.usable_keys())


def test_every_row_carries_a_citation_and_a_quote():
    for row in base_confidence.rows():
        assert row.get("citation", "").strip(), f"{row['key']} has no citation"
        assert row.get("quote", "").strip(), f"{row['key']} has no quote"


def test_unusable_rows_record_why():
    for row in base_confidence.rows():
        if row.get("usable") is not True:
            assert row.get("why_not_usable", "").strip(), f"{row['key']} is unusable without a reason"


@pytest.mark.parametrize(
    "key", ["certificate", "package", "tls", "source", "binary.dynamic_symbols"]
)
def test_lookup_refuses_every_key_today(key):
    """Recorded-but-unusable and simply-absent must both refuse, not default."""
    with pytest.raises(base_confidence.NoCitedConfidenceError):
        base_confidence.lookup(key)


def test_the_uncited_slide_ordering_is_not_reintroduced():
    """An early slide draft carried "certificate 0.95 ... package 0.30".

    Neither number appears anywhere in this repo or the harness docs, so it has
    no citable basis. This test exists so it cannot quietly come back.
    """
    text = (REPO_ROOT / "data" / "base_confidence.yaml").read_text(encoding="utf-8")
    body = text.split("# Searched for and NOT found", 1)[0]
    assert "0.95" not in body
    assert "0.30" not in body


def test_no_confidence_literal_is_hardcoded_in_src():
    """Confidence values live in data/ with citations, never in code."""
    pattern = re.compile(r"base_confidence\s*=\s*[0-9]")
    offenders = [
        path.relative_to(REPO_ROOT)
        for path in (REPO_ROOT / "src").rglob("*.py")
        if pattern.search(path.read_text(encoding="utf-8"))
    ]
    assert offenders == [], f"hardcoded base_confidence in {offenders}"

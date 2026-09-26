"""data/crypto_families.yaml hybrid_groups (Pramana_Ledger_Spec.md §5.1).

RFC 10024 (docs/sources/IETF_RFC_10024_2026.md) resolved SecP256r1MLKEM768
and SecP384r1MLKEM1024 on 2026-09-26 -- previously recorded as "searched for
and NOT found in any in-repo document" (no guess by analogy with
X25519MLKEM768 was ever made, per data/base_confidence.yaml's own rule).
"""
from __future__ import annotations

from ecdat.data.crypto_families import hybrid_groups, is_hybrid_group


def test_x25519mlkem768_is_still_a_hybrid_group():
    assert is_hybrid_group("X25519MLKEM768") is True


def test_rfc_10024_groups_are_now_cited_hybrid_groups():
    assert is_hybrid_group("SecP256r1MLKEM768") is True
    assert is_hybrid_group("SecP384r1MLKEM1024") is True
    assert {"X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024"} <= hybrid_groups()


def test_an_uncited_group_spelling_is_not_a_hybrid_group():
    """No guessing by analogy: an unlisted spelling is not hybrid."""
    assert is_hybrid_group("SecP521r1MLKEM1024") is False
    assert is_hybrid_group(None) is False

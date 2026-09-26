"""data/crypto_families.yaml hybrid_groups (Pramana_Ledger_Spec.md §5.1).

RFC 10024 (docs/sources/IETF_RFC_10024_2026.md) resolved SecP256r1MLKEM768
and SecP384r1MLKEM1024 on 2026-09-26 -- previously recorded as "searched for
and NOT found in any in-repo document" (no guess by analogy with
X25519MLKEM768 was ever made, per data/base_confidence.yaml's own rule).
"""
from __future__ import annotations

from ecdat.data.crypto_families import (
    hybrid_group_codepoint,
    hybrid_groups,
    is_deprecated_hybrid_group,
    is_hybrid_group,
)


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


# --- OI-016/OI-017 resolution: codepoints and the deprecated draft group ---


def test_the_iana_codepoints_are_cited():
    assert hybrid_group_codepoint("X25519MLKEM768") == "0x11EC"
    assert hybrid_group_codepoint("SecP256r1MLKEM768") == "0x11EB"
    assert hybrid_group_codepoint("SecP384r1MLKEM1024") == "0x11ED"
    assert hybrid_group_codepoint("X25519Kyber768Draft00") == "0x6399"


def test_an_unlisted_group_has_no_codepoint():
    assert hybrid_group_codepoint("SecP521r1MLKEM1024") is None
    assert hybrid_group_codepoint(None) is None


def test_the_legacy_draft_group_is_still_a_hybrid_group_but_flagged_deprecated():
    """X25519Kyber768Draft00 predates RFC 10024 and was obsoleted by it, but
    a server that still negotiates it really is doing hybrid PQ key
    exchange -- §5.1 classifies any negotiated hybrid group as HYBRID_KEX,
    it does not carve out an exception for a superseded one. `deprecated`
    is a visibility flag, not a withheld classification."""
    assert is_hybrid_group("X25519Kyber768Draft00") is True
    assert is_deprecated_hybrid_group("X25519Kyber768Draft00") is True


def test_the_standardised_rfc_10024_groups_are_not_deprecated():
    assert is_deprecated_hybrid_group("X25519MLKEM768") is False
    assert is_deprecated_hybrid_group("SecP256r1MLKEM768") is False
    assert is_deprecated_hybrid_group("SecP384r1MLKEM1024") is False


def test_an_unlisted_group_is_not_deprecated_by_default():
    """No guessing: an unlisted spelling is neither hybrid nor deprecated."""
    assert is_deprecated_hybrid_group("SecP521r1MLKEM1024") is False
    assert is_deprecated_hybrid_group(None) is False

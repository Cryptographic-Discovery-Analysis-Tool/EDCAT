"""certmatch.py: matching cbomkit-theia's certificate components back to an
independently re-read certificate. Tested against the real extracted
ISRG Root X2 certificate (see fixtures/.../certs/README.md for provenance),
not a synthesised one.
"""
from __future__ import annotations

from pathlib import Path

from ecdat.adapters.images.certmatch import match_one, parse_bundle

FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "fixtures"
    / "recorded"
    / "theia"
    / "edge-2026-09-19"
    / "certs"
    / "isrg-root-x2.pem"
)

# Exactly cbomkit-theia's own measured field shape for this certificate
# (../certs/README.md): Common Name alone, not the full DN.
THEIA_SUBJECT_CN = "ISRG Root X2"
THEIA_ISSUER_CN = "ISRG Root X2"
THEIA_NOT_BEFORE = "2020-09-04T00:00:00Z"
THEIA_NOT_AFTER = "2040-09-17T16:00:00Z"

REAL_DER_SHA256 = "69729b8e15a86efc177a57afb7171dfc64add28c2fca8cf1507e34453ccb1470"
REAL_SPKI_SHA256 = "762195c225586ee6c0237456e2107dc54f1efc21f61a792ebd515913cce68332"


def test_parse_bundle_reads_the_real_certificate():
    (certificate,) = parse_bundle(FIXTURE.read_bytes())
    assert certificate.subject_cn == THEIA_SUBJECT_CN
    assert certificate.issuer_cn == THEIA_ISSUER_CN
    assert certificate.not_before == THEIA_NOT_BEFORE
    assert certificate.not_after == THEIA_NOT_AFTER
    assert certificate.der_sha256 == REAL_DER_SHA256
    assert certificate.spki_sha256 == REAL_SPKI_SHA256


def test_match_one_finds_the_certificate_by_theias_own_field_values():
    certificates = parse_bundle(FIXTURE.read_bytes())
    match = match_one(
        certificates,
        subject_cn=THEIA_SUBJECT_CN,
        issuer_cn=THEIA_ISSUER_CN,
        not_before=THEIA_NOT_BEFORE,
        not_after=THEIA_NOT_AFTER,
    )
    assert match is not None
    assert match.der_sha256 == REAL_DER_SHA256


def test_match_one_refuses_a_non_matching_subject():
    certificates = parse_bundle(FIXTURE.read_bytes())
    match = match_one(
        certificates,
        subject_cn="Some Other CA",
        issuer_cn=THEIA_ISSUER_CN,
        not_before=THEIA_NOT_BEFORE,
        not_after=THEIA_NOT_AFTER,
    )
    assert match is None


def test_match_one_refuses_when_any_field_is_missing():
    certificates = parse_bundle(FIXTURE.read_bytes())
    assert (
        match_one(
            certificates, subject_cn=None, issuer_cn=THEIA_ISSUER_CN,
            not_before=THEIA_NOT_BEFORE, not_after=THEIA_NOT_AFTER,
        )
        is None
    )


def test_match_one_refuses_an_ambiguous_duplicate_rather_than_guessing():
    """Two certificates that happen to share the full match key: neither may
    be silently chosen -- this is the exact case the module docstring's
    'honest limit' describes."""
    certificates = parse_bundle(FIXTURE.read_bytes())
    duplicated = certificates + certificates  # two "different" entries, same key
    match = match_one(
        duplicated,
        subject_cn=THEIA_SUBJECT_CN,
        issuer_cn=THEIA_ISSUER_CN,
        not_before=THEIA_NOT_BEFORE,
        not_after=THEIA_NOT_AFTER,
    )
    assert match is None


def test_the_full_dn_would_never_have_matched():
    """Documents exactly the discrepancy certmatch.py exists to work around:
    matching on the full rfc4514-style subject (what certs-x509 itself
    stores) against theia's bare-CN convention finds nothing."""
    certificates = parse_bundle(FIXTURE.read_bytes())
    full_dn = "CN=ISRG Root X2,O=Internet Security Research Group,C=US"
    assert all(c.subject_cn != full_dn for c in certificates)

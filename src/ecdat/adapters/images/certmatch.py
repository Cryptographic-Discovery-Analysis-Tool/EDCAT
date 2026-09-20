"""Matching cbomkit-theia's certificate components back to an independently
re-read certificate, so this surface's certificate Findings can carry a
real, canonicalised DER hash comparable to certs-x509's and tls-endpoint's.

**Why this exists.** cbomkit-theia's own CycloneDX output (confirmed against
a real, full 5082-component capture -- see
tests/fixtures/recorded/theia/edge-2026-09-19/README.md) never carries a
certificate hash or the raw bytes: `certificateProperties` gives
subjectName/issuerName/validity dates and format only. Unlike TLS (whose
sslyze output already carries the served certificate's own PEM --
tls/parser.py reuses certs/parser.py directly on it), this tool gives no
bytes to canonicalise. The only way to get a comparable hash here is to
independently read the same file cbomkit-theia reported
(`evidence.occurrences[].location` inside the image) and hash what is
actually there ourselves.

**Why matching, not just "hash the file".** The file at one `location` is
usually a bundle of many certificates -- Alpine's own
/etc/ssl/certs/ca-certificates.crt was measured (2026-09-20, live, against
the real Tier A `edge-lb` image) to hold 121 -- and cbomkit-theia emits one
component PER certificate inside it, all sharing that one `location`.
Hashing "the file" would give every certificate found there the same hash,
which is wrong. Each parsed certificate from the bundle must be matched
back to the specific component that describes it.

**The match key, and its honest limit.** cbomkit-theia's `subjectName`/
`issuerName` were measured against that same real bundle to be the Common
Name alone -- "ISRG Root X2", not the full
"CN=ISRG Root X2,O=Internet Security Research Group,C=US" python-cryptography
prints -- so matching here is on (subject CN, issuer CN, not-valid-before,
not-valid-after), not the full DN. This is a strong disambiguator in
practice, not a cryptographic identity proof the way a hash match is. When
more than one certificate in a bundle shares the exact same four values, or
none does, this module refuses to guess: an unresolved certificate stays
without a hash rather than risking a wrong one.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID


class CertBundleParseError(ValueError):
    """The extracted bytes were not a readable PEM certificate bundle."""


@dataclass(frozen=True)
class ExtractedCertificate:
    """One certificate read directly out of an extracted image file,
    reduced to the fields needed to match it against a cbomkit-theia
    component, plus the canonicalised hashes to attach once matched."""

    subject_cn: str | None
    issuer_cn: str | None
    not_before: str
    not_after: str
    der_sha256: str
    spki_sha256: str


def _common_name(name: x509.Name) -> str | None:
    attributes = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(attributes[0].value) if attributes else None


def _iso_z(value) -> str:
    """Match cbomkit-theia's own timestamp format exactly (measured live:
    "2020-09-04T00:00:00Z", second precision, literal "Z") so a real
    certificate's dates compare equal without either side reformatting the
    other's convention."""
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _not_valid_before(certificate: x509.Certificate):
    return getattr(certificate, "not_valid_before_utc", None) or certificate.not_valid_before


def _not_valid_after(certificate: x509.Certificate):
    return getattr(certificate, "not_valid_after_utc", None) or certificate.not_valid_after


def parse_bundle(data: bytes) -> tuple[ExtractedCertificate, ...]:
    """Every certificate in a PEM bundle, reduced for matching. Tolerant of
    nothing else -- an unreadable bundle raises rather than returning an
    empty tuple, which would look identical to "we looked and found none"."""
    try:
        certificates = x509.load_pem_x509_certificates(data)
    except Exception as exc:  # noqa: BLE001
        raise CertBundleParseError(
            f"not a readable PEM certificate bundle ({type(exc).__name__})"
        ) from None

    extracted: list[ExtractedCertificate] = []
    for certificate in certificates:
        der = certificate.public_bytes(serialization.Encoding.DER)
        spki = certificate.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        extracted.append(
            ExtractedCertificate(
                subject_cn=_common_name(certificate.subject),
                issuer_cn=_common_name(certificate.issuer),
                not_before=_iso_z(_not_valid_before(certificate)),
                not_after=_iso_z(_not_valid_after(certificate)),
                der_sha256=hashlib.sha256(der).hexdigest(),
                spki_sha256=hashlib.sha256(spki).hexdigest(),
            )
        )
    return tuple(extracted)


def match_one(
    certificates: tuple[ExtractedCertificate, ...],
    *,
    subject_cn: str | None,
    issuer_cn: str | None,
    not_before: str | None,
    not_after: str | None,
) -> ExtractedCertificate | None:
    """The one certificate in the bundle whose (subject CN, issuer CN,
    validity window) matches exactly, or None when zero or more than one
    does -- see module docstring "The match key, and its honest limit"."""
    if not (subject_cn and issuer_cn and not_before and not_after):
        return None
    candidates = [
        c
        for c in certificates
        if c.subject_cn == subject_cn
        and c.issuer_cn == issuer_cn
        and c.not_before == not_before
        and c.not_after == not_after
    ]
    return candidates[0] if len(candidates) == 1 else None

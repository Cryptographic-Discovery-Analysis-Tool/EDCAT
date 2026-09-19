"""Certificate parsing: PEM, DER and PKCS#12 (P4; spec §3 row "Certificates").

    "OpenSSL 3 + python-cryptography; DER SHA-256 / SPKI identity,
     canonicalised (TOPO-X3 FACT)"

Two hashes come out of every certificate, and they answer different questions.
Conflating them is the mistake this module exists to prevent:

* `der_sha256` -- SHA-256 over the certificate's canonical DER. Proves
  **same object**: these two files are byte-identical certificates. It proves
  nothing about trust, deployment or association (registry rule
  IDENTITY-CERT-DER-001, harness §15.2 T6).
* `spki_sha256` -- SHA-256 over the SubjectPublicKeyInfo DER. Proves
  **same key**: a renewed certificate carrying the same public key has a new
  `der_sha256` and the same `spki_sha256`. That is the only honest way to say
  "the key on this endpoint is the key in that keystore".

**Canonicalised** means the hash is taken over DER re-encoded by
python-cryptography, not over the bytes as they sat on disk. A PEM file and a
DER file holding the same certificate therefore hash identically, which is the
point -- but it also means the hash is not a file checksum and must never be
described as one.

This module handles private key material and emits none. A PKCS#12 file
contains a private key; `load_pkcs12` reads it and discards it unread. No
function here returns, logs, or stores a private key, and the adapter runs
every field it emits through the secret guard before anything leaves.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import pkcs12

#: Extensions we will attempt to parse. Anything else on disk is ignored
#: rather than guessed at, and the adapter records it as skipped.
CERTIFICATE_SUFFIXES = frozenset({".pem", ".crt", ".cer", ".der", ".p12", ".pfx"})


class CertificateParseError(ValueError):
    """The bytes are not a certificate we can read.

    Carries no input bytes and no exception text from the underlying library:
    a parser that echoes what it choked on is a parser that leaks key material
    the first time someone points it at a key file.
    """


@dataclass(frozen=True)
class ParsedCertificate:
    """One certificate, reduced to what may safely leave this process.

    Location and fingerprints only (CLAUDE.md). There is no field here that
    can hold key material: `public_key_size` is an integer, and the public key
    itself appears only as a hash.
    """

    location: str
    der_sha256: str
    spki_sha256: str
    subject: str
    issuer: str
    serial_number: str
    not_before: datetime
    not_after: datetime
    public_key_algorithm: str
    public_key_size: int | None
    public_key_curve: str | None
    signature_algorithm: str
    key_usage: tuple[str, ...]
    extended_key_usage: tuple[str, ...]
    subject_alt_names: tuple[str, ...]
    is_ca: bool
    source_format: str

    @property
    def self_signed(self) -> bool:
        """Subject equals issuer. NOT a trust claim -- a self-signed
        certificate may be a root we trust or one an attacker minted."""
        return self.subject == self.issuer


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _public_key_description(certificate: x509.Certificate) -> tuple[str, int | None, str | None]:
    """(algorithm, size in bits, curve name). Never the key."""
    key = certificate.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return "RSA", key.key_size, None
    if isinstance(key, ec.EllipticCurvePublicKey):
        return "EC", key.curve.key_size, key.curve.name
    if isinstance(key, dsa.DSAPublicKey):
        return "DSA", key.key_size, None
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519", 255, None
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448", 448, None
    # A key type this build of cryptography knows and we do not. Named, not
    # guessed at, and never silently mapped onto a family it might not be.
    return type(key).__name__, None, None


#: cryptography's KeyUsage attribute name -> the X.509 field name. The X.509
#: spellings are what `function.classifier` matches on, so the mapping lives
#: here rather than being re-derived at the call site.
_KEY_USAGE_BITS: tuple[tuple[str, str], ...] = (
    ("digital_signature", "digitalSignature"),
    ("content_commitment", "contentCommitment"),
    ("key_encipherment", "keyEncipherment"),
    ("data_encipherment", "dataEncipherment"),
    ("key_agreement", "keyAgreement"),
    ("key_cert_sign", "keyCertSign"),
    ("crl_sign", "cRLSign"),
)


def _key_usage(certificate: x509.Certificate) -> tuple[str, ...]:
    try:
        usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return ()
    bits = []
    for attribute, x509_name in _KEY_USAGE_BITS:
        try:
            if getattr(usage, attribute):
                bits.append(x509_name)
        except ValueError:
            # encipher_only / decipher_only raise unless key_agreement is set;
            # the guarded attributes above do not, but a future addition might.
            continue
    return tuple(bits)


def _extended_key_usage(certificate: x509.Certificate) -> tuple[str, ...]:
    try:
        eku = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        return ()
    return tuple(oid._name or oid.dotted_string for oid in eku)


def _subject_alt_names(certificate: x509.Certificate) -> tuple[str, ...]:
    try:
        san = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    except x509.ExtensionNotFound:
        return ()
    return tuple(str(name.value) for name in san)


def _is_ca(certificate: x509.Certificate) -> bool:
    try:
        return certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value.ca
    except x509.ExtensionNotFound:
        return False


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def describe(certificate: x509.Certificate, *, location: str, source_format: str) -> ParsedCertificate:
    """Reduce a certificate to the safe-to-emit record."""
    der = certificate.public_bytes(serialization.Encoding.DER)
    spki = certificate.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    algorithm, size, curve = _public_key_description(certificate)

    try:
        signature_algorithm = certificate.signature_algorithm_oid._name or (
            certificate.signature_algorithm_oid.dotted_string
        )
    except Exception:  # noqa: BLE001 -- an unknown OID is named, never guessed
        signature_algorithm = "unknown"

    return ParsedCertificate(
        location=location,
        der_sha256=_sha256(der),
        spki_sha256=_sha256(spki),
        subject=certificate.subject.rfc4514_string(),
        issuer=certificate.issuer.rfc4514_string(),
        serial_number=format(certificate.serial_number, "x"),
        not_before=_aware(certificate.not_valid_before_utc),
        not_after=_aware(certificate.not_valid_after_utc),
        public_key_algorithm=algorithm,
        public_key_size=size,
        public_key_curve=curve,
        signature_algorithm=signature_algorithm,
        key_usage=_key_usage(certificate),
        extended_key_usage=_extended_key_usage(certificate),
        subject_alt_names=_subject_alt_names(certificate),
        is_ca=_is_ca(certificate),
        source_format=source_format,
    )


def load_pem_or_der(data: bytes, *, location: str) -> tuple[ParsedCertificate, ...]:
    """Every certificate in a PEM bundle, or the single certificate in a DER
    file. A PEM bundle legitimately holds a chain, so this returns many."""
    if b"-----BEGIN CERTIFICATE-----" in data:
        try:
            certificates = x509.load_pem_x509_certificates(data)
        except Exception as exc:  # noqa: BLE001
            raise CertificateParseError(
                f"{location}: not a readable PEM certificate ({type(exc).__name__})"
            ) from None
        return tuple(describe(c, location=location, source_format="PEM") for c in certificates)

    try:
        certificate = x509.load_der_x509_certificate(data)
    except Exception as exc:  # noqa: BLE001
        raise CertificateParseError(
            f"{location}: not a readable DER certificate ({type(exc).__name__})"
        ) from None
    return (describe(certificate, location=location, source_format="DER"),)


def load_pkcs12(data: bytes, *, location: str, password: bytes | None = None) -> tuple[ParsedCertificate, ...]:
    """Certificates from a PKCS#12 keystore. The private key is never returned.

    `password` is an INPUT and is never recorded anywhere: it does not appear
    in the returned records, in the exception text, or in any log line. A
    keystore we cannot open raises rather than being reported as empty --
    "could not open" and "contains nothing" are different facts.
    """
    try:
        key, certificate, extra = pkcs12.load_key_and_certificates(data, password)
    except Exception as exc:  # noqa: BLE001 -- never echo the bytes or the password
        raise CertificateParseError(
            f"{location}: PKCS#12 keystore could not be opened ({type(exc).__name__}); "
            "wrong password, or not a PKCS#12 file"
        ) from None

    del key  # read and discarded, unexamined. See the module docstring.

    parsed = []
    if certificate is not None:
        parsed.append(describe(certificate, location=location, source_format="PKCS12"))
    for additional in extra or ():
        parsed.append(describe(additional, location=location, source_format="PKCS12"))
    if not parsed:
        raise CertificateParseError(f"{location}: PKCS#12 keystore holds no certificate")
    return tuple(parsed)


def load_path(path: Path, *, password: bytes | None = None) -> tuple[ParsedCertificate, ...]:
    """Parse one file, choosing the reader by extension."""
    data = path.read_bytes()
    location = str(path)
    if path.suffix.lower() in {".p12", ".pfx"}:
        return load_pkcs12(data, location=location, password=password)
    return load_pem_or_der(data, location=location)

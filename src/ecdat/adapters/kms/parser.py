"""AWS KMS metadata parsing (P11, KMS half; spec §3 row "Hardware / cloud").

Parses exactly three `aws kms` CLI JSON outputs: `list-keys` (account-level
enumeration), `describe-key` (per-key metadata -- spec, usage, state,
origin), and `get-public-key` (the exported public half of an asymmetric
key, when one exists). See
tests/fixtures/recorded/aws-kms/localstack-3.0.2/README.md for exactly how
these were recorded -- against LocalStack, not a real AWS account (no
credentials were available in this environment), documented there as a
fact about provenance, not hidden.

**No key material can appear here, by construction of the API itself.**
`describe-key` and `list-keys` never carry key bytes for any key type.
`get-public-key` carries only the public half of an asymmetric key -- KMS
refuses to export a `CUSTOMER`-managed private key over its API at all, and
a symmetric key has no public half to export. This module therefore has no
field capable of holding a private key even by mistake.
"""
from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


class KmsParseError(ValueError):
    """The bytes were not a readable `aws kms` JSON response."""


@dataclass(frozen=True)
class ParsedKmsKey:
    """One key's metadata, from `describe-key`. Every field here is
    something AWS's own API states about the key -- never a guess about
    what the key is used for beyond its own declared `key_usage`."""

    key_id: str
    arn: str
    description: str
    enabled: bool
    key_state: str
    key_usage: str
    key_spec: str
    origin: str
    key_manager: str
    creation_date: datetime | None
    signing_algorithms: tuple[str, ...]
    encryption_algorithms: tuple[str, ...]
    multi_region: bool | None


def parse_list_keys(document: dict[str, Any]) -> tuple[str, ...]:
    """Every key ID `list-keys` enumerated -- the starting point for a real
    scan: describe-key is then called once per ID this returns."""
    keys = document.get("Keys")
    if not isinstance(keys, list):
        raise KmsParseError("list-keys document has no 'Keys' array")
    return tuple(str(entry.get("KeyId", "")) for entry in keys if isinstance(entry, dict))


def _epoch_to_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    except (TypeError, ValueError):
        return None


def parse_describe_key(document: dict[str, Any]) -> ParsedKmsKey:
    """Parse one `describe-key` response."""
    metadata = document.get("KeyMetadata")
    if not isinstance(metadata, dict):
        raise KmsParseError("describe-key document has no 'KeyMetadata' object")

    return ParsedKmsKey(
        key_id=str(metadata.get("KeyId", "")),
        arn=str(metadata.get("Arn", "")),
        description=str(metadata.get("Description", "")),
        enabled=bool(metadata.get("Enabled", False)),
        key_state=str(metadata.get("KeyState", "")),
        key_usage=str(metadata.get("KeyUsage", "")),
        key_spec=str(metadata.get("KeySpec") or metadata.get("CustomerMasterKeySpec") or ""),
        origin=str(metadata.get("Origin", "")),
        key_manager=str(metadata.get("KeyManager", "")),
        creation_date=_epoch_to_datetime(metadata.get("CreationDate")),
        signing_algorithms=tuple(metadata.get("SigningAlgorithms") or ()),
        encryption_algorithms=tuple(metadata.get("EncryptionAlgorithms") or ()),
        multi_region=metadata.get("MultiRegion"),
    )


def parse_get_public_key_spki_sha256(document: dict[str, Any]) -> str | None:
    """The SHA-256 hex digest of the exported public key's raw DER bytes,
    or None when the response carries no `PublicKey` field.

    AWS's own documentation for `GetPublicKey` describes `PublicKey` as
    "the exported public key... DER-encoded X.509 public key, also known as
    SubjectPublicKeyInfo (SPKI)" -- the exact same encoding
    `certs/parser.py` hashes for its own `spki_sha256` field. No
    re-derivation is needed or performed here: this is a direct base64
    decode of what AWS already returns, hashed with the same algorithm, so
    it is directly comparable to a certificate's `spki_sha256` computed
    anywhere else in this codebase -- the two are, if the underlying key
    material is the same, the same hash.
    """
    encoded = document.get("PublicKey")
    if not encoded:
        return None
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError) as exc:
        raise KmsParseError(f"PublicKey was not valid base64 ({type(exc).__name__})") from None
    return hashlib.sha256(raw).hexdigest()

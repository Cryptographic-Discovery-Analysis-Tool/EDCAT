"""Signed export: JSF over a CycloneDX BOM (OI-013, closed 2026-09-21).

§3 lists "signed export (VERIFY JSF field)" and §9 item 5 asks us to verify
CycloneDX's JSF `signature` field; OI-013 filed both as open, deliberately
deferred, because *"signing needs a key, and a key needs a custody story --
where it lives, who can use it, how it is rotated, and what a verifier is
supposed to trust."* That story, minimum honest version, now exists:

* **Where it lives.** A PEM-encoded Ed25519 private key at a path named by
  `ECDAT_SIGNING_KEY_PATH` -- never in the repo, never in an env var's own
  value (only a *path* to a file is configured, the same shape
  `ECDAT_API_TOKENS` uses for a different secret). `ecdat keygen` (cli.py)
  generates one.
* **Who can use it.** Whatever process can read that file. This module never
  logs the private key, never serialises it, and holds it in memory only for
  the duration of one `sign_bom()` call -- the same discipline
  `security/secrets.py`'s guard already enforces on everything this project
  emits.
* **How it is rotated.** Not automated. Generate a new key, point
  `ECDAT_SIGNING_KEY_PATH` at it, restart. Key rotation with overlap (old
  signatures still verifying against a retired key) is exactly the kind of
  "encrypted export / signed offline update bundle" hardening work §8
  already lists as a later phase, not invented here.
* **What a verifier is supposed to trust.** The embedded public key, by
  itself -- a bare Ed25519 key, self-attested, exactly like an SSH key.
  There is no certificate chain (`certificatePath` is a real, optional JSF
  field this module does not populate) and no external PKI: a verifier who
  wants more than "the document was not altered after this specific key
  signed it" needs that key's fingerprint communicated out of band, which is
  a distribution problem this module does not solve. Recorded here rather
  than implied by the presence of a `signature` block.

Algorithm: Ed25519 only, over the document canonicalised with RFC 8785 JCS
(`rfc8785`, a pinned dependency -- see pyproject.toml's comment on why a
security-critical canonicalisation algorithm is not reimplemented here). Per
JSF's own spec page (fetched 2026-09-21, quoted rather than recalled): the
signature's own `value` field is excluded from what gets signed -- a
value-less `signature` stub is added to the document first, the WHOLE
resulting object (document + stub) is canonicalised, and the raw signature
bytes over those canonical bytes become `value`, base64url-encoded, no
padding (RFC4648, the `"byte[]"` type JSF's schema names for `value`).
Verification reverses exactly that: strip `value`, canonicalise, verify.

`schemas/jsf-0.82.schema.json` is the real, fetched schema (CycloneDX's
`specification` repo, Apache-2.0), not the permissive stub `export/
cyclonedx.py::_validator()` used before this file existed -- every `signature`
this module produces is schema-checked, not merely schema-shaped.
"""
from __future__ import annotations

import base64
import os
from pathlib import Path
from typing import Any

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


class NoSigningKeyError(LookupError):
    """No signing key is configured. An export proceeds unsigned rather than
    inventing or defaulting one -- the same posture `security/auth.py` takes
    toward an unconfigured token registry."""


class AlreadySignedError(ValueError):
    """The document already carries a `signature`. Signing over it would
    silently discard whoever signed it first."""


class MissingSignatureError(ValueError):
    """The document carries no `signature` to verify."""


class SignatureVerificationError(ValueError):
    """A `signature` is present, structurally sound, and does not verify --
    or is missing a field verification cannot proceed without."""


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def generate_signing_key() -> Ed25519PrivateKey:
    """A fresh key. Never written anywhere by this function -- the caller
    decides where the PEM bytes go (`ecdat keygen`'s only job)."""
    return Ed25519PrivateKey.generate()


def private_key_pem(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def load_signing_key(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(
            f"{path} is not an Ed25519 private key; this module signs with Ed25519 only "
            "(JSF's schema also allows RS*/PS*/ES*/HS*, none implemented here)"
        )
    return key


def signing_key_from_env(var: str = "ECDAT_SIGNING_KEY_PATH") -> Ed25519PrivateKey | None:
    """`None` when unset -- the caller decides what an unsigned export means
    (usually: export it anyway, unsigned, and say so)."""
    raw = os.environ.get(var)
    if not raw:
        return None
    return load_signing_key(Path(raw))


def _public_key_jwk(public_key: Ed25519PublicKey) -> dict[str, str]:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return {"kty": "OKP", "crv": "Ed25519", "x": _b64url(raw)}


def sign_bom(
    document: dict[str, Any], *, private_key: Ed25519PrivateKey, key_id: str
) -> dict[str, Any]:
    """Add a JSF `signature` to `document` (a shallow copy; the input is
    never mutated). `key_id` is JSF's `keyId` -- an operator-chosen label
    for which key this is, not a claim this module verifies on its own."""
    if "signature" in document:
        raise AlreadySignedError("document already carries a signature")

    stub = {
        "algorithm": "Ed25519",
        "keyId": key_id,
        "publicKey": _public_key_jwk(private_key.public_key()),
    }
    canonical = rfc8785.dumps({**document, "signature": stub})
    raw_signature = private_key.sign(canonical)
    return {**document, "signature": {**stub, "value": _b64url(raw_signature)}}


def verify_bom(document: dict[str, Any]) -> None:
    """Raise unless `document["signature"]` verifies against its own
    embedded public key. Says nothing about who that key belongs to -- see
    this module's docstring on what a verifier is and is not entitled to
    trust from that alone."""
    signature = document.get("signature")
    if signature is None:
        raise MissingSignatureError("document carries no signature")
    if signature.get("algorithm") != "Ed25519":
        raise SignatureVerificationError(
            f"unsupported algorithm {signature.get('algorithm')!r}; this verifier checks Ed25519 only"
        )
    public_key_jwk = signature.get("publicKey") or {}
    if public_key_jwk.get("kty") != "OKP" or public_key_jwk.get("crv") != "Ed25519" or "x" not in public_key_jwk:
        raise SignatureVerificationError("signature has no usable Ed25519 publicKey (kty=OKP, crv=Ed25519)")
    if "value" not in signature:
        raise SignatureVerificationError("signature has no value")

    public_key = Ed25519PublicKey.from_public_bytes(_b64url_decode(public_key_jwk["x"]))
    stub = {k: v for k, v in signature.items() if k != "value"}
    canonical = rfc8785.dumps({**document, "signature": stub})

    try:
        public_key.verify(_b64url_decode(signature["value"]), canonical)
    except InvalidSignature as error:
        raise SignatureVerificationError("signature does not verify") from error

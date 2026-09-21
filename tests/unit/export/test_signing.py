"""Signed export: JSF over a CycloneDX BOM (OI-013)."""
from __future__ import annotations

import copy
from datetime import datetime, timezone

import pytest

from ecdat.export.cyclonedx import build_bom, validate
from ecdat.export.signing import (
    AlreadySignedError,
    MissingSignatureError,
    SignatureVerificationError,
    generate_signing_key,
    load_signing_key,
    private_key_pem,
    sign_bom,
    signing_key_from_env,
    verify_bom,
)

TIMESTAMP = datetime(2026, 9, 18, 12, 0, tzinfo=timezone.utc)


def _document():
    return build_bom([], timestamp=TIMESTAMP)


def test_signed_document_verifies():
    key = generate_signing_key()
    signed = sign_bom(_document(), private_key=key, key_id="test-key")
    verify_bom(signed)  # must not raise


def test_signed_document_validates_against_the_real_jsf_schema():
    key = generate_signing_key()
    signed = sign_bom(_document(), private_key=key, key_id="test-key")
    validate(signed)  # must not raise -- schemas/jsf-0.82.schema.json, not a stub


def test_signature_has_the_jsf_shape():
    key = generate_signing_key()
    signed = sign_bom(_document(), private_key=key, key_id="test-key")
    sig = signed["signature"]
    assert sig["algorithm"] == "Ed25519"
    assert sig["keyId"] == "test-key"
    assert sig["publicKey"]["kty"] == "OKP"
    assert sig["publicKey"]["crv"] == "Ed25519"
    assert isinstance(sig["value"], str)
    assert "=" not in sig["value"], "base64url must be unpadded per JSF's byte[] type"


def test_signing_does_not_mutate_the_input():
    document = _document()
    original = copy.deepcopy(document)
    sign_bom(document, private_key=generate_signing_key(), key_id="k")
    assert document == original


def test_a_tampered_component_fails_verification():
    key = generate_signing_key()
    signed = sign_bom(_document(), private_key=key, key_id="k")
    signed["properties"].append({"name": "tampered", "value": "true"})
    with pytest.raises(SignatureVerificationError):
        verify_bom(signed)


def test_a_tampered_signature_value_fails_verification():
    key = generate_signing_key()
    signed = sign_bom(_document(), private_key=key, key_id="k")
    other = generate_signing_key().sign(b"unrelated bytes")
    import base64

    signed["signature"]["value"] = base64.urlsafe_b64encode(other).rstrip(b"=").decode()
    with pytest.raises(SignatureVerificationError):
        verify_bom(signed)


def test_verifying_the_wrong_key_fails():
    """Swap in a different (but structurally valid) public key -- the
    signature was never made by whoever that key belongs to."""
    key = generate_signing_key()
    signed = sign_bom(_document(), private_key=key, key_id="k")
    intruder_public = generate_signing_key().public_key()
    from ecdat.export.signing import _public_key_jwk

    signed["signature"]["publicKey"] = _public_key_jwk(intruder_public)
    with pytest.raises(SignatureVerificationError):
        verify_bom(signed)


def test_verify_an_unsigned_document_raises_missing_signature():
    with pytest.raises(MissingSignatureError):
        verify_bom(_document())


def test_signing_an_already_signed_document_refuses():
    key = generate_signing_key()
    signed = sign_bom(_document(), private_key=key, key_id="k")
    with pytest.raises(AlreadySignedError):
        sign_bom(signed, private_key=key, key_id="k")


def test_verify_rejects_a_non_ed25519_algorithm():
    signed = sign_bom(_document(), private_key=generate_signing_key(), key_id="k")
    signed["signature"]["algorithm"] = "ES256"
    with pytest.raises(SignatureVerificationError):
        verify_bom(signed)


def test_key_round_trips_through_pem(tmp_path):
    key = generate_signing_key()
    path = tmp_path / "signing-key.pem"
    path.write_bytes(private_key_pem(key))

    loaded = load_signing_key(path)
    document = _document()
    signed_a = sign_bom(document, private_key=key, key_id="k")
    signed_b = sign_bom(document, private_key=loaded, key_id="k")
    assert signed_a["signature"]["value"] == signed_b["signature"]["value"]


def test_private_key_pem_never_appears_in_a_signed_document(tmp_path):
    key = generate_signing_key()
    pem = private_key_pem(key)
    signed = sign_bom(_document(), private_key=key, key_id="k")
    import json

    dumped = json.dumps(signed)
    assert pem.decode("ascii") not in dumped
    assert b"PRIVATE KEY" not in json.dumps(signed).encode()


def test_signing_key_from_env_is_none_when_unset(monkeypatch):
    monkeypatch.delenv("ECDAT_SIGNING_KEY_PATH", raising=False)
    assert signing_key_from_env() is None


def test_signing_key_from_env_loads_the_configured_path(tmp_path, monkeypatch):
    key = generate_signing_key()
    path = tmp_path / "signing-key.pem"
    path.write_bytes(private_key_pem(key))
    monkeypatch.setenv("ECDAT_SIGNING_KEY_PATH", str(path))

    loaded = signing_key_from_env()
    assert loaded is not None
    document = _document()
    signed_a = sign_bom(document, private_key=key, key_id="k")
    signed_b = sign_bom(document, private_key=loaded, key_id="k")
    assert signed_a["signature"]["value"] == signed_b["signature"]["value"]


def test_load_signing_key_rejects_a_non_ed25519_key(tmp_path):
    from cryptography.hazmat.primitives.asymmetric import rsa

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    from cryptography.hazmat.primitives import serialization

    path = tmp_path / "rsa-key.pem"
    path.write_bytes(
        rsa_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    with pytest.raises(ValueError):
        load_signing_key(path)

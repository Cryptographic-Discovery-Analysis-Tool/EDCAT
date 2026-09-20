"""kms/parser.py against the real recorded LocalStack fixtures."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from ecdat.adapters.kms.parser import (
    KmsParseError,
    parse_describe_key,
    parse_get_public_key_spki_sha256,
    parse_list_keys,
)

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "recorded" / "aws-kms" / "localstack-3.0.2"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_parse_list_keys_reads_both_real_key_ids():
    keys = parse_list_keys(_load("list-keys.json"))
    assert keys == (
        "c5e5d28f-fa8a-4b1a-859a-6e7c842352ac",
        "dd316ada-96cf-4078-93da-53ab2473536b",
    )


def test_parse_describe_key_symmetric():
    key = parse_describe_key(_load("describe-key-symmetric.json"))
    assert key.key_id == "c5e5d28f-fa8a-4b1a-859a-6e7c842352ac"
    assert key.key_usage == "ENCRYPT_DECRYPT"
    assert key.key_spec == "SYMMETRIC_DEFAULT"
    assert key.key_state == "Enabled"
    assert key.enabled is True
    assert key.origin == "AWS_KMS"
    assert key.key_manager == "CUSTOMER"
    assert key.encryption_algorithms == ("SYMMETRIC_DEFAULT",)
    assert key.signing_algorithms == ()
    assert key.creation_date is not None


def test_parse_describe_key_rsa_carries_all_six_signing_algorithms():
    key = parse_describe_key(_load("describe-key-rsa.json"))
    assert key.key_spec == "RSA_2048"
    assert len(key.signing_algorithms) == 6
    assert "RSASSA_PSS_SHA_256" in key.signing_algorithms


def test_parse_get_public_key_spki_sha256_matches_independent_computation():
    """The expected value here was computed independently (base64-decode +
    hashlib.sha256 in a throwaway script against the same real fixture
    bytes) before this function existed, then re-confirmed by this test --
    not derived from the function under test."""
    digest = parse_get_public_key_spki_sha256(_load("get-public-key-ecc.json"))
    assert digest == "9018f0999a68c4d5a5df4c94f5a77b607f7418b6ea396018e17c828b0667893f"
    assert len(digest) == 64


def test_symmetric_key_response_has_no_public_key_to_hash():
    """A describe-key response is never fed to this function in practice
    (only get-public-key responses are), but it must not fabricate a hash
    from a document that simply lacks a PublicKey field."""
    assert parse_get_public_key_spki_sha256(_load("describe-key-symmetric.json")) is None


def test_parse_list_keys_rejects_a_document_with_no_keys_array():
    with pytest.raises(KmsParseError):
        parse_list_keys({"NotKeys": []})


def test_parse_describe_key_rejects_a_document_with_no_key_metadata():
    with pytest.raises(KmsParseError):
        parse_describe_key({"NotKeyMetadata": {}})

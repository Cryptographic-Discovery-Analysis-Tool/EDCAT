import pytest

from ecdat.rules import registry


def test_verified_rules_are_registered():
    for rule_id in (
        "TLS-FRONT-001",
        "IMG-SRC-001",
        "TLS-POLICY-001",
        "IDENTITY-CERT-DER-001",
    ):
        assert registry.is_registered(rule_id)
        definition = registry.get(rule_id)
        assert definition.citation


def test_unregistered_rule_id_lookup_fails():
    assert not registry.is_registered("NOT-A-REAL-RULE")
    with pytest.raises(KeyError):
        registry.get("NOT-A-REAL-RULE")


def test_duplicate_registration_rejected():
    with pytest.raises(ValueError):
        registry.register("TLS-FRONT-001", "conflict", "dup", "dup")


def test_shares_public_key_rule_not_invented():
    # OI-006: no literal rule_id exists for shares-public-key in the
    # canonical sources, so none should be registered here.
    for definition in registry.all_rules():
        assert "SPKI" not in definition.rule_id
        assert "SHARES-PUBLIC-KEY" not in definition.rule_id.upper()

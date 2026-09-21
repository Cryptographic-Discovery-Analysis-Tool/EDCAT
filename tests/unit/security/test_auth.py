"""RBAC (build-plan.md P17)."""
from __future__ import annotations

import pytest

from ecdat.security.auth import (
    InsufficientRoleError,
    InvalidTokenError,
    MissingTokenError,
    Principal,
    Role,
    TokenRegistry,
    fingerprint,
)


def test_empty_registry_refuses_every_token():
    registry = TokenRegistry.empty()
    with pytest.raises(InvalidTokenError):
        registry.authenticate("anything")


def test_no_token_is_a_missing_token_error():
    registry = TokenRegistry.empty()
    with pytest.raises(MissingTokenError):
        registry.authenticate(None)
    with pytest.raises(MissingTokenError):
        registry.authenticate("")


def test_a_registered_token_authenticates_to_its_role():
    registry = TokenRegistry.from_raw_tokens({"viewer-secret": Role.VIEWER})
    principal = registry.authenticate("viewer-secret")
    assert principal.role == Role.VIEWER
    assert principal.fingerprint == fingerprint("viewer-secret")


def test_an_unregistered_token_is_invalid():
    registry = TokenRegistry.from_raw_tokens({"viewer-secret": Role.VIEWER})
    with pytest.raises(InvalidTokenError):
        registry.authenticate("some-other-token")


def test_the_principal_never_carries_the_raw_token():
    registry = TokenRegistry.from_raw_tokens({"my-raw-token": Role.EXPORTER})
    principal = registry.authenticate("my-raw-token")
    dumped = principal.model_dump_json()
    assert "my-raw-token" not in dumped


def test_viewer_can_view_but_not_export():
    viewer = Principal(fingerprint="x", role=Role.VIEWER)
    assert viewer.can(Role.VIEWER) is True
    assert viewer.can(Role.EXPORTER) is False


def test_exporter_can_do_both():
    exporter = Principal(fingerprint="x", role=Role.EXPORTER)
    assert exporter.can(Role.VIEWER) is True
    assert exporter.can(Role.EXPORTER) is True


def test_insufficient_role_error_names_both_roles():
    error = InsufficientRoleError(required=Role.EXPORTER, actual=Role.VIEWER)
    assert error.required == Role.EXPORTER
    assert error.actual == Role.VIEWER
    assert error.status_code == 403


def test_missing_and_invalid_token_are_401():
    assert MissingTokenError().status_code == 401
    assert InvalidTokenError().status_code == 401


def test_fingerprint_is_stable_and_not_reversible_looking():
    a = fingerprint("same-token")
    b = fingerprint("same-token")
    assert a == b
    assert len(a) == 16
    assert "same-token" not in a


def test_from_env_missing_variable_is_empty(monkeypatch):
    monkeypatch.delenv("ECDAT_API_TOKENS", raising=False)
    registry = TokenRegistry.from_env()
    with pytest.raises(InvalidTokenError):
        registry.authenticate("anything")


def test_from_env_reads_a_json_object(monkeypatch):
    monkeypatch.setenv("ECDAT_API_TOKENS", '{"env-token": "EXPORTER"}')
    registry = TokenRegistry.from_env()
    principal = registry.authenticate("env-token")
    assert principal.role == Role.EXPORTER


def test_from_env_rejects_malformed_json(monkeypatch):
    monkeypatch.setenv("ECDAT_API_TOKENS", "not json")
    with pytest.raises(ValueError):
        TokenRegistry.from_env()


def test_from_env_rejects_a_non_object(monkeypatch):
    monkeypatch.setenv("ECDAT_API_TOKENS", "[1, 2, 3]")
    with pytest.raises(ValueError):
        TokenRegistry.from_env()


def test_from_env_rejects_an_unknown_role(monkeypatch):
    monkeypatch.setenv("ECDAT_API_TOKENS", '{"tok": "ADMIN"}')
    with pytest.raises(ValueError):
        TokenRegistry.from_env()

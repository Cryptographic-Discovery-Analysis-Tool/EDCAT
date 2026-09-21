"""RBAC for the read API (build-plan.md P17).

The deck's fourth control for "the inventory is itself a sensitive asset" --
on-prem, no key material stored (`security/secrets.py`), the network
definition (P18) -- and this: an authenticated API with roles that
distinguish *reading* the ledger from *exporting* it. Export is the sensitive
verb here, not scanning: a CBOM export leaves the process with every row's
band, deadline and evidence citation in it, so it is the one action this
module gates more tightly than a read.

Two roles, closed set:

* `VIEWER` -- read the ledger, closure queue, coverage, recommendations,
  the graph, and one record's evidence card.
* `EXPORTER` -- everything a `VIEWER` can do, plus `/api/export`.

Tokens are looked up by their SHA-256 fingerprint, never compared or logged
as raw text (CLAUDE.md: "No private key / secret bytes in ... logs ...").
`TokenRegistry` holds `{fingerprint: Role}`; `authenticate(raw_token)` hashes
what it was handed and looks the hash up -- the raw token exists in memory
only for the duration of that one call.

No token registry is configured by default: an app built with
`TokenRegistry.empty()` (the default `create_app()` uses when nothing else is
supplied) accepts nothing and returns 401 for every request. That is the
secure default this module chooses on purpose -- an operator has to supply
`ECDAT_API_TOKENS` (or pass a registry directly) before the API opens up at
all, rather than shipping open until someone remembers to lock it down.
"""
from __future__ import annotations

import hashlib
import json
import os
from enum import Enum

from pydantic import BaseModel, ConfigDict


class Role(str, Enum):
    """Closed set. A third role needs a citation in this docstring and in
    build-plan.md P17 before it is added, the same discipline every other
    closed enum in this codebase already follows."""

    VIEWER = "VIEWER"
    EXPORTER = "EXPORTER"


#: EXPORTER can do everything VIEWER can; there is no role that can export
#: but not view. Not a hierarchy of more than two levels -- adding one needs
#: the same citation discipline as a new Role value.
_IMPLIES: dict[Role, frozenset[Role]] = {
    Role.VIEWER: frozenset({Role.VIEWER}),
    Role.EXPORTER: frozenset({Role.VIEWER, Role.EXPORTER}),
}


class Principal(BaseModel):
    """Who made this request, named only by a fingerprint -- never by the
    raw token, which this object never carries."""

    model_config = ConfigDict(frozen=True)

    fingerprint: str
    role: Role

    def can(self, required: Role) -> bool:
        return required in _IMPLIES[self.role]


class AuthError(Exception):
    """Base class. `status_code` lets the FastAPI wiring turn this straight
    into an HTTP response without a second mapping table to keep in sync."""

    status_code: int = 401


class MissingTokenError(AuthError):
    status_code = 401


class InvalidTokenError(AuthError):
    status_code = 401


class InsufficientRoleError(AuthError):
    status_code = 403

    def __init__(self, *, required: Role, actual: Role) -> None:
        super().__init__(f"role {actual.value} cannot perform an action requiring {required.value}")
        self.required = required
        self.actual = actual


def fingerprint(raw_token: str) -> str:
    """The only form of a token this module ever stores, logs, or compares
    against. Truncated to 16 hex chars: enough to distinguish tokens in an
    audit log, not enough to be usable as a rainbow-table target for
    anything meaningful."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()[:16]


class TokenRegistry:
    """`{fingerprint(raw_token): Role}`. Construct with `from_env()` for a
    real deployment, `empty()` for a locked-down default, or the constructor
    directly (tests only -- see module docstring on why raw tokens are never
    logged, which is a reason to keep them out of fixture files too, not a
    reason to avoid them in test code that never writes to a log)."""

    def __init__(self, tokens: dict[str, Role]):
        self._tokens = dict(tokens)

    @classmethod
    def empty(cls) -> "TokenRegistry":
        return cls({})

    @classmethod
    def from_raw_tokens(cls, raw_tokens: dict[str, Role]) -> "TokenRegistry":
        """Build a registry from `{raw_token: Role}`, hashing each token
        here so the caller's own dict (which does carry raw tokens, because
        it has to in order to configure them) is the only place they exist
        outside this call."""
        return cls({fingerprint(token): role for token, role in raw_tokens.items()})

    @classmethod
    def from_env(cls, var: str = "ECDAT_API_TOKENS") -> "TokenRegistry":
        """`{raw_token: role_name}` as a JSON object in the named
        environment variable. Unset or empty -> `empty()`, the secure
        default."""
        raw = os.environ.get(var)
        if not raw:
            return cls.empty()
        try:
            document = json.loads(raw)
        except json.JSONDecodeError as error:
            raise ValueError(f"{var} is not valid JSON: {error}") from error
        if not isinstance(document, dict):
            raise ValueError(f"{var} must be a JSON object of {{token: role}}")
        return cls.from_raw_tokens({token: Role(role) for token, role in document.items()})

    def authenticate(self, raw_token: str | None) -> Principal:
        if not raw_token:
            raise MissingTokenError("no token presented")
        role = self._tokens.get(fingerprint(raw_token))
        if role is None:
            raise InvalidTokenError("token not recognised")
        return Principal(fingerprint=fingerprint(raw_token), role=role)

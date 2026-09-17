"""Registry of every inference/identity/conflict rule_id used across ECDAT.

CLAUDE.md hard rule: rule_id is mandatory for derived fields (R-DERIVE) and
for inferred/content-identity/conflict relationships (Lock §4 TOPO-001,
harness §15.2 T1). This module is the single place a rule_id becomes valid --
`model.field_value.derive()` and `model.relationship.Relationship` both check
against it, so an unregistered rule_id fails fast instead of silently
producing an uncited derivation or edge.

Every entry must cite the Lock section or harness section (14-16) it comes
from. Do not add a rule_id here from memory -- see CLAUDE.md anti-hallucination
rules and docs/open-issues.md.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

RuleCategory = Literal["inference", "identity", "conflict"]


@dataclass(frozen=True)
class RuleDefinition:
    rule_id: str
    category: RuleCategory
    citation: str
    summary: str


_REGISTRY: dict[str, RuleDefinition] = {}


def register(rule_id: str, category: RuleCategory, citation: str, summary: str) -> RuleDefinition:
    if rule_id in _REGISTRY:
        raise ValueError(f"rule_id already registered: {rule_id!r}")
    definition = RuleDefinition(rule_id=rule_id, category=category, citation=citation, summary=summary)
    _REGISTRY[rule_id] = definition
    return definition


def is_registered(rule_id: str) -> bool:
    return rule_id in _REGISTRY


def get(rule_id: str) -> RuleDefinition:
    try:
        return _REGISTRY[rule_id]
    except KeyError:
        raise KeyError(f"rule_id not in registry: {rule_id!r}") from None


def all_rules() -> tuple[RuleDefinition, ...]:
    return tuple(_REGISTRY.values())


# --- Verified rule_ids only -------------------------------------------------
# Each of these is a literal rule_id named in the Lock or harness sections
# 14-16. Do not add a rule_id without a matching citation.

register(
    "TLS-FRONT-001",
    "conflict",
    "Lock §4 TOPO-001 'Conflict rules'; harness §15.2 T2",
    "Declared terminates-tls-for, same SNI, both certificates observed, "
    "but the wire cert doesn't match the declared termination.",
)

register(
    "IMG-SRC-001",
    "conflict",
    "Lock §4 TOPO-001 'Conflict rules'; harness §15.2 T3",
    "Declared source repository for an application differs from the "
    "artifact-asserted image.source.",
)

register(
    "TLS-POLICY-001",
    "conflict",
    "Lock §4 TOPO-001 'Conflict rules'; harness §15.2 T4",
    "A declared TLS policy (minimum version / cipher policy) differs from "
    "observed endpoint handshake behaviour.",
)

register(
    "IDENTITY-CERT-DER-001",
    "identity",
    "harness §15.2 T6 'Frozen qualifier on T6'",
    "SHA-256 over canonical DER of a certificate proves same-object byte "
    "identity only -- not genuineness, trust, deployment or association.",
)

# NOTE: the harness (§15.2 T6) also defines a shares-public-key identity rule
# (SHA-256 over SubjectPublicKeyInfo DER) but never gives it a literal
# rule_id, unlike IDENTITY-CERT-DER-001. No rule_id is registered for it here
# -- inventing one (e.g. "IDENTITY-KEY-SPKI-001") would violate the
# anti-hallucination rule. See docs/open-issues.md.

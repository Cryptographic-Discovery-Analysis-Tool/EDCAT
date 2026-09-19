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


# --- Exposure-ledger rule_ids (Pramana_Ledger_Spec.md) ----------------------
# The Lock and harness §14-16 predate the exposure ledger and name none of
# these. Their citable in-repo source is
# docs/architecture/Pramana_Ledger_Spec.md (frozen post-red-team spec, hashed
# in HASHES.lock). Section numbers below are that document's.

register(
    "TEMPORAL-POSSIBLE-001",
    "inference",
    "Pramana_Ledger_Spec.md §5.2",
    "possible_since = min(not_before, declared_go_live, "
    "first_snapshot_containing) -- the earliest date the surface COULD have "
    "been carrying traffic. Never evidence that it did.",
)

register(
    "TEMPORAL-CONFIRMED-001",
    "inference",
    "Pramana_Ledger_Spec.md §5.2",
    "confirmed_since = earliest Observed traffic-path observation; a declared "
    "go-live counts only when policy.accept_declared_go_live. notBefore alone "
    "never confirms.",
)

register(
    "FUNC-TLS-KEX-001",
    "inference",
    "Pramana_Ledger_Spec.md §5.1",
    "Negotiated ECDHE_*/DHE_* suite observed on the wire -> "
    "KEY_ESTABLISHMENT on that surface's usage context.",
)

register(
    "FUNC-TLS-KEYTRANSPORT-001",
    "inference",
    "Pramana_Ledger_Spec.md §5.1",
    "Negotiated TLS_RSA_* suite observed on the wire -> KEY_TRANSPORT (the "
    "premaster secret is RSA-encrypted to the server key).",
)

register(
    "FUNC-TLS-HYBRID-001",
    "inference",
    "Pramana_Ledger_Spec.md §5.1",
    "Negotiated hybrid group (e.g. X25519MLKEM768) observed -> HYBRID_KEX.",
)

register(
    "FUNC-CERT-AUTH-001",
    "inference",
    "Pramana_Ledger_Spec.md §5.1",
    "Certificate presented in an observed handshake -> SIGNATURE_AUTH context "
    "for that certificate's key, separate from the KEX context.",
)

register(
    "FUNC-TLS-OFFERED-001",
    "inference",
    "Pramana_Ledger_Spec.md §5.1",
    "Suite offered but not negotiated -> INFERRED capability context only. "
    "Never an observed usage.",
)

register(
    "FUNC-KEYUSAGE-001",
    "inference",
    "Pramana_Ledger_Spec.md §5.1",
    "Certificate keyUsage / extendedKeyUsage bits -> INFERRED capability "
    "context (what the key is permitted to do, not what it did).",
)

register(
    "FUNC-SRC-KEYTRANSPORT-001",
    "inference",
    "Pramana_Ledger_Spec.md §5.1",
    "Source call site: Cipher in WRAP_MODE, or an RSA/... transformation -> "
    "KEY_TRANSPORT. Algorithm may stay UNKNOWN while the function is known.",
)

register(
    "FUNC-SRC-SIGNATURE-001",
    "inference",
    "Pramana_Ledger_Spec.md §5.1",
    "Source call site: java.security.Signature -> SIGNATURE_AUTH.",
)

register(
    "FUNC-SRC-KEX-001",
    "inference",
    "Pramana_Ledger_Spec.md §5.1",
    "Source call site: javax.crypto.KeyAgreement -> KEY_ESTABLISHMENT.",
)

register(
    "LEDGER-CONF-001",
    "inference",
    "Pramana_Ledger_Spec.md §5.5",
    "Confidentiality exposure band from (start, deadline = Z - X, M, as_of). "
    "Applies only to Shor-broken confidentiality functions.",
)

register(
    "LEDGER-AUTH-001",
    "inference",
    "Pramana_Ledger_Spec.md §5.6",
    "Authentication band from required_until = signed_at + A against Z and "
    "the rollout window Y.",
)

register(
    "LEDGER-HYBRID-CLOCK-001",
    "inference",
    "Pramana_Ledger_Spec.md §5.7",
    "A surface's exposure clock stops only on an observed negotiation with "
    "classical disabled, per vantage; a later classical observation reopens "
    "it. Config-only evidence never stops the clock.",
)

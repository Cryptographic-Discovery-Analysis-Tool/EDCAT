"""Forbidden-edge gate (Final Architecture Part 5; docs/build-plan.md P6:
"Hard gate: the two forbidden edges ... must never be emitted (score.py
treats either as a correlation failure regardless of everything else)").

A pure function, no I/O: meant to be called by whatever orchestration layer
later assembles Relationships before persisting or exporting them, so it
stays trivially unit-testable and never needs a fixture to exercise.

Deliberately generic -- NOT a lookup table of specific forbidden entity
names or paths. A literal name/path table would (a) violate the
no-harness-identifiers rule the moment a real forbidden pair was copied in
from the harness's own ground truth, and (b) not generalise past that one
recorded pair. Instead this checks the STRUCTURAL shape of an unsupported
identity claim, generically:

a. any edge that is identity-shaped -- its evidence_basis is CONTENT_IDENTITY
   (Part 5's "same-object" claim), or its epistemic_state is CONFLICTING (a
   conflict is, structurally, a disputed identity/agreement claim about a
   field) -- and whose rule_id is not literally "IDENTITY-CERT-DER-001", the
   one identity rule_id actually registered (src/ecdat/rules/registry.py).
   This is the general form of "don't assert same-object identity, or paper
   over a disagreement, without the one rule that's actually registered for
   it." A "shares-public-key"/SPKI identity rule is named in the harness
   (§15.2 T6) but was never given a literal rule_id there -- see
   registry.py's own comment -- so none is invented or checked for here.
b. any edge where source_entity == target_entity: a self-edge asserts a
   relationship between an entity and itself, which is never a meaningful
   correlation regardless of evidence_basis or rule_id.
"""
from __future__ import annotations

from collections.abc import Iterable

from ecdat.model.epistemic import EpistemicState
from ecdat.model.relationship import EvidenceBasis, Relationship

#: The only rule_id actually registered for a same-object identity claim.
#: See src/ecdat/rules/registry.py -- do not add another one here from
#: memory; if a design genuinely needs a second identity rule_id, that is a
#: registry.py change (out of scope for this module) and an open question,
#: not something this gate can paper over.
IDENTITY_RULE_ID = "IDENTITY-CERT-DER-001"


def check_forbidden_edges(relationships: Iterable[Relationship]) -> tuple[str, ...]:
    """Return one description per Relationship that structurally represents
    an unsupported identity claim or a self-edge. Empty tuple = every edge
    passes the gate.
    """
    violations: list[str] = []

    for relationship in relationships:
        edge = (
            f"{relationship.type!r} {relationship.source_entity!r} -> "
            f"{relationship.target_entity!r}"
        )

        is_identity_shaped = (
            relationship.evidence_basis == EvidenceBasis.CONTENT_IDENTITY
            or relationship.epistemic_state == EpistemicState.CONFLICTING
        )
        if is_identity_shaped and relationship.rule_id != IDENTITY_RULE_ID:
            violations.append(
                f"{edge}: evidence_basis={relationship.evidence_basis.value!r}, "
                f"epistemic_state={relationship.epistemic_state.value!r}, "
                f"rule_id={relationship.rule_id!r} -- an identity-shaped or "
                "disputed edge is only supported under the one registered "
                f"identity rule ({IDENTITY_RULE_ID!r})"
            )

        if relationship.source_entity == relationship.target_entity:
            violations.append(f"{edge}: self-edge, source_entity == target_entity")

    return tuple(violations)

"""Forbidden-edge gate (Final Architecture Part 5; docs/build-plan.md P6)."""
from __future__ import annotations

from ecdat.correlation.gate import IDENTITY_RULE_ID, check_forbidden_edges
from ecdat.model.epistemic import EpistemicState
from ecdat.model.relationship import EvidenceBasis, Relationship


def make(**overrides) -> Relationship:
    fields = dict(
        type="terminates-tls-for",
        source_entity="edge-lb",
        target_entity="customer-portal",
        evidence_basis=EvidenceBasis.OBSERVED,
        epistemic_state=EpistemicState.KNOWN,
    )
    fields.update(overrides)
    return Relationship(**fields)


def test_content_identity_with_the_one_registered_identity_rule_passes():
    relationship = make(
        evidence_basis=EvidenceBasis.CONTENT_IDENTITY,
        epistemic_state=EpistemicState.KNOWN,
        rule_id=IDENTITY_RULE_ID,
    )

    assert check_forbidden_edges([relationship]) == ()


def test_inferred_edge_with_a_different_registered_rule_id_is_rejected():
    # rule_id=TLS-FRONT-001 is genuinely registered (src/ecdat/rules/
    # registry.py) and the Relationship model itself accepts it (it is a
    # valid conflict-category rule_id) -- reusing test_relationship.py's own
    # CONFLICTING+TLS-FRONT-001 shape verbatim would only re-prove the model
    # layer's is_registered() check, which is not what the gate adds. This
    # constructs a Relationship that is valid at the model layer (evidence_
    # basis=INFERRED and epistemic_state=CONFLICTING both independently
    # satisfy Relationship's own rule_id-required check) but is still
    # forbidden by the gate specifically because its rule_id is not literally
    # IDENTITY-CERT-DER-001.
    relationship = make(
        evidence_basis=EvidenceBasis.INFERRED,
        epistemic_state=EpistemicState.CONFLICTING,
        rule_id="TLS-FRONT-001",
    )

    violations = check_forbidden_edges([relationship])

    assert len(violations) == 1
    assert "TLS-FRONT-001" in violations[0]


def test_self_edge_is_rejected_regardless_of_everything_else():
    relationship = make(
        source_entity="edge-lb",
        target_entity="edge-lb",
        evidence_basis=EvidenceBasis.CONTENT_IDENTITY,
        epistemic_state=EpistemicState.KNOWN,
        rule_id=IDENTITY_RULE_ID,
    )

    violations = check_forbidden_edges([relationship])

    assert len(violations) == 1
    assert "self-edge" in violations[0]


def test_ordinary_declared_edge_with_no_rule_id_passes_cleanly():
    relationship = make(
        type="behind",
        source_entity="ivr-connector",
        target_entity="edge-lb",
        evidence_basis=EvidenceBasis.CONFIG_DECLARED,
        epistemic_state=EpistemicState.DECLARED,
    )

    assert check_forbidden_edges([relationship]) == ()


def test_empty_input_passes_trivially():
    assert check_forbidden_edges([]) == ()


def test_multiple_relationships_only_flag_the_bad_ones():
    good = make()
    bad = make(
        source_entity="same",
        target_entity="same",
        evidence_basis=EvidenceBasis.OBSERVED,
        epistemic_state=EpistemicState.KNOWN,
    )

    violations = check_forbidden_edges([good, bad])

    assert len(violations) == 1
    assert "same" in violations[0]

import pytest
from pydantic import ValidationError

from ecdat.model.epistemic import EpistemicState
from ecdat.model.relationship import Assurance, EvidenceBasis, Relationship


def make(**overrides):
    fields = dict(
        type="terminates-tls-for",
        source_entity="edge-lb",
        target_entity="customer-portal",
        evidence_basis=EvidenceBasis.OBSERVED,
        epistemic_state=EpistemicState.KNOWN,
    )
    fields.update(overrides)
    return Relationship(**fields)


def test_valid_observed_relationship_needs_no_rule_id():
    rel = make()
    assert rel.rule_id is None


def test_assurance_without_artifact_asserted_rejected():
    with pytest.raises(ValidationError):
        make(
            evidence_basis=EvidenceBasis.OBSERVED,
            assurance=Assurance.SIGNATURE_VERIFIED,
        )


def test_assurance_with_artifact_asserted_ok():
    rel = make(
        evidence_basis=EvidenceBasis.ARTIFACT_ASSERTED,
        assurance=Assurance.SIGNATURE_VERIFIED,
        epistemic_state=EpistemicState.KNOWN,
    )
    assert rel.assurance == Assurance.SIGNATURE_VERIFIED


def test_inferred_basis_requires_rule_id():
    with pytest.raises(ValidationError):
        make(evidence_basis=EvidenceBasis.INFERRED, epistemic_state=EpistemicState.INFERRED)


def test_content_identity_requires_rule_id():
    with pytest.raises(ValidationError):
        make(
            evidence_basis=EvidenceBasis.CONTENT_IDENTITY,
            epistemic_state=EpistemicState.KNOWN,
        )


def test_content_identity_with_rule_id_ok():
    rel = make(
        evidence_basis=EvidenceBasis.CONTENT_IDENTITY,
        epistemic_state=EpistemicState.KNOWN,
        rule_id="IDENTITY-CERT-DER-001",
    )
    assert rel.rule_id == "IDENTITY-CERT-DER-001"


def test_conflicting_state_requires_rule_id():
    with pytest.raises(ValidationError):
        make(evidence_basis=EvidenceBasis.OBSERVED, epistemic_state=EpistemicState.CONFLICTING)


def test_conflicting_state_with_registered_rule_id_ok():
    rel = make(
        evidence_basis=EvidenceBasis.OBSERVED,
        epistemic_state=EpistemicState.CONFLICTING,
        rule_id="TLS-FRONT-001",
    )
    assert rel.rule_id == "TLS-FRONT-001"


def test_unregistered_rule_id_rejected():
    with pytest.raises(ValidationError):
        make(
            evidence_basis=EvidenceBasis.INFERRED,
            epistemic_state=EpistemicState.INFERRED,
            rule_id="NOT-A-REAL-RULE",
        )


def test_topo_02_no_conflict_case_needs_no_rule_id():
    # harness §15.3 TOPO-02: ivr-connector behind edge-lb in mode tcp -> no
    # conflict. A plain observed/KNOWN edge with no rule_id must be valid.
    rel = make(
        type="behind",
        source_entity="ivr-connector",
        target_entity="edge-lb",
        evidence_basis=EvidenceBasis.CONFIG_DECLARED,
        epistemic_state=EpistemicState.DECLARED,
    )
    assert rel.rule_id is None

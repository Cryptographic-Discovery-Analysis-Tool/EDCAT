"""Relationship contract (Lock §4 TOPO-001; harness §15.2 T1, verbatim
schema).

    Relationship
      type, source_entity, target_entity
      evidence_basis      observed | content_identity | artifact_asserted | config_declared | human_declared | inferred
      assurance           (artifact_asserted only) unsigned_annotation | unsigned_attestation | signature_verified
      epistemic_state     Directive-2 set
      rule_id             required for inferred, content_identity, and every conflict
      evidence_refs[]     each ref carries its own Part-3 confidence; the edge has NO free-standing numeric confidence
      observed_at
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from ecdat.model.epistemic import EpistemicState
from ecdat.rules.registry import is_registered


class EvidenceBasis(str, Enum):
    OBSERVED = "observed"
    CONTENT_IDENTITY = "content_identity"
    ARTIFACT_ASSERTED = "artifact_asserted"
    CONFIG_DECLARED = "config_declared"
    HUMAN_DECLARED = "human_declared"
    INFERRED = "inferred"


class Assurance(str, Enum):
    UNSIGNED_ANNOTATION = "unsigned_annotation"
    UNSIGNED_ATTESTATION = "unsigned_attestation"
    SIGNATURE_VERIFIED = "signature_verified"


class Relationship(BaseModel):
    model_config = ConfigDict(frozen=True)

    type: str
    source_entity: str
    target_entity: str
    evidence_basis: EvidenceBasis
    assurance: Assurance | None = None
    epistemic_state: EpistemicState
    rule_id: str | None = None
    evidence_refs: tuple[str, ...] = ()
    observed_at: datetime | None = None

    @field_validator("type", "source_entity", "target_entity")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be blank")
        return value

    @model_validator(mode="after")
    def _validate(self) -> "Relationship":
        if self.assurance is not None and self.evidence_basis != EvidenceBasis.ARTIFACT_ASSERTED:
            raise ValueError(
                "assurance is only valid when evidence_basis=artifact_asserted "
                "(Lock §4 TOPO-001 relationship contract; harness §15.2 T1)"
            )

        requires_rule_id = (
            self.evidence_basis == EvidenceBasis.INFERRED
            or self.evidence_basis == EvidenceBasis.CONTENT_IDENTITY
            or self.epistemic_state == EpistemicState.CONFLICTING
        )
        if requires_rule_id and self.rule_id is None:
            raise ValueError(
                "rule_id is required for inferred edges, content-identity "
                "edges, and every conflict (Lock §4 TOPO-001; harness §15.2 T1)"
            )
        if self.rule_id is not None and not is_registered(self.rule_id):
            raise ValueError(
                f"rule_id {self.rule_id!r} is not registered in "
                "src/ecdat/rules/registry.py"
            )
        return self

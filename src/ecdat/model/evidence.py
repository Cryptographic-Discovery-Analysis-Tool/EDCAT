"""Evidence (Lock §5 row 3 "Findings & confidence": base confidence table
applies to evidence items; Relationship contract's evidence_refs[]: "each ref
carries its own Part-3 confidence; the edge has NO free-standing confidence").
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class ConfidenceBasis(BaseModel):
    """Why a given Evidence carries the base_confidence it does (OI-004, ADR-002).

    `source` is NOT an epistemic state and NOT a resolution status — it is a
    provenance axis for the confidence number itself. The closed epistemic enum
    (model.epistemic) is untouched.

    CITED_TABLE  -- the value came from a `usable: true` row in
                    data/base_confidence.yaml and names that row + citation.
    ADAPTER_DECLARED -- no cited row exists, so the adapter chose the value and
                    must say why in `justification`. These are counted and
                    reported, never silently blended with cited values.
    """

    model_config = ConfigDict(frozen=True)

    source: Literal["CITED_TABLE", "ADAPTER_DECLARED"]
    justification: str
    table_key: str | None = None
    citation: str | None = None

    @model_validator(mode="after")
    def _validate(self) -> "ConfidenceBasis":
        if self.source == "CITED_TABLE":
            if not (self.table_key and self.table_key.strip()):
                raise ValueError("CITED_TABLE requires table_key")
            if not (self.citation and self.citation.strip()):
                raise ValueError("CITED_TABLE requires citation")
        elif self.table_key or self.citation:
            raise ValueError(
                "ADAPTER_DECLARED must not claim a table_key or citation "
                "(it is by definition uncited -- OI-004)"
            )
        if len(self.justification.strip()) < 20:
            raise ValueError(
                "justification must state why this value was chosen "
                "(>= 20 characters); an unexplained confidence is an invented one"
            )
        return self


class Evidence(BaseModel):
    """A single piece of raw evidence from one source tool.

    `base_confidence` is a plain, range-validated float. The actual
    source-tool -> confidence lookup table (ECDAT_Final_Architecture.md
    Part 3) does not exist in this repo yet -- see docs/open-issues.md
    OI-004. No such mapping is hardcoded here; callers (adapters) must
    supply base_confidence themselves, from data/ once it is populated,
    never from memory. `confidence_basis` makes that provenance explicit and
    mandatory: an uncited value is allowed, but only with a written
    justification that ships with the evidence (ADR-002).

    `tool_version` is required because Lock §6 records gate results with "the
    exact tool ... versions/build IDs", and every recorded fixture in
    tests/fixtures/recorded/ is version-scoped. Evidence that cannot name the
    build that produced it cannot be re-derived.

    `raw_ref` points at captured raw tool output (e.g. a fixture path or
    hash) -- never private key or secret bytes (hard rule: "No private key /
    secret bytes in DB, logs, CLI output, CBOM, test snapshots. Store
    location + fingerprint only.").
    """

    model_config = ConfigDict(frozen=True)

    evidence_id: str
    source_tool: str
    tool_version: str
    location: str
    base_confidence: float = Field(ge=0.0, le=1.0)
    confidence_basis: ConfidenceBasis
    raw_ref: str

    @field_validator("evidence_id", "source_tool", "tool_version", "location", "raw_ref")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be blank")
        return value

"""Evidence (Lock §5 row 3 "Findings & confidence": base confidence table
applies to evidence items; Relationship contract's evidence_refs[]: "each ref
carries its own Part-3 confidence; the edge has NO free-standing confidence").
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Evidence(BaseModel):
    """A single piece of raw evidence from one source tool.

    `base_confidence` is a plain, range-validated float. The actual
    source-tool -> confidence lookup table (ECDAT_Final_Architecture.md
    Part 3) does not exist in this repo yet -- see docs/open-issues.md
    OI-004. No such mapping is hardcoded here; callers (adapters) must
    supply base_confidence themselves, from data/ once it is populated,
    never from memory.

    `raw_ref` points at captured raw tool output (e.g. a fixture path or
    hash) -- never private key or secret bytes (hard rule: "No private key /
    secret bytes in DB, logs, CLI output, CBOM, test snapshots. Store
    location + fingerprint only.").
    """

    model_config = ConfigDict(frozen=True)

    evidence_id: str
    source_tool: str
    location: str
    base_confidence: float = Field(ge=0.0, le=1.0)
    raw_ref: str

    @field_validator("evidence_id", "source_tool", "location", "raw_ref")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be blank")
        return value

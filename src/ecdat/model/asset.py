"""CryptoAsset (Lock §2 principle 3: "Finding != asset"; principle 8:
epistemic state per field).

Deliberately minimal: the full CryptoAsset business-field schema (algorithm
family, purpose, quantum tier, etc.) belongs to ECDAT_Final_Architecture.md
Part 1 ("Targets") / Part 5 ("Asset resolution"), which is empty in this repo
-- see docs/open-issues.md OI-001. Only the structural, Lock-specified
per-field-epistemic-state pattern is implemented here; concrete business
fields are added once that doc exists, so they aren't invented from memory.

`scope_anchor`: ASSUMPTION, not a verified field name -- see docs/open-issues.md
OI-003. No UNATTRIBUTED / OUT_OF_DECLARED_SCOPE logic is implemented against
it here; that is correlation-layer work.
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, field_validator

from ecdat.model.field_value import FieldValue


class CryptoAsset(BaseModel):
    model_config = ConfigDict(frozen=True)

    asset_id: str
    scope_anchor: str | None = None
    finding_refs: tuple[str, ...] = ()
    fields: dict[str, FieldValue] = {}

    @field_validator("asset_id")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be blank")
        return value

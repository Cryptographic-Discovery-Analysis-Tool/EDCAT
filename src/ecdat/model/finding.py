"""Finding (Lock §2 principle 3: "Finding != asset"; principle 9: observation
surfaces, not programming languages, structure the model).

A Finding is one tool's raw, pre-correlation observation bundle: a set of
per-field epistemic values tied to the evidence that produced them, scoped to
one observation surface. Correlation into a CryptoAsset (model.asset) is a
separate, later step -- this type intentionally does not know about assets.
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, field_validator

from ecdat.model.field_value import FieldValue


class Finding(BaseModel):
    model_config = ConfigDict(frozen=True)

    finding_id: str
    surface: str
    evidence_refs: tuple[str, ...] = ()
    fields: dict[str, FieldValue] = {}

    @field_validator("finding_id", "surface")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be blank")
        return value

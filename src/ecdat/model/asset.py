"""CryptoAsset (Lock §2 principle 3: "Finding != asset"; principle 8:
epistemic state per field).

Deliberately minimal: the full CryptoAsset business-field schema belongs to
ECDAT_Final_Architecture.md Part 5 ("Asset resolution (deliberately
constrained)"), which now exists in this repo -- see that Part for the
canonical asset key `(algorithm_family, parameters, purpose, scope_anchor)`
and the within-surface-only merge rule it defines. `src/ecdat/correlation/
merge.py` is the code that builds CryptoAsset records from Findings per that
spec. Only the structural, Lock-specified per-field-epistemic-state pattern
(the `fields` dict) plus the three plain key-readback fields below live here;
anything else Part 5 might eventually need is added only once a concrete
consumer needs it, not invented ahead of time.

`scope_anchor`: ASSUMPTION, not a verified field name -- see docs/open-issues.md
OI-003. No UNATTRIBUTED / OUT_OF_DECLARED_SCOPE logic is implemented against
it here; that is correlation-layer work.

`algorithm_family`, `parameters`, `purpose`: plain optional convenience
fields, NOT FieldValues. The per-field epistemic state for the evidence
backing them already lives in `fields` (e.g. `fields["public_key_algorithm"]`
carries its own state, possibly CONFLICTING); these three are just Part 5's
literal key-tuple components read back out in one place so a caller doesn't
have to know which `fields` key an adapter happened to use. See
`src/ecdat/correlation/merge.py` and `docs/deviations.md` DEV-007 for how
they are populated and why `algorithm_family` is not itself part of the
strict grouping-equality key there.
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, field_validator

from ecdat.model.field_value import FieldValue


class CryptoAsset(BaseModel):
    model_config = ConfigDict(frozen=True)

    asset_id: str
    scope_anchor: str | None = None
    algorithm_family: str | None = None
    parameters: str | None = None
    purpose: str | None = None
    finding_refs: tuple[str, ...] = ()
    fields: dict[str, FieldValue] = {}

    @field_validator("asset_id")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be blank")
        return value

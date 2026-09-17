"""Closed epistemic-state enum and resolution status (Lock §2 principle 7, §3).

Hard rule: epistemic states are a CLOSED enum. Never add states here.
No DERIVED/UNRESOLVED/POSSIBLY/SHADOW.
"""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, model_validator


class EpistemicState(str, Enum):
    KNOWN = "KNOWN"
    UNKNOWN = "UNKNOWN"
    NOT_OBSERVED = "NOT_OBSERVED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    INFERRED = "INFERRED"
    DECLARED = "DECLARED"
    CONFLICTING = "CONFLICTING"


# ADR-001 (docs/decisions/ADR-001-epistemic-derivation-strength-order.md):
# total order used ONLY by model.field_value.derive() to implement R-DERIVE's
# "weakest required input wins". Not a total order stated anywhere in the
# Lock or harness docs -- see docs/open-issues.md OI-005. Do not use this
# ranking for anything other than derive()'s weakest-input computation.
_DERIVATION_STRENGTH: dict[EpistemicState, int] = {
    EpistemicState.UNKNOWN: 0,
    EpistemicState.NOT_APPLICABLE: 1,
    EpistemicState.NOT_OBSERVED: 2,
    EpistemicState.CONFLICTING: 3,
    EpistemicState.INFERRED: 4,
    EpistemicState.DECLARED: 5,
    EpistemicState.KNOWN: 6,
}


def derivation_strength(state: EpistemicState) -> int:
    """Rank used only by derive() for R-DERIVE. See ADR-001."""
    return _DERIVATION_STRENGTH[state]


class ResolutionStatus(str, Enum):
    RESOLVED = "RESOLVED"
    OVERRIDDEN = "OVERRIDDEN"
    UNRESOLVED = "UNRESOLVED"


class Resolution(BaseModel):
    """resolution_status + reason as one field, kept separate from
    epistemic_state (CFG-001 / harness §14 A4: "Epistemic state vs resolution
    status are different fields.").

    harness §14 CFG-001 DECISION: "Every UNRESOLVED result carries a reason."
    """

    model_config = ConfigDict(frozen=True)

    status: ResolutionStatus
    reason: str | None = None

    @model_validator(mode="after")
    def _unresolved_requires_reason(self) -> "Resolution":
        if self.status == ResolutionStatus.UNRESOLVED and not (self.reason and self.reason.strip()):
            raise ValueError(
                "resolution_status=UNRESOLVED requires a non-empty reason "
                "(harness §14 CFG-001 DECISION)"
            )
        return self

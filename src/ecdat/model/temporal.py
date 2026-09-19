"""TemporalEvidence and MigrationEvidence (Pramana_Ledger_Spec.md §5.2, §5.7).

The red-team finding this module exists to fix: `already_lost =
years(start -> today)` over-counts, because "start" was being read off
whatever date happened to be lying around -- usually a certificate's
notBefore. A certificate can be minted years before anything is deployed
behind it, so notBefore bounds *possibility*, never *confirmation*. This
module keeps the two clocks apart and refuses to let one become the other.

Both derived fields are computed by SELECTION, not by
`model.field_value.derive()`. `min` over a set of dates returns one of its
inputs unchanged -- it makes no new claim, so it must not acquire a new
epistemic state. Running it through `derive()` would cap a KNOWN observation
down to INFERRED (CFG-001's "a derived value is never KNOWN"), and every
confirmed_since in the system would then be INFERRED, which under §5.5's
`accept_inferred=false` policy would make every row UNBOUNDED. The rule_ids
below are still registered and are recorded on the CalculationRecord, so the
selection is replayable; what is not done is inventing a weaker state for a
value that was simply picked.
"""
from __future__ import annotations

from datetime import date

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from ecdat.model.epistemic import EpistemicState
from ecdat.model.field_value import FieldValue

#: Registered in rules/registry.py; recorded on the CalculationRecord.
RULE_POSSIBLE = "TEMPORAL-POSSIBLE-001"
RULE_CONFIRMED = "TEMPORAL-CONFIRMED-001"

#: §5.2 -- states that count as "Observed" for confirmation purposes.
_OBSERVED = EpistemicState.KNOWN


def _earliest(*candidates: FieldValue[date] | None) -> FieldValue[date] | None:
    """Earliest dated candidate, returned verbatim. See module docstring for
    why this is not a derive()."""
    dated = [c for c in candidates if c is not None and c.value is not None]
    if not dated:
        return None
    return min(dated, key=lambda f: f.value)


class TemporalEvidence(BaseModel):
    """When a surface could have been carrying traffic, and when it is known
    to have been.

    Inputs are all optional and all independently stated:

    `not_before`          certificate notBefore. Bounds possibility only.
    `declared_go_live`    an operator's statement. DECLARED, not observed.
    `first_snapshot_containing`  earliest of our own snapshots the surface
                          appears in. Bounds possibility: we saw the
                          configuration, not the traffic.
    `first_observed`      earliest observation ON THE TRAFFIC PATH -- a
                          handshake from a recorded vantage. This is the only
                          input that can confirm.
    """

    model_config = ConfigDict(frozen=True)

    surface_id: str
    observation_ts: date

    not_before: FieldValue[date] | None = None
    declared_go_live: FieldValue[date] | None = None
    first_snapshot_containing: FieldValue[date] | None = None
    first_observed: FieldValue[date] | None = None

    @field_validator("surface_id")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be blank")
        return value

    @property
    def possible_since(self) -> FieldValue[date] | None:
        """§5.2: `min(not_before, declared_go_live, first_snapshot_containing)`.

        `first_observed` is included as a further candidate. The spec names
        three, and in every realistic ordering the observation is the latest
        of the four so `min` is unaffected; including it makes
        `confirmed_since >= possible_since` hold structurally rather than by
        luck, and an observation is in any case proof that the surface was
        possible by that date.
        """
        return _earliest(
            self.not_before,
            self.declared_go_live,
            self.first_snapshot_containing,
            self.first_observed,
        )

    def confirmed_since(self, *, accept_declared_go_live: bool) -> FieldValue[date] | None:
        """§5.2: earliest Observed traffic-path observation. A declared
        go-live counts only when policy says so (Policy.accept_declared_go_live,
        §5.4). notBefore and snapshot presence never confirm, at any policy
        setting -- there is no flag for that, deliberately.
        """
        observed = (
            self.first_observed
            if self.first_observed is not None and self.first_observed.state == _OBSERVED
            else None
        )
        declared = (
            self.declared_go_live
            if accept_declared_go_live
            and self.declared_go_live is not None
            and self.declared_go_live.state
            in (EpistemicState.DECLARED, EpistemicState.KNOWN)
            else None
        )
        return _earliest(observed, declared)

    @property
    def status_per_field(self) -> dict[str, EpistemicState]:
        """§5.2's `status_per_field`, read off the FieldValues themselves so
        it cannot drift out of step with them."""
        named = {
            "not_before": self.not_before,
            "declared_go_live": self.declared_go_live,
            "first_snapshot_containing": self.first_snapshot_containing,
            "first_observed": self.first_observed,
        }
        return {
            name: (fv.state if fv is not None else EpistemicState.NOT_OBSERVED)
            for name, fv in named.items()
        }


class MigrationEvidence(BaseModel):
    """One observation of what a surface actually negotiated, from one vantage
    (§5.2, §5.7).

    `classical_still_accepted=False` is the only thing that stops an exposure
    clock, and only when `status` is KNOWN (spec: Observed). A configuration
    file that says hybrid is enabled is INFERRED and stops nothing -- §5.7,
    and the "Hybrid configured, not observed" case in §6.
    """

    model_config = ConfigDict(frozen=True)

    surface_id: str
    vantage: str
    observed_at: date
    negotiated_group: str | None = None
    classical_still_accepted: bool = True
    status: EpistemicState = EpistemicState.UNKNOWN
    evidence_refs: tuple[str, ...] = ()

    @field_validator("surface_id", "vantage")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be blank")
        return value

    @model_validator(mode="after")
    def _observed_needs_evidence(self) -> "MigrationEvidence":
        if self.status == _OBSERVED and not self.evidence_refs:
            raise ValueError(
                "status=KNOWN (spec: Observed) requires at least one "
                "evidence_ref -- an unevidenced observation is exactly the "
                "'fake M' adversarial case (§7.2 phase 8)"
            )
        return self

    @property
    def stops_the_clock(self) -> bool:
        """§5.7. Observed negotiation with classical disabled, nothing else."""
        return self.status == _OBSERVED and not self.classical_still_accepted

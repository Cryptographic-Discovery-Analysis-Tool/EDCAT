"""Bands, windows, ledger inputs and the replayable CalculationRecord
(Pramana_Ledger_Spec.md §5.9, §5.10).

The claim this module has to survive is "every result replays from its
record". That is cheap to say and easy to get wrong: a record that stores a
band plus a prose summary replays nothing. So a CalculationRecord embeds the
exact frozen `LedgerInputs` it was computed from, hashes them, and
`replay(record)` re-runs the ledger over them and must return the same band.
If an input is not in the record, it cannot have influenced the band -- which
is the property that makes "no model, no score" checkable rather than
asserted.

Bands and windows live here rather than in either ledger because both ledgers
and the ranking all need them, and because a band enum that can be extended
from three different modules stops being a closed set.
"""
from __future__ import annotations

import hashlib
from datetime import date
from enum import Enum

from pydantic import BaseModel, ConfigDict, model_validator

from ecdat.context.binding import DataClassBinding, Lifetime
from ecdat.model.temporal import MigrationEvidence, TemporalEvidence
from ecdat.model.usage_context import CryptoFunction, UsageContext
from ecdat.risk.scenarios import CaptureAssumption, Policy, Scenario

#: Bumped whenever a band could change for unchanged inputs. Recorded on every
#: row so a re-scan can say "this row moved because the calculation changed",
#: not just "this row moved".
CALC_VERSION = "1"


class ExposureBand(str, Enum):
    """§5.5 / §5.6. Closed set, and deliberately not a score.

    UNBOUNDED is the honest answer, not a failure mode: it means an input was
    Unknown (or Inferred under a policy that does not accept Inferred), so no
    band is derivable. It carries a conditional band and generates a closure
    task rather than defaulting to the safe-looking or the scary-looking
    answer.
    """

    # confidentiality (§5.5)
    UNBOUNDED = "UNBOUNDED"
    SAFE = "SAFE"
    BLEEDING = "BLEEDING"
    UNSAVABLE = "UNSAVABLE"
    SAVABLE = "SAVABLE"
    # authentication (§5.6)
    ROTATE_BEFORE_Z = "ROTATE_BEFORE_Z"
    RESIGN_BEFORE_Z = "RESIGN_BEFORE_Z"
    SAFE_UNTIL_Z = "SAFE_UNTIL_Z"


class Qualifier(str, Enum):
    """§5.5 qualifiers. Facts about the row, never modifiers of its band."""

    PARTIAL = "PARTIAL"
    REOPENED = "REOPENED"
    STOPPED = "STOPPED"


#: §5.10: "band order (BLEEDING > UNSAVABLE-stopped > SAVABLE > SAFE)".
#:
#: §5.10 enumerates four bands and does not place UNBOUNDED. It is ranked
#: below UNSAVABLE and above SAVABLE here: an unbounded row might be either,
#: so it must not outrank a row we have proved is bleeding, and must not be
#: buried under rows we have proved are fine. Filed as OI-010.
_BAND_RANK: dict[ExposureBand, int] = {
    ExposureBand.BLEEDING: 0,
    ExposureBand.UNSAVABLE: 1,
    ExposureBand.UNBOUNDED: 2,
    ExposureBand.SAVABLE: 3,
    ExposureBand.SAFE: 4,
    # authentication bands, same ordering principle: act-before-Z outranks
    # safe-until-Z. Not stated in §5.10; OI-010.
    ExposureBand.RESIGN_BEFORE_Z: 1,
    ExposureBand.ROTATE_BEFORE_Z: 2,
    ExposureBand.SAFE_UNTIL_Z: 4,
}


def band_rank(band: ExposureBand) -> int:
    return _BAND_RANK[band]


class Window(BaseModel):
    """A closed interval of dates. §5.5's `unsavable_window`.

    Every quantity in the ledger is a time window. There is no traffic volume
    anywhere (§5.12 rejects it): we can say when a channel was exposed, and we
    cannot say how much went over it, so we say the first and shut up about
    the second.
    """

    model_config = ConfigDict(frozen=True)

    start: date
    end: date

    @model_validator(mode="after")
    def _ordered(self) -> "Window":
        if self.start > self.end:
            raise ValueError("window start must not be after end")
        return self

    @property
    def days(self) -> int:
        return (self.end - self.start).days

    def __str__(self) -> str:
        return f"[{self.start.isoformat()}, {self.end.isoformat()}]"


class LedgerInputs(BaseModel):
    """Everything a band depends on, and nothing else.

    Frozen and complete by construction: the ledgers take this object and
    nothing besides it (no clock reads, no globals, no table lookups at
    evaluation time), which is what makes the hash meaningful and the replay
    property true rather than aspirational.
    """

    model_config = ConfigDict(frozen=True)

    as_of: date
    scenario: Scenario
    policy: Policy
    usage_context: UsageContext
    temporal: TemporalEvidence
    binding: DataClassBinding | None = None
    migrations: tuple[MigrationEvidence, ...] = ()
    signed_at: date | None = None

    def sha256(self) -> str:
        return hashlib.sha256(self.model_dump_json().encode("utf-8")).hexdigest()


class EvidenceStatusRef(BaseModel):
    """§5.9's `evidence_refs[{id,status,ts}]`."""

    model_config = ConfigDict(frozen=True)

    id: str
    status: str
    ts: date | None = None


class CalculationRecord(BaseModel):
    """§5.9. One row of a ledger, with everything needed to re-derive it."""

    model_config = ConfigDict(frozen=True)

    record_id: str
    as_of: date
    scenario_id: str
    capture_assumption: CaptureAssumption
    policy_snapshot: Policy
    usage_context_id: str
    function: CryptoFunction | None
    evidence_refs: tuple[EvidenceStatusRef, ...]
    band: ExposureBand
    qualifiers: tuple[Qualifier, ...] = ()
    windows: tuple[Window, ...] = ()
    deadline: date | None = None
    conditional_band: ExposureBand | None = None
    reason: str = ""
    assumes_capture_since: date | None = None
    X: Lifetime | None = None
    A: Lifetime | None = None
    start_possible: date | None = None
    start_confirmed: date | None = None
    M: date | None = None
    M_evidence_ids: tuple[str, ...] = ()
    rule_version: str
    calc_version: str = CALC_VERSION
    inputs_sha256: str
    inputs: LedgerInputs

    @model_validator(mode="after")
    def _hash_matches_inputs(self) -> "CalculationRecord":
        if self.inputs_sha256 != self.inputs.sha256():
            raise ValueError(
                "inputs_sha256 does not match inputs -- a record whose hash "
                "does not cover its own inputs proves nothing"
            )
        if self.band == ExposureBand.UNBOUNDED and not self.reason:
            raise ValueError(
                "an UNBOUNDED row must say which input left it unbounded "
                "(§5.8 needs it to generate the closure task)"
            )
        return self

    @property
    def capture_sentence(self) -> str:
        """§5.5: every row outputs the literal 'assumes capture since ...'.

        Printed on the row, not in a footnote, because it is the assumption a
        hostile judge will push on and the answer is to have already said it.
        """
        if self.assumes_capture_since is None:
            return f"no capture assumption applied ({self.capture_assumption})"
        return (
            f"assumes capture since {self.assumes_capture_since.isoformat()} "
            f"({self.capture_assumption})"
        )


def replay(record: CalculationRecord) -> CalculationRecord:
    """Re-run the ledger that produced `record` over the inputs it carries.

    §5.9's property test is `replay(record).band == record.band`; in practice
    the whole record should match but for `record_id`, and the test asserts
    that.
    """
    from ecdat.risk import authentication_ledger, confidentiality_ledger

    if record.rule_version == authentication_ledger.RULE_ID:
        return authentication_ledger.evaluate(record.inputs, record_id=record.record_id)
    return confidentiality_ledger.evaluate(record.inputs, record_id=record.record_id)


def rank_key(record: CalculationRecord, criticality: int = 0) -> tuple[int, int, int]:
    """§5.10: lexicographic on categorical fields -- band, then criticality
    category, then longest window. No weights and no products: a weighted
    score is exactly the thing this design refuses to ship, because a judge
    can always ask what the weights mean and there is no defensible answer.
    """
    longest = max((w.days for w in record.windows), default=0)
    return (band_rank(record.band), criticality, -longest)

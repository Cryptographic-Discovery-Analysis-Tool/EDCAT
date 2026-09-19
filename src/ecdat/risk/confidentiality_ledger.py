"""Confidentiality exposure ledger (Pramana_Ledger_Spec.md §5.5, §5.7).

The harvest-now-decrypt-later clock. Every byte sent over a Shor-broken
confidentiality channel is recoverable at Z if it was recorded, so migrating
stops the bleed and recovers nothing. The question a row answers is therefore
not "how bad is this key" but "is there any of this data left worth
protecting, and until when".

Three red-team fixes are load-bearing here and are easy to lose in a refactor:

1. There is no `already_lost = years(start -> today)`. That over-counts,
   because the data that is beyond saving is what was sent after the deadline
   `Z - X` passed, not everything ever sent. The quantity is an intersection
   of intervals, never an elapsed-time subtraction.
2. `M` (migration) comes only from an OBSERVED negotiation with classical
   disabled (§5.7). A configuration file claiming hybrid stops nothing. The
   adversarial test for this is the "fake M" case.
3. Exposure is computed over SEGMENTS, not one window, so a surface that
   migrated and later re-accepted classical reopens rather than staying
   closed. §5.5's single-window formula is the one-stop case of this.

`as_of` and every date come from LedgerInputs. This module reads no clock and
no file, which is what makes the record replayable.
"""
from __future__ import annotations

from datetime import date

from ecdat.data.crypto_families import NoCitedFamilyError, is_shor_broken
from ecdat.model.epistemic import EpistemicState
from ecdat.model.temporal import MigrationEvidence
from ecdat.model.usage_context import CONFIDENTIALITY_FUNCTIONS, CryptoFunction
from ecdat.risk.record import (
    CalculationRecord,
    EvidenceStatusRef,
    ExposureBand,
    LedgerInputs,
    Qualifier,
    Window,
)
from ecdat.risk.scenarios import CaptureMode

RULE_ID = "LEDGER-CONF-001"


class LedgerNotApplicable(ValueError):
    """This context does not belong in the confidentiality ledger."""


# --- start date (§5.5, per capture_assumption) -----------------------------


def _start(inputs: LedgerInputs) -> tuple[date | None, str | None]:
    """`start = confirmed_since | possible_since | d`, per capture_assumption.

    Returns (start, unbounded_reason). A capture mode that asks for a date we
    do not have yields no start -- it does NOT silently fall back to the other
    mode, because that would answer a question the operator did not ask.
    """
    mode = inputs.policy.capture_assumption.mode
    temporal = inputs.temporal
    if mode == CaptureMode.SINCE_DATE:
        return inputs.policy.capture_assumption.since, None
    if mode == CaptureMode.SINCE_POSSIBLE:
        possible = temporal.possible_since
        if possible is None or possible.value is None:
            return None, (
                "capture_assumption=SINCE_POSSIBLE but no date bounds when this "
                "surface could first have carried traffic (no notBefore, no "
                "declared go-live, no snapshot, no observation)"
            )
        return possible.value, None
    confirmed = temporal.confirmed_since(
        accept_declared_go_live=inputs.policy.accept_declared_go_live
    )
    if confirmed is None or confirmed.value is None:
        return None, (
            "capture_assumption=SINCE_CONFIRMED but nothing confirms when this "
            "surface began carrying traffic (notBefore and snapshot presence "
            "never confirm -- §5.2)"
        )
    return confirmed.value, None


# --- migration timeline (§5.7) ---------------------------------------------


class _Timeline:
    """Observed migration events for one surface, resolved into the intervals
    during which classical key establishment was (as far as we observed)
    still accepted."""

    def __init__(self, migrations: tuple[MigrationEvidence, ...], start: date, as_of: date):
        self.events = sorted(
            (m for m in migrations if m.status == EpistemicState.KNOWN),
            key=lambda m: m.observed_at,
        )
        self.start = start
        self.as_of = as_of

    @property
    def first_stop(self) -> MigrationEvidence | None:
        return next((m for m in self.events if m.stops_the_clock), None)

    @property
    def reopened(self) -> bool:
        """A classical negotiation observed after a stop (§5.7)."""
        stop = self.first_stop
        if stop is None:
            return False
        return any(
            m.classical_still_accepted and m.observed_at > stop.observed_at
            for m in self.events
        )

    @property
    def partial(self) -> bool:
        """Hybrid observed but classical still accepted, per vantage (§5.5)."""
        return any(
            m.negotiated_group and m.classical_still_accepted for m in self.events
        )

    def exposure_intervals(self) -> tuple[tuple[date, date], ...]:
        """Intervals in which classical was accepted, from `start` to `as_of`.

        Walks the observations in order: a stop closes the current interval at
        its date, a later classical observation opens a new one from its date.
        """
        intervals: list[tuple[date, date]] = []
        open_at: date | None = self.start
        for event in self.events:
            if event.stops_the_clock:
                if open_at is not None:
                    intervals.append((open_at, min(event.observed_at, self.as_of)))
                    open_at = None
            elif event.classical_still_accepted and open_at is None:
                open_at = event.observed_at
        if open_at is not None:
            intervals.append((open_at, self.as_of))
        return tuple(i for i in intervals if i[0] <= i[1])

    @property
    def currently_stopped(self) -> bool:
        stop = self.first_stop
        return stop is not None and not self.reopened


# --- evaluation ------------------------------------------------------------


def _evidence_refs(inputs: LedgerInputs) -> tuple[EvidenceStatusRef, ...]:
    refs: list[EvidenceStatusRef] = []
    fn = inputs.usage_context.function
    for ref in fn.evidence_refs:
        refs.append(EvidenceStatusRef(id=ref, status=fn.state.value))
    algorithm = inputs.usage_context.algorithm
    if algorithm is not None:
        for ref in algorithm.evidence_refs:
            refs.append(EvidenceStatusRef(id=ref, status=algorithm.state.value))
    for name, fv in (
        ("not_before", inputs.temporal.not_before),
        ("declared_go_live", inputs.temporal.declared_go_live),
        ("first_snapshot_containing", inputs.temporal.first_snapshot_containing),
        ("first_observed", inputs.temporal.first_observed),
    ):
        if fv is not None:
            for ref in fv.evidence_refs:
                refs.append(EvidenceStatusRef(id=ref, status=fv.state.value, ts=fv.value))
    for migration in inputs.migrations:
        for ref in migration.evidence_refs:
            refs.append(
                EvidenceStatusRef(
                    id=ref, status=migration.status.value, ts=migration.observed_at
                )
            )
    return tuple(refs)


def _record(
    inputs: LedgerInputs,
    record_id: str,
    *,
    band: ExposureBand,
    reason: str = "",
    qualifiers: tuple[Qualifier, ...] = (),
    windows: tuple[Window, ...] = (),
    deadline: date | None = None,
    conditional_band: ExposureBand | None = None,
    start: date | None = None,
    timeline: _Timeline | None = None,
) -> CalculationRecord:
    stop = timeline.first_stop if timeline is not None else None
    return CalculationRecord(
        record_id=record_id,
        as_of=inputs.as_of,
        scenario_id=inputs.scenario.id,
        capture_assumption=inputs.policy.capture_assumption,
        policy_snapshot=inputs.policy,
        usage_context_id=inputs.usage_context.usage_context_id,
        function=inputs.usage_context.function.value,
        evidence_refs=_evidence_refs(inputs),
        band=band,
        qualifiers=qualifiers,
        windows=windows,
        deadline=deadline,
        conditional_band=conditional_band,
        reason=reason,
        assumes_capture_since=start,
        X=inputs.binding.secrecy_lifetime_X if inputs.binding is not None else None,
        start_possible=(
            inputs.temporal.possible_since.value
            if inputs.temporal.possible_since is not None
            else None
        ),
        start_confirmed=(
            confirmed.value
            if (
                confirmed := inputs.temporal.confirmed_since(
                    accept_declared_go_live=inputs.policy.accept_declared_go_live
                )
            )
            is not None
            else None
        ),
        M=stop.observed_at if stop is not None else None,
        M_evidence_ids=stop.evidence_refs if stop is not None else (),
        rule_version=RULE_ID,
        inputs_sha256=inputs.sha256(),
        inputs=inputs,
    )


def _shor_broken(inputs: LedgerInputs) -> bool | None:
    """True / False for a cited family, None when we cannot say."""
    function = inputs.usage_context.function.value
    if function == CryptoFunction.HYBRID_KEX:
        return False
    algorithm = inputs.usage_context.algorithm
    if algorithm is None or algorithm.value is None:
        return None
    family = algorithm.value.split("/", 1)[0]
    try:
        return is_shor_broken(family)
    except NoCitedFamilyError:
        return None


def evaluate(inputs: LedgerInputs, *, record_id: str = "") -> CalculationRecord:
    """§5.5. One usage context in, one CalculationRecord out."""
    context = inputs.usage_context
    function = context.function.value
    record_id = record_id or f"conf:{context.usage_context_id}:{inputs.scenario.id}"

    if function is not None and function not in CONFIDENTIALITY_FUNCTIONS:
        raise LedgerNotApplicable(
            f"{function.value} is not a confidentiality function; §5.5 applies "
            "only to KEX / key transport / PKE. Symmetric encryption is a "
            "Grover case and goes to a policy flag, signatures to §5.6."
        )

    # --- Unknown input -> UNBOUNDED, no conditional (§5.5, §6 'Unknown KEX')
    if context.function.state == EpistemicState.UNKNOWN:
        return _record(
            inputs,
            record_id,
            band=ExposureBand.UNBOUNDED,
            reason=(
                "crypto function is UNKNOWN for this context, so no clock "
                "applies; no conditional band is derivable either"
            ),
        )

    if inputs.binding is None:
        return _record(
            inputs,
            record_id,
            band=ExposureBand.UNBOUNDED,
            reason=(
                "no data-class binding: X (secrecy lifetime) is unknown, so "
                "the deadline Z - X cannot be computed"
            ),
        )

    deadline = inputs.binding.deadline(inputs.scenario.z_date)
    start, start_reason = _start(inputs)
    if start is None:
        return _record(
            inputs,
            record_id,
            band=ExposureBand.UNBOUNDED,
            reason=start_reason or "no start date",
            deadline=deadline,
        )

    timeline = _Timeline(inputs.migrations, start=start, as_of=inputs.as_of)
    qualifiers: list[Qualifier] = []
    if timeline.first_stop is not None:
        qualifiers.append(Qualifier.STOPPED)
    if timeline.reopened:
        qualifiers.append(Qualifier.REOPENED)
    if timeline.partial:
        qualifiers.append(Qualifier.PARTIAL)

    windows = tuple(
        Window(start=lo, end=hi)
        for lo, hi in (
            (max(interval_start, deadline), min(interval_end, inputs.as_of))
            for interval_start, interval_end in timeline.exposure_intervals()
        )
        if lo < hi
    )

    def banded(band: ExposureBand, reason: str = "") -> CalculationRecord:
        return _record(
            inputs,
            record_id,
            band=band,
            reason=reason,
            qualifiers=tuple(qualifiers),
            windows=windows if band in (ExposureBand.BLEEDING, ExposureBand.UNSAVABLE) else (),
            deadline=deadline,
            start=start,
            timeline=timeline,
        )

    # --- Inferred input under a policy that does not accept it -> UNBOUNDED
    # with the conditional band attached (§5.5, §6 'Inferred configuration').
    inferred_inputs = _inferred_input_names(inputs)
    shor = _shor_broken(inputs)
    if inferred_inputs and not inputs.policy.accept_inferred_inputs:
        conditional = _band_for(
            shor_broken=True if shor is None else shor,
            timeline=timeline,
            windows=windows,
            deadline=deadline,
            as_of=inputs.as_of,
        )
        return _record(
            inputs,
            record_id,
            band=ExposureBand.UNBOUNDED,
            reason=(
                "policy does not accept INFERRED inputs; inferred here: "
                + ", ".join(inferred_inputs)
            ),
            qualifiers=tuple(qualifiers),
            windows=(),
            deadline=deadline,
            conditional_band=conditional,
            start=start,
            timeline=timeline,
        )

    if shor is None:
        conditional = _band_for(
            shor_broken=True,
            timeline=timeline,
            windows=windows,
            deadline=deadline,
            as_of=inputs.as_of,
        )
        return _record(
            inputs,
            record_id,
            band=ExposureBand.UNBOUNDED,
            reason=(
                "no cited row classifies this algorithm family, so whether it "
                "is Shor-broken is unknown"
            ),
            qualifiers=tuple(qualifiers),
            deadline=deadline,
            conditional_band=conditional,
            start=start,
            timeline=timeline,
        )

    return banded(
        _band_for(
            shor_broken=shor,
            timeline=timeline,
            windows=windows,
            deadline=deadline,
            as_of=inputs.as_of,
        )
    )


def _inferred_input_names(inputs: LedgerInputs) -> tuple[str, ...]:
    """Which required inputs are INFERRED (§5.5). Only required ones: an
    INFERRED field the calculation never reads must not unbound a row."""
    names: list[str] = []
    if inputs.usage_context.function.state == EpistemicState.INFERRED:
        names.append("function")
    algorithm = inputs.usage_context.algorithm
    if algorithm is not None and algorithm.state == EpistemicState.INFERRED:
        names.append("algorithm")
    return tuple(names)


def _band_for(
    *,
    shor_broken: bool,
    timeline: _Timeline,
    windows: tuple[Window, ...],
    deadline: date,
    as_of: date,
) -> ExposureBand:
    """§5.5's band ladder, in the order the spec states it."""
    if not shor_broken:
        return ExposureBand.SAFE
    if as_of > deadline and not timeline.currently_stopped:
        return ExposureBand.BLEEDING
    if windows and timeline.currently_stopped:
        return ExposureBand.UNSAVABLE
    if not windows and as_of <= deadline:
        return ExposureBand.SAVABLE
    # Stopped before the deadline was ever crossed: nothing was sent after the
    # deadline, so nothing is beyond saving. §5.5 does not name this case; it
    # is the only remaining one and SAFE is the sole answer consistent with
    # an empty unsavable window.
    return ExposureBand.SAFE

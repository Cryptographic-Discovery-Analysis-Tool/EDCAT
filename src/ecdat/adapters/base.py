"""The contract every observation-surface adapter implements.

Lock §2 principle 9: observation surfaces, not languages, structure the model;
language-specific logic lives only inside adapters.
Lock §4 (PRV-001): "Language adapters declare a support level in {full,
partial, detect-only, unsupported}, which feeds the visibility matrix."
Lock §5 row 2: "every adapter declares a language/surface support level."
Lock §5 row 4: coverage % is superseded by the visibility matrix, which
includes "failed/timeout targets".
harness §7.3 (TRAP-07): a zero-crypto target must produce "zero crypto assets
AND a coverage entry confirming the target was scanned (silence != scanned)".

`run()` is deliberately concrete and must not be overridden: it is where those
invariants are enforced. A subclass implements `_scan()` only. The invariants
are enforced a second time on `AdapterRunResult` itself, so a hand-built result
cannot bypass them either.

Nothing here hardcodes a confidence value, an algorithm name, or a tool version
(CLAUDE.md anti-hallucination rules).
"""
from __future__ import annotations

import abc
from collections.abc import Callable
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from ecdat.model.evidence import Evidence
from ecdat.model.finding import Finding
from ecdat.model.topology import ObservationContext, ProbeTargetIdentity
from ecdat.model.visibility import SupportLevel, VisibilityDimension, VisibilityEntry


class AdapterContractError(RuntimeError):
    """A _scan() implementation violated this module's invariants.

    Never converted into a FAILED outcome: a defect in our own code must not be
    laundered into a claim that the target failed.
    """


class AdapterTimeout(Exception):
    """Raised by _scan() when its per-target budget is exhausted.

    Lock §5 row 4 lists failed/timeout targets as a visibility dimension: a
    timeout is an OUTCOME that must be reported, never an absence.
    """


class AdapterOutcome(str, Enum):
    """How one adapter run against one target ended.

    NOT an epistemic state (that enum is closed -- model.epistemic) and NOT a
    resolution status. This is a third, separate axis: it distinguishes
    "scanned, found nothing" from "failed" and "timed out", which Lock §5 row 4
    requires the visibility matrix to tell apart. The Lock names
    "failed/timeout targets" but gives no literal enum, so this is an
    engineering DECISION recorded in docs/decisions/ADR-003.
    """

    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"


class ScanTarget(BaseModel):
    """One unit of work. `locator` is opaque here (a path, an image ref, an
    endpoint); `probe` is set only for network probes.

    Lock §5 row 1: "The network allow-list, consent flag and probe vantage are
    recorded per probe." CLAUDE.md: "Network probing only for targets in scan
    allow-list with consent flag. Record probe_vantage."
    """

    model_config = ConfigDict(frozen=True)

    target_id: str
    locator: str
    probe: ProbeTargetIdentity | None = None
    consent: bool = False

    @field_validator("target_id", "locator")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be blank")
        return value

    @model_validator(mode="after")
    def _probe_requires_consent(self) -> "ScanTarget":
        if self.probe is not None and not self.consent:
            raise ValueError(
                "a probe target requires consent=True (Lock §5 row 1; CLAUDE.md "
                "network-probing hard rule)"
            )
        return self


class RawCapture(BaseModel):
    """A reference to preserved raw tool output.

    Reference only: no tool output bytes cross this contract. CLAUDE.md: "No
    private key / secret bytes in DB, logs, CLI output, CBOM, test snapshots.
    Store location + fingerprint only."
    """

    model_config = ConfigDict(frozen=True)

    raw_ref: str
    source_tool: str
    tool_version: str
    sha256: str
    captured_at: datetime

    @field_validator("raw_ref", "source_tool", "tool_version")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be blank")
        return value

    @field_validator("sha256")
    @classmethod
    def _looks_like_sha256(cls, value: str) -> str:
        normalised = value.strip().lower()
        if len(normalised) != 64 or any(c not in "0123456789abcdef" for c in normalised):
            raise ValueError("sha256 must be 64 hexadecimal characters")
        return normalised


class Coverage(BaseModel):
    """What the tool actually looked at, as the tool itself reported it.

    This exists because "no findings" and "did not look" are different claims
    and the difference is not visible in a findings list. harness §7.3 TRAP-07
    fails a tool that reports zero assets without evidence it scanned the
    target. Recorded observation (docs/build-plan.md finding 4): Semgrep run
    with Java rules over a Python target returns `results: []` *and*
    `paths.scanned: []` -- treating that as "clean" is precisely the failure
    TRAP-07 tests for.

    Paths are recorded exactly as the tool reported them; this model does not
    interpret or normalise them.
    """

    model_config = ConfigDict(frozen=True)

    scanned: tuple[str, ...] = ()
    skipped: tuple[str, ...] = ()

    @property
    def looked_at_anything(self) -> bool:
        return bool(self.scanned)


class AdapterRunResult(BaseModel):
    """Exactly what one adapter returns for one target."""

    model_config = ConfigDict(frozen=True)

    adapter_id: str
    support_level: SupportLevel
    target: ScanTarget
    outcome: AdapterOutcome
    context: ObservationContext
    coverage: Coverage
    visibility: tuple[VisibilityEntry, ...] = Field(min_length=1)
    raw_captures: tuple[RawCapture, ...] = ()
    evidence: tuple[Evidence, ...] = ()
    findings: tuple[Finding, ...] = ()
    failure_reason: str | None = None

    @model_validator(mode="after")
    def _validate(self) -> "AdapterRunResult":
        if self.outcome in (AdapterOutcome.FAILED, AdapterOutcome.TIMED_OUT):
            if not (self.failure_reason and self.failure_reason.strip()):
                raise ValueError("FAILED/TIMED_OUT requires a failure_reason")
            if self.findings or self.evidence:
                raise ValueError(
                    "a failed or timed-out target emits no findings and no evidence; "
                    "it is a distinct visibility outcome, not partial truth "
                    "(Lock §5 row 4; R-MONOTONE)"
                )
            if not any(
                e.dimension == VisibilityDimension.FAILED_TIMEOUT for e in self.visibility
            ):
                raise ValueError(
                    "FAILED/TIMED_OUT requires a FAILED_TIMEOUT visibility entry "
                    "(Lock §5 row 4)"
                )
        if self.support_level == SupportLevel.UNSUPPORTED and self.findings:
            raise ValueError(
                "an adapter declaring support_level=unsupported emits visibility "
                "only, never findings (Lock §4: the declared level feeds the "
                "visibility matrix)"
            )
        if self.findings and not self.coverage.looked_at_anything:
            raise ValueError(
                "findings were emitted but coverage.scanned is empty: a finding "
                "must come from something the tool actually looked at"
            )
        captured = {c.raw_ref for c in self.raw_captures}
        for evidence in self.evidence:
            if evidence.raw_ref not in captured:
                raise ValueError(
                    f"Evidence.raw_ref {evidence.raw_ref!r} is not among raw_captures; "
                    "raw tool output is preserved and referenced, never re-synthesised"
                )
        known_evidence = {evidence.evidence_id for evidence in self.evidence}
        for finding in self.findings:
            dangling = set(finding.evidence_refs) - known_evidence
            for field_value in finding.fields.values():
                dangling |= set(field_value.evidence_refs) - known_evidence
            if dangling:
                raise ValueError(
                    f"finding {finding.finding_id!r} cites evidence not in this result: "
                    f"{sorted(dangling)}"
                )
        return self


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Adapter(abc.ABC):
    """Base class for every adapter. Subclasses implement `_scan()` only.

    `adapter_id`, `support_level` and `dimensions` are class-level declarations,
    so an adapter cannot exist without declaring what surface it covers and how
    well (Lock §4, §5 row 2).
    """

    adapter_id: str
    support_level: SupportLevel
    dimensions: tuple[VisibilityDimension, ...]

    def __init__(self, *, clock: Callable[[], datetime] = _utc_now) -> None:
        for attribute in ("adapter_id", "support_level", "dimensions"):
            if not getattr(type(self), attribute, None):
                raise AdapterContractError(
                    f"{type(self).__name__} must declare {attribute} "
                    "(Lock §4; Lock §5 row 2)"
                )
        self._clock = clock

    @abc.abstractmethod
    def _scan(self, target: ScanTarget) -> AdapterRunResult:
        """Do the work and return a complete result.

        Must populate `coverage` and `visibility` even when nothing is found.
        Raise AdapterTimeout when a per-target budget is exhausted; any other
        exception is recorded as AdapterOutcome.FAILED by run().
        """

    def run(self, target: ScanTarget) -> AdapterRunResult:
        """Run this adapter against one target. Do not override.

        Exactly one result per target, always -- so an orchestrator can assert
        `len(results) == len(targets)` and diff the visibility matrix against
        the target list mechanically. A generator or a bare findings list would
        make "never attempted" and "attempted, found nothing" the same shape,
        which is the TRAP-07 failure.
        """
        try:
            result = self._scan(target)
        except (AdapterContractError, ValidationError):
            # Our own defect. Re-raised, never reported as a target failure:
            # laundering a bug into "this target failed" is a false visibility
            # claim about the target.
            raise
        except AdapterTimeout as exc:
            return self._outcome_only(target, AdapterOutcome.TIMED_OUT, type(exc).__name__)
        except Exception as exc:  # noqa: BLE001 -- recorded as an outcome, never swallowed
            # Only the exception TYPE is recorded. Exception *text* routinely
            # contains the offending input (a parser echoing the bytes it
            # choked on), and this string reaches the DB, the CLI and
            # snapshots. CLAUDE.md forbids secret bytes in all three.
            return self._outcome_only(target, AdapterOutcome.FAILED, type(exc).__name__)

        if not isinstance(result, AdapterRunResult):
            raise AdapterContractError("_scan() must return an AdapterRunResult")
        if result.adapter_id != self.adapter_id:
            raise AdapterContractError("result must carry this adapter's declared adapter_id")
        if result.support_level != self.support_level:
            raise AdapterContractError("result must carry this adapter's declared support_level")
        if result.target != target:
            raise AdapterContractError("result must carry the target it was given")
        self._check_declared_coverage(result)
        return result

    def _check_declared_coverage(self, result: AdapterRunResult) -> None:
        """An adapter may not claim more coverage than it declared.

        Without this, a detect-only adapter could emit `support_level=full`
        entries, or emit dimensions it has no capability for, and the visibility
        matrix would assert coverage nobody implemented -- overstating coverage
        is the specific failure this project is scored on.
        FAILED_TIMEOUT is exempt: any adapter may report that it failed.
        """
        for entry in result.visibility:
            if entry.dimension == VisibilityDimension.FAILED_TIMEOUT:
                continue
            if entry.dimension not in self.dimensions:
                raise AdapterContractError(
                    f"{self.adapter_id} emitted a visibility entry for "
                    f"{entry.dimension.value!r}, which it did not declare"
                )
            if entry.support_level != self.support_level:
                raise AdapterContractError(
                    f"{self.adapter_id} emitted a visibility entry claiming "
                    f"support_level={entry.support_level.value!r} but declares "
                    f"{self.support_level.value!r}"
                )

    def _outcome_only(
        self, target: ScanTarget, outcome: AdapterOutcome, reason: str
    ) -> AdapterRunResult:
        """A failed/timed-out run still reports every dimension it covers.

        The failure gets its own FAILED_TIMEOUT row, and each declared dimension
        gets a row saying it was not observed for this target -- otherwise a
        timed-out probe silently vanishes from the surface it was meant to cover.
        """
        entries = [
            VisibilityEntry(
                dimension=VisibilityDimension.FAILED_TIMEOUT,
                support_level=self.support_level,
                detail=f"{target.target_id}: {outcome.value} ({reason})",
            )
        ]
        entries.extend(
            VisibilityEntry(
                dimension=dimension,
                support_level=self.support_level,
                detail=f"{target.target_id}: not observed -- run {outcome.value}",
            )
            for dimension in self.dimensions
        )
        return AdapterRunResult(
            adapter_id=self.adapter_id,
            support_level=self.support_level,
            target=target,
            outcome=outcome,
            context=ObservationContext(observed_at=self._clock()),
            coverage=Coverage(),
            visibility=tuple(entries),
            failure_reason=reason,
        )

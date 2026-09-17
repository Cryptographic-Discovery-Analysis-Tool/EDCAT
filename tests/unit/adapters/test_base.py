"""The adapter contract's invariants.

Each test names the canonical rule it encodes. The theme throughout: an adapter
may not overstate what it saw, and "found nothing" must never be indistinguishable
from "did not look" (harness §7.3 TRAP-07: "silence != scanned").
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from ecdat.adapters.base import (
    Adapter,
    AdapterContractError,
    AdapterOutcome,
    AdapterRunResult,
    AdapterTimeout,
    Coverage,
    RawCapture,
    ScanTarget,
)
from ecdat.model.epistemic import EpistemicState
from ecdat.model.evidence import ConfidenceBasis, Evidence
from ecdat.model.field_value import FieldValue
from ecdat.model.finding import Finding
from ecdat.model.topology import ObservationContext, ProbeTargetIdentity
from ecdat.model.visibility import SupportLevel, VisibilityDimension, VisibilityEntry

FIXED_TIME = datetime(2026, 9, 17, 12, 0, tzinfo=timezone.utc)
SHA = "0" * 64


def _clock() -> datetime:
    return FIXED_TIME


def _context() -> ObservationContext:
    return ObservationContext(observed_at=FIXED_TIME)


def _basis() -> ConfidenceBasis:
    return ConfidenceBasis(
        source="ADAPTER_DECLARED",
        justification="test double; no cited table exists for this tool yet (OI-004)",
    )


class _Base(Adapter):
    adapter_id = "test-source"
    support_level = SupportLevel.PARTIAL
    dimensions = (VisibilityDimension.SOURCE,)


def _entry(
    dimension: VisibilityDimension = VisibilityDimension.SOURCE,
    support_level: SupportLevel = SupportLevel.PARTIAL,
    detail: str = "scanned",
) -> VisibilityEntry:
    return VisibilityEntry(dimension=dimension, support_level=support_level, detail=detail)


def _result(target: ScanTarget, **overrides) -> AdapterRunResult:
    defaults = dict(
        adapter_id="test-source",
        support_level=SupportLevel.PARTIAL,
        target=target,
        outcome=AdapterOutcome.COMPLETED,
        context=_context(),
        coverage=Coverage(scanned=("a.java",)),
        visibility=(_entry(),),
    )
    defaults.update(overrides)
    return AdapterRunResult(**defaults)


# --- TRAP-07: silence is not coverage --------------------------------------


def test_scanned_but_found_nothing_still_reports_coverage():
    """harness §7.3 TRAP-07: zero assets AND a coverage entry confirming the scan."""

    class Empty(_Base):
        def _scan(self, target):
            return _result(target, findings=())

    result = Empty(clock=_clock).run(ScanTarget(target_id="t1", locator="repo"))
    assert result.findings == ()
    assert result.outcome is AdapterOutcome.COMPLETED
    assert result.visibility, "a run that found nothing must still report visibility"
    assert result.coverage.looked_at_anything


def test_result_without_a_visibility_entry_is_rejected():
    with pytest.raises(ValidationError):
        _result(ScanTarget(target_id="t", locator="l"), visibility=())


def test_findings_without_any_scanned_path_are_rejected():
    """A finding must come from something the tool actually looked at."""
    finding = Finding(finding_id="f1", surface="source")
    with pytest.raises(ValidationError):
        _result(
            ScanTarget(target_id="t", locator="l"),
            coverage=Coverage(scanned=()),
            findings=(finding,),
        )


def test_zero_findings_with_zero_scanned_paths_is_representable():
    """The 'looked at nothing' case must be expressible, not coerced into 'clean'.

    Recorded: Java rules over a Python target return results=[] and
    paths.scanned=[] (see tests/fixtures/recorded/semgrep/1.99.0/ecdat-rules/).
    """
    result = _result(
        ScanTarget(target_id="t", locator="l"),
        coverage=Coverage(scanned=()),
        findings=(),
    )
    assert result.coverage.looked_at_anything is False


# --- Declared capability must bound claimed capability ----------------------


def test_adapter_cannot_claim_a_dimension_it_never_declared():
    class Overreach(_Base):
        def _scan(self, target):
            return _result(target, visibility=(_entry(dimension=VisibilityDimension.RUNTIME),))

    with pytest.raises(AdapterContractError, match="did not declare"):
        Overreach(clock=_clock).run(ScanTarget(target_id="t", locator="l"))


def test_adapter_cannot_claim_a_stronger_support_level_than_it_declared():
    class Overclaim(_Base):
        def _scan(self, target):
            return _result(target, visibility=(_entry(support_level=SupportLevel.FULL),))

    with pytest.raises(AdapterContractError, match="support_level"):
        Overclaim(clock=_clock).run(ScanTarget(target_id="t", locator="l"))


def test_subclass_without_a_declared_support_level_cannot_be_constructed():
    """Lock §4 / §5 row 2: every adapter declares a support level."""

    class NoLevel(Adapter):
        adapter_id = "nope"
        dimensions = (VisibilityDimension.SOURCE,)

        def _scan(self, target): ...

    with pytest.raises(AdapterContractError, match="support_level"):
        NoLevel(clock=_clock)


# --- Failure and timeout are outcomes, not absences -------------------------


def test_timeout_is_a_reported_outcome_with_its_own_dimension():
    """Lock §5 row 4 lists failed/timeout targets as a visibility dimension."""

    class Hangs(Adapter):
        adapter_id = "test-net"
        support_level = SupportLevel.PARTIAL
        dimensions = (VisibilityDimension.NETWORK,)

        def _scan(self, target):
            raise AdapterTimeout("budget exhausted")

    target = ScanTarget(
        target_id="t2",
        locator="endpoint",
        consent=True,
        probe=ProbeTargetIdentity(requested_host="host.invalid", port=9443, probe_vantage="lab"),
    )
    result = Hangs(clock=_clock).run(target)
    assert result.outcome is AdapterOutcome.TIMED_OUT
    assert result.findings == () and result.evidence == ()
    dimensions = {entry.dimension for entry in result.visibility}
    assert VisibilityDimension.FAILED_TIMEOUT in dimensions
    # The covered surface must still appear, or a timed-out probe silently
    # vanishes from the surface it was supposed to cover.
    assert VisibilityDimension.NETWORK in dimensions


def test_failure_reason_records_the_exception_type_not_its_text():
    """Exception text routinely echoes the input that caused it, and this string
    reaches the store, the CLI and snapshots. CLAUDE.md forbids secret bytes in
    all three, so only the type is recorded."""

    class Explodes(_Base):
        def _scan(self, target):
            raise ValueError("-----BEGIN EC PRIVATE KEY----- MHcCAQEEIH")

    result = Explodes(clock=_clock).run(ScanTarget(target_id="t3", locator="l"))
    assert result.outcome is AdapterOutcome.FAILED
    assert result.failure_reason == "ValueError"
    rendered = result.model_dump_json()
    assert "PRIVATE KEY" not in rendered
    assert "MHcCAQEEIH" not in rendered


def test_a_contract_violation_is_raised_not_disguised_as_a_target_failure():
    """A defect in our own code must not be laundered into "this target failed" —
    that would be a false claim about the target."""

    class Broken(_Base):
        def _scan(self, target):
            raise AdapterContractError("built a malformed result")

    with pytest.raises(AdapterContractError):
        Broken(clock=_clock).run(ScanTarget(target_id="t4", locator="l"))


def test_failed_run_may_not_also_report_findings():
    """R-MONOTONE: a failed target yields no partial truth."""
    with pytest.raises(ValidationError):
        _result(
            ScanTarget(target_id="t", locator="l"),
            outcome=AdapterOutcome.FAILED,
            failure_reason="ValueError",
            visibility=(_entry(dimension=VisibilityDimension.FAILED_TIMEOUT),),
            findings=(Finding(finding_id="f", surface="source"),),
        )


# --- Evidence provenance ----------------------------------------------------


def test_evidence_must_reference_preserved_raw_output():
    """Raw tool output is preserved and referenced, never re-synthesised."""
    evidence = Evidence(
        evidence_id="e1",
        source_tool="tool",
        tool_version="1.0.0",
        location="a.java:1",
        base_confidence=0.5,
        confidence_basis=_basis(),
        raw_ref="never/captured.json",
    )
    with pytest.raises(ValidationError, match="raw_captures"):
        _result(
            ScanTarget(target_id="t", locator="l"),
            raw_captures=(
                RawCapture(
                    raw_ref="captured.json",
                    source_tool="tool",
                    tool_version="1.0.0",
                    sha256=SHA,
                    captured_at=FIXED_TIME,
                ),
            ),
            evidence=(evidence,),
        )


def test_findings_may_not_cite_evidence_absent_from_the_result():
    finding = Finding(
        finding_id="f1",
        surface="source",
        fields={"algorithm": FieldValue(value="X", state=EpistemicState.KNOWN, evidence_refs=("ghost",))},
    )
    with pytest.raises(ValidationError, match="cites evidence"):
        _result(ScanTarget(target_id="t", locator="l"), findings=(finding,))


def test_unsupported_surface_emits_visibility_only():
    class Unsupported(Adapter):
        adapter_id = "test-unsupported"
        support_level = SupportLevel.UNSUPPORTED
        dimensions = (VisibilityDimension.SOURCE,)

        def _scan(self, target): ...

    with pytest.raises(ValidationError):
        AdapterRunResult(
            adapter_id="test-unsupported",
            support_level=SupportLevel.UNSUPPORTED,
            target=ScanTarget(target_id="t", locator="l"),
            outcome=AdapterOutcome.COMPLETED,
            context=_context(),
            coverage=Coverage(scanned=("a.java",)),
            visibility=(_entry(support_level=SupportLevel.UNSUPPORTED),),
            findings=(Finding(finding_id="f", surface="source"),),
        )


# --- Probe consent ----------------------------------------------------------


def test_a_network_probe_without_consent_is_rejected():
    """Lock §5 row 1 / CLAUDE.md: probing requires an allow-listed target with
    a consent flag, and the vantage is recorded."""
    with pytest.raises(ValidationError, match="consent"):
        ScanTarget(
            target_id="t",
            locator="endpoint",
            probe=ProbeTargetIdentity(
                requested_host="host.invalid", port=443, probe_vantage="lab"
            ),
        )

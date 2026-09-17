"""P1: the Semgrep source adapter, tested against harness ground truth.

Every assertion traces to a line of canonical ground truth, cited inline:
harness ground-truth/assets/PAY-001..003, PAY-008, ground-truth/traps.yaml
(TRAP-01, TRAP-07), harness §7.2/§7.3, Lock §4, Lock §7 OQ-4/OQ-5.

Input is only recorded tool output under tests/fixtures/recorded/ (CLAUDE.md:
"Never write a parser for tool output that isn't in tests/fixtures/recorded/").
The fixtures here come from ECDAT's own rules, recorded 2026-09-17; see that
directory's README for the exact commands.

The recurring theme is what the source surface may NOT claim. A literal at a
call site is observable; an algorithm that arrives through configuration is not;
a key size that is only implied by a parameter name is not; reachability is not
observable at all.
"""
from __future__ import annotations

import inspect
import json
from pathlib import Path

import pytest

from ecdat.adapters.base import AdapterOutcome, ScanTarget
from ecdat.adapters.source.semgrep import SemgrepSourceAdapter, UnrecordedToolOutput
from ecdat.model.epistemic import EpistemicState, ResolutionStatus
from ecdat.model.evidence import ConfidenceBasis
from ecdat.model.visibility import SupportLevel, VisibilityDimension

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures/recorded/semgrep/1.99.0/ecdat-rules"
TIER_A = FIXTURES / "tier-a-java.raw.json"
NO_CRYPTO = FIXTURES / "no-crypto-control.raw.json"
ARGUMENT_FORMS = FIXTURES / "argument-forms.raw.json"

# A test value, not a claim about Semgrep's real confidence: no cited
# source-tool confidence table exists (OI-004 / ADR-002), which is why the
# adapter requires the caller to supply one rather than holding a default.
TEST_CONFIDENCE = 0.5
TEST_BASIS = ConfidenceBasis(
    source="ADAPTER_DECLARED",
    justification="test value; no cited confidence table exists for semgrep (OI-004)",
)


def _adapter() -> SemgrepSourceAdapter:
    return SemgrepSourceAdapter(base_confidence=TEST_CONFIDENCE, confidence_basis=TEST_BASIS)


def _run(path: Path):
    return _adapter().run(ScanTarget(target_id=path.stem, locator=str(path)))


@pytest.fixture(scope="module")
def tier_a():
    return _run(TIER_A)


@pytest.fixture(scope="module")
def no_crypto():
    return _run(NO_CRYPTO)


@pytest.fixture(scope="module")
def argument_forms():
    return _run(ARGUMENT_FORMS)


def _by_file(result, filename: str):
    return [f for f in result.findings if f.fields["path"].value.endswith(filename)]


def _state(finding, field: str):
    value = finding.fields.get(field)
    return None if value is None else value.state


# --- PAY-001: the algorithm arrives through configuration -------------------


def test_pay001_algorithm_is_not_observable_from_source(tier_a):
    """PAY-001 expected_observation.must_not: "algorithm state KNOWN from source
    alone". The call site passes a getter, not a string."""
    findings = _by_file(tier_a, "KeyWrapService.java")
    assert len(findings) == 1
    finding = findings[0]
    assert _state(finding, "algorithm") is EpistemicState.UNKNOWN
    assert finding.fields["algorithm"].value is None


def test_pay001_records_why_the_algorithm_is_unresolved(tier_a):
    """An UNKNOWN with no reason is indistinguishable from not having looked.
    harness §14 CFG-001: every UNRESOLVED result carries a reason."""
    finding = _by_file(tier_a, "KeyWrapService.java")[0]
    resolution = finding.fields["algorithm"].resolution
    assert resolution is not None
    assert resolution.status is ResolutionStatus.UNRESOLVED
    assert resolution.reason and resolution.reason.strip()


def test_pay001_preserves_the_unresolved_argument_for_config_resolution(tier_a):
    """The configuration adapter needs to know WHAT to resolve. Dropping the
    expression would make the call site unresolvable later."""
    finding = _by_file(tier_a, "KeyWrapService.java")[0]
    assert finding.fields["algorithm_argument"].value == "props.getTransformation()"
    assert _state(finding, "algorithm_argument") is EpistemicState.KNOWN


def test_pay001_call_site_itself_is_observed(tier_a):
    """The call site is real and observed even though its algorithm is not."""
    finding = _by_file(tier_a, "KeyWrapService.java")[0]
    assert _state(finding, "path") is EpistemicState.KNOWN
    assert finding.fields["line"].value == 25


# --- PAY-002 / PAY-003: literals are observable, their parameters are not ---


def test_pay002_literal_algorithm_is_known(tier_a):
    """PAY-002 must_be: "algorithm KNOWN (literal Mac.getInstance(...))"."""
    finding = _by_file(tier_a, "WebhookSigner.java")[0]
    assert _state(finding, "algorithm") is EpistemicState.KNOWN
    assert finding.fields["algorithm"].value == "HmacSHA256"


def test_pay002_purpose_is_never_claimed_from_a_call_site(tier_a):
    """PAY-002 must_not: "purpose KNOWN from Semgrep alone -- MAC => integrity
    is INFERENCE, not observation". CLAUDE.md: purpose defaults to UNKNOWN,
    never guessed. Applies to every finding, not just this one."""
    for finding in tier_a.findings:
        assert _state(finding, "purpose") in (None, EpistemicState.UNKNOWN)
        if "purpose" in finding.fields:
            assert finding.fields["purpose"].value is None


def test_pay003_literal_algorithm_is_known(tier_a):
    """PAY-003 must_be: "algorithm KNOWN (literal Cipher.getInstance(...))"."""
    finding = _by_file(tier_a, "TokenVault.java")[0]
    assert _state(finding, "algorithm") is EpistemicState.KNOWN
    assert finding.fields["algorithm"].value == "AES/GCM/NoPadding"


def test_pay003_key_size_is_never_emitted_from_source(tier_a):
    """PAY-003's planted truth says "256-bit key", but the source surface cannot
    see it: the key arrives as a method parameter, and 256 appears only inside an
    identifier. Reading a parameter name as a measurement is exactly the
    false-certainty failure the project is scored on."""
    for finding in tier_a.findings:
        assert "key_bits" not in finding.fields
        assert "key_size" not in finding.fields


def test_no_parameter_of_the_operation_is_inferred_from_the_algorithm_string(tier_a):
    """A transformation string does not fix every parameter of the operation --
    PAY-001's own planted truth records mgf1_hash as provider-dependent, and
    notes the transformation string does not fix it. So a literal makes the
    string KNOWN, not the whole parameter set."""
    for finding in tier_a.findings:
        for field in ("mgf1_hash", "padding", "provider", "family", "primitive"):
            assert field not in finding.fields, f"{field} is not observable at a call site"


# --- TRAP-01: dead code is still a real call site ---------------------------


def test_trap01_dead_code_finding_is_emitted(tier_a):
    """traps.yaml TRAP-01: "finding allowed (the call site itself is real)"."""
    findings = _by_file(tier_a, "LegacyCardHash.java")
    assert len(findings) == 1
    assert findings[0].fields["algorithm"].value == "MD5"
    assert _state(findings[0], "algorithm") is EpistemicState.KNOWN


def test_trap01_reachability_is_unknown_never_asserted(tier_a):
    """Lock §7 OQ-5: "No reachability analysis. reachable = UNKNOWN."
    traps.yaml allows UNKNOWN or false; OQ-5 settles it as UNKNOWN, because
    Semgrep output carries no reachability signal at all. Asserting `false`
    would be a claim we cannot support."""
    finding = _by_file(tier_a, "LegacyCardHash.java")[0]
    assert _state(finding, "reachable") is EpistemicState.UNKNOWN
    assert finding.fields["reachable"].value is None


def test_no_finding_claims_to_be_in_use(tier_a):
    """TRAP-01: the asset "must NOT appear in the risk queue as 'in use'"."""
    for finding in tier_a.findings:
        assert _state(finding, "reachable") in (None, EpistemicState.UNKNOWN)


# --- TRAP-07: silence is not coverage ---------------------------------------


def test_trap07_control_yields_no_findings(no_crypto):
    """traps.yaml TRAP-07: "zero crypto assets"."""
    assert no_crypto.findings == ()


def test_trap07_control_does_not_claim_to_have_been_scanned(no_crypto):
    """The other half of TRAP-07: "AND a coverage entry confirming the target was
    scanned (silence != scanned)".

    Recorded fact: these are Java rules and the control is a Python service, so
    paths.scanned is empty -- Semgrep looked at nothing. Reporting this as
    "scanned, no crypto found" would be the false-assurance failure. The honest
    report is that the target was not covered, and the visibility entry has to
    say so."""
    assert no_crypto.coverage.scanned == ()
    assert no_crypto.coverage.looked_at_anything is False
    entries = [e for e in no_crypto.visibility if e.dimension is VisibilityDimension.SOURCE]
    assert len(entries) == 1
    detail = entries[0].detail or ""
    assert "no file" in detail.lower() or "not covered" in detail.lower(), (
        f"visibility detail must say the target was not covered, got {detail!r}"
    )


def test_a_scanned_target_records_what_was_looked_at(tier_a):
    """The positive half: coverage names the files actually examined, so a
    coverage claim can be checked rather than taken on trust."""
    assert len(tier_a.coverage.scanned) == 6
    assert any(p.endswith("KeyWrapService.java") for p in tier_a.coverage.scanned)


# --- PAY-008: a package is a capability, not a usage ------------------------


def test_pay008_no_dependency_surface_claim_from_a_source_adapter(tier_a):
    """PAY-008 is planted in pom.xml with surface: dependency, and must_not:
    "any algorithm-usage finding attributed to Bouncy Castle". No source file
    imports it. A source adapter must neither see it nor claim its surface."""
    for finding in tier_a.findings:
        assert not finding.fields["path"].value.endswith("pom.xml")
        rendered = json.dumps({k: v.value for k, v in finding.fields.items()}).lower()
        assert "bouncycastle" not in rendered and "bcprov" not in rendered
    assert all(
        e.dimension is not VisibilityDimension.DEPENDENCY for e in tier_a.visibility
    )


# --- Rule semantics that must not blur --------------------------------------


def test_a_protocol_argument_never_populates_an_algorithm_field(argument_forms):
    """SSLContext.getInstance("TLSv1.3") names a protocol. Mapping it onto the
    algorithm field would manufacture an algorithm asset that does not exist."""
    protocol_findings = [f for f in argument_forms.findings if "protocol" in f.fields]
    assert protocol_findings, "the protocol call site must still be inventoried"
    for finding in protocol_findings:
        assert "algorithm" not in finding.fields
        assert finding.fields["protocol"].value == "TLSv1.3"


def test_every_call_site_is_classified_and_none_is_dropped(argument_forms):
    """The literal / non-literal split must be an exhaustive partition. A call
    site that matches neither rule would vanish silently, and a vanished asset
    is worse than an unknown one."""
    algorithm_findings = [f for f in argument_forms.findings if "algorithm" in f.fields]
    assert len(algorithm_findings) == 5
    known = [f for f in algorithm_findings if _state(f, "algorithm") is EpistemicState.KNOWN]
    unknown = [f for f in algorithm_findings if _state(f, "algorithm") is EpistemicState.UNKNOWN]
    assert len(known) + len(unknown) == len(algorithm_findings)
    assert len(unknown) == 2  # the concatenation and the method call


def test_a_value_not_written_at_the_call_site_is_marked_as_such(argument_forms):
    """Semgrep constant-propagates, so a literal assigned elsewhere is reported
    with its value while the call site reads `getInstance(ALG)`. The value is
    statically determined, but it is not written here -- record that, because it
    changes what a reader of the evidence is entitled to conclude."""
    propagated = [
        f
        for f in argument_forms.findings
        if f.fields.get("algorithm") is not None
        and f.fields["algorithm"].value == "AES/CBC/PKCS5Padding"
    ]
    assert len(propagated) == 1
    assert propagated[0].fields["algorithm_literal_at_call_site"].value is False


def test_an_explicit_provider_does_not_create_a_second_call_site(argument_forms):
    """Two rules match the same line: one for the algorithm, one for the pinned
    provider. They are one call site with additive evidence, not two assets."""
    at_line_47 = [f for f in argument_forms.findings if f.fields["line"].value == 47]
    assert len(at_line_47) == 1
    finding = at_line_47[0]
    assert finding.fields["algorithm"].value == "HmacSHA256"
    assert finding.fields["provider_argument"].value == "SunJCE"


# --- Evidence discipline -----------------------------------------------------


def test_every_finding_cites_evidence_that_names_the_pinned_tool(tier_a):
    """Lock §5 row 3: confidence lives on evidence_refs. Lock §6: results are
    recorded with the exact tool version."""
    evidence_ids = {e.evidence_id for e in tier_a.evidence}
    assert evidence_ids
    for finding in tier_a.findings:
        assert set(finding.evidence_refs) <= evidence_ids
    for evidence in tier_a.evidence:
        assert evidence.source_tool == "semgrep"
        assert evidence.tool_version == "1.99.0"
        assert evidence.confidence_basis.source == "ADAPTER_DECLARED"


def test_source_text_is_never_carried_into_a_finding(tier_a):
    """Semgrep echoes the matched source line. It is used transiently to tell a
    propagated value from a written one, then dropped: source text is how key
    material would leak into the store, the CLI and snapshots."""
    for finding in tier_a.findings:
        rendered = json.dumps({k: str(v.value) for k, v in finding.fields.items()})
        assert "getInstance" not in rendered
        assert "MessageDigest" not in rendered


def test_output_of_an_unrecorded_tool_version_is_refused():
    """CLAUDE.md: never parse tool output that is not in tests/fixtures/recorded/.
    A version we have never recorded may have a different JSON shape, and
    guessing is how a parser starts inventing."""
    raw = json.loads(TIER_A.read_text(encoding="utf-8"))
    raw["version"] = "1.100.0"
    with pytest.raises(UnrecordedToolOutput):
        _adapter().parse(raw, raw_ref="synthetic")


def test_the_adapter_requires_a_confidence_it_does_not_choose_itself():
    """OI-004 / ADR-002: no cited source-tool confidence table exists, so the
    adapter must not hold a default."""
    with pytest.raises(TypeError):
        SemgrepSourceAdapter()


def test_the_adapter_declares_partial_support_not_full(tier_a):
    """Lock §4: the declared level feeds the visibility matrix. This ruleset
    covers Java call sites only -- not other languages, not reachability, not
    key sizes -- so `full` would overstate it."""
    assert tier_a.support_level is SupportLevel.PARTIAL
    assert tier_a.outcome is AdapterOutcome.COMPLETED


def test_the_adapter_carries_no_harness_identifiers():
    """CLAUDE.md hard rule, enforced for src/ by tools/ci/check_no_harness_identifiers.py."""
    import ecdat.adapters.source.semgrep as module

    text = inspect.getsource(module).lower()
    for token in ("meridian", "ecdat-harness", "targets/"):
        assert token not in text

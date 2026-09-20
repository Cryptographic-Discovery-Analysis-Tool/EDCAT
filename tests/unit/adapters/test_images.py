"""Container-image adapter (P4b; wraps cbomkit-theia, CBOM import).

The success fixture here is a REAL, trimmed slice of a live cbomkit-theia run
-- tests/fixtures/recorded/theia/edge-2026-09-19/README.md has the full
provenance: exact image + digest, exact docker command, and the real
5082-component / 847-dependency totals from the untrimmed run this six-
component file was cut from. The failure mode exercised below (directory-
traversal, non-zero exit, empty stdout) is the other real, recorded outcome
from that same capture session, against a different image -- it is not
replayed byte-for-byte here (the adapter's runner returns an already-parsed
document or raises; it never sees stderr text), only its *shape* -- a raising
runner -- is used to prove the adapter reports it as FAILED, not as a clean
empty scan.
"""
from __future__ import annotations

import json
from pathlib import Path

from ecdat.adapters.base import AdapterOutcome, ScanTarget
from ecdat.adapters.images.adapter import ImagesAdapter, build_theia_argv
from ecdat.model.epistemic import EpistemicState
from ecdat.model.evidence import ConfidenceBasis
from ecdat.model.visibility import SupportLevel, VisibilityDimension
from ecdat.security.secrets import find_secrets

FIXTURES = (
    Path(__file__).resolve().parents[2] / "fixtures" / "recorded" / "theia" / "edge-2026-09-19"
)
SUCCESS_FIXTURE = FIXTURES / "edge-lb.sample.json"

BASIS = ConfidenceBasis(
    source="ADAPTER_DECLARED",
    justification=(
        "No cited row exists for cbomkit-theia CBOM-import confidence "
        "(data/base_confidence.yaml usable_row_count is 0); import_cbom() "
        "already marks every field DECLARED rather than KNOWN, so this "
        "value only weights a third-party tool's own assertion."
    ),
)

TARGET = ScanTarget(target_id="sample-image", locator="sample-image:latest")


def adapter(runner):
    return ImagesAdapter(base_confidence=0.5, confidence_basis=BASIS, runner=runner)


def _load_success_document() -> dict:
    with SUCCESS_FIXTURE.open(encoding="utf-8") as handle:
        return json.load(handle)


# --- (a) the real recorded success fixture, end to end -----------------------


def test_success_fixture_yields_one_finding_per_crypto_component_all_declared():
    document = _load_success_document()
    expected_count = sum(1 for c in document["components"] if c.get("cryptoProperties"))
    assert expected_count == 6, "the recorded fixture is a known six-component slice"

    result = adapter(lambda target: document).run(TARGET)

    assert result.outcome == AdapterOutcome.COMPLETED
    assert len(result.findings) == expected_count

    for finding in result.findings:
        assert finding.fields, "every finding must carry the fields it was built with"
        for field_name, field in finding.fields.items():
            assert field.state != EpistemicState.KNOWN, (
                f"{finding.finding_id}.{field_name} is KNOWN -- another tool's "
                "CBOM assertion must never be laundered into our own observation"
            )
            assert field.state in (EpistemicState.DECLARED, EpistemicState.UNKNOWN)

    assert find_secrets(result.model_dump_json()) == ()


# --- (b) the real recorded failure mode: directory-traversal ------------------


def test_directory_traversal_failure_is_failed_not_a_clean_empty_scan():
    """README.md for this fixture: a real cbomkit-theia run against a
    different image failed with "max allowable directory traversal depth
    reached (maybe a link cycle?)", exit non-zero, empty stdout. That must
    not come back looking like a genuinely clean scan of an image with no
    crypto material -- the two are very different claims."""

    def raising_runner(target):
        raise RuntimeError("cbomkit-theia exited non-zero for this target")

    result = adapter(raising_runner).run(TARGET)

    assert result.outcome == AdapterOutcome.FAILED
    assert result.failure_reason
    assert result.findings == ()
    assert result.evidence == ()


# --- (c) declared support level and the named limitation ----------------------


def test_support_level_is_partial_and_no_source_scanning_is_named():
    result = adapter(lambda target: _load_success_document()).run(TARGET)

    assert ImagesAdapter.support_level == SupportLevel.PARTIAL
    assert result.support_level == SupportLevel.PARTIAL

    artifact_entries = [v for v in result.visibility if v.dimension == VisibilityDimension.ARTIFACT]
    assert len(artifact_entries) == 1
    detail = artifact_entries[0].detail
    assert detail is not None
    assert "does not perform source code scanning" in detail


# --- supporting behaviour: the live-invocation argv shape ---------------------


def test_live_argv_mounts_the_docker_socket_and_names_the_image_subcommand():
    argv = build_theia_argv("sample-image:latest")

    assert argv[0] == "docker"
    assert "run" in argv
    assert "-v" in argv
    assert argv[argv.index("-v") + 1] == "/var/run/docker.sock:/var/run/docker.sock"
    assert argv[-2] == "image"
    assert argv[-1] == "sample-image:latest"


def test_coverage_is_never_empty_even_when_nothing_is_found():
    """TRAP-07: silence != scanned. A document with no cryptoProperties
    components must still prove the image was looked at."""
    empty_document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:00000000-0000-0000-0000-000000000000",
        "version": 1,
        "metadata": {"timestamp": "2026-09-19T00:00:00Z"},
        "components": [],
    }
    result = adapter(lambda target: empty_document).run(TARGET)

    assert result.outcome == AdapterOutcome.COMPLETED
    assert result.findings == ()
    assert result.coverage.scanned
    assert result.coverage.looked_at_anything

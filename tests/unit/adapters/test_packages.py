"""Package-inventory adapter (P5; spec §3 row "Packages").

Parses recorded trivy `rootfs --list-all-pkgs` output only -- this project
does not run trivy itself in tests (CLAUDE.md: parsers are written only
against tests/fixtures/recorded/). The live-invocation shape is exercised
through the pure `build_trivy_argv` function, never a real subprocess.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from ecdat.adapters.base import AdapterOutcome, ScanTarget
from ecdat.adapters.packages.adapter import (
    PackagesAdapter,
    TrivyScanBundle,
    build_trivy_argv,
)
from ecdat.model.epistemic import EpistemicState
from ecdat.model.evidence import ConfidenceBasis
from ecdat.model.visibility import SupportLevel, VisibilityDimension
from ecdat.security.secrets import find_secrets

FIXTURES = (
    Path(__file__).resolve().parents[2] / "fixtures" / "recorded" / "trivy" / "0.74.0"
)
FATJAR_FIXTURE = FIXTURES / "e1_supplemental_payment-gateway-fatjar.raw.json"
NO_CRYPTO_FIXTURE = FIXTURES / "e1_supplemental_no-crypto-service.raw.json"

BASIS = ConfidenceBasis(
    source="ADAPTER_DECLARED",
    justification=(
        "No cited row exists for trivy package-presence confidence (OI-004; "
        "data/base_confidence.yaml usable_row_count is 0); package presence "
        "is direct tool output, not an inference, so a moderate declared "
        "value is used pending a cited table."
    ),
)

#: Field names that would launder package presence into a usage claim.
#: CLAUDE.md: "Package presence = capability, never usage. purpose defaults
#: to UNKNOWN, never guessed." None of these may ever appear on a Finding
#: this adapter emits.
FORBIDDEN_FIELD_NAMES = frozenset({"purpose", "function", "algorithm", "in_use", "usage"})


def adapter(**kw):
    kw.setdefault("scan_runner", lambda target: TrivyScanBundle(stdout_json=None))
    return PackagesAdapter(base_confidence=0.5, confidence_basis=BASIS, **kw)


def _bundle_from(path: Path) -> TrivyScanBundle:
    return TrivyScanBundle(stdout_json=path.read_text(encoding="utf-8"))


def _run_against_fixture(path: Path):
    return adapter(scan_runner=lambda target: _bundle_from(path)).run(
        ScanTarget(target_id="fixture", locator=str(path))
    )


# --- (a) the real fat-jar fixture, end to end --------------------------------


def test_fatjar_fixture_yields_one_finding_per_package_and_no_usage_claim():
    document = json.loads(FATJAR_FIXTURE.read_text(encoding="utf-8"))
    expected_count = sum(
        len(result.get("Packages") or ())
        for result in document.get("Results") or ()
        if isinstance(result, dict)
    )
    assert expected_count > 0, "the fixture must actually contain packages"

    result = _run_against_fixture(FATJAR_FIXTURE)

    assert result.outcome == AdapterOutcome.COMPLETED
    assert result.support_level == SupportLevel.DETECT_ONLY
    assert len(result.findings) == expected_count

    for finding in result.findings:
        assert not (FORBIDDEN_FIELD_NAMES & finding.fields.keys()), (
            f"finding {finding.finding_id!r} carries a usage-shaped field: "
            f"{FORBIDDEN_FIELD_NAMES & finding.fields.keys()}"
        )
        assert finding.fields["name"].state == EpistemicState.KNOWN
        assert finding.fields["name"].value

    # The secret guard already ran inside _scan (it would have raised); this
    # re-asserts directly against the serialised result, as certs/adapter.py's
    # own tests do.
    assert find_secrets(result.model_dump_json()) == ()


# --- (b) the zero-package fixture: TRAP-07 ------------------------------------


def test_no_crypto_fixture_is_zero_findings_but_proves_it_looked():
    result = _run_against_fixture(NO_CRYPTO_FIXTURE)

    assert result.outcome == AdapterOutcome.COMPLETED
    assert result.findings == ()
    assert result.coverage.scanned, "silence != scanned -- coverage must be non-empty"
    assert result.coverage.looked_at_anything

    assert len(result.visibility) >= 1
    entry = result.visibility[0]
    assert entry.dimension == VisibilityDimension.DEPENDENCY
    assert entry.support_level == SupportLevel.DETECT_ONLY
    assert entry.detail


# --- (c) the live-invocation argv shape ---------------------------------------


def test_live_argv_uses_rootfs_not_fs_and_pins_skip_db_update():
    argv = build_trivy_argv("/some/target", timeout_seconds=120)

    assert "rootfs" in argv
    assert "fs" not in argv, "fs mode returns zero language-specific files for a jar"
    assert "--skip-db-update" in argv
    assert "--list-all-pkgs" in argv
    assert argv[0] == "trivy"

    format_index = argv.index("--format")
    assert argv[format_index + 1] == "json", (
        "trivy's default output is a human-readable table even when stdout is not a TTY "
        "(confirmed live 2026-09-20) -- without --format json this adapter's JSON parse fails "
        "against a real invocation"
    )
    # timeout is passed as a single "<n>s" token, not two separate args
    timeout_index = argv.index("--timeout")
    assert argv[timeout_index + 1] == "120s"
    assert argv[-1] == "/some/target"


def test_live_argv_carries_an_offline_cache_dir_when_configured():
    argv = build_trivy_argv("/some/target", timeout_seconds=60, offline_db_path="/var/trivy-db")

    assert "--cache-dir" in argv
    assert argv[argv.index("--cache-dir") + 1] == "/var/trivy-db"


# --- (d) a synthetic package with no Licenses key at all ----------------------


def test_absent_licenses_key_is_unknown_not_empty():
    synthetic = {
        "SchemaVersion": 2,
        "Trivy": {"Version": "0.74.0"},
        "ArtifactName": "synthetic-target",
        "ArtifactType": "filesystem",
        "Results": [
            {
                "Target": "Java",
                "Class": "lang-pkgs",
                "Type": "jar",
                "Packages": [
                    {
                        "Name": "org.bouncycastle:bcprov-jdk18on",
                        "Identifier": {
                            "PURL": "pkg:maven/org.bouncycastle/bcprov-jdk18on@1.81",
                            "UID": "synthetic0000001",
                        },
                        "Version": "1.81",
                        # deliberately no "Licenses" key at all
                        "FilePath": "synthetic.jar/BOOT-INF/lib/bcprov-jdk18on-1.81.jar",
                        "AnalyzedBy": "jar",
                    }
                ],
            }
        ],
    }
    bundle = TrivyScanBundle(stdout_json=json.dumps(synthetic))
    result = adapter(scan_runner=lambda target: bundle).run(
        ScanTarget(target_id="synthetic", locator="synthetic-target")
    )

    assert len(result.findings) == 1
    licenses_field = result.findings[0].fields["licenses"]
    assert licenses_field.state == EpistemicState.UNKNOWN
    assert licenses_field.value is None
    assert result.findings[0].fields["name"].value == "org.bouncycastle:bcprov-jdk18on"
    assert result.findings[0].fields["version"].value == "1.81"


# --- supporting behaviour ------------------------------------------------------


def test_a_document_with_results_key_but_no_packages_is_also_zero_findings():
    synthetic = {
        "SchemaVersion": 2,
        "Trivy": {"Version": "0.74.0"},
        "ArtifactName": "empty-results",
        "ArtifactType": "filesystem",
        "Results": [{"Target": "Java", "Class": "lang-pkgs", "Type": "jar", "Packages": []}],
    }
    bundle = TrivyScanBundle(stdout_json=json.dumps(synthetic))
    result = adapter(scan_runner=lambda target: bundle).run(
        ScanTarget(target_id="t", locator="l")
    )
    assert result.findings == ()
    assert result.coverage.scanned == ("empty-results",)


def test_the_secret_guard_runs_on_the_way_out(monkeypatch):
    """The gate must be on the emission path, not a separate lint (mirrors
    certs/adapter.py's own test of the same invariant)."""
    import ecdat.adapters.packages.adapter as module
    from ecdat.security.secrets import SecretLeakError

    def leaky(*args, **kwargs):
        raise SecretLeakError("guard fired")

    monkeypatch.setattr(module, "scan_for_secrets", leaky)
    with pytest.raises(SecretLeakError):
        adapter(scan_runner=lambda target: _bundle_from(NO_CRYPTO_FIXTURE))._scan(
            ScanTarget(target_id="t", locator=str(NO_CRYPTO_FIXTURE))
        )


def test_no_output_at_all_is_a_failed_outcome_not_a_crash():
    result = adapter(scan_runner=lambda target: TrivyScanBundle(stdout_json=None)).run(
        ScanTarget(target_id="gone", locator="nowhere")
    )
    assert result.outcome == AdapterOutcome.FAILED
    assert result.findings == ()

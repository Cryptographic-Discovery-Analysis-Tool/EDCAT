"""ConfigChainAdapter -- the Adapter-contract wrapper around resolver.resolve()
and spring.gather() (P3; CFG-001, harness §14).

These tests exercise the adapter's own contract obligations (Finding shape,
evidence/raw_capture wiring, visibility, the secret guard) against small
synthetic repository trees. The resolver's own eight-state matrix is already
covered by test_config_resolver.py and is not re-litigated here.
"""
from pathlib import Path

import yaml

from ecdat.adapters.base import AdapterOutcome, ScanTarget
from ecdat.adapters.config.adapter import ConfigChainAdapter
from ecdat.adapters.config.spring import relaxed_env_name
from ecdat.model.epistemic import EpistemicState, ResolutionStatus
from ecdat.model.evidence import ConfidenceBasis
from ecdat.model.visibility import SupportLevel, VisibilityDimension

KEY = "pay.keywrap.transformation"
OAEP = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
PKCS1 = "RSA/ECB/PKCS1Padding"
IMAGE = "registry.internal/payment-gateway"
IMAGES = frozenset({IMAGE})
ABSENT_KEY = "unrelated.feature.flag"

_BASIS = ConfidenceBasis(
    source="ADAPTER_DECLARED",
    justification="static config-chain reading has no cited base-confidence row (OI-004)",
)


# --- fixture construction ----------------------------------------------------


def _project(tmp_path: Path) -> Path:
    (tmp_path / "src" / "main" / "resources").mkdir(parents=True)
    return tmp_path


def _application_yml(root: Path, value: str, *, profile: str | None = None) -> None:
    name = f"application-{profile}.yml" if profile else "application.yml"
    (root / "src" / "main" / "resources" / name).write_text(
        f"pay:\n  keywrap:\n    transformation: {value}\n", encoding="utf-8"
    )


def _deployment(root: Path, *, env=None, args=None, image=IMAGE, name="deploy.yaml"):
    container: dict = {"name": "gateway", "image": image}
    if env:
        container["env"] = env
    if args:
        container["args"] = args
    document = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "payment-gateway"},
        "spec": {"template": {"spec": {"containers": [container]}}},
    }
    (root / name).write_text(yaml.safe_dump(document), encoding="utf-8")


def _adapter(**kwargs) -> ConfigChainAdapter:
    return ConfigChainAdapter(
        property_keys=kwargs.pop("property_keys", (KEY,)),
        base_confidence=0.5,
        confidence_basis=_BASIS,
        declared_images=kwargs.pop("declared_images", IMAGES),
        active_profile=kwargs.pop("active_profile", None),
    )


def _run(root: Path, **kwargs):
    adapter = _adapter(**kwargs)
    target = ScanTarget(target_id="t1", locator=str(root))
    return adapter.run(target)


def _finding_for(result, key: str):
    surface = f"config:{result.target.locator}:{key}"
    matches = [f for f in result.findings if f.surface == surface]
    assert len(matches) == 1, f"expected exactly one finding for {surface}, got {len(matches)}"
    return matches[0]


def _common_assertions(result, key: str = KEY) -> None:
    assert result.outcome == AdapterOutcome.COMPLETED
    finding = _finding_for(result, key)
    assert finding.fields["resolved_value"].state != EpistemicState.KNOWN
    assert finding.fields["source_kind"].state != EpistemicState.KNOWN
    assert finding.fields["source_location"].state != EpistemicState.KNOWN

    config_entries = [
        v for v in result.visibility if v.dimension == VisibilityDimension.CONFIGURATION
    ]
    assert len(config_entries) == 1
    assert config_entries[0].support_level == SupportLevel.PARTIAL
    assert finding.fields["higher_precedence_not_inspected"].value, (
        "higher_precedence_not_inspected must be non-empty (W1)"
    )

    scan_for_secrets_ok(result.model_dump_json())


def scan_for_secrets_ok(payload: str) -> None:
    from ecdat.security.secrets import scan_for_secrets

    scan_for_secrets(payload, context="test")


# --- 1. cleanly resolved from application.yml alone --------------------------


def test_resolved_from_application_yml_alone(tmp_path):
    root = _project(tmp_path)
    _application_yml(root, OAEP)
    result = _run(root)
    _common_assertions(result)
    finding = _finding_for(result, KEY)
    resolved = finding.fields["resolved_value"]
    assert resolved.state == EpistemicState.INFERRED
    assert resolved.value == OAEP
    assert resolved.resolution.status == ResolutionStatus.RESOLVED
    assert finding.fields["source_kind"].value == "spring-config-data"
    assert finding.fields["rule_applied"].state == EpistemicState.KNOWN
    assert finding.fields["rule_applied"].value == "Spring Boot property-source order"
    assert finding.evidence_refs, "a resolved finding must cite the evidence that produced it"
    evidence = [e for e in result.evidence if e.evidence_id in finding.evidence_refs]
    assert len(evidence) == 1
    assert evidence[0].raw_ref in {c.raw_ref for c in result.raw_captures}
    assert evidence[0].source_tool == "ecdat-config-resolver"


# --- 2. overridden by an attached k8s env var ---------------------------------


def test_overridden_by_attached_k8s_env_var(tmp_path):
    root = _project(tmp_path)
    _application_yml(root, OAEP)
    _deployment(root, env=[{"name": relaxed_env_name(KEY), "value": PKCS1}])
    result = _run(root)
    _common_assertions(result)
    finding = _finding_for(result, KEY)
    resolved = finding.fields["resolved_value"]
    assert resolved.state == EpistemicState.INFERRED
    assert resolved.value == PKCS1
    assert resolved.resolution.status == ResolutionStatus.OVERRIDDEN
    assert finding.fields["source_kind"].value == "os-env"
    losing = finding.fields["losing_candidates"].value
    assert len(losing) == 1
    assert "spring-config-data" in losing[0] and OAEP in losing[0]


# --- 3. degraded to UNRESOLVED by a CLI-arg blocker (state F) ----------------


def test_cli_arg_blocker_degrades_to_unresolved_state_f(tmp_path):
    root = _project(tmp_path)
    _application_yml(root, OAEP)
    _deployment(root, args=[f"--{KEY}={PKCS1}"])
    result = _run(root)
    _common_assertions(result)
    finding = _finding_for(result, KEY)
    resolved = finding.fields["resolved_value"]
    assert resolved.state == EpistemicState.UNKNOWN, (
        "§14.3 state F: never report an override value as effective beneath "
        "an unsupported higher-precedence source"
    )
    assert resolved.state != EpistemicState.INFERRED
    assert resolved.value is None
    assert resolved.resolution.status == ResolutionStatus.UNRESOLVED
    assert resolved.resolution.reason
    assert finding.fields["source_kind"].value is None
    assert finding.fields["source_location"].value is None


# --- 4. CONFLICTING profile case ----------------------------------------------


def test_conflicting_profile_specific_files(tmp_path):
    root = _project(tmp_path)
    _application_yml(root, OAEP)
    _application_yml(root, PKCS1, profile="prod")
    result = _run(root)
    _common_assertions(result)
    finding = _finding_for(result, KEY)
    resolved = finding.fields["resolved_value"]
    assert resolved.state == EpistemicState.CONFLICTING
    assert resolved.value is None
    assert resolved.resolution.status == ResolutionStatus.UNRESOLVED
    losing = finding.fields["losing_candidates"].value
    assert len(losing) == 2


# --- 5. property key present nowhere ------------------------------------------


def test_property_key_present_nowhere(tmp_path):
    root = _project(tmp_path)
    # A real application.yml exists (for a different key) so the adapter
    # genuinely reads a file for this key too, rather than touching nothing
    # at all under root.
    _application_yml(root, OAEP)
    result = _run(root, property_keys=(ABSENT_KEY,))
    _common_assertions(result, key=ABSENT_KEY)
    finding = _finding_for(result, ABSENT_KEY)
    resolved = finding.fields["resolved_value"]
    assert resolved.state == EpistemicState.UNKNOWN
    assert resolved.value is None
    assert resolved.resolution.status == ResolutionStatus.UNRESOLVED
    assert resolved.resolution.reason == "no binding value found"
    assert finding.fields["losing_candidates"].value == ()


def test_property_key_nowhere_in_a_wholly_empty_repository(tmp_path):
    """Degenerate case: root exists but nothing under it is a config source
    at all. Still a COMPLETED run with an UNKNOWN finding, never a failure,
    and the finding may carry no evidence since nothing was read."""
    root = _project(tmp_path)
    result = _run(root)
    assert result.outcome == AdapterOutcome.COMPLETED
    finding = _finding_for(result, KEY)
    resolved = finding.fields["resolved_value"]
    assert resolved.state == EpistemicState.UNKNOWN
    assert resolved.resolution.status == ResolutionStatus.UNRESOLVED
    assert result.coverage.looked_at_anything, "root itself is always recorded as scanned"
    scan_for_secrets_ok(result.model_dump_json())


# --- cross-cutting invariants --------------------------------------------------


def test_multiple_property_keys_in_one_run_each_get_their_own_finding(tmp_path):
    root = _project(tmp_path)
    _application_yml(root, OAEP)
    result = _run(root, property_keys=(KEY, ABSENT_KEY))
    assert len(result.findings) == 2
    _finding_for(result, KEY)
    _finding_for(result, ABSENT_KEY)


def test_adapter_id_and_support_level_declared():
    adapter = _adapter()
    assert adapter.adapter_id == "config-chain-spring"
    assert adapter.support_level == SupportLevel.PARTIAL
    assert adapter.dimensions == (VisibilityDimension.CONFIGURATION,)


def test_missing_root_fails_rather_than_fabricating_a_result(tmp_path):
    missing = tmp_path / "does-not-exist"
    result = _run(missing)
    assert result.outcome == AdapterOutcome.FAILED
    assert result.findings == ()
    assert result.evidence == ()

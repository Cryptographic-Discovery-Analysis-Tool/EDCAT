"""The CFG-001 config-chain resolver (harness §14; build-plan P3).

The eight states A–H of §14.3 (A–G there, plus H added by W1), each built as
a real project tree on disk rather than as a hand-made candidate list — the
point of P3 is that the *scan* produces the right answer, not that the
resolver does when fed the right input.

§14.3's scoring rule is the acceptance criterion:

    "any state where the transformation is reported KNOWN, or where F/G
     report an override value as effective, is a false-certainty failure."
"""
from pathlib import Path

import pytest

from ecdat.adapters.config.resolver import resolve
from ecdat.adapters.config.spring import gather, relaxed_env_name
from ecdat.model.epistemic import EpistemicState, ResolutionStatus

KEY = "pay.keywrap.transformation"
OAEP = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
PKCS1 = "RSA/ECB/PKCS1Padding"
IMAGE = "registry.internal/payment-gateway"
IMAGES = frozenset({IMAGE})


# --- fixture construction ----------------------------------------------------


def _project(tmp_path: Path) -> Path:
    (tmp_path / "src" / "main" / "resources").mkdir(parents=True)
    return tmp_path


def _application_yml(root: Path, value: str, *, profile: str | None = None) -> None:
    name = f"application-{profile}.yml" if profile else "application.yml"
    (root / "src" / "main" / "resources" / name).write_text(
        f"pay:\n  keywrap:\n    transformation: {value}\n", encoding="utf-8"
    )


def _deployment(root: Path, *, env=None, args=None, volumes=None, image=IMAGE, name="deploy.yaml"):
    container: dict = {"name": "gateway", "image": image}
    if env:
        container["env"] = env
    if args:
        container["args"] = args
    spec: dict = {"containers": [container]}
    if volumes:
        spec["volumes"] = volumes
    document = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "payment-gateway"},
        "spec": {"template": {"spec": spec}},
    }
    import yaml

    (root / name).write_text(yaml.safe_dump(document), encoding="utf-8")


def _resolve(root: Path, *, images=IMAGES, active_profile=None):
    found = gather(root, KEY, declared_images=images)
    candidates, blockers, inspected = found.as_tuples()
    return resolve(
        KEY,
        candidates,
        blockers=blockers,
        sources_inspected=inspected,
        active_profile=active_profile,
    )


# --- the invariant that applies to every state -------------------------------


def _never_known(inference):
    assert inference.epistemic_state != EpistemicState.KNOWN, (
        "CFG-001 DECISION: successful resolution is INFERRED, never KNOWN"
    )
    assert inference.runtime_observation == EpistemicState.NOT_OBSERVED


# --- state A -----------------------------------------------------------------


def test_state_a_source_only(tmp_path):
    """A: source only, no yml value -> UNKNOWN; UNRESOLVED(no binding value
    found)."""
    root = _project(tmp_path)
    inference = _resolve(root)
    _never_known(inference)
    assert inference.epistemic_state == EpistemicState.UNKNOWN
    assert inference.resolution.status == ResolutionStatus.UNRESOLVED
    assert inference.resolution.reason == "no binding value found"
    assert inference.winning_candidate is None


# --- state B -----------------------------------------------------------------


def test_state_b_application_yml_only(tmp_path):
    """B: + application.yml = OAEP -> INFERRED; RESOLVED."""
    root = _project(tmp_path)
    _application_yml(root, OAEP)
    inference = _resolve(root)
    _never_known(inference)
    assert inference.epistemic_state == EpistemicState.INFERRED
    assert inference.resolution.status == ResolutionStatus.RESOLVED
    assert inference.winning_candidate.value == OAEP
    assert inference.losing_candidates == ()
    assert inference.higher_precedence_not_inspected, (
        "W1: sources invisible to static scanning are listed, not allowed to "
        "collapse the result"
    )


# --- state C -----------------------------------------------------------------


def test_state_c_env_override_on_a_matching_image(tmp_path):
    """C: B + k8s env override, image matches (A5) -> INFERRED; OVERRIDDEN,
    with the yml kept as a losing candidate."""
    root = _project(tmp_path)
    _application_yml(root, OAEP)
    _deployment(root, env=[{"name": relaxed_env_name(KEY), "value": PKCS1}])
    inference = _resolve(root)
    _never_known(inference)
    assert inference.epistemic_state == EpistemicState.INFERRED
    assert inference.resolution.status == ResolutionStatus.OVERRIDDEN
    assert inference.winning_candidate.value == PKCS1
    assert [c.value for c in inference.losing_candidates] == [OAEP]


def test_a5_an_unmatched_image_does_not_attach_the_override(tmp_path):
    """A5: 'a manifest override only applies if the manifest provably runs
    this application'. Otherwise it is recorded, not applied."""
    root = _project(tmp_path)
    _application_yml(root, OAEP)
    _deployment(root, env=[{"name": relaxed_env_name(KEY), "value": PKCS1}], image="other/app")
    inference = _resolve(root)
    _never_known(inference)
    assert inference.resolution.status == ResolutionStatus.UNRESOLVED
    assert "deployment-to-application link unresolved" in inference.resolution.reason
    assert inference.winning_candidate is None


# --- state D -----------------------------------------------------------------


def test_state_d_profile_file_with_no_known_active_profile(tmp_path):
    """D: B + application-prod.yml = PKCS1, no known active profile ->
    CONFLICTING {OAEP, PKCS1}.

    Two values we CANNOT order. CFG-001 rejected labelling any two-valued
    situation CONFLICTING; this one qualifies because no precedence settles it.
    """
    root = _project(tmp_path)
    _application_yml(root, OAEP)
    _application_yml(root, PKCS1, profile="prod")
    inference = _resolve(root)
    _never_known(inference)
    assert inference.epistemic_state == EpistemicState.CONFLICTING
    assert {c.value for c in inference.losing_candidates} == {OAEP, PKCS1}
    assert inference.winning_candidate is None
    assert "no known active profile" in inference.resolution.reason


def test_a_known_active_profile_settles_state_d(tmp_path):
    """The same tree stops conflicting once the active profile is known --
    precedence exists, so it is an override, not a conflict."""
    root = _project(tmp_path)
    _application_yml(root, OAEP)
    _application_yml(root, PKCS1, profile="prod")
    inference = _resolve(root, active_profile="prod")
    _never_known(inference)
    assert inference.epistemic_state == EpistemicState.INFERRED
    assert inference.winning_candidate.value == PKCS1


# --- state E -----------------------------------------------------------------


def test_state_e_env_outranks_the_conflicting_pair(tmp_path):
    """E: D + the state-C env override -> same as C.

    §14.3: 'profile uncertainty irrelevant for this key: env (5) outranks all
    config data (3)'. R-MONOTONE in the useful direction -- more evidence
    removed uncertainty rather than adding it.
    """
    root = _project(tmp_path)
    _application_yml(root, OAEP)
    _application_yml(root, PKCS1, profile="prod")
    _deployment(root, env=[{"name": relaxed_env_name(KEY), "value": PKCS1}])
    inference = _resolve(root)
    _never_known(inference)
    assert inference.epistemic_state == EpistemicState.INFERRED
    assert inference.resolution.status == ResolutionStatus.OVERRIDDEN
    assert inference.winning_candidate.source_kind.value == "os-env"
    assert len(inference.losing_candidates) == 2, "both config-data values are kept"


# --- state F -----------------------------------------------------------------


def test_state_f_a_command_line_arg_blocks_everything(tmp_path):
    """F: B + args ["--pay.keywrap.transformation=..."] -> UNKNOWN;
    UNRESOLVED(higher-precedence source present, unsupported).

    §14.3: 'must not report B's or C's value as effective (A1)'.
    """
    root = _project(tmp_path)
    _application_yml(root, OAEP)
    _deployment(root, args=[f"--{KEY}={PKCS1}"])
    inference = _resolve(root)
    _never_known(inference)
    assert inference.epistemic_state == EpistemicState.UNKNOWN
    assert inference.resolution.status == ResolutionStatus.UNRESOLVED
    assert inference.resolution.reason == "higher-precedence source present, unsupported"
    assert inference.winning_candidate is None
    assert [c.value for c in inference.losing_candidates] == [OAEP], (
        "the evidence chain is preserved; only the claim is withdrawn"
    )


def test_state_f_also_fires_for_system_properties_and_app_json(tmp_path):
    """A1 names three detect-only sources, not one."""
    for env in (
        [{"name": "JAVA_TOOL_OPTIONS", "value": f"-D{KEY}={PKCS1}"}],
        [{"name": "SPRING_APPLICATION_JSON", "value": '{"pay.keywrap.transformation":"x"}'}],
    ):
        root = _project(Path(tmp_path / f"case{hash(str(env)) & 0xffff}"))
        _application_yml(root, OAEP)
        _deployment(root, env=env)
        inference = _resolve(root)
        assert inference.resolution.status == ResolutionStatus.UNRESOLVED, env
        assert inference.winning_candidate is None, env


# --- state G -----------------------------------------------------------------


def test_state_g_an_unrendered_helm_values_file_is_never_an_override(tmp_path):
    """G: B + a Helm values.yaml carrying the env entry that no template
    references. §14.3: 'must not report OVERRIDDEN'."""
    root = _project(tmp_path)
    _application_yml(root, OAEP)
    chart = root / "chart"
    chart.mkdir()
    (chart / "Chart.yaml").write_text("name: payment-gateway\nversion: 0.1.0\n", encoding="utf-8")
    (chart / "values.yaml").write_text(
        f"env:\n  {relaxed_env_name(KEY)}: {PKCS1}\n", encoding="utf-8"
    )
    inference = _resolve(root)
    _never_known(inference)
    assert inference.resolution.status != ResolutionStatus.OVERRIDDEN
    assert inference.resolution.status == ResolutionStatus.UNRESOLVED
    assert "unrendered Helm chart" in inference.resolution.reason
    assert inference.winning_candidate is None


def test_a_helm_chart_not_mentioning_the_key_blocks_nothing(tmp_path):
    """R-UNSEEN, first half: a merely possible unseen source does not
    invalidate an inference. An unrelated chart must not break state B."""
    root = _project(tmp_path)
    _application_yml(root, OAEP)
    chart = root / "chart"
    chart.mkdir()
    (chart / "Chart.yaml").write_text("name: other\nversion: 0.1.0\n", encoding="utf-8")
    (chart / "values.yaml").write_text("replicas: 2\n", encoding="utf-8")
    inference = _resolve(root)
    assert inference.resolution.status == ResolutionStatus.RESOLVED
    assert inference.winning_candidate.value == OAEP


# --- state H (W1) --------------------------------------------------------------


def test_state_h_configmap_mounted_config_data_overrides_the_repo_yml(tmp_path):
    """H (W1): B + a ConfigMap volume mounting /config/application.yml with
    PKCS1, the ConfigMap being in the same repository -> OVERRIDDEN/INFERRED.

    W1: 'config data outside the jar overrides the packaged file — lower than
    env, higher than the repo yml'.
    """
    import yaml

    root = _project(tmp_path)
    _application_yml(root, OAEP)
    _deployment(root, volumes=[{"name": "config", "configMap": {"name": "gateway-config"}}])
    (root / "configmap.yaml").write_text(
        yaml.safe_dump(
            {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {"name": "gateway-config"},
                "data": {"application.yml": f"pay:\n  keywrap:\n    transformation: {PKCS1}\n"},
            }
        ),
        encoding="utf-8",
    )
    inference = _resolve(root)
    _never_known(inference)
    assert inference.epistemic_state == EpistemicState.INFERRED
    assert inference.resolution.status == ResolutionStatus.OVERRIDDEN
    assert inference.winning_candidate.value == PKCS1
    assert [c.value for c in inference.losing_candidates] == [OAEP]


def test_state_h_env_still_outranks_external_config_data(tmp_path):
    """W1's ordering, tested at both ends: external config data beats the repo
    yml and loses to the environment."""
    import yaml

    root = _project(tmp_path)
    _application_yml(root, OAEP)
    _deployment(
        root,
        env=[{"name": relaxed_env_name(KEY), "value": "RSA/ECB/OAEPWithSHA-1AndMGF1Padding"}],
        volumes=[{"name": "config", "configMap": {"name": "gateway-config"}}],
    )
    (root / "configmap.yaml").write_text(
        yaml.safe_dump(
            {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {"name": "gateway-config"},
                "data": {"application.yml": f"pay:\n  keywrap:\n    transformation: {PKCS1}\n"},
            }
        ),
        encoding="utf-8",
    )
    inference = _resolve(root)
    assert inference.winning_candidate.source_kind.value == "os-env"
    assert len(inference.losing_candidates) == 2


def test_a_configmap_outside_the_repository_is_unresolved(tmp_path):
    """W1: resolvable only when the ConfigMap is in the same repository."""
    root = _project(tmp_path)
    _application_yml(root, OAEP)
    _deployment(root, volumes=[{"name": "config", "configMap": {"name": "elsewhere"}}])
    inference = _resolve(root)
    assert inference.resolution.status == ResolutionStatus.UNRESOLVED
    assert "not found in this repository" in inference.resolution.reason


# --- A2: indirect env ----------------------------------------------------------


def test_value_from_is_unresolved_not_ignored(tmp_path):
    """A2: 'env[].valueFrom (secretKeyRef / configMapKeyRef) ->
    UNRESOLVED(reason: indirect env source)'."""
    root = _project(tmp_path)
    _application_yml(root, OAEP)
    _deployment(
        root,
        env=[{"name": relaxed_env_name(KEY), "valueFrom": {"secretKeyRef": {"name": "s"}}}],
    )
    inference = _resolve(root)
    assert inference.resolution.status == ResolutionStatus.UNRESOLVED
    assert "indirect env source" in inference.resolution.reason


# --- scoring rule --------------------------------------------------------------


def test_no_state_ever_reports_known(tmp_path):
    """§14.3 scoring: reporting the transformation KNOWN is a false-certainty
    failure in every state."""
    import yaml

    root = _project(tmp_path)
    _application_yml(root, OAEP)
    _application_yml(root, PKCS1, profile="prod")
    _deployment(root, env=[{"name": relaxed_env_name(KEY), "value": PKCS1}])
    for active in (None, "prod"):
        _never_known(_resolve(root, active_profile=active))


def test_relaxed_binding_matches_springs_documented_form():
    """CFG-001 VERIFIED FACTS: PAY_KEYWRAP_TRANSFORMATION binds
    pay.keywrap.transformation."""
    assert relaxed_env_name(KEY) == "PAY_KEYWRAP_TRANSFORMATION"

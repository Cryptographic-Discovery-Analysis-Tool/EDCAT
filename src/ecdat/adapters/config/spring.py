"""Gathering configuration candidates from a Spring project (CFG-001 §14).

Reads only what CFG-001 puts in scope: `application*.yml` in the repository,
plain Kubernetes manifests, ConfigMap-mounted config data, and Helm values
files (detected, never rendered). Everything else — Consul, Vault, cloud
secret managers, Spring Cloud Config, JNDI, cross-repo config, reflection —
is out of scope by the decision, and a file we do not understand is recorded
as a blocker rather than ignored.

The important asymmetry, from A1: this module **resolves** config data and
environment variables, and only **detects** command-line args, system
properties and `SPRING_APPLICATION_JSON`. Detection is a deliberate string
match, not a parser — A1 says so in as many words — and finding the property
key in one of them degrades the whole answer to UNRESOLVED. Reporting an env
value as effective while `--pay.keywrap.transformation=` sits two lines below
it in the same manifest is precisely the failure §14.3 state F scores.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import yaml

from ecdat.adapters.config.resolver import (
    EXTERNAL_CONFIG_DATA_RANK,
    PRECEDENCE,
    Blocker,
)
from ecdat.model.configuration import (
    Applicability,
    ConfigurationCandidate,
    SourceKind,
)

#: `application.yml`, `application-prod.yaml`, ...
_CONFIG_DATA = re.compile(r"^application(?:-(?P<profile>[A-Za-z0-9_-]+))?\.ya?ml$")

#: Where Spring's own config data lives inside a repository. A yml elsewhere
#: in the tree is not automatically config data.
_RESOURCE_DIRS = ("src/main/resources", "config", "resources")


def relaxed_env_name(property_key: str) -> str:
    """`pay.keywrap.transformation` -> `PAY_KEYWRAP_TRANSFORMATION`.

    CFG-001 VERIFIED FACTS: "Env vars bind via uppercase/underscore relaxed
    binding".
    """
    return property_key.upper().replace(".", "_").replace("-", "_")


@dataclass
class Gathered:
    """Everything the scan found for one property key."""

    candidates: list[ConfigurationCandidate] = field(default_factory=list)
    blockers: list[Blocker] = field(default_factory=list)
    sources_inspected: list[str] = field(default_factory=list)
    unattached: list[ConfigurationCandidate] = field(default_factory=list)

    def as_tuples(self):
        return tuple(self.candidates), tuple(self.blockers), tuple(self.sources_inspected)


def _load_documents(path: Path) -> list[dict[str, Any]]:
    try:
        return [d for d in yaml.safe_load_all(path.read_text(encoding="utf-8")) if isinstance(d, dict)]
    except (yaml.YAMLError, OSError, UnicodeDecodeError):
        return []


def _nested_get(document: dict[str, Any], dotted_key: str) -> Any:
    """Read `pay.keywrap.transformation` out of nested YAML mappings.

    Spring also accepts the flat form (`pay.keywrap.transformation: x` as a
    single key), so both are tried.
    """
    if dotted_key in document:
        return document[dotted_key]
    node: Any = document
    for part in dotted_key.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node if not isinstance(node, (dict, list)) else None


# --- repository config data ---------------------------------------------------


def _config_data_candidates(root: Path, property_key: str, gathered: Gathered) -> None:
    for resource_dir in _RESOURCE_DIRS:
        base = root / resource_dir
        if not base.is_dir():
            continue
        for path in sorted(base.glob("application*.y*ml")):
            match = _CONFIG_DATA.match(path.name)
            if match is None:
                continue
            gathered.sources_inspected.append(str(path))
            for document in _load_documents(path):
                value = _nested_get(document, property_key)
                if value is None:
                    continue
                profile = match.group("profile")
                gathered.candidates.append(
                    ConfigurationCandidate(
                        property_key=property_key,
                        value=str(value),
                        source_kind=SourceKind.SPRING_CONFIG_DATA,
                        source_location=str(path),
                        precedence_rank=PRECEDENCE[SourceKind.SPRING_CONFIG_DATA],
                        applicability=(
                            Applicability.CONDITIONAL if profile else Applicability.APPLICABLE
                        ),
                        condition=f"profile={profile}" if profile else None,
                    )
                )


# --- Kubernetes manifests -----------------------------------------------------


def _containers(document: dict[str, Any]) -> Iterable[dict[str, Any]]:
    spec = (document.get("spec") or {}).get("template", {}).get("spec", {})
    for container in spec.get("containers") or []:
        if isinstance(container, dict):
            yield container


def _manifest_candidates(
    root: Path, property_key: str, declared_images: frozenset[str], gathered: Gathered
) -> None:
    env_name = relaxed_env_name(property_key)

    for path in sorted(root.rglob("*.y*ml")):
        if _CONFIG_DATA.match(path.name):
            continue
        documents = _load_documents(path)
        if not any(d.get("kind") == "Deployment" for d in documents):
            continue
        gathered.sources_inspected.append(str(path))

        for document in documents:
            if document.get("kind") != "Deployment":
                continue
            for container in _containers(document):
                image = str(container.get("image", ""))

                # A5: an override only applies if the manifest provably runs
                # THIS application. Otherwise the candidate is recorded and
                # left unattached rather than silently applied to us.
                attached = any(image.startswith(declared) for declared in declared_images)

                _scan_container(
                    container,
                    path=path,
                    property_key=property_key,
                    env_name=env_name,
                    attached=attached,
                    gathered=gathered,
                )

            _configmap_config_data(document, path, property_key, declared_images, gathered)


def _scan_container(
    container: dict[str, Any],
    *,
    path: Path,
    property_key: str,
    env_name: str,
    attached: bool,
    gathered: Gathered,
) -> None:
    # --- env[] ---------------------------------------------------------------
    for entry in container.get("env") or []:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name", ""))

        if name == env_name:
            if "valueFrom" in entry:
                # A2: secretKeyRef / configMapKeyRef -- present, relevant,
                # unsupported. R-UNSEEN's second half.
                gathered.blockers.append(
                    Blocker(
                        reason="indirect env source",
                        source_kind=SourceKind.OS_ENV,
                        location=str(path),
                    )
                )
                continue
            candidate = ConfigurationCandidate(
                property_key=property_key,
                value=str(entry.get("value", "")),
                source_kind=SourceKind.OS_ENV,
                source_location=str(path),
                precedence_rank=PRECEDENCE[SourceKind.OS_ENV],
                applicability=Applicability.APPLICABLE,
            )
            if attached:
                gathered.candidates.append(candidate)
            else:
                gathered.unattached.append(candidate)
                gathered.blockers.append(
                    Blocker(
                        reason="deployment-to-application link unresolved",
                        source_kind=SourceKind.OS_ENV,
                        location=str(path),
                    )
                )
            continue

        # --- detect-only sources carried inside env (A1) ---------------------
        raw = str(entry.get("value", ""))
        if name == "JAVA_TOOL_OPTIONS" and f"-D{property_key}=" in raw:
            gathered.blockers.append(
                Blocker(
                    reason="higher-precedence source present, unsupported",
                    source_kind=SourceKind.SYSTEM_PROP,
                    location=f"{path} (JAVA_TOOL_OPTIONS)",
                )
            )
        if name == "SPRING_APPLICATION_JSON" and property_key in raw:
            gathered.blockers.append(
                Blocker(
                    reason="higher-precedence source present, unsupported",
                    source_kind=SourceKind.SPRING_APP_JSON,
                    location=f"{path} (SPRING_APPLICATION_JSON)",
                )
            )

    # --- args / command: a string match, not a parser (A1) -------------------
    for key in ("args", "command"):
        for argument in container.get(key) or []:
            if f"--{property_key}=" in str(argument):
                gathered.blockers.append(
                    Blocker(
                        reason="higher-precedence source present, unsupported",
                        source_kind=SourceKind.CLI_ARG,
                        location=f"{path} ({key})",
                    )
                )


def _configmap_config_data(
    document: dict[str, Any],
    path: Path,
    property_key: str,
    declared_images: frozenset[str],
    gathered: Gathered,
) -> None:
    """State H (W1): a ConfigMap mounting an external `application.yml`.

    External config data overrides the packaged file and is itself beaten by
    the environment. Resolvable only when the ConfigMap is in the same
    repository; otherwise its content is not something we have read.
    """
    spec = (document.get("spec") or {}).get("template", {}).get("spec", {})
    for volume in spec.get("volumes") or []:
        if not isinstance(volume, dict) or "configMap" not in volume:
            continue
        name = str((volume.get("configMap") or {}).get("name", ""))
        value, location = _find_configmap_value(path.parent, name, property_key)
        if value is None:
            gathered.blockers.append(
                Blocker(
                    reason=(
                        "ConfigMap-mounted configuration present but its content "
                        "was not found in this repository"
                    ),
                    source_kind=SourceKind.SPRING_CONFIG_DATA,
                    location=f"{path} (configMap {name})",
                )
            )
            continue
        gathered.sources_inspected.append(location)
        gathered.candidates.append(
            ConfigurationCandidate(
                property_key=property_key,
                value=value,
                source_kind=SourceKind.SPRING_CONFIG_DATA,
                source_location=location,
                # W1: "lower than env, higher than the repo yml".
                precedence_rank=EXTERNAL_CONFIG_DATA_RANK,
                applicability=Applicability.APPLICABLE,
            )
        )


def _find_configmap_value(
    search_root: Path, configmap_name: str, property_key: str
) -> tuple[str | None, str]:
    for path in sorted(search_root.rglob("*.y*ml")):
        for document in _load_documents(path):
            if document.get("kind") != "ConfigMap":
                continue
            if str((document.get("metadata") or {}).get("name", "")) != configmap_name:
                continue
            for filename, content in (document.get("data") or {}).items():
                if not str(filename).startswith("application"):
                    continue
                for embedded in yaml.safe_load_all(str(content)):
                    if not isinstance(embedded, dict):
                        continue
                    value = _nested_get(embedded, property_key)
                    if value is not None:
                        return str(value), f"{path} (ConfigMap {configmap_name}/{filename})"
    return None, ""


# --- Helm ---------------------------------------------------------------------


def _helm_blockers(root: Path, property_key: str, gathered: Gathered) -> None:
    """A2: a Helm `values.yaml` is not deployment configuration.

    A value there does nothing unless a template renders it, and the
    environment-specific values files and `--set` flags that would decide it
    are usually invisible. Detected and reported, never rendered, never
    treated as an override.
    """
    env_name = relaxed_env_name(property_key)
    for chart in sorted(root.rglob("Chart.y*ml")):
        values = chart.parent / "values.yaml"
        if not values.is_file():
            values = chart.parent / "values.yml"
        if not values.is_file():
            continue
        text = values.read_text(encoding="utf-8", errors="replace")
        if property_key not in text and env_name not in text:
            continue
        gathered.sources_inspected.append(str(values))
        gathered.blockers.append(
            Blocker(
                reason="unrendered Helm chart; values overrides unknown",
                location=str(values),
            )
        )


# --- entry point ---------------------------------------------------------------


def gather(
    root: Path, property_key: str, *, declared_images: frozenset[str] = frozenset()
) -> Gathered:
    """Collect every candidate and blocker for `property_key` under `root`.

    `declared_images` is the set of image names this repository's build config
    declares. A5: without it, a manifest override cannot be attached to this
    application and is recorded as unattached rather than applied.
    """
    gathered = Gathered()
    _config_data_candidates(root, property_key, gathered)
    _manifest_candidates(root, property_key, declared_images, gathered)
    _helm_blockers(root, property_key, gathered)
    return gathered

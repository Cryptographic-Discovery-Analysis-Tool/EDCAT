"""Trivy `rootfs --list-all-pkgs` JSON -> ParsedPackage (P5; spec §3 row
"Packages").

Recorded observation (tests/fixtures/recorded/trivy/0.74.0/README.md):
`trivy fs` returns `Number of language-specific files num=0` against a
standalone fat jar, whether pointed at the jar directly or at its containing
directory -- `fs` mode simply does not open it. `trivy rootfs
--scanners vuln --list-all-pkgs <dir>` does. This module is written only
against that recorded `rootfs` shape; it does not attempt to parse `fs`
output, which has a different top-level structure.

**Package presence = capability, never usage** (CLAUDE.md). A package
embedded in a jar says nothing about whether any source file imports it --
the recorded fat-jar fixture is the proof: it carries a cryptography
library among its 22 packages, and this module has no way to know, and does
not claim to know, whether anything in the artifact actually calls it. This
parser therefore has no notion of "purpose", "function" or "in use" -- it
reduces each package entry to the fields Trivy itself reported and nothing
else. Turning package presence into a usage claim is `function.classifier`'s
job, and it is explicitly out of scope for every adapter (Final Architecture:
"Trivy sees a package and tells you nothing [about purpose]").

A document with no top-level `"Results"` key is not a parse error: it is
exactly the shape trivy produces for a target with nothing installed
(recorded fixture: e1_supplemental_no-crypto-service.raw.json, the TRAP-07
negative case). Silence in `Results` means zero packages, not "could not
read this document".
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


class TrivyParseError(ValueError):
    """Trivy output we cannot read as the recorded `rootfs` shape.

    Carries no captured bytes: only a description of what was expected.
    """


@dataclass(frozen=True)
class ParsedPackage:
    """One entry from a trivy `Results[].Packages[]` array, reduced to what
    this project ever needs from it. No field here is a judgement about
    whether the package is used -- see the module docstring."""

    name: str
    version: str | None
    purl: str | None
    licenses: tuple[str, ...]
    file_path: str | None
    analyzed_by: str | None


@dataclass(frozen=True)
class ParsedScan:
    """One trivy document, reduced to what the adapter needs.

    `artifact_name` and `artifact_type` are kept even when `packages` is
    empty: they are the only honest signal of "what trivy actually looked
    at" on a document that carries no `Results` key at all, and the adapter
    uses `artifact_name` to populate `Coverage.scanned` so a genuinely clean
    target still records that it was examined (harness §7.3 TRAP-07:
    "silence != scanned").
    """

    schema_version: int | None
    trivy_version: str | None
    artifact_name: str | None
    artifact_type: str | None
    packages: tuple[ParsedPackage, ...]


def _string_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _int_or_none(value: Any) -> int | None:
    return value if isinstance(value, int) else None


def _licenses(value: Any) -> tuple[str, ...]:
    """Absent or empty `Licenses` becomes an empty tuple here; the adapter
    is the layer that turns "empty" into the epistemic state UNKNOWN
    (CLAUDE.md: "absent extension is unknown not empty" -- this parser only
    reports what trivy sent, the adapter assigns the state)."""
    if not isinstance(value, list):
        return ()
    return tuple(entry for entry in value if isinstance(entry, str) and entry.strip())


def _parse_package(raw: dict[str, Any]) -> ParsedPackage | None:
    """None when the entry has no name at all -- a package this project
    cannot even label is not reported as one (never fabricated)."""
    name = _string_or_none(raw.get("Name"))
    if name is None:
        return None
    identifier = raw.get("Identifier")
    purl = _string_or_none(identifier.get("PURL")) if isinstance(identifier, dict) else None
    return ParsedPackage(
        name=name,
        version=_string_or_none(raw.get("Version")),
        purl=purl,
        licenses=_licenses(raw.get("Licenses")),
        file_path=_string_or_none(raw.get("FilePath")),
        analyzed_by=_string_or_none(raw.get("AnalyzedBy")),
    )


def parse(document: dict[str, Any]) -> ParsedScan:
    """Parse one trivy `rootfs --list-all-pkgs --scanners vuln` JSON
    document. Tolerant of a missing `Results` key (see module docstring);
    raises only when `document` itself is not the JSON-object shape trivy
    always emits at the top level."""
    if not isinstance(document, dict):
        raise TrivyParseError("trivy output is not a JSON object at the top level")

    trivy_block = document.get("Trivy")
    trivy_version = (
        _string_or_none(trivy_block.get("Version")) if isinstance(trivy_block, dict) else None
    )

    packages: list[ParsedPackage] = []
    for result in document.get("Results") or ():
        if not isinstance(result, dict):
            continue
        for raw_package in result.get("Packages") or ():
            if not isinstance(raw_package, dict):
                continue
            parsed_package = _parse_package(raw_package)
            if parsed_package is not None:
                packages.append(parsed_package)

    return ParsedScan(
        schema_version=_int_or_none(document.get("SchemaVersion")),
        trivy_version=trivy_version,
        artifact_name=_string_or_none(document.get("ArtifactName")),
        artifact_type=_string_or_none(document.get("ArtifactType")),
        packages=tuple(packages),
    )

"""CycloneDX 1.6 export and import (Pramana_Ledger_Spec.md §5.11).

Export is how a ledger row leaves this tool and survives in someone else's.
Three rules shape the whole module:

1. **Exposure is carried in our own namespace.** Every band, window and
   deadline goes out as a `pramana:exposure:*` property. CycloneDX 1.6 has no
   field for "this channel has been leaking since 2021" and inventing one
   would be a lie about the standard. §5.11: describe these as
   "CycloneDX-compatible properties", never as a standard field.
2. **The undetermined bucket is explicit.** Rows we could not determine are
   listed, counted, and pointed at by BOM-level properties. A consumer must
   never be able to read our silence as "clean" -- that is the same failure
   as an adapter reporting zero findings without saying what it scanned.
3. **No confidence number is emitted, ever.** CycloneDX has
   `evidence.identity.confidence` (a float 0-1) and it is deliberately left
   empty: data/base_confidence.yaml has no usable row (OI-004, ADR-002), so
   any number here would be invented. `pramana:evidence:confidenceLevel`
   carries the epistemic state instead -- a word we can defend rather than a
   number we cannot.

Import is the mirror: any tool's CycloneDX 1.6 CBOM becomes evidence. What it
deliberately does NOT do is create usage contexts. A third-party CBOM is an
inventory, and §5.1 is explicit that inventory presence yields no context --
another tool telling us an algorithm exists is not a usage, and promoting it
to one would manufacture rows nobody observed.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urljoin

from jsonschema import Draft7Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7
from pydantic import BaseModel, ConfigDict

from ecdat.model.epistemic import EpistemicState
from ecdat.security.secrets import SecretLeakError, scan_for_secrets
from ecdat.model.usage_context import CryptoFunction
from ecdat.risk.record import CalculationRecord, ExposureBand

SPEC_VERSION = "1.6"
NAMESPACE = "pramana"
_SCHEMA_FILE = "cyclonedx-1.6.schema.json"


class SchemaValidationError(ValueError):
    """The document does not validate against the bundled 1.6 schema."""


# --- schema validation ------------------------------------------------------


_JSF_SCHEMA_FILE = "jsf-0.82.schema.json"


def _schema_path() -> Path:
    # src/ecdat/export/cyclonedx.py -> repository root -> schemas/
    return Path(__file__).resolve().parents[3] / "schemas" / _SCHEMA_FILE


def _jsf_schema_path() -> Path:
    return Path(__file__).resolve().parents[3] / "schemas" / _JSF_SCHEMA_FILE


@lru_cache(maxsize=1)
def _validator() -> Draft7Validator:
    """A validator that cannot reach the network.

    The 1.6 schema references two external documents, `spdx.schema.json` (SPDX
    licence expressions) and `jsf-0.82.schema.json` (signatures). Neither may
    be fetched at validation time -- the delivery target is an air-gapped
    network, and a validator that silently reaches for the internet is a
    finding in its own right.

    `jsf-0.82.schema.json` is the real, fetched schema (CycloneDX's own
    `specification` repo, Apache-2.0), vendored here the same way
    `cyclonedx-1.6.schema.json` itself was -- fetched once during
    development, shipped, never fetched again at runtime. OI-013's
    `export/signing.py` now emits real `signature` blocks, and this
    validator checks them for real (see `test_signing.py`'s
    `test_signed_document_validates_against_the_real_jsf_schema`).

    `spdx.schema.json` (licence expressions) stays a permissive stub: this
    project emits no `licenses` field, so nothing here is validated by it and
    fetching a schema for a field we never use would be work with no
    corresponding test to prove it is right.
    """
    schema = json.loads(_schema_path().read_text(encoding="utf-8"))
    jsf_schema = json.loads(_jsf_schema_path().read_text(encoding="utf-8"))
    base = schema.get("$id", "")
    registry = Registry().with_resources(
        [
            (
                urljoin(base, "spdx.schema.json"),
                Resource.from_contents({}, default_specification=DRAFT7),
            ),
            (
                urljoin(base, "jsf-0.82.schema.json"),
                Resource.from_contents(jsf_schema, default_specification=DRAFT7),
            ),
        ]
    )
    # format_checker: without it, "format": "uri" is annotation-only and
    # never actually checked, which makes JSF's signature.algorithm oneOf
    # (an enum branch vs. a "proprietary algorithm as a URI" branch)
    # genuinely ambiguous -- see pyproject.toml's comment on the
    # jsonschema[format] extra this requires.
    return Draft7Validator(schema, registry=registry, format_checker=Draft7Validator.FORMAT_CHECKER)


def validate(document: dict[str, Any]) -> None:
    """Raise SchemaValidationError unless `document` is valid CycloneDX 1.6."""
    errors = sorted(_validator().iter_errors(document), key=lambda e: list(e.absolute_path))
    if errors:
        detail = "; ".join(
            f"{'/'.join(str(p) for p in error.absolute_path) or '<root>'}: {error.message}"
            for error in errors[:5]
        )
        raise SchemaValidationError(f"{len(errors)} schema error(s): {detail}")


# --- the property map (§5.11) -----------------------------------------------


def _p(name: str, value: Any) -> dict[str, str]:
    return {"name": f"{NAMESPACE}:{name}", "value": str(value)}


#: CryptoFunction -> CycloneDX `algorithmProperties.primitive`. A presentation
#: mapping between two vocabularies, not a risk claim: nothing downstream of
#: this reads the band from it. Anything we are not sure of maps to the
#: schema's own `unknown`, which is why that member exists.
_PRIMITIVE: dict[CryptoFunction, str] = {
    CryptoFunction.SIGNATURE_AUTH: "signature",
    CryptoFunction.KEY_ESTABLISHMENT: "key-agree",
    CryptoFunction.KEY_TRANSPORT: "pke",
    CryptoFunction.HYBRID_KEX: "combiner",
    CryptoFunction.ENCRYPTION: "ae",
    CryptoFunction.UNKNOWN: "unknown",
}


def _exposure_properties(record: CalculationRecord) -> list[dict[str, str]]:
    """§5.11's property list, one row's worth."""
    context = record.inputs.usage_context
    function = record.function
    properties = [
        _p("exposure:band", record.band.value),
        _p("exposure:scenario", record.scenario_id),
        _p("exposure:as_of", record.as_of.isoformat()),
        _p("exposure:capture_assumption", str(record.capture_assumption)),
        _p("exposure:record_id", record.record_id),
        _p("exposure:function", function.value if function else "UNKNOWN"),
        _p("exposure:function_status", context.function.state.value),
        _p("exposure:calc_version", record.calc_version),
        _p("exposure:rule_version", record.rule_version),
        _p("exposure:inputs_sha256", record.inputs_sha256),
    ]
    for qualifier in record.qualifiers:
        properties.append(_p("exposure:qualifiers", qualifier.value))
    for window in record.windows:
        properties.append(_p("exposure:unsavable_window", str(window)))
    if record.deadline is not None:
        properties.append(_p("exposure:deadline", record.deadline.isoformat()))
    if record.conditional_band is not None:
        properties.append(_p("exposure:conditional_band", record.conditional_band.value))
    if record.assumes_capture_since is not None:
        properties.append(_p("exposure:assumes_capture", record.capture_sentence))
    if record.reason:
        properties.append(_p("exposure:reason", record.reason))
    if record.X is not None:
        properties.append(_p("exposure:secrecy_lifetime_X", str(record.X)))
    if record.A is not None:
        properties.append(_p("exposure:authenticity_lifetime_A", str(record.A)))
    if record.M is not None:
        properties.append(_p("exposure:M", record.M.isoformat()))

    # §5.11's confidenceLevel / detectionContext, both in our namespace.
    # confidenceLevel is a WORD, not a number -- see the module docstring.
    properties.append(_p("evidence:confidenceLevel", context.function.state.value))
    properties.append(
        _p("evidence:detectionContext", f"{context.surface_id} | {context.protocol_context}")
    )
    for ref in record.evidence_refs:
        properties.append(_p("evidence:ref", f"{ref.id} ({ref.status})"))
    return properties


def _component(record: CalculationRecord) -> dict[str, Any]:
    context = record.inputs.usage_context
    algorithm = context.algorithm.value if context.algorithm is not None else None
    function = record.function or CryptoFunction.UNKNOWN

    crypto_properties: dict[str, Any] = {"assetType": "algorithm"}
    algorithm_properties: dict[str, Any] = {"primitive": _PRIMITIVE[function]}
    crypto_properties["algorithmProperties"] = algorithm_properties

    return {
        "type": "cryptographic-asset",
        # record_id, not usage_context_id: one usage context produces one row
        # PER SCENARIO, and a BOM carrying all three Z answers for the same
        # context would otherwise emit three components sharing a bom-ref.
        # bom-ref has to be unique for any consumer to resolve a reference.
        "bom-ref": record.record_id,
        "name": algorithm or f"unknown-algorithm ({context.asset_id})",
        "description": (
            f"{function.value} on {context.surface_id}, as observed at "
            f"{context.protocol_context}"
        ),
        "cryptoProperties": crypto_properties,
        "properties": _exposure_properties(record),
    }


# --- export -----------------------------------------------------------------


def build_bom(
    records: Iterable[CalculationRecord],
    *,
    timestamp: datetime,
    serial_number: str | None = None,
    tool_version: str = "0.1.0",
) -> dict[str, Any]:
    """Build a CycloneDX 1.6 document from ledger rows.

    `timestamp` is a parameter rather than a clock read so an export is
    reproducible and diffable -- two runs over the same rows produce byte-
    identical output.
    """
    rows = list(records)
    components = [_component(record) for record in rows]
    undetermined = [r for r in rows if r.band == ExposureBand.UNBOUNDED]

    bom_properties = [
        _p("export:spec", "exposure carried as pramana:* properties; not CycloneDX fields"),
        _p("undetermined:count", len(undetermined)),
        _p("undetermined:total_rows", len(rows)),
    ]
    for record in undetermined:
        bom_properties.append(
            _p("undetermined:ref", f"{record.usage_context_id}: {record.reason}")
        )

    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": serial_number or f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp.isoformat(),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "pramana",
                        "version": tool_version,
                    }
                ]
            },
        },
        "components": components,
        "properties": bom_properties,
    }


def to_json(document: dict[str, Any], *, indent: int = 2) -> str:
    """Validate, scan for secrets, and serialise. In that order.

    Both gates run on every export, including test snapshots, because an
    export path with a bypass is an export path with a leak.
    """
    validate(document)
    serialised = json.dumps(document, indent=indent, sort_keys=False, ensure_ascii=False)
    scan_for_secrets(serialised, context="CycloneDX export")
    return serialised


def write(document: dict[str, Any], path: Path, *, indent: int = 2) -> Path:
    path.write_text(to_json(document, indent=indent), encoding="utf-8")
    return path


# --- import -----------------------------------------------------------------


class ImportedCryptoAsset(BaseModel):
    """One `cryptographic-asset` component read out of someone else's CBOM.

    `state` is DECLARED and only DECLARED. Another tool asserting that an
    algorithm exists is a statement, not an observation we made -- we did not
    see the call site, we saw a line in a file. Recording it as KNOWN would
    launder a third party's certainty into ours, which R-MONOTONE forbids.

    No UsageContext is produced. A CBOM is an inventory; §5.1 gives inventory
    presence no context, and that rule does not relax because the inventory
    arrived in a standard format.
    """

    model_config = ConfigDict(frozen=True)

    bom_ref: str
    name: str
    asset_type: str
    source_tool: str
    source_tool_version: str
    state: EpistemicState = EpistemicState.DECLARED
    primitive: str | None = None
    oid: str | None = None
    properties: tuple[tuple[str, str], ...] = ()


def _producing_tool(document: dict[str, Any]) -> tuple[str, str]:
    tools = (document.get("metadata") or {}).get("tools") or {}
    candidates = tools.get("components") if isinstance(tools, dict) else tools
    if isinstance(candidates, list) and candidates:
        first = candidates[0]
        if isinstance(first, dict):
            return (
                str(first.get("name") or "unknown-tool"),
                str(first.get("version") or "unknown-version"),
            )
    return ("unknown-tool", "unknown-version")


def import_cbom(document: dict[str, Any]) -> tuple[ImportedCryptoAsset, ...]:
    """Read any CycloneDX 1.6 CBOM as evidence (§3 "CBOM import from other
    tools as an evidence source").

    The document is schema-validated first: an import path that accepts
    malformed input is an injection surface, and "some other tool wrote it"
    is not a reason to trust bytes.
    """
    validate(document)
    if document.get("specVersion") != SPEC_VERSION:
        raise SchemaValidationError(
            f"expected specVersion {SPEC_VERSION}, got {document.get('specVersion')!r}"
        )
    tool_name, tool_version = _producing_tool(document)

    imported: list[ImportedCryptoAsset] = []
    for component in document.get("components") or ():
        crypto = component.get("cryptoProperties")
        if not crypto:
            # Not a crypto asset. §5.1: presence is not usage, and a plain
            # library component is not even presence of an algorithm.
            continue
        algorithm_properties = crypto.get("algorithmProperties") or {}
        imported.append(
            ImportedCryptoAsset(
                bom_ref=str(component.get("bom-ref") or component.get("name") or ""),
                name=str(component.get("name") or ""),
                asset_type=str(crypto.get("assetType") or "unknown"),
                source_tool=tool_name,
                source_tool_version=tool_version,
                primitive=algorithm_properties.get("primitive"),
                oid=crypto.get("oid"),
                properties=tuple(
                    (str(p.get("name")), str(p.get("value", "")))
                    for p in (component.get("properties") or ())
                ),
            )
        )
    return tuple(imported)


def exposure_properties_of(asset: ImportedCryptoAsset) -> dict[str, str]:
    """Our own `pramana:exposure:*` properties, read back off an imported
    asset. Only meaningful when the CBOM we are importing is one we wrote --
    which is exactly the round-trip case."""
    prefix = f"{NAMESPACE}:exposure:"
    return {
        name.removeprefix(prefix): value
        for name, value in asset.properties
        if name.startswith(prefix)
    }

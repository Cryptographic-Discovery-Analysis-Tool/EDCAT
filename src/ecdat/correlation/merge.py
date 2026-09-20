"""Within-surface CryptoAsset merge (Final Architecture Part 5 "Asset
resolution (deliberately constrained)").

    "Canonical asset key = (algorithm_family, parameters, purpose,
    scope_anchor) where scope_anchor is per-surface: repo path, image + layer
    digest, host:port, or binary path. Within a surface: merge aggressively
    ... Across surfaces: do not merge. Emit explicit relationship edges
    instead."

This module does ONLY the within-surface half of Part 5: group Findings from
ONE adapter/surface into `CryptoAsset` records. Cross-surface relationship
GENERATION -- the declared/artifact_asserted edges Part 5 also describes
("TLS endpoint -> served by -> container image -> contains -> OpenSSL
package") -- needs topology/context input this module is never given, and is
explicitly out of scope here. `src/ecdat/correlation/gate.py` is the other
half of this phase: a pure check over whatever Relationships an orchestrator
eventually assembles.

Everything the merge key reads comes only from fields a real adapter Finding
actually populates (grounded in `CertificateAdapter._fields()`,
src/ecdat/adapters/certs/adapter.py) -- `purpose` is not one of them (that is
function.classifier's separate job, done later with more context than one
Finding carries), so it is never part of the grouping key and never invented.

`algorithm_family` is deliberately NOT part of the strict grouping-equality
key either, even though Part 5's literal key tuple lists it. See
docs/deviations.md DEV-007 for why: two Findings that disagree on it must
still be able to land in one CryptoAsset with a CONFLICTING field (R-MONOTONE
-- silently reporting "two unrelated, individually-certain assets" instead of
"one asset, disputed field" would manufacture unsupported *distinctness*).
The grouping key here is `(parameters, scope_anchor)`; `algorithm_family`
flows through the same agree/CONFLICT field-merge path as every other field.
"""
from __future__ import annotations

import hashlib
from collections.abc import Iterable
from typing import NamedTuple

from ecdat.model.asset import CryptoAsset
from ecdat.model.epistemic import EpistemicState, Resolution, ResolutionStatus
from ecdat.model.field_value import FieldValue
from ecdat.model.finding import Finding

#: Field names read to build the merge key's algorithm-family/parameters
#: components. Grounded in what an existing adapter actually emits --
#: CertificateAdapter._fields() (src/ecdat/adapters/certs/adapter.py) -- not
#: invented. A future surface's adapter may need its own key-field mapping
#: added here; none is guessed at for a surface that doesn't exist yet.
_ALGORITHM_FAMILY_FIELD = "public_key_algorithm"
_PARAMETER_FIELDS: tuple[str, ...] = ("public_key_size", "public_key_curve")


class MergeKey(NamedTuple):
    """The grouping identity for one CryptoAsset. See module docstring and
    DEV-007 for why `algorithm_family` is read (for the convenience readback
    field) but not included here."""

    parameters: tuple
    scope_anchor: str


def _field_value(finding: Finding, name: str):
    field = finding.fields.get(name)
    return field.value if field is not None else None


def _merge_key(finding: Finding) -> MergeKey:
    parameters = tuple(_field_value(finding, name) for name in _PARAMETER_FIELDS)
    # scope_anchor: naturally the surface string already on the Finding (e.g.
    # "certdir:<root>") -- Part 5: "scope_anchor is per-surface: repo path,
    # image + layer digest, host:port, or binary path." This is what makes
    # cross-surface merging structurally impossible: two Findings with a
    # different `surface` can never land in the same group.
    return MergeKey(parameters=parameters, scope_anchor=finding.surface)


def _parameters_string(parameters: tuple) -> str | None:
    parts = [str(part) for part in parameters if part is not None]
    return "/".join(parts) if parts else None


def _asset_id(key: MergeKey) -> str:
    canonical = f"{key.scope_anchor}|{_parameters_string(key.parameters)}"
    digest = hashlib.sha256(canonical.encode()).hexdigest()[:16]
    return f"asset:{digest}"


def _merge_field(name: str, values: list[FieldValue]) -> FieldValue:
    """Merge one field name across a group of Findings that share a merge key.

    R-MONOTONE (CLAUDE.md): more evidence never manufactures unsupported
    certainty. A field stays a single value only when every contributing
    Finding reports the SAME value under the SAME epistemic state; any
    disagreement -- in the value or in the certainty behind it -- becomes
    CONFLICTING with no value chosen, rather than silently keeping one side's
    answer.
    """
    evidence_refs = tuple(dict.fromkeys(ref for value in values for ref in value.evidence_refs))
    first = values[0]
    all_agree = all(value.value == first.value and value.state == first.state for value in values)

    if all_agree:
        return FieldValue(value=first.value, state=first.state, evidence_refs=evidence_refs)

    distinct_values: list = []
    for value in values:
        if value.value not in distinct_values:
            distinct_values.append(value.value)
    return FieldValue(
        value=None,
        state=EpistemicState.CONFLICTING,
        resolution=Resolution(
            status=ResolutionStatus.UNRESOLVED,
            reason=(
                f"merged Findings within one surface disagree on {name!r}: "
                f"{[str(value) for value in distinct_values]}"
            ),
        ),
        evidence_refs=evidence_refs,
    )


def _plain_readback(fields: dict[str, FieldValue], name: str) -> str | None:
    """Read one field back out as CryptoAsset's plain convenience string,
    only when it is not itself in dispute -- a CONFLICTING field never gets
    silently collapsed into a single string on the asset (R-MONOTONE)."""
    field = fields.get(name)
    if field is None or field.state == EpistemicState.CONFLICTING or field.value is None:
        return None
    return str(field.value)


def merge_within_surface(findings: Iterable[Finding]) -> tuple[CryptoAsset, ...]:
    """Group Findings from ONE adapter/surface into CryptoAsset records.

    Findings from different surfaces (different `finding.surface`, i.e.
    different scope_anchor) NEVER merge, even when algorithm/parameters match
    byte-for-byte: Part 5's "within a surface only" rule is enforced by
    including scope_anchor in the grouping key itself, so a caller cannot
    accidentally defeat it by passing mixed-surface input to this function.

    Cross-surface relationship generation is explicitly out of scope for this
    function; see the module docstring.
    """
    groups: dict[MergeKey, list[Finding]] = {}
    for finding in findings:
        groups.setdefault(_merge_key(finding), []).append(finding)

    assets: list[CryptoAsset] = []
    for key, group in groups.items():
        field_names: dict[str, None] = {}
        for finding in group:
            for name in finding.fields:
                field_names.setdefault(name, None)

        fields: dict[str, FieldValue] = {}
        for name in field_names:
            values = [finding.fields[name] for finding in group if name in finding.fields]
            if values:
                fields[name] = _merge_field(name, values)

        assets.append(
            CryptoAsset(
                asset_id=_asset_id(key),
                scope_anchor=key.scope_anchor,
                algorithm_family=_plain_readback(fields, _ALGORITHM_FAMILY_FIELD),
                parameters=_parameters_string(key.parameters),
                purpose=_plain_readback(fields, "purpose"),
                finding_refs=tuple(finding.finding_id for finding in group),
                fields=fields,
            )
        )

    return tuple(assets)

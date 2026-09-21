"""Agility evidence (build-plan.md P14; DEV-012, OI-018).

Three fields, narrowed from an outside review's proposal after checking what
the adapters already observe:

* `algorithm_selection` -- HARDCODED / CONFIGURATION_DRIVEN / UNKNOWN. The
  source rules already split literal from non-literal at the call site
  (`source-semgrep`'s `_ALGORITHM_LITERAL` vs `_ALGORITHM_NONLITERAL` rules);
  this module only names that split.
* `hybrid_capable` -- KNOWN only when observed. `tls-endpoint`'s own
  `negotiated_group` field, read back under a name a reader does not have to
  already know the ledger's vocabulary to understand.
* `provider_pluggable` -- INFERRED ceiling, never KNOWN. JCA provider
  indirection (`provider_argument`) is readable from source; an actual
  provider registration executing at runtime is not observable from a
  source-only surface, so the claim this field makes is weaker than the text
  it is built from.

Two fields the review proposed are refused, not narrowed:

* `migration_complexity` would be a score, and slide 2's own claim is "no
  weights, no score, no model -- lexicographic order only" (§5.10). Adding it
  here would falsify that claim in exchange for a number nobody can defend.
* a bare boolean `hardcoded` collapses HARDCODED and "we could not tell"
  (UNKNOWN) into one value. Three states or none.

DEV-012 records why none of this goes through `model.field_value.derive()`:
none of the three fields is named in the canonical architecture docs, so no
`rule_id` exists to register and cite. `algorithm_selection` and
`hybrid_capable` are direct relabellings of an already-observed field (same
state, same evidence_refs, no new epistemic content -- the same principle
`model/temporal.py`'s `_earliest()` already applies to selection vs
inference). `provider_pluggable` is a genuine downgrade and is built with
its state capped directly rather than through `derive()`, with
`derived_from` left empty per DEV-012 rather than cited against an invented
rule.
"""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict

from ecdat.model.epistemic import EpistemicState
from ecdat.model.field_value import FieldValue


class AlgorithmSelection(str, Enum):
    """Closed set. UNKNOWN is a real member: a call site with neither
    semgrep rule firing tells us nothing about how the algorithm is chosen,
    and that is a fact, not an omission."""

    HARDCODED = "HARDCODED"
    CONFIGURATION_DRIVEN = "CONFIGURATION_DRIVEN"
    UNKNOWN = "UNKNOWN"


def _unknown_selection() -> FieldValue[AlgorithmSelection]:
    return FieldValue[AlgorithmSelection](value=AlgorithmSelection.UNKNOWN, state=EpistemicState.UNKNOWN)


def algorithm_selection_for(fields: dict[str, FieldValue]) -> FieldValue[AlgorithmSelection]:
    """Reads `source-semgrep`'s own literal/non-literal split and names it.
    Not a derivation: the state and evidence_refs are copied verbatim from
    whichever source field answered the question, because naming an
    already-made observation adds no new epistemic content.

    `_ALGORITHM_LITERAL` fired -> `fields["algorithm"]` is a KNOWN literal
    value with no `algorithm_argument` alongside it -> HARDCODED, sourced
    from `algorithm`'s own state and evidence (the literal capture itself
    is what proves hardcoding; `algorithm_literal_at_call_site` is a
    separate caveat about constant propagation, not this split).

    `_ALGORITHM_NONLITERAL` fired -> `algorithm_argument` is present
    (an argument/variable feeds the call site, whether or not a later
    config-chain resolution succeeds) -> CONFIGURATION_DRIVEN, sourced from
    `algorithm_argument`'s own state and evidence.

    Neither rule fired -> UNKNOWN.
    """
    argument = fields.get("algorithm_argument")
    if argument is not None:
        return FieldValue[AlgorithmSelection](
            value=AlgorithmSelection.CONFIGURATION_DRIVEN,
            state=argument.state,
            evidence_refs=argument.evidence_refs,
        )

    algorithm = fields.get("algorithm")
    literal_flag = fields.get("algorithm_literal_at_call_site")
    if algorithm is not None and algorithm.state == EpistemicState.KNOWN and literal_flag is not None:
        return FieldValue[AlgorithmSelection](
            value=AlgorithmSelection.HARDCODED,
            state=algorithm.state,
            evidence_refs=algorithm.evidence_refs,
        )

    return _unknown_selection()


def hybrid_capable_for(fields: dict[str, FieldValue]) -> FieldValue[bool]:
    """`tls-endpoint`'s `negotiated_group`, read back under this name.
    KNOWN only when a real handshake observed a group (never upgraded from
    a configured cipher list, which would be INFERRED at best); UNKNOWN
    when the negotiation itself was not observed. Direct relabelling, same
    state and evidence_refs as the source field."""
    negotiated = fields.get("negotiated_group")
    if negotiated is None:
        return FieldValue[bool](value=None, state=EpistemicState.UNKNOWN)
    if negotiated.state != EpistemicState.KNOWN or not negotiated.value:
        return FieldValue[bool](
            value=None, state=negotiated.state, evidence_refs=negotiated.evidence_refs
        )
    return FieldValue[bool](
        value=True, state=EpistemicState.KNOWN, evidence_refs=negotiated.evidence_refs
    )


def provider_pluggable_for(fields: dict[str, FieldValue]) -> FieldValue[bool]:
    """DEV-012 / OI-018: a genuine downgrade, built without `derive()`
    because no rule_id exists to cite for it. `provider_argument` observed
    in source (KNOWN: the text is really there) caps here to INFERRED,
    never KNOWN -- a call site that accepts a provider argument does not
    prove a second provider is registered and reachable at runtime, which
    is a weaker claim than what was directly read off the source file."""
    argument = fields.get("provider_argument")
    if argument is None or argument.state == EpistemicState.UNKNOWN:
        return FieldValue[bool](value=None, state=EpistemicState.UNKNOWN)
    return FieldValue[bool](
        value=True,
        state=EpistemicState.INFERRED,
        evidence_refs=argument.evidence_refs,
    )


class AgilityEvidence(BaseModel):
    """The three adopted fields, together, for one asset. Presentation and
    routing convenience only -- each field is independently computable from
    `fields` by the functions above, and this model adds no field of its
    own that is not one of those three."""

    model_config = ConfigDict(frozen=True)

    asset_id: str
    algorithm_selection: FieldValue[AlgorithmSelection]
    hybrid_capable: FieldValue[bool]
    provider_pluggable: FieldValue[bool]


def agility_evidence_for(asset_id: str, fields: dict[str, FieldValue]) -> AgilityEvidence:
    return AgilityEvidence(
        asset_id=asset_id,
        algorithm_selection=algorithm_selection_for(fields),
        hybrid_capable=hybrid_capable_for(fields),
        provider_pluggable=provider_pluggable_for(fields),
    )

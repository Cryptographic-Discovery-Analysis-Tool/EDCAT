"""The evidence graph view (build-plan.md P15; correlation/engine.py's
`CorrelationReport`).

`CorrelationReport` already carries everything a graph needs: the merged
`CryptoAsset`s, the `same-object` `Relationship`s (content_identity,
rule_id=`IDENTITY-CERT-DER-001`), and the SPKI-only pairs that are
deliberately NOT relationships (`shares_public_key_unclaimed` -- OI-006: no
`rule_id` is registered for that claim, so no edge claiming it may be built).
This module is presentation only: it turns that data into nodes and typed,
epistemically-labelled edges. Nothing here infers a new relationship, weighs
one edge over another, or decides what counts as identity -- all of that
already happened in `engine.py` and `gate.py`.

This is also, per engine.py's own module docstring, "the easiest place in
the whole project to draw a lie". Three rules exist here for exactly that
reason and are enforced structurally, not by convention:

1. Every edge renders its `type` and its epistemic basis (`evidence_basis`,
   `epistemic_state` for a claimed edge; an explicit "no registered rule_id"
   note for an unclaimed one) -- `GraphEdge` has no field that lets an edge
   exist without one.
2. `shares_public_key_unclaimed` pairs render as `EdgeStrength.UNCLAIMED`,
   a distinct value from `EdgeStrength.CLAIMED`, and are never merged into
   the same list without that tag -- a renderer cannot collapse them into
   `same-object` without discarding a field it was handed.
3. The review's seven-layer chain names two links this engine refuses to
   draw at all: library -> usage, and service -> protected data. They are
   not rendered as missing lines between real nodes (which would read as
   "nothing to see" -- exactly the false-certainty failure this exists to
   prevent); `EvidenceGraph.gaps` names them, and why, as data a caller must
   actively choose not to show.
"""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict

from ecdat.agility.evidence import AgilityEvidence, agility_evidence_for
from ecdat.correlation.engine import CorrelationReport
from ecdat.model.asset import CryptoAsset
from ecdat.model.relationship import Relationship


class EdgeStrength(str, Enum):
    """How much weight a reader may put on this line. Closed set: a fourth
    value without a registered rule_id behind it would be the over-claim
    this module exists to prevent."""

    CLAIMED = "claimed"
    UNCLAIMED = "unclaimed"


class GraphNode(BaseModel):
    model_config = ConfigDict(frozen=True)

    asset_id: str
    algorithm_family: str | None
    purpose: str | None
    scope_anchor: str | None
    #: build-plan.md P14. Computed from this same asset's `fields`, so a
    #: node's agility evidence is never a separate lookup that could drift
    #: out of step with what correlated it.
    agility: AgilityEvidence


class GraphEdge(BaseModel):
    model_config = ConfigDict(frozen=True)

    source: str
    target: str
    strength: EdgeStrength
    type: str
    evidence_basis: str | None
    rule_id: str | None
    epistemic_state: str | None
    note: str


class GraphGap(BaseModel):
    """A chain link this engine deliberately does not draw between real
    nodes. Named so its absence is legible instead of reading as nothing to
    see."""

    model_config = ConfigDict(frozen=True)

    from_layer: str
    to_layer: str
    why: str


#: The two links from the review's seven-layer chain this engine refuses to
#: draw (correlation/engine.py's own docstring + build-plan.md P15). The two
#: real edges in that chain -- config -> algorithm (P3) and certificate ->
#: service (P4) -- are not listed here: they are genuine, evidenced edges
#: this module already draws from the report itself.
CHAIN_GAPS: tuple[GraphGap, ...] = (
    GraphGap(
        from_layer="library",
        to_layer="usage",
        why=(
            "the package and binary readers refuse to claim usage on purpose "
            "-- package presence is a capability, never usage (CLAUDE.md hard "
            "rule) -- and that refusal is tested"
        ),
    ),
    GraphGap(
        from_layer="service",
        to_layer="protected data",
        why=(
            "the data class is DECLARED by a person, and there is still "
            "nowhere to declare it (correlation phase's open item); drawing "
            "this edge would be false certainty on the one screen a judge is "
            "most likely to photograph"
        ),
    ),
)


def _node(asset: CryptoAsset) -> GraphNode:
    return GraphNode(
        asset_id=asset.asset_id,
        algorithm_family=asset.algorithm_family,
        purpose=asset.purpose,
        scope_anchor=asset.scope_anchor,
        agility=agility_evidence_for(asset.asset_id, asset.fields),
    )


def _claimed_edge(relationship: Relationship) -> GraphEdge:
    return GraphEdge(
        source=relationship.source_entity,
        target=relationship.target_entity,
        strength=EdgeStrength.CLAIMED,
        type=relationship.type,
        evidence_basis=relationship.evidence_basis.value,
        rule_id=relationship.rule_id,
        epistemic_state=relationship.epistemic_state.value,
        note=f"{relationship.type} ({relationship.evidence_basis.value}, rule {relationship.rule_id})",
    )


def _unclaimed_edge(pair: tuple[str, str]) -> GraphEdge:
    source, target = pair
    return GraphEdge(
        source=source,
        target=target,
        strength=EdgeStrength.UNCLAIMED,
        type="shares_public_key_unclaimed",
        evidence_basis=None,
        rule_id=None,
        epistemic_state=None,
        note=(
            "same SPKI hash, different certificate object -- a real signal, "
            "no registered rule_id exists for this claim (OI-006); must not "
            "render as same-object"
        ),
    )


class EvidenceGraph(BaseModel):
    """§7.2's graph view. `edges` mixes both strengths on purpose -- a
    consumer that wants only claimed edges filters on `.strength`, which is
    a smaller mistake to make than never seeing the unclaimed signal at
    all."""

    model_config = ConfigDict(frozen=True)

    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]
    gaps: tuple[GraphGap, ...]

    @property
    def claimed_edges(self) -> tuple[GraphEdge, ...]:
        return tuple(e for e in self.edges if e.strength == EdgeStrength.CLAIMED)

    @property
    def unclaimed_edges(self) -> tuple[GraphEdge, ...]:
        return tuple(e for e in self.edges if e.strength == EdgeStrength.UNCLAIMED)


def build_graph(report: CorrelationReport) -> EvidenceGraph:
    """Turn a `CorrelationReport` into a graph view. Every edge is read off
    a `Relationship` or a `shares_public_key_unclaimed` pair the report
    already carries -- nothing here decides an identity or invents a
    rule_id."""
    return EvidenceGraph(
        nodes=tuple(_node(asset) for asset in report.assets),
        edges=tuple(_claimed_edge(r) for r in report.relationships)
        + tuple(_unclaimed_edge(pair) for pair in report.shares_public_key_unclaimed),
        gaps=CHAIN_GAPS,
    )

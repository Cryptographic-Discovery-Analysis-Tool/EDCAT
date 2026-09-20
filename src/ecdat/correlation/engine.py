"""The correlation engine: one asset view across every adapter that ran.

Ties together the two halves already built this phase --
`merge.py` (within-surface merge) and `gate.py` (the forbidden-edge check) --
with the one piece that was still missing: turning "the same real-world
object was observed on two different surfaces" into an actual
`Relationship`, the way Part 5 says to ("stop trying to prove identity [by
merging] and model relationships instead").

**What this engine does emit.** Cross-surface `same-object` identity, and
ONLY that: two `CryptoAsset`s (from any two surfaces, including two
different runs of the same adapter) whose Findings carry the same
`der_sha256` -- the one hash CLAUDE.md's registry actually has a rule_id
for (`IDENTITY-CERT-DER-001`, TOPO-X3-proven canonicalised-DER identity).
Today that means certs-x509 findings can be linked to other certs-x509
findings (e.g. the same certificate present in two scanned directories, or
bundled two ways in a keystore). No adapter yet exposes a certificate hash
for the TLS-served leaf or an imported CBOM certificate component, so those
surfaces correlate zero relationships today, honestly, rather than being
forced through a weaker signal (e.g. matching on `leaf_subject`, a string,
would be exactly the over-claim R-UNSEEN warns against) -- see
"Deliberately NOT built" below.

**What this engine does NOT emit.** `shares-public-key` relationships
(SPKI hash match): the harness names this identity concept but never gave
it a literal `rule_id` (src/ecdat/rules/registry.py's own comment explains
why none is registered), so no relationship claiming it can be built
without inventing a rule_id from memory -- exactly what CLAUDE.md's
anti-hallucination rules forbid. Any SPKI-only match is reported back to
the caller as a `shares_public_key_unclaimed` note in `CorrelationReport`
instead of being silently dropped or silently asserted.

Declared/artifact_asserted cross-surface edges ("TLS endpoint -> served by
-> container image") are also not built here: they need topology/context
input (which application owns which endpoint, which image) that nothing in
this codebase supplies yet -- `merge.py`'s own docstring says the same
thing about the within-surface half. Wiring that up is context-ingestion
work (Final Architecture Part 6), not a correlation-engine gap.
"""
from __future__ import annotations

from collections.abc import Iterable
from itertools import combinations

from pydantic import BaseModel, ConfigDict

from ecdat.adapters.base import AdapterRunResult
from ecdat.correlation.gate import check_forbidden_edges
from ecdat.correlation.merge import merge_within_surface
from ecdat.model.asset import CryptoAsset
from ecdat.model.epistemic import EpistemicState
from ecdat.model.relationship import EvidenceBasis, Relationship

#: The one identity rule this engine is allowed to act on. See module
#: docstring "What this engine does NOT emit" for why there is only one.
_DER_IDENTITY_RULE_ID = "IDENTITY-CERT-DER-001"
_DER_FIELD = "der_sha256"
_SPKI_FIELD = "spki_sha256"


class CorrelationReport(BaseModel):
    """One asset view: every CryptoAsset merged from every surface that was
    scanned, the Relationships correlating them across surfaces, and enough
    provenance to say which adapters contributed. Frozen, like every other
    record type in this codebase -- a report is a fact about one run, not a
    thing to be edited in place."""

    model_config = ConfigDict(frozen=True)

    assets: tuple[CryptoAsset, ...]
    relationships: tuple[Relationship, ...]
    source_adapter_ids: tuple[str, ...]
    #: Asset id pairs that share an SPKI hash but NOT a DER hash -- a real
    #: signal (same key material, different certificate object) that this
    #: engine deliberately does not turn into a Relationship (see module
    #: docstring). Surfaced here so a caller can decide what, if anything,
    #: to do with it, rather than the signal being silently thrown away.
    shares_public_key_unclaimed: tuple[tuple[str, str], ...] = ()


class ForbiddenEdgeError(RuntimeError):
    """The gate rejected at least one relationship this engine tried to
    emit. Raised rather than silently dropping the bad edge or returning a
    report that looks clean: a correlation engine that could produce a
    forbidden edge and just quietly not mention it would be worse than one
    that never ran, per this project's whole "false certainty is the worst
    possible bug" premise. Every violation string from the gate is
    preserved in `.violations` for the caller to act on."""

    def __init__(self, violations: tuple[str, ...]) -> None:
        super().__init__(
            f"{len(violations)} relationship(s) rejected by the forbidden-edge gate: "
            + "; ".join(violations)
        )
        self.violations = violations


def _hash_groups(assets: tuple[CryptoAsset, ...], field_name: str) -> dict[str, list[CryptoAsset]]:
    """asset id, keyed by every KNOWN, non-empty value of `field_name` any
    of its fields carries. A CONFLICTING or absent hash never participates
    -- R-UNSEEN: an identity claim needs a positively observed hash on both
    sides, not the mere possibility of one."""
    groups: dict[str, list[CryptoAsset]] = {}
    for asset in assets:
        field = asset.fields.get(field_name)
        if field is None or field.state != EpistemicState.KNOWN or not field.value:
            continue
        groups.setdefault(str(field.value), []).append(asset)
    return groups


def _identity_relationships(
    assets: tuple[CryptoAsset, ...],
) -> tuple[tuple[Relationship, ...], tuple[tuple[str, str], ...]]:
    der_groups = _hash_groups(assets, _DER_FIELD)
    spki_groups = _hash_groups(assets, _SPKI_FIELD)

    der_linked_pairs: set[frozenset[str]] = set()
    relationships: list[Relationship] = []
    for der_hash, members in der_groups.items():
        if len(members) < 2:
            continue
        for source, target in combinations(sorted(members, key=lambda a: a.asset_id), 2):
            if source.asset_id == target.asset_id:
                continue
            der_linked_pairs.add(frozenset({source.asset_id, target.asset_id}))
            evidence_refs = tuple(
                dict.fromkeys(
                    (*source.fields[_DER_FIELD].evidence_refs, *target.fields[_DER_FIELD].evidence_refs)
                )
            )
            relationships.append(
                Relationship(
                    type="same-object",
                    source_entity=source.asset_id,
                    target_entity=target.asset_id,
                    evidence_basis=EvidenceBasis.CONTENT_IDENTITY,
                    epistemic_state=EpistemicState.KNOWN,
                    rule_id=_DER_IDENTITY_RULE_ID,
                    evidence_refs=evidence_refs,
                )
            )

    # SPKI-only matches: same key, different certificate object -- a real
    # signal, deliberately not promoted to a Relationship (module docstring).
    unclaimed: list[tuple[str, str]] = []
    for members in spki_groups.values():
        if len(members) < 2:
            continue
        for source, target in combinations(sorted(members, key=lambda a: a.asset_id), 2):
            pair = frozenset({source.asset_id, target.asset_id})
            if pair in der_linked_pairs or source.asset_id == target.asset_id:
                continue
            unclaimed.append(tuple(sorted((source.asset_id, target.asset_id))))

    return tuple(relationships), tuple(dict.fromkeys(unclaimed))


def correlate(results: Iterable[AdapterRunResult]) -> CorrelationReport:
    """Build one asset view from every adapter result handed in.

    Takes `AdapterRunResult`s directly (not run documents) so this is the
    natural function an orchestrator calls right after running N adapters in
    one process, with no lossy JSON round-trip in between. `ecdat correlate`
    (cli.py) is the command-line front end over exactly this function.
    """
    results = tuple(results)
    all_findings = [finding for result in results for finding in result.findings]
    assets = merge_within_surface(all_findings)
    relationships, unclaimed = _identity_relationships(assets)

    violations = check_forbidden_edges(relationships)
    if violations:
        raise ForbiddenEdgeError(violations)

    return CorrelationReport(
        assets=assets,
        relationships=relationships,
        source_adapter_ids=tuple(sorted({result.adapter_id for result in results})),
        shares_public_key_unclaimed=unclaimed,
    )

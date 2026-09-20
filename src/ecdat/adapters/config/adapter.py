"""Config-chain adapter wrapper (P3; CFG-001, harness §14).

Wraps `resolver.resolve()` and `spring.gather()` -- both already complete and
already tested against §14.3's eight states -- in the `Adapter` contract every
other observation surface implements, so a config-chain answer can be
produced by `Adapter.run()` like any other adapter's, and slot into the same
orchestration and visibility machinery.

**What this adapter does not do, deliberately.** It does not discover which
property keys matter: that is upstream work (a source-surface adapter reading
`@ConfigurationProperties` / `@Value` bindings out of Java source) and stays
out of scope here, exactly as `CertificateAdapter` takes `keystore_password`
as an injected input rather than discovering it itself. `property_keys` is
supplied by the caller for the same reason.

**Never KNOWN.** `EffectiveConfigurationInference.epistemic_state` is
restricted at the model layer to INFERRED, CONFLICTING or UNKNOWN --
"reading files is not watching a process" (resolver.py). The fields on the
`Finding` this adapter emits for the *effective* value (`resolved_value`,
`source_kind`, `source_location`) carry that same state and resolution
straight through, unmodified: this module adds no certainty the resolver
itself did not already establish. `rule_applied`, `sources_inspected`,
`higher_precedence_not_inspected` and `losing_candidates` are a different
kind of claim -- facts about what this adapter itself read and ran, not
claims about the target's effective configuration -- and are KNOWN.
"""
from __future__ import annotations

import hashlib
from datetime import datetime
from pathlib import Path
from typing import Callable

from ecdat.adapters.base import (
    Adapter,
    AdapterOutcome,
    AdapterRunResult,
    Coverage,
    RawCapture,
    ScanTarget,
)
from ecdat.adapters.config.resolver import NOT_INSPECTABLE_STATICALLY, resolve
from ecdat.adapters.config.spring import Gathered, gather
from ecdat.model.configuration import EffectiveConfigurationInference
from ecdat.model.epistemic import EpistemicState
from ecdat.model.evidence import ConfidenceBasis, Evidence
from ecdat.model.field_value import FieldValue
from ecdat.model.finding import Finding
from ecdat.model.topology import ObservationContext
from ecdat.model.visibility import SupportLevel, VisibilityDimension, VisibilityEntry
from ecdat.security.secrets import scan_for_secrets

#: There is no external tool here -- this is a static analysis this codebase
#: performs on itself -- so `source_tool` names the resolver module rather
#: than a third-party binary, and `tool_version` is a stable string for this
#: module rather than something read off a subprocess.
_TOOL_NAME = "ecdat-config-resolver"
_TOOL_VERSION = "1"


class ConfigChainAdapter(Adapter):
    adapter_id = "config-chain-spring"

    #: PARTIAL, not FULL: CFG-001 explicitly scopes OUT Consul, Vault, cloud
    #: secret managers, Spring Cloud Config, JNDI, cross-repo config and
    #: reflection. This is a partial reader by design, not a cautious default.
    support_level = SupportLevel.PARTIAL
    dimensions = (VisibilityDimension.CONFIGURATION,)

    def __init__(
        self,
        *,
        property_keys: tuple[str, ...],
        base_confidence: float,
        confidence_basis: ConfidenceBasis,
        declared_images: frozenset[str] = frozenset(),
        active_profile: str | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        super().__init__(**({"clock": clock} if clock else {}))
        self._property_keys = property_keys
        self._base_confidence = base_confidence
        self._confidence_basis = confidence_basis
        self._declared_images = declared_images
        self._active_profile = active_profile

    # --- emission --------------------------------------------------------------

    @staticmethod
    def _serialise_losing(candidates) -> tuple[str, ...]:
        """A short, honest string per losing candidate. Not the primary claim
        -- the primary claim is `resolved_value` -- so this is a display
        convenience over the same objects, not a new source of truth."""
        return tuple(
            f"{candidate.source_kind.value}@{candidate.source_location}={candidate.value}"
            for candidate in candidates
        )

    def _fields(
        self,
        inference: EffectiveConfigurationInference,
        evidence_refs: tuple[str, ...],
    ) -> dict[str, FieldValue]:
        winning = inference.winning_candidate

        # resolved_value / source_kind / source_location carry the
        # resolver's own epistemic_state and resolution verbatim: this is
        # the claim the model layer already refuses to let be KNOWN, and
        # this adapter must not launder that refusal away.
        def effective(value) -> FieldValue:
            return FieldValue(
                value=value,
                state=inference.epistemic_state,
                resolution=inference.resolution,
                evidence_refs=evidence_refs,
            )

        def known(value) -> FieldValue:
            return FieldValue(value=value, state=EpistemicState.KNOWN, evidence_refs=evidence_refs)

        return {
            "resolved_value": effective(winning.value if winning else None),
            "source_kind": effective(winning.source_kind.value if winning else None),
            "source_location": effective(winning.source_location if winning else None),
            # A fact about which rule this adapter ran, not a claim about the
            # target -- KNOWN is correct here specifically.
            "rule_applied": known(inference.rule_applied),
            "sources_inspected": known(inference.sources_inspected),
            "higher_precedence_not_inspected": known(inference.higher_precedence_not_inspected),
            "losing_candidates": known(self._serialise_losing(inference.losing_candidates)),
        }

    def _scan(self, target: ScanTarget) -> AdapterRunResult:
        root = Path(target.locator)
        observed_at = self._clock()

        if not root.exists():
            raise FileNotFoundError(target.locator)

        per_key: list[tuple[str, Gathered, EffectiveConfigurationInference]] = []
        ordered_sources: list[str] = []
        seen_sources: set[str] = set()

        for property_key in self._property_keys:
            gathered = gather(root, property_key, declared_images=self._declared_images)
            candidates, blockers, sources_inspected = gathered.as_tuples()
            inference = resolve(
                property_key,
                candidates,
                blockers=blockers,
                sources_inspected=sources_inspected,
                active_profile=self._active_profile,
            )
            per_key.append((property_key, gathered, inference))
            for source in sources_inspected:
                if source not in seen_sources:
                    seen_sources.add(source)
                    ordered_sources.append(source)

        # --- raw captures: one per file actually read, hashed for real. A
        # `sources_inspected` entry for external config data carries an
        # annotation ("path (ConfigMap name/file)") after the real path --
        # the annotation is kept as the raw_ref (it is the fact we recorded),
        # but the bytes are read from the path portion alone.
        raw_captures: list[RawCapture] = []
        for source in ordered_sources:
            real_path = Path(source.split(" (", 1)[0])
            raw_captures.append(
                RawCapture(
                    raw_ref=source,
                    source_tool=_TOOL_NAME,
                    tool_version=_TOOL_VERSION,
                    sha256=hashlib.sha256(real_path.read_bytes()).hexdigest(),
                    captured_at=observed_at,
                )
            )
        raw_ref_available = seen_sources

        evidence: list[Evidence] = []
        findings: list[Finding] = []

        for property_key, gathered, inference in per_key:
            winning = inference.winning_candidate
            if winning is not None:
                raw_ref = winning.source_location
            elif gathered.sources_inspected:
                raw_ref = gathered.sources_inspected[0]
            else:
                # Nothing was read at all for this key (e.g. no config-data,
                # manifest or Helm file anywhere under root touched it): there
                # is no raw material to cite, so this key's finding carries no
                # evidence rather than one fabricated to satisfy the shape.
                raw_ref = None

            evidence_refs: tuple[str, ...] = ()
            if raw_ref is not None and raw_ref in raw_ref_available:
                evidence_id = f"{self.adapter_id}:{len(evidence)}"
                evidence.append(
                    Evidence(
                        evidence_id=evidence_id,
                        source_tool=_TOOL_NAME,
                        tool_version=_TOOL_VERSION,
                        location=f"{root}:{property_key}",
                        base_confidence=self._base_confidence,
                        confidence_basis=self._confidence_basis,
                        raw_ref=raw_ref,
                    )
                )
                evidence_refs = (evidence_id,)

            surface = f"config:{root}:{property_key}"
            findings.append(
                Finding(
                    finding_id=f"{self.adapter_id}:{surface}",
                    surface=surface,
                    evidence_refs=evidence_refs,
                    fields=self._fields(inference, evidence_refs),
                )
            )

        # `root` itself is always recorded as scanned: gather() inspects the
        # repository for config-data, manifest and Helm sources whether or
        # not any exist, and a property key resolving to nothing is "scanned,
        # found nothing", never "never looked" (base.py's TRAP-07 guard).
        scanned = (str(root), *ordered_sources)

        detail = (
            f"{target.target_id}: resolved {len(self._property_keys)} property key(s) under "
            f"{root} against Spring config-data files, Kubernetes Deployment manifests and "
            "same-repository ConfigMaps; Helm values are detected, never rendered. PARTIAL by "
            "design (CFG-001): Consul, Vault, cloud secret managers, Spring Cloud Config, JNDI, "
            "cross-repo config and reflection are out of scope. Command-line arguments, system "
            "properties and SPRING_APPLICATION_JSON are only detected, never parsed -- their "
            "mere presence degrades a result to UNRESOLVED rather than being resolved (A1). Not "
            "inspectable statically at all: " + "; ".join(NOT_INSPECTABLE_STATICALLY) + "."
        )

        result = AdapterRunResult(
            adapter_id=self.adapter_id,
            support_level=self.support_level,
            target=target,
            outcome=AdapterOutcome.COMPLETED,
            context=ObservationContext(observed_at=observed_at),
            coverage=Coverage(scanned=scanned),
            visibility=(
                VisibilityEntry(
                    dimension=VisibilityDimension.CONFIGURATION,
                    support_level=self.support_level,
                    detail=detail,
                ),
            ),
            raw_captures=tuple(raw_captures),
            evidence=tuple(evidence),
            findings=tuple(findings),
        )

        scan_for_secrets(
            result.model_dump_json(), context=f"{self.adapter_id} result for {target.target_id}"
        )
        return result

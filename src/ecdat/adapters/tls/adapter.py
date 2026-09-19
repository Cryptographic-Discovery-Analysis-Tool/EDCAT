"""TLS endpoint adapter (P4; spec §3 row "TLS", §7.1 P4).

Produces the ledger's most important input: whether a surface still accepts
classical key establishment, and what it negotiates when offered everything.

**Two probes, because one tool cannot answer both questions** (see
`parser.py`): sslyze enumerates what is accepted and returns the certificate
chain; an `openssl s_client` on OpenSSL 3.5+ reports the negotiated group,
which sslyze structurally cannot see. Both run as SEPARATE PROCESSES -- for
sslyze that is also the AGPL-3.0 boundary the stack decision relies on
(spec §3: "separate process, optional adapter").

**Probe identity is recorded, not assumed.** Lock §5 row 1 and CLAUDE.md both
require the allow-list, the consent flag and the vantage per probe; the base
`ScanTarget` refuses a probe target without consent, and every finding here
carries the SNI that was sent and the vantage it was sent from. Two scans of
"the same host" from different vantages are different observations and are
kept apart.

**The visibility entry states what the probe could not see.** When only sslyze
runs, the entry says so in words: its curve list is evidence about the curves
nassl knows and says nothing about hybrid groups. That sentence is the whole
reason this project has a visibility matrix.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date, datetime
from typing import Callable

from ecdat.adapters.base import (
    Adapter,
    AdapterContractError,
    AdapterOutcome,
    AdapterRunResult,
    Coverage,
    RawCapture,
    ScanTarget,
)
from ecdat.adapters.tls.parser import (
    NASSL_KEY_TYPES,
    NegotiatedHandshake,
    SslyzeObservation,
    parse_negotiated,
    parse_sslyze,
)
from ecdat.model.epistemic import EpistemicState
from ecdat.model.evidence import ConfidenceBasis, Evidence
from ecdat.model.field_value import FieldValue
from ecdat.model.finding import Finding
from ecdat.model.temporal import MigrationEvidence
from ecdat.model.topology import ObservationContext
from ecdat.model.visibility import SupportLevel, VisibilityDimension, VisibilityEntry
from ecdat.security.secrets import scan_for_secrets

#: The sentence the visibility matrix carries whenever sslyze's curve list is
#: the only group evidence available. Stated once, so it cannot drift.
NASSL_CEILING_NOTE = (
    "sslyze's TLS stack (nassl) knows only these key types: "
    + ", ".join(sorted(NASSL_KEY_TYPES))
    + ". It therefore cannot report a hybrid post-quantum group even when one "
    "is negotiated; its curve list is evidence about the curves it knows and "
    "says nothing about the ones it does not. See OI-017."
)


@dataclass(frozen=True)
class TlsProbeBundle:
    """Raw output of the probes for one endpoint, before parsing.

    `classical_only` is optional but is what proves a migration is real: an
    endpoint that negotiates a hybrid group AND still completes a handshake
    when offered only classical has not stopped anything (§5.7).
    """

    sslyze_json: str | None = None
    negotiated_text: str | None = None
    classical_only_text: str | None = None


#: A callable that runs the probes. Injected so that tests replay recorded
#: output and so the subprocess boundary is explicit rather than buried.
ProbeRunner = Callable[[ScanTarget], TlsProbeBundle]


class TlsEndpointAdapter(Adapter):
    adapter_id = "tls-endpoint"

    #: PARTIAL and not FULL, for a reason that is measured rather than
    #: cautious: no probe here enumerates every group an endpoint would
    #: accept. We learn what it negotiated, and whether classical still works.
    support_level = SupportLevel.PARTIAL
    dimensions = (VisibilityDimension.NETWORK,)

    def __init__(
        self,
        *,
        base_confidence: float,
        confidence_basis: ConfidenceBasis,
        probe_runner: ProbeRunner,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        super().__init__(**({"clock": clock} if clock else {}))
        self._base_confidence = base_confidence
        self._confidence_basis = confidence_basis
        self._probe_runner = probe_runner

    # --- emission ------------------------------------------------------------

    @staticmethod
    def _known(value, evidence_id: str) -> FieldValue:
        return FieldValue(
            value=value, state=EpistemicState.KNOWN, evidence_refs=(evidence_id,)
        )

    @staticmethod
    def _unknown() -> FieldValue:
        return FieldValue(value=None, state=EpistemicState.UNKNOWN)

    def _scan(self, target: ScanTarget) -> AdapterRunResult:
        if target.probe is None:
            raise AdapterContractError(
                f"{self.adapter_id} requires a ScanTarget with a ProbeTargetIdentity "
                "(Lock §5 row 1: requested host, port, SNI and vantage are recorded "
                "per probe)"
            )

        observed_at = self._clock()
        bundle = self._probe_runner(target)
        probe = target.probe

        sslyze: SslyzeObservation | None = None
        negotiated: NegotiatedHandshake | None = None
        classical: NegotiatedHandshake | None = None
        scanned: list[str] = []
        skipped: list[str] = []
        evidence: list[Evidence] = []
        raw_captures: list[RawCapture] = []

        def capture(raw_ref: str, tool: str, version: str, payload: str) -> str:
            import hashlib

            raw_captures.append(
                RawCapture(
                    raw_ref=raw_ref,
                    source_tool=tool,
                    tool_version=version,
                    sha256=hashlib.sha256(payload.encode("utf-8")).hexdigest(),
                    captured_at=observed_at,
                )
            )
            evidence_id = f"{self.adapter_id}:{len(evidence)}"
            evidence.append(
                Evidence(
                    evidence_id=evidence_id,
                    source_tool=tool,
                    tool_version=version,
                    location=f"{probe.requested_host}:{probe.port}",
                    base_confidence=self._base_confidence,
                    confidence_basis=self._confidence_basis,
                    raw_ref=raw_ref,
                )
            )
            return evidence_id

        sslyze_evidence = None
        if bundle.sslyze_json:
            sslyze = parse_sslyze(json.loads(bundle.sslyze_json))
            sslyze_evidence = capture(
                f"sslyze://{probe.requested_host}:{probe.port}",
                "sslyze",
                sslyze.sslyze_version or "unknown",
                bundle.sslyze_json,
            )
            scanned.append(f"sslyze {probe.requested_host}:{probe.port}")
        else:
            skipped.append("sslyze: not run for this target")

        negotiated_evidence = None
        if bundle.negotiated_text:
            negotiated = parse_negotiated(bundle.negotiated_text)
            negotiated_evidence = capture(
                f"openssl-s_client://{probe.requested_host}:{probe.port}",
                "openssl s_client",
                "3.5.8",
                bundle.negotiated_text,
            )
            scanned.append(f"openssl s_client {probe.requested_host}:{probe.port}")
        else:
            skipped.append(
                "openssl s_client: not run -- the negotiated group is unobserved, "
                "so no migration evidence can be produced for this endpoint"
            )

        classical_evidence = None
        if bundle.classical_only_text:
            classical = parse_negotiated(bundle.classical_only_text)
            classical_evidence = capture(
                f"openssl-s_client-classical://{probe.requested_host}:{probe.port}",
                "openssl s_client",
                "3.5.8",
                bundle.classical_only_text,
            )
            scanned.append(f"openssl s_client (classical only) {probe.requested_host}:{probe.port}")
        else:
            skipped.append(
                "classical-only probe: not run -- whether classical key "
                "establishment is still accepted is unobserved (§5.7)"
            )

        surface = f"tls:{probe.requested_host}:{probe.port}"
        fields: dict[str, FieldValue] = {
            "requested_host": self._known(probe.requested_host, sslyze_evidence or negotiated_evidence or ""),
            "port": self._known(probe.port, sslyze_evidence or negotiated_evidence or ""),
            "sni_sent": (
                self._known(probe.sni_sent, sslyze_evidence or negotiated_evidence or "")
                if probe.sni_sent
                else self._unknown()
            ),
            "probe_vantage": self._known(
                probe.probe_vantage, sslyze_evidence or negotiated_evidence or ""
            ),
        }

        if negotiated is not None and negotiated_evidence:
            fields["negotiated_protocol"] = self._known(negotiated.protocol, negotiated_evidence)
            fields["negotiated_cipher_suite"] = self._known(
                negotiated.cipher_suite, negotiated_evidence
            )
            fields["negotiated_group"] = self._known(negotiated.group, negotiated_evidence)
            fields["negotiated_group_source"] = self._known(
                negotiated.group_source, negotiated_evidence
            )
            fields["peer_signature_type"] = self._known(
                negotiated.signature_type, negotiated_evidence
            )
        else:
            fields["negotiated_group"] = self._unknown()

        if classical is not None and classical_evidence:
            fields["classical_still_accepted"] = self._known(
                classical.established, classical_evidence
            )
            fields["classical_group"] = self._known(classical.group, classical_evidence)
        else:
            fields["classical_still_accepted"] = self._unknown()

        if sslyze is not None and sslyze_evidence:
            for command, suites in sslyze.accepted_cipher_suites.items():
                fields[f"accepted_{command}"] = self._known(suites, sslyze_evidence)
            fields["supported_curves"] = self._known(sslyze.supported_curves, sslyze_evidence)
            if sslyze.leaf_fingerprint_sha256:
                fields["leaf_fingerprint_sha256"] = self._known(
                    sslyze.leaf_fingerprint_sha256, sslyze_evidence
                )
                fields["leaf_subject"] = self._known(sslyze.leaf_subject, sslyze_evidence)
                fields["chain_subjects"] = self._known(sslyze.chain_subjects, sslyze_evidence)

        detail = (
            f"{target.target_id}: probed {probe.requested_host}:{probe.port} "
            f"(SNI {probe.sni_sent or 'none'}) from vantage {probe.probe_vantage}. "
        )
        if negotiated is None:
            detail += "Negotiated group NOT observed. " + NASSL_CEILING_NOTE
        elif sslyze is not None:
            detail += (
                f"Negotiated group {negotiated.group!r} came from openssl s_client, "
                "not from sslyze. " + NASSL_CEILING_NOTE
            )

        result = AdapterRunResult(
            adapter_id=self.adapter_id,
            support_level=self.support_level,
            target=target,
            outcome=AdapterOutcome.COMPLETED,
            context=ObservationContext(observed_at=observed_at),
            coverage=Coverage(scanned=tuple(scanned), skipped=tuple(skipped)),
            visibility=(
                VisibilityEntry(
                    dimension=VisibilityDimension.NETWORK,
                    support_level=self.support_level,
                    detail=detail,
                ),
            ),
            raw_captures=tuple(raw_captures),
            evidence=tuple(evidence),
            findings=(
                (
                    Finding(
                        finding_id=f"{self.adapter_id}:{surface}",
                        surface=surface,
                        evidence_refs=tuple(e.evidence_id for e in evidence),
                        fields=fields,
                    ),
                )
                if scanned
                else ()
            ),
        )
        scan_for_secrets(
            result.model_dump_json(), context=f"{self.adapter_id} result for {target.target_id}"
        )
        return result


# --- the bridge to the ledger -------------------------------------------------


def migration_evidence_from(
    result: AdapterRunResult, *, observed_on: date
) -> MigrationEvidence | None:
    """Turn a completed TLS probe into §5.7 migration evidence.

    Returns None when the negotiated group was not observed: a missing
    observation must not become a MigrationEvidence with a default, because
    the only thing MigrationEvidence is used for is deciding whether a clock
    stops.

    The clock-stopping rule is enforced by the model, not here:
    `MigrationEvidence.stops_the_clock` is true only when `status` is KNOWN and
    `classical_still_accepted` is false. This function's job is to report both
    faithfully, including the awkward case -- a hybrid group negotiated while
    classical still works, which stops nothing.
    """
    if not result.findings:
        return None
    finding = result.findings[0]
    group = finding.fields.get("negotiated_group")
    if group is None or group.state != EpistemicState.KNOWN or group.value is None:
        return None

    classical = finding.fields.get("classical_still_accepted")
    if classical is None or classical.state != EpistemicState.KNOWN:
        # We saw what it negotiated but never tested whether classical still
        # works. Conservative and honest: assume it does, so the clock keeps
        # running until someone actually checks.
        classical_accepted = True
        status = EpistemicState.INFERRED
    else:
        classical_accepted = bool(classical.value)
        status = EpistemicState.KNOWN

    probe = result.target.probe
    return MigrationEvidence(
        surface_id=finding.surface,
        vantage=probe.probe_vantage if probe else "unknown",
        observed_at=observed_on,
        negotiated_group=group.value,
        classical_still_accepted=classical_accepted,
        status=status,
        evidence_refs=tuple(e.evidence_id for e in result.evidence),
    )

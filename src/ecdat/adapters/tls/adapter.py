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

**DEV-013 adds a third probe shape: one `openssl s_client` per named group.**
The full-offer probe above (`negotiated_text`) answers "what does this
endpoint PREFER when everything is on the table" -- exactly one group, per
handshake. It does not answer "does this endpoint also ACCEPT
SecP256r1MLKEM768", because that group was never the only thing offered. The
per-group probe path (`TlsProbeBundle.group_probe_texts`) offers ONE named
group per handshake and records whether it was accepted, for every hybrid
group `data/crypto_families.yaml` knows about plus a small classical control
set -- see `parser.py`'s "individual group probes" section and
`tests/fixtures/recorded/openssl/3.5.4/hybrid_groups_probe/README.md` for the
real recordings this was built and tested against.

This needs an `openssl` CLI new enough to negotiate a hybrid group at all
(3.5+; ML-KEM hybrid support did not exist before that series). The machine
running the adapter may have an OLDER `openssl` on `PATH`, or none, or a
different one may be configured via `ECDAT_OPENSSL_BIN` -- `live_probe_runner`
checks `openssl version` at runtime and refuses to guess: below 3.5, or
missing, the group-probe fields are reported UNKNOWN with a visibility note
naming the version it found, never silently skipped and never assumed
capable.
"""
from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Callable

from ecdat.adapters.base import (
    Adapter,
    AdapterContractError,
    AdapterRunResult,
    AdapterOutcome,
    AdapterTimeout,
    Coverage,
    RawCapture,
    ScanTarget,
)
from ecdat.adapters.tls.parser import (
    NASSL_KEY_TYPES,
    MIN_OPENSSL_VERSION,
    NegotiatedHandshake,
    SslyzeObservation,
    meets_min_openssl_version,
    parse_group_probe,
    parse_negotiated,
    parse_sslyze,
)
from ecdat.data.crypto_families import (
    canonical_family,
    classical_control_groups,
    hybrid_group_codepoint,
    hybrid_groups as cited_hybrid_groups,
    is_deprecated_hybrid_group,
    is_hybrid_group,
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

    `group_probe_texts` (DEV-013) is one `openssl s_client -groups <G> -brief`
    recording per named group, keyed by that group's name exactly as offered
    -- present only for groups an openssl new enough to negotiate them was
    actually asked about. `group_probe_openssl_version` is that binary's own
    `openssl version` output, carried alongside so the adapter can cite the
    exact tool version on every derived field instead of a constant; when
    `group_probe_texts` is empty, `group_probe_unavailable_reason` says why
    (no binary new enough, or none found) so the adapter can report UNKNOWN
    with a visibility note rather than silently emitting nothing.
    """

    sslyze_json: str | None = None
    negotiated_text: str | None = None
    classical_only_text: str | None = None
    group_probe_texts: dict[str, str] = field(default_factory=dict)
    group_probe_openssl_version: str | None = None
    group_probe_unavailable_reason: str | None = None


#: A callable that runs the probes. Injected so that tests replay recorded
#: output and so the subprocess boundary is explicit rather than buried.
ProbeRunner = Callable[[ScanTarget], TlsProbeBundle]


def default_group_probe_list() -> tuple[str, ...]:
    """Every group the group-probe path asks about by default: every hybrid
    group `data/crypto_families.yaml` cites (standardised and deprecated
    alike -- a deprecated group not being probed would silently stop this
    adapter from ever observing one again) plus a small classical control
    set from the same registry. Sourced from the registry, not written here
    as literals, so a new RFC-cited group is picked up with a data change,
    not a code change."""
    return tuple(sorted(cited_hybrid_groups())) + classical_control_groups()


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

    @staticmethod
    def _known_multi(value, evidence_ids: tuple[str, ...]) -> FieldValue:
        return FieldValue(
            value=value, state=EpistemicState.KNOWN, evidence_refs=tuple(evidence_ids)
        )

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

        # --- individual group probes (DEV-013; OI-016/OI-017 resolution) ---
        #
        # Answers a question neither sslyze nor the full-offer probe above
        # can: does this endpoint ACCEPT a given hybrid group, not just
        # which one it PREFERS. One capture per group, so a reader can see
        # exactly which groups were asked about and what each one answered.
        # Captured here, BEFORE the main `fields` dict below, so its evidence
        # ids are available as a fallback for requested_host/port/etc. when
        # this is the only probe that ran for a target.
        accepted_groups: list[str] = []
        group_evidence_ids: list[str] = []
        deprecated_accepted: list[str] = []
        group_probe_fields: dict[str, FieldValue] = {}
        if bundle.group_probe_texts:
            tool_version = bundle.group_probe_openssl_version or "unknown"
            for group in sorted(bundle.group_probe_texts):
                text = bundle.group_probe_texts[group]
                probe_result = parse_group_probe(group, text, canonicalize=canonical_family)
                evidence_id = capture(
                    f"openssl-s_client-group-{group}://{probe.requested_host}:{probe.port}",
                    "openssl s_client",
                    tool_version,
                    text,
                )
                group_evidence_ids.append(evidence_id)
                group_probe_fields[f"group_accepted_{group}"] = self._known(
                    probe_result.accepted, evidence_id
                )
                codepoint = hybrid_group_codepoint(group)
                if codepoint is not None:
                    group_probe_fields[f"group_codepoint_{group}"] = self._known(
                        codepoint, evidence_id
                    )
                if probe_result.accepted:
                    accepted_groups.append(group)
                    if is_deprecated_hybrid_group(group):
                        deprecated_accepted.append(group)
            scanned.append(
                f"openssl s_client group-probe ({len(bundle.group_probe_texts)} groups) "
                f"{probe.requested_host}:{probe.port}"
            )
        elif bundle.group_probe_unavailable_reason:
            skipped.append(
                "group probe: not run -- " + bundle.group_probe_unavailable_reason
            )
        else:
            skipped.append("group probe: not run for this target")

        _fallback_evidence = (
            sslyze_evidence
            or negotiated_evidence
            or (group_evidence_ids[0] if group_evidence_ids else "")
        )
        surface = f"tls:{probe.requested_host}:{probe.port}"
        fields: dict[str, FieldValue] = {
            "requested_host": self._known(probe.requested_host, _fallback_evidence),
            "port": self._known(probe.port, _fallback_evidence),
            "sni_sent": (
                self._known(probe.sni_sent, _fallback_evidence)
                if probe.sni_sent
                else self._unknown()
            ),
            "probe_vantage": self._known(probe.probe_vantage, _fallback_evidence),
        }
        fields.update(group_probe_fields)
        if bundle.group_probe_texts:
            fields["group_probe_accepted_groups"] = self._known_multi(
                tuple(accepted_groups), tuple(group_evidence_ids)
            )
            hybrid_accepted = tuple(g for g in accepted_groups if is_hybrid_group(g))
            fields["hybrid_kex_supported"] = self._known_multi(
                bool(hybrid_accepted), tuple(group_evidence_ids)
            )
            if hybrid_accepted:
                fields["hybrid_kex_accepted_groups"] = self._known_multi(
                    hybrid_accepted, tuple(group_evidence_ids)
                )
            if deprecated_accepted:
                fields["hybrid_kex_deprecated_groups_accepted"] = self._known_multi(
                    tuple(deprecated_accepted), tuple(group_evidence_ids)
                )
        elif bundle.group_probe_unavailable_reason:
            fields["hybrid_kex_supported"] = self._unknown()

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
            if sslyze.leaf_subject:
                fields["leaf_subject"] = self._known(sslyze.leaf_subject, sslyze_evidence)
                fields["chain_subjects"] = self._known(sslyze.chain_subjects, sslyze_evidence)
                # Named identically to certs-x509's own fields (not
                # "leaf_der_sha256") so correlation/engine.py's cross-surface
                # identity match -- which looks for a field literally named
                # der_sha256/spki_sha256 -- picks this Finding up with no
                # engine change: same field name, same canonicalisation
                # pipeline (parser.py), genuinely the same claim.
                if sslyze.leaf_der_sha256:
                    fields["der_sha256"] = self._known(sslyze.leaf_der_sha256, sslyze_evidence)
                    fields["spki_sha256"] = self._known(sslyze.leaf_spki_sha256, sslyze_evidence)
                else:
                    fields["der_sha256"] = self._unknown()

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

        if bundle.group_probe_texts:
            detail += (
                f" Individual-group probe: {len(accepted_groups)}/"
                f"{len(bundle.group_probe_texts)} groups accepted "
                f"({', '.join(accepted_groups) or 'none'})."
            )
            if deprecated_accepted:
                detail += (
                    " DEPRECATED hybrid group(s) accepted: "
                    f"{', '.join(deprecated_accepted)} -- pre-standardisation, "
                    "obsoleted by RFC 10024 (see docs/sources/"
                    "IANA_TLS_SupportedGroups_2026.md). Migration credit for "
                    "this endpoint should not be read as 'on the standard "
                    "track' from this group alone."
                )
        elif bundle.group_probe_unavailable_reason:
            detail += " Individual-group probe NOT run: " + bundle.group_probe_unavailable_reason

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


# --- live invocation: the group-probe path (DEV-013) ------------------------
#
# CLAUDE.md: "Every adapter MUST be able to invoke its tool (subprocess) on a
# real target path, with pinned flags, per-target timeout, and network
# egress disabled [as a deployment control]." Before DEV-013 the TLS
# adapter had no live path at all -- `cli.py::_build_tls` refuses `--live`
# outright and points at `tools/prober/` instead, because sslyze's own live
# wiring (the AGPL-3.0 separate-process boundary in spec §3) is a larger,
# still-open piece of work this change does not attempt. What follows is
# scoped to exactly what DEV-013 adds: the individual `openssl s_client`
# group probes, real subprocess and all, mirroring the injection pattern
# `hsm.adapter.live_probe_runner` already established (small dataclass of
# raw text is the seam; a factory builds a callable that shells out; tests
# never call the factory, only the pure argv builders and the parser).

#: Env var naming an `openssl` binary to use instead of bare `openssl` on
#: PATH -- the exact "configurable path/env var" the background for this
#: change calls for, because the interpreter's OWN linked OpenSSL (whatever
#: `ssl.OPENSSL_VERSION` is) is not what any of this shells out to, and on a
#: machine with more than one `openssl` on PATH the caller may need to name
#: a specific one.
OPENSSL_BIN_ENV_VAR = "ECDAT_OPENSSL_BIN"

DEFAULT_GROUP_PROBE_TIMEOUT_SECONDS = 10

#: Output-size cap per subprocess call, matching the other live adapters
#: (hsm/packages/images) -- a `-brief` handshake transcript is at most a few
#: hundred bytes; anything past this is not a handshake transcript.
MAX_GROUP_PROBE_OUTPUT_BYTES = 1 * 1024 * 1024


class TlsProbeInvocationError(RuntimeError):
    """`openssl` could not be run, or ran and produced something this
    module refuses to trust (oversized output, non-zero from `version`)."""


def resolve_openssl_bin(*, openssl_bin: str | None = None) -> str:
    """The `openssl` binary to shell out to: an explicit argument, else
    `ECDAT_OPENSSL_BIN`, else bare `openssl` resolved from PATH. Never the
    interpreter's own linked OpenSSL -- there is no subprocess-free way to
    ask a *different* binary's version, and the whole point here is that the
    system `openssl` CLI and Python's linked library commonly differ."""
    return openssl_bin or os.environ.get(OPENSSL_BIN_ENV_VAR) or "openssl"


def build_openssl_version_argv(openssl_bin: str) -> list[str]:
    return [openssl_bin, "version"]


def build_group_probe_argv(
    openssl_bin: str, *, host: str, port: int, group: str, sni: str | None = None
) -> list[str]:
    """The pinned argv for one individual-group `s_client` probe.

    A pure function, tested directly, so the exact flags (`-groups <G>`
    offering ONLY that one group, `-brief` for the parseable summary this
    module's parser already reads) can be asserted without shelling out."""
    argv = [
        openssl_bin,
        "s_client",
        "-connect",
        f"{host}:{port}",
        "-groups",
        group,
        "-brief",
    ]
    if sni:
        argv += ["-servername", sni]
    return argv


def _run(
    argv: list[str], *, timeout_seconds: int, allow_nonzero: bool = False
) -> str:
    """Run one subprocess with a timeout and an output-size cap.

    `allow_nonzero` is set for `s_client` probes: a refused handshake
    (unsupported group, alert 40) is openssl exiting non-zero with useful
    stderr/stdout describing the refusal, not an invocation failure -- the
    parser reads that text and reports `accepted=False`, which is a real
    answer, not a crash. `openssl version` failing non-zero, by contrast,
    means the binary itself is broken and IS an invocation failure.
    """
    try:
        completed = subprocess.run(
            argv,
            input="",
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise AdapterTimeout(f"{argv[0]} timed out after {timeout_seconds}s") from exc
    except OSError as exc:
        raise TlsProbeInvocationError(
            f"could not start {argv[0]!r}: {type(exc).__name__}"
        ) from None

    output = (completed.stdout or "") + (completed.stderr or "")
    if len(output.encode("utf-8", errors="ignore")) > MAX_GROUP_PROBE_OUTPUT_BYTES:
        raise TlsProbeInvocationError(f"{argv[0]} output exceeded the output-size cap")
    if completed.returncode != 0 and not allow_nonzero:
        raise TlsProbeInvocationError(f"{' '.join(argv)} exited {completed.returncode}")
    return output


def probe_openssl_version(
    *, openssl_bin: str | None = None, timeout_seconds: int = DEFAULT_GROUP_PROBE_TIMEOUT_SECONDS
) -> str | None:
    """Run `openssl version` and return its raw stdout, or None when the
    binary cannot be started at all (never a guess in the permissive
    direction -- the caller must treat None exactly like "too old")."""
    resolved = resolve_openssl_bin(openssl_bin=openssl_bin)
    try:
        return _run(build_openssl_version_argv(resolved), timeout_seconds=timeout_seconds)
    except TlsProbeInvocationError:
        return None


def live_group_probe_runner(
    *,
    openssl_bin: str | None = None,
    groups: tuple[str, ...] | None = None,
    timeout_seconds: int = DEFAULT_GROUP_PROBE_TIMEOUT_SECONDS,
) -> Callable[[ScanTarget], TlsProbeBundle]:
    """Build a callable that actually shells out to `openssl s_client`, one
    invocation per group in `groups` (default: `default_group_probe_list()`),
    against the target's declared probe identity.

    Kept as a factory returning a plain callable, never the adapter's
    default -- exactly as `hsm.adapter.live_probe_runner` and
    `TlsEndpointAdapter.__init__`'s mandatory `probe_runner` keyword already
    require, so a live subprocess path is never reached by accident, and
    never reached at all in a test (tests inject a bundle-returning lambda
    directly; nothing in `tests/` calls this factory).

    Version-gates BEFORE probing anything: `openssl version` is run once,
    parsed, and compared against `MIN_OPENSSL_VERSION`. Below that -- or if
    the binary could not even be started -- no group is probed and the
    returned bundle carries `group_probe_unavailable_reason` instead, so the
    adapter reports the hybrid-support fields UNKNOWN with a visibility note
    naming what was actually found, never a silent skip and never an assumed
    capability.
    """
    resolved_bin = resolve_openssl_bin(openssl_bin=openssl_bin)
    probe_groups = groups if groups is not None else default_group_probe_list()

    def _run_probes(target: ScanTarget) -> TlsProbeBundle:
        if target.probe is None:
            raise AdapterContractError(
                "live_group_probe_runner requires a ScanTarget with a ProbeTargetIdentity"
            )
        probe = target.probe
        version_text = probe_openssl_version(openssl_bin=resolved_bin, timeout_seconds=timeout_seconds)
        if not meets_min_openssl_version(version_text):
            found = version_text.strip() if version_text else "not found"
            major, minor, patch = MIN_OPENSSL_VERSION
            return TlsProbeBundle(
                group_probe_unavailable_reason=(
                    f"{resolved_bin!r} reports {found!r}; group probe requires "
                    f"openssl >= {major}.{minor}.{patch} to negotiate a hybrid group at all "
                    f"(set {OPENSSL_BIN_ENV_VAR} to a newer binary's path)"
                ),
            )

        texts: dict[str, str] = {}
        for group in probe_groups:
            argv = build_group_probe_argv(
                resolved_bin,
                host=probe.requested_host,
                port=probe.port,
                group=group,
                sni=probe.sni_sent,
            )
            texts[group] = _run(argv, timeout_seconds=timeout_seconds, allow_nonzero=True)

        return TlsProbeBundle(
            group_probe_texts=texts,
            group_probe_openssl_version=version_text.strip() if version_text else None,
        )

    return _run_probes

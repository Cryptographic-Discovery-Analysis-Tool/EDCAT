"""ECDAT command line.

`scan` runs one adapter over one target and writes a run document: the
findings, their per-field epistemic states, the evidence behind them, and the
visibility entries saying what was and was not examined.

The run document is the only thing a scorer ever sees. ECDAT itself never reads
ground truth -- the join between a run and planted truth happens on the harness
side, so the tool cannot be tuned against the answer key.

**Eight adapters, two very different shapes.** `certs-x509`, `config-chain-spring`
and `source-semgrep` read a local path directly -- `--input` *is* the target.
The other five (`packages-trivy`, `images-cbomkit-theia`, `hsm-pkcs11`,
`binary-yara-readelf`, `tls-endpoint`) wrap a real tool behind a "runner"
(CLAUDE.md's subprocess-injection pattern, see each adapter's own module):
pass `--live` to actually shell out to that tool with its pinned flags, or
omit it to replay pre-recorded raw output through the same parser instead
(CLAUDE.md: "Replay of a recorded file (--input) is for tests and scoring
only") -- this is exactly what every one of those adapters' own unit tests
already do, just driven from argv instead of from Python. `tls-endpoint` has
no `--live` path here yet: its live probe needs two coordinated tools from a
declared vantage (`tools/prober/`), which is a deliberately separate
concern from this single-process CLI, not an oversight.

`correlate` runs several `scan`-shaped specs from one JSON plan file, in one
process, and feeds every resulting `AdapterRunResult` straight into
`ecdat.correlation.engine.correlate()` -- the one asset view across whichever
adapters were in the plan, with cross-surface same-object relationships
where a `der_sha256` hash actually matches. Kept in-process rather than
reading back `scan`'s own JSON output: that run-document shape is a
flattened, scorer-facing serialisation (fields become a list, not a dict),
and reconstructing full `Finding`/`FieldValue` objects from it would be a
lossy round-trip for no reason when the results are already sitting in
memory right after running each scan.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Callable

from ecdat.adapters.base import Adapter, AdapterRunResult, ScanTarget
from ecdat.adapters.binary.adapter import BinaryAdapter, BinaryScanBundle
from ecdat.adapters.binary.adapter import live_scan_runner as live_binary_runner
from ecdat.adapters.certs.adapter import CertificateAdapter
from ecdat.adapters.config.adapter import ConfigChainAdapter
from ecdat.adapters.hsm.adapter import HsmPkcs11Adapter, Pkcs11ProbeBundle
from ecdat.adapters.hsm.adapter import live_probe_runner as live_hsm_runner
from ecdat.adapters.kms.adapter import KmsAdapter, KmsProbeBundle
from ecdat.adapters.kms.adapter import live_kms_runner
from ecdat.adapters.images.adapter import ImagesAdapter
from ecdat.adapters.images.adapter import live_file_reader, live_theia_runner
from ecdat.adapters.packages.adapter import PackagesAdapter, TrivyScanBundle
from ecdat.adapters.packages.adapter import live_scan_runner as live_packages_runner
from ecdat.adapters.source.semgrep import SemgrepSourceAdapter
from ecdat.adapters.tls.adapter import TlsEndpointAdapter, TlsProbeBundle
from ecdat.correlation.engine import CorrelationReport, ForbiddenEdgeError, correlate
from ecdat.model.evidence import ConfidenceBasis
from ecdat.model.topology import ProbeTargetIdentity

#: Every adapter that exists, keyed by its own declared `adapter_id`. Not
#: only a CLI concern -- kept as the canonical id -> class map other code
#: (scoring, a future orchestrator) can import instead of re-listing adapters.
ADAPTERS: dict[str, type[Adapter]] = {
    SemgrepSourceAdapter.adapter_id: SemgrepSourceAdapter,
    CertificateAdapter.adapter_id: CertificateAdapter,
    TlsEndpointAdapter.adapter_id: TlsEndpointAdapter,
    ConfigChainAdapter.adapter_id: ConfigChainAdapter,
    PackagesAdapter.adapter_id: PackagesAdapter,
    ImagesAdapter.adapter_id: ImagesAdapter,
    HsmPkcs11Adapter.adapter_id: HsmPkcs11Adapter,
    KmsAdapter.adapter_id: KmsAdapter,
    BinaryAdapter.adapter_id: BinaryAdapter,
}

#: Path to this repository's own YARA rules, used as `binary-yara-readelf`'s
#: `--live` default so a caller does not have to know the package layout to
#: run it. src/ecdat/cli.py -> src/ecdat -> src -> repo root.
_DEFAULT_RULES_PATH = str(
    Path(__file__).resolve().parents[2] / "rules" / "yara" / "crypto-constants.yar"
)


class CliUsageError(RuntimeError):
    """A `--adapter`-specific requirement was not met (e.g. a required flag
    for that adapter is missing). Distinct from argparse's own errors: this
    is a semantic requirement ("hsm-pkcs11 --live needs --pkcs11-module"),
    not a syntax one, and depends on which `--adapter` was chosen."""


def _read_optional_path(path: str | None) -> str | None:
    """None when no path was given at all; None when a given path does not
    exist, exactly like a real probe that never ran a particular sub-command
    -- this mirrors how e.g. `BinaryScanBundle`'s own fields distinguish
    "did not run" from "ran and got an empty string" (see its docstring)."""
    if not path:
        return None
    candidate = Path(path)
    return candidate.read_text(encoding="utf-8") if candidate.is_file() else None


# --- per-adapter construction --------------------------------------------------
# Each builder returns (adapter, target) from the same argparse.Namespace and
# ConfidenceBasis. Kept as one function per adapter rather than one generic
# path: the eight adapters take genuinely different required arguments
# (a property key list, a probe identity, a PKCS#11 module path, ...) and
# forcing them through one shape would either hide required inputs behind
# silent defaults or make every flag "required" for every adapter -- both are
# the kind of false uniformity this project's own adapter contract (Lock §4)
# was written to avoid.


def _build_semgrep(args: argparse.Namespace, basis: ConfidenceBasis) -> tuple[Adapter, ScanTarget]:
    if not args.input:
        raise CliUsageError("source-semgrep requires --input <recorded semgrep JSON file>")
    adapter = SemgrepSourceAdapter(base_confidence=args.confidence, confidence_basis=basis)
    return adapter, ScanTarget(target_id=args.target_id, locator=args.input)


def _build_certs(args: argparse.Namespace, basis: ConfidenceBasis) -> tuple[Adapter, ScanTarget]:
    if not args.input:
        raise CliUsageError("certs-x509 requires --input <certificate file or directory>")
    password = args.keystore_password.encode("utf-8") if args.keystore_password else None
    adapter = CertificateAdapter(
        base_confidence=args.confidence, confidence_basis=basis, keystore_password=password
    )
    return adapter, ScanTarget(target_id=args.target_id, locator=args.input)


def _build_config(args: argparse.Namespace, basis: ConfidenceBasis) -> tuple[Adapter, ScanTarget]:
    if not args.input:
        raise CliUsageError("config-chain-spring requires --input <repository root>")
    if not args.property_key:
        raise CliUsageError(
            "config-chain-spring requires at least one --property-key (it resolves specific "
            "keys handed to it by an upstream source-adapter finding, never discovers them "
            "itself -- see adapters/config/adapter.py's module docstring)"
        )
    adapter = ConfigChainAdapter(
        property_keys=tuple(args.property_key),
        base_confidence=args.confidence,
        confidence_basis=basis,
        active_profile=args.active_profile,
    )
    return adapter, ScanTarget(target_id=args.target_id, locator=args.input)


def _build_packages(args: argparse.Namespace, basis: ConfidenceBasis) -> tuple[Adapter, ScanTarget]:
    if args.live:
        if not args.input:
            raise CliUsageError("packages-trivy --live requires --input <rootfs directory>")
        runner = live_packages_runner(offline_db_path=args.offline_db_path)
    else:
        if not args.input:
            raise CliUsageError(
                "packages-trivy replay mode requires --input <recorded trivy JSON file> "
                "(or pass --live to run trivy for real)"
            )
        stdout_json = Path(args.input).read_text(encoding="utf-8")

        def runner(target: ScanTarget, _text: str = stdout_json) -> TrivyScanBundle:
            return TrivyScanBundle(stdout_json=_text)

    adapter = PackagesAdapter(
        base_confidence=args.confidence, confidence_basis=basis, scan_runner=runner
    )
    return adapter, ScanTarget(target_id=args.target_id, locator=args.input)


def _build_images(args: argparse.Namespace, basis: ConfidenceBasis) -> tuple[Adapter, ScanTarget]:
    if args.live:
        if not args.input:
            raise CliUsageError("images-cbomkit-theia --live requires --input <image ref>")
        runner = live_theia_runner()
        # --live also enables certificate-hash enrichment (see
        # adapters/images/adapter.py's "Certificate hash enrichment"):
        # cbomkit-theia's own CBOM never carries one, so the adapter
        # independently re-reads and hashes each certificate it reported,
        # the same real capability replay mode has no bytes to offer.
        file_reader = live_file_reader()
    else:
        if not args.input:
            raise CliUsageError(
                "images-cbomkit-theia replay mode requires --input <recorded cbomkit-theia "
                "CycloneDX JSON file> (or pass --live to run it for real)"
            )
        document = json.loads(Path(args.input).read_text(encoding="utf-8"))

        def runner(target: ScanTarget, _document: dict[str, Any] = document) -> dict[str, Any]:
            return _document

        file_reader = None

    adapter = ImagesAdapter(
        base_confidence=args.confidence, confidence_basis=basis, runner=runner, file_reader=file_reader
    )
    return adapter, ScanTarget(target_id=args.target_id, locator=args.input)


def _build_hsm(args: argparse.Namespace, basis: ConfidenceBasis) -> tuple[Adapter, ScanTarget]:
    if args.live:
        if not args.pkcs11_module:
            raise CliUsageError("hsm-pkcs11 --live requires --pkcs11-module <path to .so>")
        runner = live_hsm_runner(module_path=args.pkcs11_module, pin=args.pin)
        locator = args.pkcs11_module
    else:
        if not (args.pkcs11_slots_input or args.pkcs11_objects_input or args.pkcs11_mechanisms_input):
            raise CliUsageError(
                "hsm-pkcs11 replay mode requires at least one of --pkcs11-slots-input / "
                "--pkcs11-objects-input / --pkcs11-mechanisms-input (or pass --live with "
                "--pkcs11-module to probe a real token)"
            )
        bundle = Pkcs11ProbeBundle(
            slots_text=_read_optional_path(args.pkcs11_slots_input),
            objects_text=_read_optional_path(args.pkcs11_objects_input),
            authenticated=args.authenticated,
            mechanisms_text=_read_optional_path(args.pkcs11_mechanisms_input),
        )

        def runner(target: ScanTarget, _bundle: Pkcs11ProbeBundle = bundle) -> Pkcs11ProbeBundle:
            return _bundle

        locator = args.input or args.target_id
    adapter = HsmPkcs11Adapter(
        base_confidence=args.confidence, confidence_basis=basis, probe_runner=runner
    )
    return adapter, ScanTarget(target_id=args.target_id, locator=locator)


def _build_kms(args: argparse.Namespace, basis: ConfidenceBasis) -> tuple[Adapter, ScanTarget]:
    if args.live:
        runner = live_kms_runner(endpoint_url=args.kms_endpoint_url, region=args.kms_region)
        locator = args.kms_region or "aws-kms"
    else:
        if not args.kms_list_keys_input:
            raise CliUsageError(
                "kms-aws replay mode requires --kms-list-keys-input <recorded list-keys JSON "
                "file> (or pass --live, optionally with --kms-endpoint-url for LocalStack, to "
                "read a real account)"
            )
        bundle = KmsProbeBundle(
            list_keys_text=_read_optional_path(args.kms_list_keys_input),
            describe_key_texts=tuple(
                text for p in args.kms_describe_key_input if (text := _read_optional_path(p))
            ),
            public_key_texts=tuple(
                text for p in args.kms_public_key_input if (text := _read_optional_path(p))
            ),
        )

        def runner(target: ScanTarget, _bundle: KmsProbeBundle = bundle) -> KmsProbeBundle:
            return _bundle

        locator = args.kms_region or args.target_id
    adapter = KmsAdapter(base_confidence=args.confidence, confidence_basis=basis, runner=runner)
    return adapter, ScanTarget(target_id=args.target_id, locator=locator)


def _build_binary(args: argparse.Namespace, basis: ConfidenceBasis) -> tuple[Adapter, ScanTarget]:
    if args.live:
        if not args.input:
            raise CliUsageError("binary-yara-readelf --live requires --input <path to binary>")
        rules_path = args.rules_path or _DEFAULT_RULES_PATH
        runner = live_binary_runner(rules_path=rules_path)
    else:
        if not (args.yara_input or args.readelf_header_input or args.readelf_dynamic_input):
            raise CliUsageError(
                "binary-yara-readelf replay mode requires at least one of --yara-input / "
                "--readelf-header-input / --readelf-dynamic-input (or pass --live with "
                "--input <binary path> to scan a real file)"
            )
        bundle = BinaryScanBundle(
            yara_output=_read_optional_path(args.yara_input),
            readelf_header_output=_read_optional_path(args.readelf_header_input),
            readelf_dynamic_output=_read_optional_path(args.readelf_dynamic_input),
        )

        def runner(target: ScanTarget, _bundle: BinaryScanBundle = bundle) -> BinaryScanBundle:
            return _bundle

    adapter = BinaryAdapter(
        base_confidence=args.confidence, confidence_basis=basis, scan_runner=runner
    )
    locator = args.input or args.target_id
    return adapter, ScanTarget(target_id=args.target_id, locator=locator)


def _build_tls(args: argparse.Namespace, basis: ConfidenceBasis) -> tuple[Adapter, ScanTarget]:
    if args.live:
        raise CliUsageError(
            "tls-endpoint has no CLI-driven --live probe yet -- it needs sslyze and an "
            "openssl s_client probe coordinated from a declared vantage; see tools/prober/ "
            "for the existing live invocation path instead"
        )
    if not (args.host and args.vantage):
        raise CliUsageError(
            "tls-endpoint requires --host and --vantage: probe identity is recorded, never "
            "assumed (Lock §5 row 1 / CLAUDE.md)"
        )
    if not (args.sslyze_input or args.negotiated_input or args.classical_only_input):
        raise CliUsageError(
            "tls-endpoint replay mode requires at least one of --sslyze-input / "
            "--negotiated-input / --classical-only-input"
        )
    bundle = TlsProbeBundle(
        sslyze_json=_read_optional_path(args.sslyze_input),
        negotiated_text=_read_optional_path(args.negotiated_input),
        classical_only_text=_read_optional_path(args.classical_only_input),
    )

    def runner(target: ScanTarget, _bundle: TlsProbeBundle = bundle) -> TlsProbeBundle:
        return _bundle

    probe = ProbeTargetIdentity(
        requested_host=args.host, port=args.port or 443, sni_sent=args.sni, probe_vantage=args.vantage
    )
    adapter = TlsEndpointAdapter(
        base_confidence=args.confidence, confidence_basis=basis, probe_runner=runner
    )
    target = ScanTarget(
        target_id=args.target_id,
        locator=f"{args.host}:{args.port or 443}",
        probe=probe,
        consent=args.consent,
    )
    return adapter, target


BUILDERS: dict[str, Callable[[argparse.Namespace, ConfidenceBasis], tuple[Adapter, ScanTarget]]] = {
    SemgrepSourceAdapter.adapter_id: _build_semgrep,
    CertificateAdapter.adapter_id: _build_certs,
    ConfigChainAdapter.adapter_id: _build_config,
    PackagesAdapter.adapter_id: _build_packages,
    ImagesAdapter.adapter_id: _build_images,
    HsmPkcs11Adapter.adapter_id: _build_hsm,
    KmsAdapter.adapter_id: _build_kms,
    BinaryAdapter.adapter_id: _build_binary,
    TlsEndpointAdapter.adapter_id: _build_tls,
}


def _run_document(result: AdapterRunResult) -> dict[str, Any]:
    """Serialise a run for scoring and for a human reader.

    `fields` is a list rather than a map because the scorer works field by
    field: the headline metric counts fields reported as observed that the
    answer key says could only be inferred, declared or unknown.
    """
    findings = []
    for finding in result.findings:
        fields = []
        for name, value in finding.fields.items():
            entry: dict[str, Any] = {
                "field": name,
                "value": value.value,
                "epistemic_state": value.state.value,
                "evidence_refs": list(value.evidence_refs),
            }
            if value.resolution is not None:
                entry["resolution_status"] = value.resolution.status.value
                entry["resolution_reason"] = value.resolution.reason
            if value.rule_id is not None:
                entry["rule_id"] = value.rule_id
                entry["derived_from"] = list(value.derived_from)
            fields.append(entry)
        findings.append(
            {
                "finding_id": finding.finding_id,
                "surface": finding.surface,
                "evidence_refs": list(finding.evidence_refs),
                "fields": fields,
            }
        )

    return {
        "adapter_id": result.adapter_id,
        "support_level": result.support_level.value,
        "target_id": result.target.target_id,
        "outcome": result.outcome.value,
        "failure_reason": result.failure_reason,
        "observed_at": result.context.observed_at.isoformat(),
        "coverage": {
            "scanned": list(result.coverage.scanned),
            "skipped": list(result.coverage.skipped),
        },
        "visibility": [
            {
                "dimension": entry.dimension.value,
                "support_level": entry.support_level.value,
                "detail": entry.detail,
            }
            for entry in result.visibility
        ],
        "evidence": [
            {
                "evidence_id": evidence.evidence_id,
                "source_tool": evidence.source_tool,
                "tool_version": evidence.tool_version,
                "location": evidence.location,
                "base_confidence": evidence.base_confidence,
                "confidence_basis": {
                    "source": evidence.confidence_basis.source,
                    "justification": evidence.confidence_basis.justification,
                    "table_key": evidence.confidence_basis.table_key,
                    "citation": evidence.confidence_basis.citation,
                },
                "raw_ref": evidence.raw_ref,
            }
            for evidence in result.evidence
        ],
        "raw_captures": [
            {
                "raw_ref": capture.raw_ref,
                "source_tool": capture.source_tool,
                "tool_version": capture.tool_version,
                "sha256": capture.sha256,
            }
            for capture in result.raw_captures
        ],
        "findings": findings,
    }


def _scan(args: argparse.Namespace) -> int:
    builder = BUILDERS.get(args.adapter)
    if builder is None:
        print(
            f"unknown adapter {args.adapter!r}; available: {sorted(BUILDERS)}",
            file=sys.stderr,
        )
        return 2

    # No cited source-tool confidence table exists (OI-004 / ADR-002), so the
    # value is supplied here with its justification rather than held as a
    # default inside the adapter, and it travels with every evidence item.
    basis = ConfidenceBasis(
        source="ADAPTER_DECLARED",
        justification=args.confidence_justification,
    )

    try:
        adapter, target = builder(args, basis)
    except CliUsageError as exc:
        print(f"{args.adapter}: {exc}", file=sys.stderr)
        return 2

    result = adapter.run(target)
    document = _run_document(result)

    output = json.dumps(document, indent=2, sort_keys=False)
    if args.out:
        Path(args.out).write_text(output + "\n", encoding="utf-8")
        print(
            f"{result.adapter_id}: {result.outcome.value}, {len(result.findings)} finding(s) "
            f"from {len(result.coverage.scanned)} item(s) examined -> {args.out}"
        )
    else:
        print(output)
    return 0


# --- correlate: one asset view over several scans in one process ---------------

#: Every flag `scan`'s parser defines, with the same default argparse itself
#: would give it. A correlation plan entry only has to state what differs
#: from these -- exactly like typing a shorter `scan` command line that
#: relies on argparse's own defaults for everything else.
_PLAN_ENTRY_DEFAULTS: dict[str, Any] = {
    "input": None,
    "out": None,
    "live": False,
    "property_key": [],
    "active_profile": None,
    "keystore_password": None,
    "offline_db_path": None,
    "pkcs11_module": None,
    "pin": None,
    "authenticated": False,
    "pkcs11_slots_input": None,
    "pkcs11_objects_input": None,
    "pkcs11_mechanisms_input": None,
    "rules_path": None,
    "yara_input": None,
    "readelf_header_input": None,
    "readelf_dynamic_input": None,
    "host": None,
    "port": None,
    "sni": None,
    "vantage": None,
    "consent": False,
    "sslyze_input": None,
    "negotiated_input": None,
    "classical_only_input": None,
    "kms_endpoint_url": None,
    "kms_region": None,
    "kms_list_keys_input": None,
    "kms_describe_key_input": [],
    "kms_public_key_input": [],
}


def _args_from_plan_entry(entry: dict[str, Any]) -> argparse.Namespace:
    """One correlation-plan entry -> the same `argparse.Namespace` shape
    `scan`'s own builders already consume, so a plan entry and a `scan`
    command line are two spellings of exactly the same thing -- no second
    code path to keep in sync with BUILDERS."""
    for required in ("adapter", "target_id", "confidence", "confidence_justification"):
        if required not in entry:
            raise CliUsageError(f"plan entry missing required key {required!r}: {entry}")
    merged = {**_PLAN_ENTRY_DEFAULTS, **entry}
    return argparse.Namespace(**merged)


def _correlate_document(report: CorrelationReport) -> dict[str, Any]:
    """Serialise a CorrelationReport the same way `_run_document` serialises
    an AdapterRunResult: fields as a list (not a dict) for a scorer's sake,
    every epistemic state spelled out, nothing summarised away."""

    def asset_document(asset) -> dict[str, Any]:
        fields = []
        for name, value in asset.fields.items():
            entry: dict[str, Any] = {
                "field": name,
                "value": value.value,
                "epistemic_state": value.state.value,
                "evidence_refs": list(value.evidence_refs),
            }
            if value.resolution is not None:
                entry["resolution_status"] = value.resolution.status.value
                entry["resolution_reason"] = value.resolution.reason
            fields.append(entry)
        return {
            "asset_id": asset.asset_id,
            "scope_anchor": asset.scope_anchor,
            "algorithm_family": asset.algorithm_family,
            "parameters": asset.parameters,
            "purpose": asset.purpose,
            "finding_refs": list(asset.finding_refs),
            "fields": fields,
        }

    return {
        "source_adapter_ids": list(report.source_adapter_ids),
        "assets": [asset_document(asset) for asset in report.assets],
        "relationships": [
            {
                "type": relationship.type,
                "source_entity": relationship.source_entity,
                "target_entity": relationship.target_entity,
                "evidence_basis": relationship.evidence_basis.value,
                "epistemic_state": relationship.epistemic_state.value,
                "rule_id": relationship.rule_id,
                "evidence_refs": list(relationship.evidence_refs),
            }
            for relationship in report.relationships
        ],
        "shares_public_key_unclaimed": [list(pair) for pair in report.shares_public_key_unclaimed],
    }


def _correlate(args: argparse.Namespace) -> int:
    try:
        plan = json.loads(Path(args.plan).read_text(encoding="utf-8"))
    except OSError as exc:
        print(f"could not read plan file {args.plan!r}: {type(exc).__name__}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"plan file {args.plan!r} is not valid JSON: {exc}", file=sys.stderr)
        return 2
    if not isinstance(plan, list) or not plan:
        print(f"plan file {args.plan!r} must be a non-empty JSON list of scan specs", file=sys.stderr)
        return 2

    results: list[AdapterRunResult] = []
    for index, entry in enumerate(plan):
        try:
            entry_args = _args_from_plan_entry(entry)
        except CliUsageError as exc:
            print(f"plan entry {index}: {exc}", file=sys.stderr)
            return 2
        builder = BUILDERS.get(entry_args.adapter)
        if builder is None:
            print(f"plan entry {index}: unknown adapter {entry_args.adapter!r}", file=sys.stderr)
            return 2
        basis = ConfidenceBasis(
            source="ADAPTER_DECLARED", justification=entry_args.confidence_justification
        )
        try:
            adapter, target = builder(entry_args, basis)
        except CliUsageError as exc:
            print(f"plan entry {index} ({entry_args.adapter}): {exc}", file=sys.stderr)
            return 2
        results.append(adapter.run(target))

    try:
        report = correlate(results)
    except ForbiddenEdgeError as exc:
        print(f"correlation refused: {exc}", file=sys.stderr)
        return 3

    document = _correlate_document(report)
    output = json.dumps(document, indent=2, sort_keys=False)
    if args.out:
        Path(args.out).write_text(output + "\n", encoding="utf-8")
        print(
            f"{len(results)} scan(s) -> {len(report.assets)} asset(s), "
            f"{len(report.relationships)} relationship(s) -> {args.out}"
        )
    else:
        print(output)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ecdat", description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="run one adapter over one target")
    scan.add_argument("--adapter", required=True, choices=sorted(ADAPTERS))
    scan.add_argument(
        "--input",
        help="recorded tool output to replay, or (with --live) the real target -- meaning "
        "depends on --adapter; see each builder's error message for what it expects",
    )
    scan.add_argument("--target-id", required=True, help="identifier for the scanned target")
    scan.add_argument("--out", help="write the run document here (default: stdout)")
    scan.add_argument(
        "--confidence",
        type=float,
        required=True,
        help="base confidence for this tool's evidence; there is no cited table "
        "yet (OI-004), so it must be supplied and justified explicitly",
    )
    scan.add_argument(
        "--confidence-justification",
        required=True,
        help="why this confidence value was chosen; recorded with every evidence item",
    )
    scan.add_argument(
        "--live",
        action="store_true",
        help="packages-trivy / images-cbomkit-theia / hsm-pkcs11 / binary-yara-readelf only: "
        "actually shell out to the real tool instead of replaying --input",
    )

    # config-chain-spring
    scan.add_argument(
        "--property-key",
        action="append",
        default=[],
        help="config-chain-spring only: a Spring property key to resolve; repeatable",
    )
    scan.add_argument(
        "--active-profile", help="config-chain-spring only: the active Spring profile, if known"
    )

    # certs-x509
    scan.add_argument(
        "--keystore-password",
        help="certs-x509 only: PKCS#12 keystore password, if needed (held in memory only, "
        "never logged, never written to the run document)",
    )

    # packages-trivy --live
    scan.add_argument(
        "--offline-db-path", help="packages-trivy --live only: offline vulnerability-DB cache directory"
    )

    # hsm-pkcs11
    scan.add_argument("--pkcs11-module", help="hsm-pkcs11 --live only: path to the PKCS#11 module (.so)")
    scan.add_argument(
        "--pin",
        help="hsm-pkcs11 --live only: token PIN, passed only to the subprocess argv, never "
        "logged or written to the run document",
    )
    scan.add_argument(
        "--authenticated",
        action="store_true",
        help="hsm-pkcs11 replay mode only: mark --pkcs11-objects-input as having come from an "
        "authenticated (--login) listing",
    )
    scan.add_argument("--pkcs11-slots-input", help="hsm-pkcs11 replay mode: recorded --list-slots output")
    scan.add_argument("--pkcs11-objects-input", help="hsm-pkcs11 replay mode: recorded --list-objects output")
    scan.add_argument(
        "--pkcs11-mechanisms-input", help="hsm-pkcs11 replay mode: recorded --list-mechanisms output"
    )

    # kms-aws
    scan.add_argument(
        "--kms-endpoint-url",
        help="kms-aws --live only: override the AWS endpoint (e.g. a LocalStack URL such as "
        "http://localhost:4566). Omit entirely to read a real AWS account.",
    )
    scan.add_argument("--kms-region", help="kms-aws only: the AWS region to use")
    scan.add_argument("--kms-list-keys-input", help="kms-aws replay mode: recorded `aws kms list-keys` output")
    scan.add_argument(
        "--kms-describe-key-input",
        action="append",
        default=[],
        help="kms-aws replay mode: recorded `aws kms describe-key` output for one key; repeatable",
    )
    scan.add_argument(
        "--kms-public-key-input",
        action="append",
        default=[],
        help="kms-aws replay mode: recorded `aws kms get-public-key` output for one asymmetric "
        "key; repeatable, optional",
    )

    # binary-yara-readelf
    scan.add_argument(
        "--rules-path",
        help=f"binary-yara-readelf --live only: path to the YARA rule file "
        f"(default: {_DEFAULT_RULES_PATH})",
    )
    scan.add_argument("--yara-input", help="binary-yara-readelf replay mode: recorded `yara -s` output")
    scan.add_argument(
        "--readelf-header-input", help="binary-yara-readelf replay mode: recorded `readelf -h` output"
    )
    scan.add_argument(
        "--readelf-dynamic-input", help="binary-yara-readelf replay mode: recorded `readelf -d` output"
    )

    # tls-endpoint
    scan.add_argument("--host", help="tls-endpoint only: requested host")
    scan.add_argument("--port", type=int, help="tls-endpoint only: requested port (default 443)")
    scan.add_argument("--sni", help="tls-endpoint only: SNI sent")
    scan.add_argument("--vantage", help="tls-endpoint only: probe vantage (Lock §5 row 1)")
    scan.add_argument(
        "--consent",
        action="store_true",
        help="tls-endpoint only: consent to probe this target (required by ScanTarget itself)",
    )
    scan.add_argument("--sslyze-input", help="tls-endpoint replay mode: recorded sslyze JSON output")
    scan.add_argument(
        "--negotiated-input", help="tls-endpoint replay mode: recorded `openssl s_client` negotiated-group output"
    )
    scan.add_argument(
        "--classical-only-input",
        help="tls-endpoint replay mode: recorded classical-only `openssl s_client` probe output",
    )

    scan.set_defaults(func=_scan)

    correlate_parser = subparsers.add_parser(
        "correlate",
        help="run several scans from a JSON plan file and produce one asset view",
    )
    correlate_parser.add_argument(
        "--plan",
        required=True,
        help="JSON file: a list of scan specs, each the same keys as `scan`'s own flags "
        "(adapter, target_id, confidence, confidence_justification required; everything "
        "else optional, defaulting the same way `scan` itself defaults it)",
    )
    correlate_parser.add_argument("--out", help="write the correlation report here (default: stdout)")
    correlate_parser.set_defaults(func=_correlate)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

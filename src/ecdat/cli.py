"""ECDAT command line.

`scan` runs one adapter over one target and writes a run document: the
findings, their per-field epistemic states, the evidence behind them, and the
visibility entries saying what was and was not examined.

The run document is the only thing a scorer ever sees. ECDAT itself never reads
ground truth -- the join between a run and planted truth happens on the harness
side, so the tool cannot be tuned against the answer key.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from ecdat.adapters.base import Adapter, AdapterRunResult, ScanTarget
from ecdat.adapters.source.semgrep import SemgrepSourceAdapter
from ecdat.model.evidence import ConfidenceBasis

ADAPTERS: dict[str, type[Adapter]] = {
    SemgrepSourceAdapter.adapter_id: SemgrepSourceAdapter,
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
    adapter_class = ADAPTERS.get(args.adapter)
    if adapter_class is None:
        print(
            f"unknown adapter {args.adapter!r}; available: {sorted(ADAPTERS)}",
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
    adapter = adapter_class(base_confidence=args.confidence, confidence_basis=basis)
    result = adapter.run(ScanTarget(target_id=args.target_id, locator=args.input))
    document = _run_document(result)

    output = json.dumps(document, indent=2, sort_keys=False)
    if args.out:
        Path(args.out).write_text(output + "\n", encoding="utf-8")
        print(
            f"{result.adapter_id}: {len(result.findings)} finding(s) from "
            f"{len(result.coverage.scanned)} file(s) examined -> {args.out}"
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
        "--input", required=True, help="recorded tool output for the adapter to parse"
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
    scan.set_defaults(func=_scan)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

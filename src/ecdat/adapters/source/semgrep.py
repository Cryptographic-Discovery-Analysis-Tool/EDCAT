"""Source-surface adapter: Semgrep JSON -> Findings + Evidence.

Reads output produced by ECDAT's own rules (`rules/semgrep/crypto-inventory-java.yaml`).
It does not run Semgrep; it parses output recorded under
tests/fixtures/recorded/, because CLAUDE.md forbids writing a parser for tool
output that has not been recorded first.

What this adapter is careful NOT to claim, and why:

* An algorithm that arrives through configuration is not observable here. The
  rules separate a literal argument from a non-literal one, and only a literal
  makes the algorithm field observed. A non-literal one leaves the field UNKNOWN
  with an UNRESOLVED resolution naming the expression to resolve, which is the
  configuration adapter's input (harness §14 CFG-001: resolution yields INFERRED,
  never observed).
* A literal transformation string fixes the string, not every parameter of the
  operation -- provider defaults can decide parameters the string does not name.
  So no parameter field is emitted from a call site at all.
* Purpose is never derivable from an API call (CLAUDE.md: purpose defaults to
  UNKNOWN, never guessed).
* Reachability is not observable: Lock §7 OQ-5 fixes `reachable` at UNKNOWN,
  with no reachability analysis anywhere in scope.
* Key sizes are not observable from a call site, even when a parameter is named
  after one.

The matched source line Semgrep returns is used transiently, to tell a value
written at the call site from one the engine propagated there, and is then
dropped: source text is the route by which key material would reach the store,
the CLI, an export or a snapshot.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from ecdat.adapters.base import (
    Adapter,
    AdapterOutcome,
    AdapterRunResult,
    Coverage,
    RawCapture,
    ScanTarget,
    _utc_now,
)
from ecdat.model.epistemic import EpistemicState, Resolution, ResolutionStatus
from ecdat.model.evidence import ConfidenceBasis, Evidence
from ecdat.model.field_value import FieldValue
from ecdat.model.finding import Finding
from ecdat.model.topology import ObservationContext
from ecdat.model.visibility import SupportLevel, VisibilityDimension, VisibilityEntry

SOURCE_TOOL = "semgrep"

#: Versions whose JSON shape we have actually recorded and parsed. Output from
#: any other version is refused rather than parsed on the assumption that the
#: shape did not change.
RECORDED_VERSIONS = frozenset({"1.99.0"})

#: Rule id (final segment of Semgrep's check_id) -> what that match means.
#: Keying on the rule id rather than on a service name in the matched text is
#: deliberate: the rule already encodes whether the captured argument names an
#: algorithm, a protocol or a trust service, so the adapter never has to
#: re-derive that by matching strings.
_ALGORITHM_LITERAL = "crypto-call-literal-algorithm"
_ALGORITHM_NONLITERAL = "crypto-call-nonliteral-algorithm"
_PROTOCOL_LITERAL = "crypto-call-literal-protocol"
_PROTOCOL_NONLITERAL = "crypto-call-nonliteral-protocol"
_TRUST_SERVICE_LITERAL = "crypto-call-literal-trust-service"
_PROVIDER_ARGUMENT = "crypto-call-explicit-provider-argument"
_CONFIG_BINDING = "crypto-config-property-binding-declaration"

_UNRESOLVED_NONLITERAL = (
    "algorithm argument is not a literal at the call site; "
    "resolution requires the configuration chain"
)


class UnrecordedToolOutput(ValueError):
    """The output came from a tool version whose shape we have not recorded."""


def _rule_id(check_id: str) -> str:
    """Semgrep prefixes check_id with the config path it was loaded from, so
    only the final segment is stable across machines and layouts."""
    return check_id.rsplit(".", 1)[-1]


def _metavar(result: dict[str, Any], name: str) -> str | None:
    entry = result.get("extra", {}).get("metavars", {}).get(name)
    if entry is None:
        return None
    content = entry.get("abstract_content")
    return content if isinstance(content, str) else None


def _strip_quotes(value: str) -> str:
    """Some rules capture the quotes with the value and some do not, depending
    on whether the pattern put the quotes around the metavariable."""
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return value[1:-1]
    return value


def _observed(value: Any, evidence_id: str) -> FieldValue:
    return FieldValue(value=value, state=EpistemicState.KNOWN, evidence_refs=(evidence_id,))


def _unknown(evidence_id: str, resolution: Resolution | None = None) -> FieldValue:
    return FieldValue(
        value=None,
        state=EpistemicState.UNKNOWN,
        resolution=resolution,
        evidence_refs=(evidence_id,),
    )


class SemgrepSourceAdapter(Adapter):
    adapter_id = "source-semgrep"
    #: Java call sites only -- not other languages, not reachability, not key
    #: sizes. `full` would overstate what this ruleset can see (Lock §4: the
    #: declared level feeds the visibility matrix).
    support_level = SupportLevel.PARTIAL
    dimensions = (VisibilityDimension.SOURCE,)

    def __init__(
        self,
        *,
        base_confidence: float,
        confidence_basis: ConfidenceBasis,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        """`base_confidence` is injected, never defaulted: no cited source-tool
        confidence table exists (OI-004 / ADR-002), so the value is a caller's
        declared choice that travels with its own justification."""
        super().__init__(clock=clock)
        self._base_confidence = base_confidence
        self._confidence_basis = confidence_basis

    def parse(
        self, raw: dict[str, Any], *, raw_ref: str
    ) -> tuple[tuple[Finding, ...], tuple[Evidence, ...], Coverage]:
        version = raw.get("version")
        if version not in RECORDED_VERSIONS:
            raise UnrecordedToolOutput(
                f"semgrep {version!r} output has not been recorded under "
                f"tests/fixtures/recorded/; recorded versions: {sorted(RECORDED_VERSIONS)}"
            )

        paths = raw.get("paths") or {}
        coverage = Coverage(
            scanned=tuple(paths.get("scanned") or ()),
            skipped=tuple(
                entry.get("path", "")
                for entry in (paths.get("skipped") or ())
                if isinstance(entry, dict)
            ),
        )

        # One call site can be matched by more than one rule -- an explicit
        # provider argument is additive evidence about the same site, not a
        # second asset -- so results are grouped by their exact span first.
        grouped: dict[tuple[str, int, int], list[dict[str, Any]]] = {}
        for result in raw.get("results") or ():
            key = (result["path"], result["start"]["line"], result["start"]["col"])
            grouped.setdefault(key, []).append(result)

        findings: list[Finding] = []
        evidence: list[Evidence] = []
        for index, (key, results) in enumerate(sorted(grouped.items())):
            path, line, _column = key
            evidence_id = f"{self.adapter_id}:{index}"
            evidence.append(
                Evidence(
                    evidence_id=evidence_id,
                    source_tool=SOURCE_TOOL,
                    tool_version=version,
                    location=f"{path}:{line}",
                    base_confidence=self._base_confidence,
                    confidence_basis=self._confidence_basis,
                    raw_ref=raw_ref,
                )
            )
            fields = self._fields_for_call_site(results, path, line, evidence_id)
            if fields is None:
                evidence.pop()
                continue
            findings.append(
                Finding(
                    finding_id=f"{self.adapter_id}:{index}",
                    surface=VisibilityDimension.SOURCE.value,
                    evidence_refs=(evidence_id,),
                    fields=fields,
                )
            )
        return tuple(findings), tuple(evidence), coverage

    def _fields_for_call_site(
        self, results: list[dict[str, Any]], path: str, line: int, evidence_id: str
    ) -> dict[str, FieldValue] | None:
        rule_ids = {_rule_id(r["check_id"]) for r in results}
        by_rule = {_rule_id(r["check_id"]): r for r in results}

        fields: dict[str, FieldValue] = {
            "path": _observed(path, evidence_id),
            "line": _observed(line, evidence_id),
        }

        if _CONFIG_BINDING in rule_ids:
            prefix = _metavar(by_rule[_CONFIG_BINDING], "$PREFIX")
            if prefix is None:
                return None
            # Not a crypto asset: a declared binding between configuration and
            # code. It becomes useful only when the configuration adapter joins
            # it to an unresolved call site.
            fields["config_binding_prefix"] = _observed(_strip_quotes(prefix), evidence_id)
            return fields

        # Reachability is not observable here, and there is no reachability
        # analysis in scope (Lock §7 OQ-5). Recorded as UNKNOWN on every call
        # site so nothing downstream can read its absence as "in use".
        fields["reachable"] = _unknown(evidence_id)
        fields["purpose"] = _unknown(evidence_id)

        # The JCA class at the call site (`Cipher`, `Mac`, `Signature`, ...).
        # Read from the rule's `$1` capture (metavariable-regex group), which
        # the recorded 1.99.0 fixture carries; `$CLASS` repeats the token and
        # is the fallback. P21's bridge needs it: the crypto *function* comes
        # from which API is called, not from the algorithm string.
        for result in results:
            api_class = _metavar(result, "$1") or (
                (_metavar(result, "$CLASS") or "").split()[:1] or [None]
            )[0]
            if api_class:
                fields["api_class"] = _observed(api_class, evidence_id)
                break

        if _ALGORITHM_LITERAL in rule_ids:
            result = by_rule[_ALGORITHM_LITERAL]
            captured = _metavar(result, "$ALGO")
            if captured is None:
                return None
            value = _strip_quotes(captured)
            fields["algorithm"] = _observed(value, evidence_id)
            # Semgrep propagates constants, so a value can be reported for a
            # call site that does not literally contain it. The matched line is
            # inspected here and deliberately not kept.
            matched_line = result.get("extra", {}).get("lines", "")
            fields["algorithm_literal_at_call_site"] = _observed(
                value in matched_line, evidence_id
            )
        elif _ALGORITHM_NONLITERAL in rule_ids:
            result = by_rule[_ALGORITHM_NONLITERAL]
            argument = _metavar(result, "$ARG")
            if argument is None:
                return None
            fields["algorithm"] = _unknown(
                evidence_id,
                Resolution(status=ResolutionStatus.UNRESOLVED, reason=_UNRESOLVED_NONLITERAL),
            )
            # Kept so the configuration adapter knows what to resolve; without
            # it the call site could never be resolved later.
            fields["algorithm_argument"] = _observed(argument, evidence_id)
        elif _PROTOCOL_LITERAL in rule_ids:
            captured = _metavar(by_rule[_PROTOCOL_LITERAL], "$PROTO")
            if captured is None:
                return None
            fields["protocol"] = _observed(_strip_quotes(captured), evidence_id)
        elif _PROTOCOL_NONLITERAL in rule_ids:
            argument = _metavar(by_rule[_PROTOCOL_NONLITERAL], "$ARG")
            if argument is None:
                return None
            fields["protocol"] = _unknown(
                evidence_id,
                Resolution(status=ResolutionStatus.UNRESOLVED, reason=_UNRESOLVED_NONLITERAL),
            )
            fields["protocol_argument"] = _observed(argument, evidence_id)
        elif _TRUST_SERVICE_LITERAL in rule_ids:
            captured = _metavar(by_rule[_TRUST_SERVICE_LITERAL], "$SERVICE")
            if captured is None:
                return None
            fields["trust_service"] = _observed(_strip_quotes(captured), evidence_id)
        elif _PROVIDER_ARGUMENT not in rule_ids:
            return None

        if _PROVIDER_ARGUMENT in rule_ids:
            provider = _metavar(by_rule[_PROVIDER_ARGUMENT], "$PROVIDER")
            if provider is not None:
                # The provider *requested* at this call site. Whether that is
                # the provider that executes is a different question this
                # surface cannot answer, so the field is named for the argument.
                fields["provider_argument"] = _observed(_strip_quotes(provider), evidence_id)

        return fields

    def _scan(self, target: ScanTarget) -> AdapterRunResult:
        path = Path(target.locator)
        payload = path.read_bytes()
        raw = json.loads(payload.decode("utf-8"))
        raw_ref = path.name

        findings, evidence, coverage = self.parse(raw, raw_ref=raw_ref)
        capture = RawCapture(
            raw_ref=raw_ref,
            source_tool=SOURCE_TOOL,
            tool_version=raw["version"],
            sha256=hashlib.sha256(payload).hexdigest(),
            captured_at=self._clock(),
        )
        return AdapterRunResult(
            adapter_id=self.adapter_id,
            support_level=self.support_level,
            target=target,
            outcome=AdapterOutcome.COMPLETED,
            context=ObservationContext(observed_at=self._clock()),
            coverage=coverage,
            visibility=(self._visibility(target, coverage, findings),),
            raw_captures=(capture,),
            evidence=evidence,
            findings=findings,
        )

    def _visibility(
        self, target: ScanTarget, coverage: Coverage, findings: tuple[Finding, ...]
    ) -> VisibilityEntry:
        """What this run can honestly claim about the target.

        The distinction that matters: zero findings after examining files is a
        result; zero findings after examining nothing is not. Reporting the
        second as the first is the failure harness §7.3 tests for.
        """
        if not coverage.looked_at_anything:
            detail = (
                f"{target.target_id}: no file was examined -- this ruleset covers Java "
                "only, so the target is not covered by this adapter"
            )
        else:
            detail = (
                f"{target.target_id}: {len(coverage.scanned)} file(s) examined, "
                f"{len(findings)} call site(s) inventoried"
            )
        return VisibilityEntry(
            dimension=VisibilityDimension.SOURCE,
            support_level=self.support_level,
            detail=detail,
        )

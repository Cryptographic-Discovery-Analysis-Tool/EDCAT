"""Compiled-binary adapter (P12; stack decision "Binaries | YARA constants +
readelf/strings; family only").

Runs Pramana's own YARA rule set (`rules/yara/crypto-constants.yar` -- read,
never modified here) against one binary and cross-checks it with `readelf`.
Two probes, because one tool cannot answer both questions, exactly the
reasoning `tls.adapter.TlsEndpointAdapter` already documents for sslyze +
`openssl s_client`:

* **yara** finds published, public-domain algorithm constants (FIPS-197's
  AES S-box, FIPS-180-4's SHA-256 `H0`) compiled directly into the binary.
  A match is the strongest claim this adapter can make: the family's
  reference tables are physically present in this file.
* **readelf -d** reads the ELF dynamic section's `NEEDED` entries -- the
  shared libraries this binary asks the loader for. This is a *weaker*,
  *different* kind of evidence: "this binary asks for a library whose name
  suggests a crypto family", not "this binary contains that family's
  bytes". The real recorded pair proves why both are needed: `haproxy`
  itself never matches any YARA rule (AES is not compiled into it), yet it
  unmistakably has AES capability via its `NEEDED libcrypto.so.3` entry,
  which round-trips to `libcrypto.so.3`'s own SONAME (see
  tests/fixtures/recorded/readelf/README.md). Reporting only the YARA
  result would silently say "no AES here"; reporting only the NEEDED
  entries would silently say "AES is embedded here". Both are wrong on
  their own, which is why `embedded_constant_families` and
  `linked_libraries` are two separate fields on the Finding and are never
  collapsed into one "has AES" boolean.

**RSA/ECDSA are a permanent, structural capability gap for this technique**:
neither has a fixed constant table to scan for (no S-box, no fixed IV; see
`rules/yara/crypto-constants.yar`'s own header comment). `visibility[0].detail`
states this on *every* run this adapter makes, whether or not anything
matched -- a reader who only sees a clean-looking positive AES match must
still be told, every time, that RSA/ECDSA presence was never checked.

**KNOWN-empty vs UNKNOWN, on a zero-match yara scan.** `certs.adapter
.CertificateAdapter._fields`'s `known_or_unknown()` maps an empty parsed
value to UNKNOWN -- but that adapter's parser runs unconditionally on every
certificate it reads, so "empty" there is genuinely ambiguous between "the
extension is absent" and cases the parser cannot fully distinguish. This
adapter's yara leg is different: when `bundle.yara_output` is not `None`,
yara was actually invoked against this exact target and returned a
complete, successful scan (see the real `haproxy.no-match.txt` fixture --
exit code 1, and still a fully valid, non-failed run). Reporting UNKNOWN in
that case would say "we did not check this binary for AES/SHA-256
constants", which is false; we did, and the answer was a definite no. So
`embedded_constant_families` is:
  * UNKNOWN only when the yara leg was never run at all
    (`bundle.yara_output is None` -- coverage.skipped explains why), and
  * KNOWN with an empty tuple when yara ran and matched nothing, and
  * KNOWN with the matched family names otherwise.
`linked_libraries` follows the identical rule for `readelf -d`'s NEEDED
entries, for the same reason.

The tool-runner is injected exactly as `tls.adapter.TlsEndpointAdapter`
injects `probe_runner` and `packages.adapter.PackagesAdapter` injects
`scan_runner`: one callable returning a small dataclass of raw text, so
tests replay recorded fixtures directly and the subprocess boundary stays a
single, explicit seam. `live_scan_runner()` builds the runner that actually
shells out, with yara's `-s -w <rules> <target>` and readelf's `-h`/`-d`
against the same target, each with a wall-clock timeout and no argument
that would cause network egress.
"""
from __future__ import annotations

import hashlib
import subprocess
from dataclasses import dataclass
from datetime import datetime
from typing import Callable

from ecdat.adapters.base import (
    Adapter,
    AdapterOutcome,
    AdapterRunResult,
    AdapterTimeout,
    Coverage,
    RawCapture,
    ScanTarget,
)
from ecdat.adapters.binary.parser import (
    parse_readelf_dynamic,
    parse_readelf_header,
    parse_yara,
)
from ecdat.model.epistemic import EpistemicState
from ecdat.model.evidence import ConfidenceBasis, Evidence
from ecdat.model.field_value import FieldValue
from ecdat.model.finding import Finding
from ecdat.model.topology import ObservationContext
from ecdat.model.visibility import SupportLevel, VisibilityDimension, VisibilityEntry
from ecdat.security.secrets import scan_for_secrets

YARA_SOURCE_TOOL = "yara"
READELF_SOURCE_TOOL = "readelf"

#: A sane per-invocation ceiling, not a confidence value or a cited fact --
#: same status as packages.adapter.DEFAULT_TIMEOUT_SECONDS. CLAUDE.md's
#: "per-target timeout" is the hard rule; this number is an overridable
#: engineering default.
DEFAULT_TIMEOUT_SECONDS = 60

#: packages.adapter.MAX_OUTPUT_BYTES's rationale, unchanged: bounds a
#: runaway or hostile tool while comfortably exceeding every recorded
#: fixture (each well under 1 KiB).
MAX_OUTPUT_BYTES = 64 * 1024 * 1024

#: Stated on every visibility entry this adapter emits, matched or not.
#: FIPS-197 defines AES's S-box and FIPS-180-4 defines SHA-256's H0 as
#: fixed published tables, which is exactly what makes them matchable by
#: constant; RSA and ECDSA have no analogous fixed byte sequence (key
#: material is generated, not compiled in), so no YARA rule -- this one or
#: any other -- can ever detect them this way. See
#: rules/yara/crypto-constants.yar's own header comment and
#: tests/fixtures/recorded/yara/4.5.0/README.md.
RSA_ECDSA_GAP_NOTE = (
    "RSA and ECDSA have no fixed constant table to match against (no S-box, "
    "no fixed IV analogous to FIPS-197/FIPS-180-4): this rule set cannot "
    "detect either family in any binary, by construction. Silence on "
    "RSA/ECDSA from this adapter is never evidence that either is absent."
)


class BinaryInvocationError(RuntimeError):
    """A live yara/readelf subprocess failed in a way this adapter cannot
    interpret as a scanned-but-empty result. Carries only a description,
    never captured stdout/stderr -- the same convention
    packages.adapter.TrivyInvocationError documents."""


@dataclass(frozen=True)
class BinaryScanBundle:
    """Raw output of the yara and readelf probes for one binary, before
    parsing. Mirrors `tls.adapter.TlsProbeBundle`'s shape.

    Each field is `None` when that probe was not run at all (its
    coverage.skipped entry says why, and its Finding field is UNKNOWN), and
    a string -- possibly empty -- when it ran (its Finding field is
    KNOWN, empty or not). The two are kept structurally apart; see
    adapter.py's module docstring.
    """

    yara_output: str | None = None
    readelf_header_output: str | None = None
    readelf_dynamic_output: str | None = None


#: A callable that runs both probes against one target. Injected so tests
#: replay recorded output and the subprocess boundary is explicit rather
#: than buried -- the same reasoning `tls.adapter.ProbeRunner` and
#: `packages.adapter.ScanRunner` document.
ScanRunner = Callable[[ScanTarget], BinaryScanBundle]


def build_yara_argv(rules_path: str, locator: str) -> list[str]:
    """Pinned live argv for one yara invocation: `-s` prints matched
    strings with their offsets (the evidence detail this adapter needs),
    `-w` suppresses warnings so they cannot be mistaken for a match line.
    A pure function so the live-invocation shape can be asserted without
    ever shelling out (see tests/unit/adapters/test_binary.py)."""
    return ["yara", "-s", "-w", rules_path, locator]


def build_readelf_header_argv(locator: str) -> list[str]:
    return ["readelf", "-h", locator]


def build_readelf_dynamic_argv(locator: str) -> list[str]:
    return ["readelf", "-d", locator]


def live_scan_runner(
    *, rules_path: str, timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
) -> ScanRunner:
    """Build a `ScanRunner` that actually shells out to yara and readelf.

    Kept as a factory returning a plain callable, never the adapter's
    default, so a `BinaryAdapter` can never be constructed with a live
    subprocess path by accident -- exactly as `TlsEndpointAdapter` requires
    `probe_runner` and `PackagesAdapter` requires `scan_runner` as mandatory
    keyword arguments with no default. Network egress for the invoked
    processes is a deployment-level control (both tools only ever read a
    local file path here, and neither argv below takes a network target);
    what this function enforces directly is the pinned flag set, the
    per-call wall-clock timeout, and the output-size cap.
    """

    def _run_one(argv: list[str], *, tool: str, accept_returncodes: frozenset[int]) -> str:
        try:
            completed = subprocess.run(
                argv, capture_output=True, text=True, timeout=timeout_seconds, check=False
            )
        except subprocess.TimeoutExpired as exc:
            raise AdapterTimeout(f"{tool} timed out after {timeout_seconds}s") from exc
        except OSError as exc:
            raise BinaryInvocationError(f"could not start {tool}: {type(exc).__name__}") from None

        if len(completed.stdout.encode("utf-8", errors="ignore")) > MAX_OUTPUT_BYTES:
            raise BinaryInvocationError(f"{tool} stdout exceeded the output-size cap")
        if completed.returncode not in accept_returncodes:
            raise BinaryInvocationError(f"{tool} exited {completed.returncode}")
        return completed.stdout

    def _run(target: ScanTarget) -> BinaryScanBundle:
        yara_output = _run_one(
            build_yara_argv(rules_path, target.locator),
            tool="yara",
            # Recorded real behaviour (tests/fixtures/recorded/yara/4.5.0/
            # README.md): yara exits 0 when a rule matches and exits 1 when
            # none did -- both are a completed, honest scan of this target,
            # never a failure.
            accept_returncodes=frozenset({0, 1}),
        )
        header_output = _run_one(
            build_readelf_header_argv(target.locator),
            tool="readelf -h",
            accept_returncodes=frozenset({0}),
        )
        dynamic_output = _run_one(
            build_readelf_dynamic_argv(target.locator),
            tool="readelf -d",
            accept_returncodes=frozenset({0}),
        )
        return BinaryScanBundle(
            yara_output=yara_output,
            readelf_header_output=header_output,
            readelf_dynamic_output=dynamic_output,
        )

    return _run


class BinaryAdapter(Adapter):
    adapter_id = "binary-yara-readelf"

    #: DETECT_ONLY: this adapter detects the presence of a small, fixed set
    #: of families via constant-matching and dynamic-link inspection. It
    #: resolves no usage, understands no algorithm family outside the rule
    #: set, and -- structurally, permanently -- cannot see RSA/ECDSA at
    #: all. Declaring PARTIAL or FULL would claim coverage nobody
    #: implemented (Lock §4: the declared level feeds the visibility
    #: matrix).
    support_level = SupportLevel.DETECT_ONLY

    #: A binary file is an artifact -- the same dimension
    #: certs.adapter.CertificateAdapter declares for files on disk (see
    #: model/visibility.py's dimension list; no new dimension is invented).
    dimensions = (VisibilityDimension.ARTIFACT,)

    def __init__(
        self,
        *,
        base_confidence: float,
        confidence_basis: ConfidenceBasis,
        scan_runner: ScanRunner,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """`base_confidence` is injected, never defaulted: no cited row
        exists in data/base_confidence.yaml for yara/readelf binary
        evidence (checked: the one binary.* row there is `usable: false`),
        so the caller supplies a value together with its own justification,
        exactly as certs/adapter.py and tls/adapter.py require."""
        super().__init__(**({"clock": clock} if clock else {}))
        self._base_confidence = base_confidence
        self._confidence_basis = confidence_basis
        self._scan_runner = scan_runner

    # --- emission ------------------------------------------------------------

    @staticmethod
    def _known(value, evidence_id: str) -> FieldValue:
        return FieldValue(value=value, state=EpistemicState.KNOWN, evidence_refs=(evidence_id,))

    @staticmethod
    def _known_empty(evidence_id: str) -> FieldValue:
        """KNOWN with an empty tuple: a completed scan's definite negative.
        See the module docstring's KNOWN-empty-vs-UNKNOWN note."""
        return FieldValue(value=(), state=EpistemicState.KNOWN, evidence_refs=(evidence_id,))

    @staticmethod
    def _unknown() -> FieldValue:
        return FieldValue(value=None, state=EpistemicState.UNKNOWN)

    def _scan(self, target: ScanTarget) -> AdapterRunResult:
        observed_at = self._clock()
        bundle = self._scan_runner(target)

        scanned: list[str] = []
        skipped: list[str] = []
        evidence: list[Evidence] = []
        raw_captures: list[RawCapture] = []
        fields: dict[str, FieldValue] = {}

        def capture(raw_ref: str, tool: str, version: str, payload: str) -> str:
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
                    location=target.locator,
                    base_confidence=self._base_confidence,
                    confidence_basis=self._confidence_basis,
                    raw_ref=raw_ref,
                )
            )
            return evidence_id

        # --- YARA leg: embedded constants ------------------------------------
        # `is not None`, not a truthiness check: a live yara run that
        # legitimately returns empty stdout (a real "no match" exit) must
        # still count as "ran", not be mistaken for "never run" the way a
        # bare `if bundle.yara_output:` would treat it.
        if bundle.yara_output is not None:
            yara_matches = parse_yara(bundle.yara_output)
            yara_evidence_id = capture(
                f"yara://{target.locator}", YARA_SOURCE_TOOL, "4.5.0", bundle.yara_output
            )
            scanned.append(f"yara {target.locator}")

            if yara_matches:
                matched_families = tuple(sorted({m.family for m in yara_matches}))
                fields["embedded_constant_families"] = self._known(
                    matched_families, yara_evidence_id
                )
                for match in yara_matches:
                    slug = match.family.replace("-", "_").replace(" ", "_")
                    fields[f"embedded_constant_offsets_{slug}"] = self._known(
                        match.offsets, yara_evidence_id
                    )
            else:
                fields["embedded_constant_families"] = self._known_empty(yara_evidence_id)
        else:
            skipped.append("yara: not run for this target")
            fields["embedded_constant_families"] = self._unknown()

        # --- readelf -d leg: dynamic dependencies -----------------------------
        # Kept as fields entirely separate from the YARA leg above -- an
        # embedded constant and a linked library name are different
        # evidence strengths and must never collapse into one boolean.
        if bundle.readelf_dynamic_output is not None:
            dynamic = parse_readelf_dynamic(bundle.readelf_dynamic_output)
            dynamic_evidence_id = capture(
                f"readelf-d://{target.locator}",
                READELF_SOURCE_TOOL,
                "unknown",
                bundle.readelf_dynamic_output,
            )
            scanned.append(f"readelf -d {target.locator}")
            fields["linked_libraries"] = (
                self._known(dynamic.needed, dynamic_evidence_id)
                if dynamic.needed
                else self._known_empty(dynamic_evidence_id)
            )
            fields["own_soname"] = (
                self._known(dynamic.soname, dynamic_evidence_id)
                if dynamic.soname
                else self._unknown()
            )
        else:
            skipped.append(
                "readelf -d: not run -- dynamic dependencies are unobserved for this target"
            )
            fields["linked_libraries"] = self._unknown()
            fields["own_soname"] = self._unknown()

        # --- readelf -h leg: ELF header ---------------------------------------
        if bundle.readelf_header_output is not None:
            header = parse_readelf_header(bundle.readelf_header_output)
            header_evidence_id = capture(
                f"readelf-h://{target.locator}",
                READELF_SOURCE_TOOL,
                "unknown",
                bundle.readelf_header_output,
            )
            scanned.append(f"readelf -h {target.locator}")
            fields["elf_class"] = (
                self._known(header.elf_class, header_evidence_id)
                if header.elf_class
                else self._unknown()
            )
            fields["elf_type"] = (
                self._known(header.elf_type, header_evidence_id)
                if header.elf_type
                else self._unknown()
            )
            fields["elf_machine"] = (
                self._known(header.machine, header_evidence_id)
                if header.machine
                else self._unknown()
            )
        else:
            skipped.append("readelf -h: not run -- the ELF header is unobserved for this target")
            fields["elf_class"] = self._unknown()
            fields["elf_type"] = self._unknown()
            fields["elf_machine"] = self._unknown()

        families_field = fields["embedded_constant_families"]
        if families_field.state == EpistemicState.KNOWN and families_field.value:
            match_clause = (
                "Embedded-constant match for: " + ", ".join(families_field.value) + "."
            )
        elif families_field.state == EpistemicState.KNOWN:
            match_clause = "yara ran and matched no embedded-constant family in this binary."
        else:
            match_clause = "yara was not run against this target."

        surface = f"binary:{target.locator}"
        detail = (
            f"{target.target_id}: scanned {target.locator} with yara "
            "(rules/yara/crypto-constants.yar) and readelf. "
            f"{match_clause} An embedded-constant match and a dynamically "
            "linked dependency are different evidence strengths and are "
            "kept on separate fields (embedded_constant_families vs "
            "linked_libraries), never merged into one presence claim. "
            f"{RSA_ECDSA_GAP_NOTE}"
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
                    dimension=VisibilityDimension.ARTIFACT,
                    support_level=self.support_level,
                    detail=detail,
                ),
            ),
            raw_captures=tuple(raw_captures),
            evidence=tuple(evidence),
            findings=(
                (
                    Finding(
                        finding_id=f"{self.adapter_id}:{target.target_id}",
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

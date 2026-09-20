"""Container-image adapter (P4b; spec §3 row "Container images").

Wraps `cbomkit-theia` (ghcr.io/ibm/cbomkit-theia:latest, invoked over the
docker socket) and feeds its CycloneDX 1.6 output through the existing CBOM
importer (`ecdat.export.cyclonedx.import_cbom`, built in an earlier phase and
left untouched here) to produce Findings on this surface's Adapter contract.

**This adapter is a thin shell around two already-built pieces.** The tool
invocation is the only new subprocess boundary; everything downstream of a
parsed CBOM document -- reading `cryptoProperties`, deciding a component is a
crypto asset at all, choosing `state=DECLARED` -- already happened inside
`import_cbom`, and this module does not re-decide any of it. What this module
adds is only: shell out, hand the parsed document to the importer, and wrap
each `ImportedCryptoAsset` the importer returns in a `Finding` that fits the
same `AdapterRunResult` shape every other surface uses.

**`support_level = PARTIAL`, not `full`.** cbomkit-theia's own `--help` states
it plainly: "CBOMkit-theia does *not* perform source code scanning." Its
default plugin set (certificates, secrets) finds crypto material inside an
image's filesystem; it does not find crypto call sites in source. Declaring
`full` here would assert coverage this tool does not provide (Lock §4: the
declared level feeds the visibility matrix), so the visibility entry this
adapter emits names the gap in words on every run, not just in this
docstring.

**`dimensions = (ARTIFACT,)`.** The tool inspects an already-built image's
filesystem contents -- the same kind of observation `certs.adapter
.CertificateAdapter` makes over a directory of files, just reached through a
container image instead of a bare path. `VisibilityDimension` has no
container-specific member, and inventing one would violate the closed-set
spirit of the visibility matrix in exactly the way the epistemic-state enum
is closed; ARTIFACT is the correct existing member.

**Every field this adapter emits is `DECLARED`, never `KNOWN`.**
`ImportedCryptoAsset.state` already encodes why (see its docstring in
`ecdat/export/cyclonedx.py`): another tool asserting an algorithm exists is a
statement, not an observation this process made. That is R-MONOTONE in
practice -- laundering a third party's certainty into our own would create
certainty nobody here actually earned.

**A failed scan is reported as failed, never as a clean empty result.** A
directory-traversal failure inside the tool (a real failure mode a live run
of this exact tool produced against a real image -- see
`tests/fixtures/recorded/theia/edge-2026-09-19/README.md`) looks, from the
outside, exactly like "the image has no crypto material" unless the adapter
tells the two apart. The runner raises a plain exception naming only the
failure *type*, never captured tool output (that output can carry filesystem
paths from inside someone else's image), and `_scan()` does not catch it --
`Adapter.run()`'s own exception handling converts it into
`AdapterOutcome.FAILED` with a real `failure_reason`, the same mechanism
`certs.adapter.CertificateAdapter` relies on for a missing path.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import datetime
from typing import Any, Callable

from ecdat.adapters.base import (
    Adapter,
    AdapterOutcome,
    AdapterRunResult,
    AdapterTimeout,
    Coverage,
    RawCapture,
    ScanTarget,
)
from ecdat.export.cyclonedx import ImportedCryptoAsset, import_cbom
from ecdat.model.epistemic import EpistemicState
from ecdat.model.evidence import ConfidenceBasis, Evidence
from ecdat.model.field_value import FieldValue
from ecdat.model.finding import Finding
from ecdat.model.topology import ObservationContext
from ecdat.model.visibility import SupportLevel, VisibilityDimension, VisibilityEntry
from ecdat.security.secrets import scan_for_secrets

#: The pinned image this adapter shells out to. Not a version number -- the
#: tool reports its own version as the literal string "edge" inside the CBOM
#: it writes (there is no separate numbered release to pin against), so the
#: image reference itself is the pin.
IMAGE_REF = "ghcr.io/ibm/cbomkit-theia:latest"

#: The sentence this adapter's visibility entry must always carry, taken
#: (paraphrased) from the tool's own --help output, so a reader is never left
#: thinking this surface covers source-level crypto-call-site detection.
NO_SOURCE_SCANNING_NOTE = (
    "cbomkit-theia does not perform source code scanning (its own --help "
    "says so explicitly); no crypto-call-site detection exists on this "
    "surface, only what its certificates and secrets plugins find inside "
    "the image's filesystem contents."
)

#: A sane per-invocation ceiling, not a confidence value or a cited fact --
#: the default wall-clock budget for one live invocation when the caller does
#: not override it. CLAUDE.md's "per-target timeout" is the hard rule; this
#: number is an engineering default, overridable per call.
DEFAULT_TIMEOUT_SECONDS = 300

#: A cap on how much stdout a single invocation may hand back before this
#: process gives up reading it (CLAUDE.md subprocess default: "output size
#: cap").
MAX_OUTPUT_BYTES = 64 * 1024 * 1024


class TheiaInvocationError(RuntimeError):
    """A live cbomkit-theia subprocess exited non-zero or produced unusable
    output.

    Carries only a description, never the captured stdout/stderr: a
    directory-traversal failure (the recorded real failure mode this surface
    guards against) walks an image's filesystem and its log lines can name
    paths from inside someone else's image, which is exactly the kind of
    text CLAUDE.md's "never echo what you choked on" convention keeps out of
    an exception message.
    """


#: A callable that runs cbomkit-theia against one target and returns the
#: already-parsed CycloneDX document, or raises to report a failure. Injected
#: exactly as tls.adapter.ProbeRunner and packages.adapter.ScanRunner are, so
#: tests replay a recorded document directly and the subprocess boundary
#: stays a single, explicit seam rather than being buried inside `_scan`.
TheiaRunner = Callable[[ScanTarget], dict[str, Any]]


def build_theia_argv(image_ref: str) -> list[str]:
    """The pinned argv for one live cbomkit-theia invocation.

    A pure function so the live-invocation shape can be asserted without
    ever shelling out (mirrors packages.adapter.build_trivy_argv).
    """
    return [
        "docker",
        "run",
        "--rm",
        "-v",
        "/var/run/docker.sock:/var/run/docker.sock",
        IMAGE_REF,
        "image",
        image_ref,
    ]


def live_theia_runner(*, timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS) -> TheiaRunner:
    """Build a `TheiaRunner` that actually shells out to cbomkit-theia over
    the docker socket.

    Kept as a factory returning a plain callable, never the adapter's
    default, exactly as `packages.adapter.live_scan_runner` and
    `tls.adapter.TlsEndpointAdapter`'s mandatory `probe_runner` keep a live
    subprocess path out of the constructor's default -- an adapter can never
    be constructed with a live invocation by accident.
    """

    def _run(target: ScanTarget) -> dict[str, Any]:
        argv = build_theia_argv(target.locator)
        try:
            completed = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise AdapterTimeout(f"cbomkit-theia timed out after {timeout_seconds}s") from exc
        except OSError as exc:
            raise TheiaInvocationError(
                f"could not start cbomkit-theia: {type(exc).__name__}"
            ) from None

        if len(completed.stdout.encode("utf-8", errors="ignore")) > MAX_OUTPUT_BYTES:
            raise TheiaInvocationError("cbomkit-theia stdout exceeded the output-size cap")
        if completed.returncode != 0:
            raise TheiaInvocationError(f"cbomkit-theia exited {completed.returncode}")
        if not completed.stdout.strip():
            raise TheiaInvocationError("cbomkit-theia produced no output for this target")
        try:
            return json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise TheiaInvocationError(
                f"cbomkit-theia stdout was not valid JSON: {type(exc).__name__}"
            ) from None

    return _run


class ImagesAdapter(Adapter):
    adapter_id = "images-cbomkit-theia"

    #: PARTIAL, not FULL: see module docstring -- the tool's own --help says
    #: it does not perform source code scanning, so declaring FULL would
    #: claim call-site coverage nobody implemented.
    support_level = SupportLevel.PARTIAL
    dimensions = (VisibilityDimension.ARTIFACT,)

    def __init__(
        self,
        *,
        base_confidence: float,
        confidence_basis: ConfidenceBasis,
        runner: TheiaRunner,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """`base_confidence` is injected, never defaulted: no cited row
        exists for this surface in data/base_confidence.yaml
        (usable_row_count is 0), so the caller supplies a value together
        with its own justification, exactly as certs/adapter.py and
        tls/adapter.py require."""
        super().__init__(**({"clock": clock} if clock else {}))
        self._base_confidence = base_confidence
        self._confidence_basis = confidence_basis
        self._runner = runner

    # --- emission --------------------------------------------------------

    def _fields(self, asset: ImportedCryptoAsset, evidence_id: str) -> dict[str, FieldValue]:
        """Every field is DECLARED or UNKNOWN, never KNOWN:
        `ImportedCryptoAsset.state` already establishes that a third-party
        CBOM component is a statement, not an observation this process made
        (see its docstring in ecdat/export/cyclonedx.py); nothing here may
        launder that back into stronger certainty.
        """
        refs = (evidence_id,)

        def declared(value: Any) -> FieldValue:
            return FieldValue(value=value, state=EpistemicState.DECLARED, evidence_refs=refs)

        def declared_or_unknown(value: Any) -> FieldValue:
            # UNKNOWN only when the value is genuinely absent (None), never
            # for an empty string: an empty string is itself something the
            # tool emitted, and collapsing it into UNKNOWN would misstate
            # what was actually read.
            if value is None:
                return FieldValue(value=None, state=EpistemicState.UNKNOWN)
            return declared(value)

        return {
            "name": declared(asset.name),
            "asset_type": declared(asset.asset_type),
            "primitive": declared_or_unknown(asset.primitive),
            "oid": declared_or_unknown(asset.oid),
        }

    def _scan(self, target: ScanTarget) -> AdapterRunResult:
        observed_at = self._clock()
        # Any failure here (non-zero exit, unparseable JSON, the recorded
        # directory-traversal mode) is a plain exception from the runner.
        # It is deliberately NOT caught: Adapter.run() converts it into
        # AdapterOutcome.FAILED with a real failure_reason, exactly as it
        # does for CertificateAdapter's FileNotFoundError.
        document = self._runner(target)

        imported = import_cbom(document)

        surface = f"image:{target.locator}"
        raw_ref = f"cbomkit-theia://{target.locator}"

        evidence: list[Evidence] = []
        findings: list[Finding] = []
        for asset in imported:
            evidence_id = f"{self.adapter_id}:{len(evidence)}"
            evidence.append(
                Evidence(
                    evidence_id=evidence_id,
                    source_tool=asset.source_tool,
                    tool_version=asset.source_tool_version,
                    location=surface,
                    base_confidence=self._base_confidence,
                    confidence_basis=self._confidence_basis,
                    raw_ref=raw_ref,
                )
            )
            findings.append(
                Finding(
                    finding_id=f"{self.adapter_id}:{asset.bom_ref}",
                    surface=surface,
                    evidence_refs=(evidence_id,),
                    fields=self._fields(asset, evidence_id),
                )
            )

        raw_captures = (
            RawCapture(
                raw_ref=raw_ref,
                source_tool=imported[0].source_tool if imported else "cbomkit-theia",
                tool_version=imported[0].source_tool_version if imported else "unknown",
                sha256=hashlib.sha256(
                    json.dumps(document, sort_keys=True, ensure_ascii=False).encode("utf-8")
                ).hexdigest(),
                captured_at=observed_at,
            ),
        )

        detail = (
            f"{target.target_id}: cbomkit-theia scanned image {target.locator!r}, "
            f"reported {len(findings)} cryptographic asset(s) as third-party-"
            "DECLARED evidence via import_cbom(), never KNOWN. " + NO_SOURCE_SCANNING_NOTE
        )

        result = AdapterRunResult(
            adapter_id=self.adapter_id,
            support_level=self.support_level,
            target=target,
            outcome=AdapterOutcome.COMPLETED,
            context=ObservationContext(observed_at=observed_at),
            # target.locator, not len(scanned files): the tool scans the
            # image as a whole and does not report per-file paths the way
            # certs/adapter.py's filesystem walk does -- this still proves
            # the image was looked at (TRAP-07: silence != scanned) even
            # when import_cbom() returns zero assets.
            coverage=Coverage(scanned=(target.locator,)),
            visibility=(
                VisibilityEntry(
                    dimension=VisibilityDimension.ARTIFACT,
                    support_level=self.support_level,
                    detail=detail,
                ),
            ),
            raw_captures=raw_captures,
            evidence=tuple(evidence),
            findings=tuple(findings),
        )

        scan_for_secrets(
            result.model_dump_json(), context=f"{self.adapter_id} result for {target.target_id}"
        )
        return result

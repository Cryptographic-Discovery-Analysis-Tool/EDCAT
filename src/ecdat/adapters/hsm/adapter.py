"""PKCS#11/SoftHSM2 metadata adapter (P11, HSM half; spec §3 row "HSM/KMS").

Reads slot, token, object and mechanism inventory through `pkcs11-tool`.
Scope is deliberately narrow: **PKCS#11 metadata only** -- no cloud KMS, no
attestation, no vendor-specific extension. The KMS-export/cloud-reader half
of P11 is a separate, out-of-scope surface with no recorded fixture to build
a parser against (CLAUDE.md: parsers are written only against
tests/fixtures/recorded/).

**What this adapter never does, deliberately:**

* **It never reads, derives, or represents key material.** A private key
  object on a PKCS#11 token is, by construction, an opaque token-internal
  handle -- there is no location and no fingerprint for this adapter to
  store, because unlike a certificate or a keystore entry, the bytes never
  existed outside the module in the first place. The only fact available
  about a private key object is what the token's own attribute set claims
  about it, and that is exactly the headline field this adapter reports:
  whether `Access:` states `never extractable`. `ParsedPkcs11Object` (see
  `parser.py`) has no field that could hold a key.
* **It never reports "we could not verify never-extractable" as an
  ambiguous state.** The field is observed directly off the token's own
  attribute report and is always KNOWN, one way or the other: either the
  `Access:` line said `never extractable` or it did not. There is no third
  state here to invent (the epistemic enum is closed).
* **It never claims a private key exists when it was never shown one.** An
  unauthenticated `--list-objects` run sees public objects only -- private
  objects are invisible, not merely missing an attribute. This adapter emits
  no Finding, and no field on any Finding, that implies a private key was
  looked for and not found in that mode; it says so in the visibility entry
  instead, in words, exactly as `tls.adapter`'s `NASSL_CEILING_NOTE` states
  its own ceiling.
* **It never presents "what the token supports" as "what is in use".** The
  mechanism list from `--list-mechanisms` is capability information about
  the token instance, surfaced on its own token-level Finding with that
  distinction stated explicitly, never folded into a per-object claim.

Real-tool invocation mirrors `packages.adapter.live_scan_runner`, which
itself mirrors `tls.adapter.TlsEndpointAdapter`'s `probe_runner` injection
point: a small dataclass of raw text is the seam, `live_probe_runner()`
builds a callable that actually shells out to `pkcs11-tool` with pinned
flags and a per-invocation timeout, and tests replay a recorded fixture
directly through that same dataclass without ever touching a subprocess. A
PIN, when supplied, reaches the subprocess argv only -- it is never echoed
into a raw capture, a log line, an error message, or any field this adapter
emits (CLAUDE.md: no secret bytes in logs, CLI output, or test snapshots;
a PIN is exactly that kind of secret).
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
from ecdat.adapters.hsm.parser import (
    ParsedPkcs11Object,
    ParsedSlot,
    parse_mechanisms,
    parse_objects,
    parse_slots,
    primary_slot,
)
from ecdat.model.epistemic import EpistemicState
from ecdat.model.evidence import ConfidenceBasis, Evidence
from ecdat.model.field_value import FieldValue
from ecdat.model.finding import Finding
from ecdat.model.topology import ObservationContext
from ecdat.model.visibility import SupportLevel, VisibilityDimension, VisibilityEntry
from ecdat.security.secrets import scan_for_secrets

SOURCE_TOOL = "pkcs11-tool"

#: `pkcs11-tool`'s plain-text listings carry no self-reported version (unlike
#: trivy's JSON or sslyze's JSON, both of which embed one) -- there is
#: nothing in the output for a parser to read it from. Pinned here exactly as
#: `tls.adapter` pins `"3.5.8"` for `openssl s_client`, which has the same
#: property: the version is what the fixtures were recorded against, stated
#: once, not extracted.
TOOL_VERSION = "0.25.0"

#: Per-invocation wall-clock ceiling. `pkcs11-tool` makes three separate
#: calls for one target (slots, objects, mechanisms); this is applied to
#: each one individually, not split across them, so a slow token cannot
#: starve the later calls of budget the earlier ones did not use.
DEFAULT_TIMEOUT_SECONDS = 30

#: CLAUDE.md subprocess default ("output size cap"). Every recorded fixture
#: here is a few KiB; this comfortably bounds a runaway or hostile module.
MAX_OUTPUT_BYTES = 16 * 1024 * 1024


class Pkcs11InvocationError(RuntimeError):
    """A live `pkcs11-tool` subprocess exited non-zero or produced no output.

    Carries only a description, never captured stdout/stderr and never a
    PIN: an invocation error is exactly the kind of message that must not
    become the channel a secret leaks through.
    """


@dataclass(frozen=True)
class Pkcs11ProbeBundle:
    """Raw output of up to three `pkcs11-tool` invocations, before parsing.

    Mirrors `tls.adapter.TlsProbeBundle` and `packages.adapter.
    TrivyScanBundle`: a dataclass of text the adapter has not looked at yet,
    so a test can construct one directly from a recorded fixture without
    ever touching a subprocess.

    `authenticated` records whether `objects_text` came from a `--login` run
    -- it is metadata about *how the probe was taken*, not something the
    adapter could recover by inspecting the text itself (an unauthenticated
    listing does not say "I am unauthenticated"; it just omits every private
    object).
    """

    slots_text: str | None = None
    objects_text: str | None = None
    authenticated: bool = False
    mechanisms_text: str | None = None


#: A callable that runs the probes for one target. Injected so that tests
#: replay recorded output and so the subprocess boundary is explicit rather
#: than buried -- the same reasoning `tls.adapter.ProbeRunner` documents.
Pkcs11ProbeRunner = Callable[[ScanTarget], Pkcs11ProbeBundle]


# --- live invocation ----------------------------------------------------------


def build_pkcs11_argv(
    module_path: str, *, action: str, login: bool = False, pin: str | None = None
) -> list[str]:
    """The pinned argv for one live `pkcs11-tool` invocation.

    A pure function so the live-invocation shape (in particular: that a PIN
    lands only here, never in a log line built elsewhere) can be asserted
    without ever shelling out.
    """
    if action not in ("list-slots", "list-objects", "list-mechanisms"):
        raise ValueError(f"unknown pkcs11-tool action {action!r}")

    argv = ["pkcs11-tool", "--module", module_path]
    if login:
        argv.append("--login")
        if pin is not None:
            argv += ["--pin", pin]
    argv.append(f"--{action}")
    return argv


def live_probe_runner(
    *, module_path: str, pin: str | None = None, timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
) -> Pkcs11ProbeRunner:
    """Build a `Pkcs11ProbeRunner` that actually shells out to `pkcs11-tool`.

    Kept as a factory returning a plain callable, never the adapter's
    default, so an `HsmPkcs11Adapter` can never be constructed with a live
    subprocess path by accident -- exactly as `TlsEndpointAdapter` requires
    `probe_runner` as a mandatory keyword argument with no default.

    Runs `--list-slots` and `--list-mechanisms` unauthenticated (neither
    needs a PIN), and `--list-objects` with `--login`/`--pin` whenever `pin`
    is supplied, unauthenticated otherwise -- so a caller with no PIN still
    gets the honest reduced-visibility listing rather than no listing at
    all. Network egress is a deployment-level control (this module talks to
    a local PKCS#11 module, not a network endpoint); what this function
    enforces is the pinned flags, the per-invocation timeout, and the
    output-size cap below. The PIN is passed to each subprocess's argv only
    -- it is never interpolated into a message this function raises or logs.
    """

    def _invoke(action: str, *, login: bool = False) -> str:
        argv = build_pkcs11_argv(module_path, action=action, login=login, pin=pin if login else None)
        try:
            completed = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise AdapterTimeout(f"pkcs11-tool --{action} timed out after {timeout_seconds}s") from exc
        except OSError as exc:
            raise Pkcs11InvocationError(
                f"could not start pkcs11-tool --{action}: {type(exc).__name__}"
            ) from None

        if len(completed.stdout.encode("utf-8", errors="ignore")) > MAX_OUTPUT_BYTES:
            raise Pkcs11InvocationError(f"pkcs11-tool --{action} stdout exceeded the output-size cap")
        if completed.returncode != 0:
            raise Pkcs11InvocationError(f"pkcs11-tool --{action} exited {completed.returncode}")
        return completed.stdout

    def _run(target: ScanTarget) -> Pkcs11ProbeBundle:
        slots_text = _invoke("list-slots")
        objects_text = _invoke("list-objects", login=pin is not None)
        mechanisms_text = _invoke("list-mechanisms")
        return Pkcs11ProbeBundle(
            slots_text=slots_text,
            objects_text=objects_text,
            authenticated=pin is not None,
            mechanisms_text=mechanisms_text,
        )

    return _run


# --- the adapter ----------------------------------------------------------------


def _surface_id(slot: ParsedSlot) -> str:
    label = slot.token_label or "unlabelled-token"
    identity = slot.serial_number or slot.slot_hex
    return f"pkcs11:{label}:{identity}"


class HsmPkcs11Adapter(Adapter):
    adapter_id = "hsm-pkcs11"

    #: PARTIAL, not FULL: PKCS#11 metadata (slot/token/object/mechanism
    #: inventory) is read; cloud KMS export, remote attestation and
    #: vendor-specific PKCS#11 extensions are not. Declaring FULL would
    #: assert coverage of surfaces nobody has implemented (Lock §4: the
    #: declared level feeds the visibility matrix).
    support_level = SupportLevel.PARTIAL
    dimensions = (VisibilityDimension.HSM_KMS,)

    def __init__(
        self,
        *,
        base_confidence: float,
        confidence_basis: ConfidenceBasis,
        probe_runner: Pkcs11ProbeRunner,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """`base_confidence` is injected, never defaulted: no cited
        source-tool confidence row exists for pkcs11-tool metadata
        (data/base_confidence.yaml usable_row_count == 0), so the caller
        supplies a value together with its own justification, exactly as
        certs/adapter.py and tls/adapter.py require."""
        super().__init__(**({"clock": clock} if clock else {}))
        self._base_confidence = base_confidence
        self._confidence_basis = confidence_basis
        self._probe_runner = probe_runner

    # --- emission ------------------------------------------------------------

    @staticmethod
    def _known(value, evidence_id: str) -> FieldValue:
        return FieldValue(value=value, state=EpistemicState.KNOWN, evidence_refs=(evidence_id,))

    @staticmethod
    def _known_or_unknown(value, evidence_id: str) -> FieldValue:
        if value in (None, (), ""):
            return FieldValue(value=None, state=EpistemicState.UNKNOWN)
        return FieldValue(value=value, state=EpistemicState.KNOWN, evidence_refs=(evidence_id,))

    def _object_fields(self, obj: ParsedPkcs11Object, evidence_id: str) -> dict[str, FieldValue]:
        """Every field is KNOWN or UNKNOWN, never derived: this is metadata
        read directly off the token via `--list-objects`, the same
        evidentiary strength as `CertificateAdapter`'s fields. Field
        presence follows what `pkcs11-tool` actually printed for that
        specific object kind -- a Public Key Object block never printed a
        `never_extractable` line, and a Private Key Object block never
        printed a size or curve, so neither field is fabricated for the
        other kind, not even as an UNKNOWN placeholder."""
        known = self._known
        known_or_unknown = self._known_or_unknown

        fields: dict[str, FieldValue] = {
            "object_kind": known(obj.object_kind, evidence_id),
            "algorithm_family": known(obj.algorithm_family, evidence_id),
            "label": known_or_unknown(obj.label, evidence_id),
            "key_id": known_or_unknown(obj.key_id, evidence_id),
            "usage": known_or_unknown(obj.usage, evidence_id),
            "access_flags": known_or_unknown(obj.access, evidence_id),
        }
        if obj.object_kind == "Public Key Object":
            if obj.algorithm_family == "RSA":
                fields["key_size_bits"] = known_or_unknown(obj.key_size_bits, evidence_id)
            elif obj.algorithm_family == "EC":
                fields["curve_oid"] = known_or_unknown(obj.curve_oid, evidence_id)
        else:  # Private Key Object
            # The headline fact: PKCS#11's own attribute report, read
            # directly, never inferred. Always KNOWN -- the Access line was
            # observed either way; there is no "could not verify" state.
            fields["never_extractable"] = known(bool(obj.never_extractable), evidence_id)
        return fields

    def _scan(self, target: ScanTarget) -> AdapterRunResult:
        observed_at = self._clock()
        bundle = self._probe_runner(target)

        if not bundle.slots_text or not bundle.slots_text.strip():
            raise Pkcs11InvocationError("pkcs11-tool produced no slot listing for this target")

        slot = primary_slot(parse_slots(bundle.slots_text))
        if slot is None:
            raise Pkcs11InvocationError("no initialised token found in --list-slots output")

        surface = _surface_id(slot)
        scanned: list[str] = [f"list-slots {target.locator}"]
        skipped: list[str] = []
        evidence: list[Evidence] = []
        findings: list[Finding] = []
        raw_captures: list[RawCapture] = []

        def capture(raw_ref: str, payload: str) -> str:
            raw_captures.append(
                RawCapture(
                    raw_ref=raw_ref,
                    source_tool=SOURCE_TOOL,
                    tool_version=TOOL_VERSION,
                    sha256=hashlib.sha256(payload.encode("utf-8")).hexdigest(),
                    captured_at=observed_at,
                )
            )
            evidence_id = f"{self.adapter_id}:{len(evidence)}"
            evidence.append(
                Evidence(
                    evidence_id=evidence_id,
                    source_tool=SOURCE_TOOL,
                    tool_version=TOOL_VERSION,
                    location=surface,
                    base_confidence=self._base_confidence,
                    confidence_basis=self._confidence_basis,
                    raw_ref=raw_ref,
                )
            )
            return evidence_id

        # `--list-slots` output is captured for provenance even though no
        # Finding is emitted from it directly -- it is what proves the
        # target was examined, and what `surface` was built from.
        capture(f"pkcs11-slots://{target.locator}", bundle.slots_text)

        objects_detail: str
        if bundle.objects_text is None:
            skipped.append("list-objects: not requested for this run")
            objects_detail = "Object listing was not requested for this run."
        elif not bundle.objects_text.strip():
            skipped.append("list-objects: pkcs11-tool produced no output")
            objects_detail = "Object listing was requested but pkcs11-tool produced no output."
        else:
            objects_evidence = capture(
                f"pkcs11-objects://{target.locator}", bundle.objects_text
            )
            scanned.append(
                f"list-objects {target.locator}"
                + (" (authenticated)" if bundle.authenticated else " (unauthenticated)")
            )
            objects = parse_objects(bundle.objects_text)
            public_count = sum(1 for o in objects if o.object_kind == "Public Key Object")
            private_count = sum(1 for o in objects if o.object_kind == "Private Key Object")

            for index, obj in enumerate(objects):
                kind_tag = "private" if obj.is_private else "public"
                findings.append(
                    Finding(
                        finding_id=(
                            f"{self.adapter_id}:{kind_tag}:{obj.algorithm_family.lower()}:"
                            f"{obj.key_id or index}"
                        ),
                        surface=surface,
                        evidence_refs=(objects_evidence,),
                        fields=self._object_fields(obj, objects_evidence),
                    )
                )

            if bundle.authenticated:
                objects_detail = (
                    f"Object listing authenticated: {public_count} public and "
                    f"{private_count} private key object(s) observed, including "
                    "PKCS#11's own never-extractable attribute for each private key."
                )
            else:
                objects_detail = (
                    f"Object listing UNAUTHENTICATED (no PIN): {public_count} public "
                    "key object(s) observed. Private key objects are invisible "
                    "entirely without authentication, not merely missing an "
                    "attribute -- this run makes no claim about them, positive or "
                    "negative. This is the honest ceiling for unauthenticated access."
                )

        mechanisms_detail: str
        if bundle.mechanisms_text is None:
            skipped.append("list-mechanisms: not requested for this run")
            mechanisms_detail = "Mechanism list was not requested for this run."
        elif not bundle.mechanisms_text.strip():
            skipped.append("list-mechanisms: pkcs11-tool produced no output")
            mechanisms_detail = "Mechanism list was requested but pkcs11-tool produced no output."
        else:
            mechanisms_evidence = capture(
                f"pkcs11-mechanisms://{target.locator}", bundle.mechanisms_text
            )
            scanned.append(f"list-mechanisms {target.locator}")
            mechanisms = parse_mechanisms(bundle.mechanisms_text)
            findings.append(
                Finding(
                    finding_id=f"{self.adapter_id}:mechanisms:{surface}",
                    surface=surface,
                    evidence_refs=(mechanisms_evidence,),
                    fields={
                        "supported_mechanisms": self._known(mechanisms, mechanisms_evidence),
                        "mechanism_count": self._known(len(mechanisms), mechanisms_evidence),
                    },
                )
            )
            mechanisms_detail = (
                f"Token declares support for {len(mechanisms)} mechanism(s) via "
                "--list-mechanisms. This is token CAPABILITY, not observed usage."
            )

        detail = (
            f"{target.target_id}: pkcs11-tool against token "
            f"{slot.token_label or '(unlabelled)'!r} in slot {slot.slot_hex}. "
            f"{objects_detail} {mechanisms_detail}"
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
                    dimension=VisibilityDimension.HSM_KMS,
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

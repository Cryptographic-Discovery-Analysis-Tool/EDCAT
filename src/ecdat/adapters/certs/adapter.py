"""Certificate adapter (P4; spec §3 row "Certificates").

Reads a directory or a single file and emits one Finding per certificate. It
is the first adapter that reaches a *primary evidence anchor*: Final
Architecture Part 5 notes that only two surfaces carry cryptographic purpose
explicitly, and X.509 `keyUsage`/`extendedKeyUsage` is one of them.

What it does NOT do, deliberately:

* **It does not decide a purpose.** It reports the keyUsage bits it read;
  turning those into a UsageContext is `function.classifier`'s job, and that
  classifier marks them INFERRED because a permission is not a usage. An
  adapter that wrote `purpose: key_transport` here would be laundering a
  capability into an observation.
* **It does not judge the certificate.** No expiry verdict, no weak-key
  finding, no chain validation. Lifecycle and trust are separate concerns
  (§6: "Expired certificate on live endpoint | ledger unaffected; lifecycle
  EXPIRED flagged separately"); this adapter's job is to say what is there.
* **It emits no key material**, and proves it: every finding is serialised and
  run through the shared secret guard before the result is returned.

`base_confidence` is injected rather than defaulted, exactly as the Semgrep
adapter does it: no cited source-tool confidence exists yet (OI-004, ADR-002),
so the caller must supply one together with its justification.
"""
from __future__ import annotations

import hashlib
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable

from ecdat.adapters.base import (
    Adapter,
    AdapterOutcome,
    AdapterRunResult,
    Coverage,
    RawCapture,
    ScanTarget,
)
from ecdat.adapters.certs.parser import (
    CERTIFICATE_SUFFIXES,
    CertificateParseError,
    ParsedCertificate,
    load_path,
)
from ecdat.model.epistemic import EpistemicState
from ecdat.model.evidence import ConfidenceBasis, Evidence
from ecdat.model.field_value import FieldValue
from ecdat.model.finding import Finding
from ecdat.model.topology import ObservationContext
from ecdat.model.visibility import SupportLevel, VisibilityDimension, VisibilityEntry
from ecdat.security.secrets import scan_for_secrets

#: python-cryptography is the parser; there is no external tool to version, so
#: the library version is what a fixture would be recorded against.
def _library_version() -> str:
    import cryptography

    return cryptography.__version__


class CertificateAdapter(Adapter):
    adapter_id = "certs-x509"

    #: PARTIAL, not FULL: PEM, DER and PKCS#12 are read; Java keystores (JKS,
    #: BCFKS) and PKCS#7 bundles are not. Declaring FULL here would assert
    #: coverage of keystore formats nobody has implemented, which is exactly
    #: the overstatement the visibility matrix exists to prevent.
    support_level = SupportLevel.PARTIAL
    dimensions = (VisibilityDimension.ARTIFACT,)

    def __init__(
        self,
        *,
        base_confidence: float,
        confidence_basis: ConfidenceBasis,
        keystore_password: bytes | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        super().__init__(**({"clock": clock} if clock else {}))
        self._base_confidence = base_confidence
        self._confidence_basis = confidence_basis
        # Held for the duration of the scan and never recorded. It is not a
        # field on any emitted object, and parser errors are raised without it.
        self._keystore_password = keystore_password

    # --- file discovery ------------------------------------------------------

    def _candidates(self, root: Path) -> tuple[list[Path], list[str]]:
        """(files we will try, paths we skipped and why).

        A skipped path is recorded, never silently dropped: "we did not look
        at this" is a fact the visibility matrix needs.
        """
        if root.is_file():
            return ([root], []) if root.suffix.lower() in CERTIFICATE_SUFFIXES else (
                [],
                [f"{root}: unrecognised extension {root.suffix or '(none)'}"],
            )

        attempt: list[Path] = []
        skipped: list[str] = []
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            if path.suffix.lower() in CERTIFICATE_SUFFIXES:
                attempt.append(path)
            else:
                skipped.append(f"{path}: unrecognised extension {path.suffix or '(none)'}")
        return attempt, skipped

    # --- emission ------------------------------------------------------------

    def _fields(self, certificate: ParsedCertificate, evidence_id: str) -> dict[str, FieldValue]:
        """Every field is KNOWN: we read it out of the artefact. None of them
        is a judgement, so none of them is derived."""
        refs = (evidence_id,)

        def known(value):
            return FieldValue(value=value, state=EpistemicState.KNOWN, evidence_refs=refs)

        def known_or_unknown(value):
            return (
                known(value)
                if value not in (None, (), "")
                else FieldValue(value=None, state=EpistemicState.UNKNOWN)
            )

        return {
            "der_sha256": known(certificate.der_sha256),
            "spki_sha256": known(certificate.spki_sha256),
            "subject": known(certificate.subject),
            "issuer": known(certificate.issuer),
            "serial_number": known(certificate.serial_number),
            "not_before": known(certificate.not_before.date().isoformat()),
            "not_after": known(certificate.not_after.date().isoformat()),
            "public_key_algorithm": known(certificate.public_key_algorithm),
            "public_key_size": known_or_unknown(certificate.public_key_size),
            "public_key_curve": known_or_unknown(certificate.public_key_curve),
            "signature_algorithm": known(certificate.signature_algorithm),
            # Absent extensions are UNKNOWN, not empty: "this certificate
            # states no keyUsage" and "we did not look" must not collapse.
            "key_usage": known_or_unknown(certificate.key_usage),
            "extended_key_usage": known_or_unknown(certificate.extended_key_usage),
            "subject_alt_names": known_or_unknown(certificate.subject_alt_names),
            "is_ca": known(certificate.is_ca),
            "source_format": known(certificate.source_format),
        }

    def _scan(self, target: ScanTarget) -> AdapterRunResult:
        root = Path(target.locator)
        observed_at = self._clock()

        if not root.exists():
            raise FileNotFoundError(target.locator)

        attempt, skipped = self._candidates(root)
        scanned: list[str] = []
        evidence: list[Evidence] = []
        findings: list[Finding] = []
        library_version = _library_version()

        for path in attempt:
            try:
                certificates = load_path(path, password=self._keystore_password)
            except CertificateParseError as error:
                # The message carries a path and an exception TYPE, never the
                # bytes and never the password (parser module contract).
                skipped.append(str(error))
                continue
            except OSError as error:
                skipped.append(f"{path}: unreadable ({type(error).__name__})")
                continue

            scanned.append(str(path))
            raw_sha = hashlib.sha256(path.read_bytes()).hexdigest()

            for index, certificate in enumerate(certificates):
                evidence_id = f"{self.adapter_id}:{len(evidence)}"
                raw_ref = f"file://{path}"
                evidence.append(
                    Evidence(
                        evidence_id=evidence_id,
                        source_tool="python-cryptography",
                        tool_version=library_version,
                        location=f"{path}#{index}",
                        base_confidence=self._base_confidence,
                        confidence_basis=self._confidence_basis,
                        raw_ref=raw_ref,
                    )
                )
                findings.append(
                    Finding(
                        finding_id=f"{self.adapter_id}:{certificate.der_sha256[:16]}:{index}",
                        surface=f"certdir:{root}",
                        evidence_refs=(evidence_id,),
                        fields=self._fields(certificate, evidence_id),
                    )
                )

        raw_captures = tuple(
            RawCapture(
                raw_ref=f"file://{path}",
                source_tool="python-cryptography",
                tool_version=library_version,
                sha256=hashlib.sha256(Path(path).read_bytes()).hexdigest(),
                captured_at=observed_at,
            )
            for path in scanned
        )

        visibility = [
            VisibilityEntry(
                dimension=VisibilityDimension.ARTIFACT,
                support_level=self.support_level,
                detail=(
                    f"{target.target_id}: read {len(scanned)} certificate file(s), "
                    f"skipped {len(skipped)}. PEM/DER/PKCS#12 only -- JKS, BCFKS "
                    "and PKCS#7 are not supported and are reported as skipped."
                ),
            )
        ]

        result = AdapterRunResult(
            adapter_id=self.adapter_id,
            support_level=self.support_level,
            target=target,
            outcome=AdapterOutcome.COMPLETED,
            context=ObservationContext(observed_at=observed_at),
            coverage=Coverage(scanned=tuple(scanned), skipped=tuple(skipped)),
            visibility=tuple(visibility),
            raw_captures=raw_captures,
            evidence=tuple(evidence),
            findings=tuple(findings),
        )

        # The gate, on the way out. This adapter is the one that holds private
        # keys in memory, so it proves it emitted none rather than asserting it.
        scan_for_secrets(
            result.model_dump_json(), context=f"{self.adapter_id} result for {target.target_id}"
        )
        return result


def certificate_findings(result: AdapterRunResult) -> Iterable[Finding]:
    """Convenience for callers that only want the certificates."""
    return result.findings

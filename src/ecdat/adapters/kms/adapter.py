"""AWS KMS adapter (P11, KMS half; spec §3 row "Hardware / cloud").

Reads customer-managed key *metadata* from AWS KMS -- existence, spec,
usage, state, and (for an asymmetric key) the exported public half -- via
the real `aws kms` CLI. Built and tested against LocalStack because no real
AWS account/credentials exist in this environment; see
tests/fixtures/recorded/aws-kms/localstack-3.0.2/README.md for that record
and for exactly why LocalStack was used and what it does and does not
prove. The live path itself (`build_*_argv`, `live_kms_runner`) talks to
the unmodified real `aws kms` API surface -- pointed at LocalStack only via
`--endpoint-url`, an option a real account run simply omits.

**No key material can appear here, by construction of the API itself, not
by anything this module has to enforce.** `describe-key` and `list-keys`
never carry key bytes for any key type -- KMS does not expose a
`CUSTOMER`-managed private key over its API at all, full stop, and a
symmetric key has no public half to export. `get-public-key` carries only
an asymmetric key's PUBLIC half. This is a stronger, structural guarantee
than `hsm-pkcs11` has to make (a PKCS#11 token *can* technically be asked
to export a private key and must refuse and prove it did; here the API
itself never offers the option).

**Every field is KNOWN, not DECLARED.** Unlike `images-cbomkit-theia`
(another tool's third-party assertion, laundered into evidence), this
adapter calls the AWS API directly and reports exactly what it returned --
the same evidentiary strength `hsm-pkcs11` and `certs-x509` already claim
for their own directly-read metadata.

**`spki_sha256` reuses AWS's own bytes directly, no re-derivation.** See
`kms/parser.py::parse_get_public_key_spki_sha256`'s docstring: AWS's
`GetPublicKey` already returns DER-encoded SubjectPublicKeyInfo, the exact
encoding `certs/parser.py` hashes for its own `spki_sha256` field, so this
adapter's KMS keys plug into `correlation/engine.py`'s existing
`shares_public_key_unclaimed` mechanism (a KMS key never gets a
`same-object` Relationship the way two certificates can -- there is no
certificate here, only a raw key, so no `der_sha256` field exists on this
surface at all) with zero engine changes.

**A key that vanished between `list-keys` and `describe-key` is a per-key
skip, never a scan failure.** `describe-key-not-found.stderr.txt` in the
fixture directory is a real recorded `NotFoundException` -- a real race in
a live account (something else deleted the key), not a hypothetical.
"""
from __future__ import annotations

import hashlib
import json
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
from ecdat.adapters.kms.parser import (
    KmsParseError,
    ParsedKmsKey,
    parse_describe_key,
    parse_get_public_key_spki_sha256,
    parse_list_keys,
)
from ecdat.model.epistemic import EpistemicState
from ecdat.model.evidence import ConfidenceBasis, Evidence
from ecdat.model.field_value import FieldValue
from ecdat.model.finding import Finding
from ecdat.model.topology import ObservationContext
from ecdat.model.visibility import SupportLevel, VisibilityDimension, VisibilityEntry
from ecdat.security.secrets import scan_for_secrets

#: A key spec with no asymmetric public half to export. Never call
#: get-public-key for one of these -- AWS itself would refuse, and this
#: adapter should not even try, since it is not a claim this surface makes.
_SYMMETRIC_KEY_SPECS = frozenset({"SYMMETRIC_DEFAULT", "HMAC_224", "HMAC_256", "HMAC_384", "HMAC_512"})

DEFAULT_TIMEOUT_SECONDS = 60
MAX_OUTPUT_BYTES = 8 * 1024 * 1024


class KmsInvocationError(RuntimeError):
    """A live `aws kms` subprocess exited non-zero (other than a per-key
    NotFoundException, handled separately) or produced unusable output.
    Carries only a description, never captured output -- CLAUDE.md's
    convention every other adapter's runner follows."""


@dataclass(frozen=True)
class KmsProbeBundle:
    """Raw output of the `aws kms` calls for one account/region, before
    parsing. Mirrors every other adapter's *ProbeBundle/*ScanBundle shape
    (tls.adapter.TlsProbeBundle, packages.adapter.TrivyScanBundle,
    hsm.adapter.Pkcs11ProbeBundle): plain text a test can construct
    directly from a recorded fixture, never touching a subprocess."""

    list_keys_text: str | None = None
    #: One describe-key response's raw text per key actually described.
    describe_key_texts: tuple[str, ...] = ()
    #: One get-public-key response's raw text per asymmetric key that had
    #: one to export. Shorter than describe_key_texts whenever any key is
    #: symmetric -- that is expected, not a gap.
    public_key_texts: tuple[str, ...] = ()


KmsRunner = Callable[[ScanTarget], KmsProbeBundle]


def build_list_keys_argv(*, endpoint_url: str | None = None, region: str | None = None) -> list[str]:
    """Pure function so the live-invocation shape can be asserted without
    ever shelling out (mirrors every other adapter's build_*_argv)."""
    argv = ["aws"]
    if endpoint_url:
        argv += ["--endpoint-url", endpoint_url]
    if region:
        argv += ["--region", region]
    argv += ["kms", "list-keys", "--output", "json"]
    return argv


def build_describe_key_argv(
    key_id: str, *, endpoint_url: str | None = None, region: str | None = None
) -> list[str]:
    argv = ["aws"]
    if endpoint_url:
        argv += ["--endpoint-url", endpoint_url]
    if region:
        argv += ["--region", region]
    argv += ["kms", "describe-key", "--key-id", key_id, "--output", "json"]
    return argv


def build_get_public_key_argv(
    key_id: str, *, endpoint_url: str | None = None, region: str | None = None
) -> list[str]:
    argv = ["aws"]
    if endpoint_url:
        argv += ["--endpoint-url", endpoint_url]
    if region:
        argv += ["--region", region]
    argv += ["kms", "get-public-key", "--key-id", key_id, "--output", "json"]
    return argv


def live_kms_runner(
    *,
    endpoint_url: str | None = None,
    region: str | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> KmsRunner:
    """Build a `KmsRunner` that actually shells out to the real `aws` CLI.

    `endpoint_url` is the one option that distinguishes a LocalStack run
    from a real AWS account -- omit it entirely for a real account. Kept as
    a factory returning a plain callable, never the adapter's default,
    exactly as every other live_*_runner in this codebase keeps a live
    subprocess path out of a constructor default.
    """

    def _run_one(argv: list[str], *, tool: str, allow_not_found: bool = False) -> str | None:
        try:
            completed = subprocess.run(
                argv, capture_output=True, text=True, timeout=timeout_seconds, check=False
            )
        except subprocess.TimeoutExpired as exc:
            raise AdapterTimeout(f"{tool} timed out after {timeout_seconds}s") from exc
        except OSError as exc:
            raise KmsInvocationError(f"could not start aws: {type(exc).__name__}") from None

        if len(completed.stdout.encode("utf-8", errors="ignore")) > MAX_OUTPUT_BYTES:
            raise KmsInvocationError(f"{tool} stdout exceeded the output-size cap")
        if completed.returncode != 0:
            if allow_not_found and "NotFoundException" in completed.stderr:
                return None
            raise KmsInvocationError(f"{tool} exited {completed.returncode}")
        return completed.stdout

    def _run(target: ScanTarget) -> KmsProbeBundle:
        list_keys_text = _run_one(
            build_list_keys_argv(endpoint_url=endpoint_url, region=region), tool="list-keys"
        )
        key_ids = parse_list_keys(json.loads(list_keys_text)) if list_keys_text else ()

        describe_texts: list[str] = []
        public_key_texts: list[str] = []
        for key_id in key_ids:
            described = _run_one(
                build_describe_key_argv(key_id, endpoint_url=endpoint_url, region=region),
                tool="describe-key",
                allow_not_found=True,
            )
            if described is None:
                continue  # vanished between list-keys and describe-key
            describe_texts.append(described)
            spec = str((json.loads(described).get("KeyMetadata") or {}).get("KeySpec", ""))
            if spec and spec not in _SYMMETRIC_KEY_SPECS:
                public_key = _run_one(
                    build_get_public_key_argv(key_id, endpoint_url=endpoint_url, region=region),
                    tool="get-public-key",
                    allow_not_found=True,
                )
                if public_key is not None:
                    public_key_texts.append(public_key)

        return KmsProbeBundle(
            list_keys_text=list_keys_text,
            describe_key_texts=tuple(describe_texts),
            public_key_texts=tuple(public_key_texts),
        )

    return _run


class KmsAdapter(Adapter):
    adapter_id = "kms-aws"

    #: PARTIAL, not FULL: this is metadata only (existence, spec, usage,
    #: state) for AWS KMS specifically -- no other cloud provider, no usage
    #: observation (a key existing says nothing about whether anything
    #: calls Encrypt/Sign with it).
    support_level = SupportLevel.PARTIAL
    dimensions = (VisibilityDimension.HSM_KMS,)

    def __init__(
        self,
        *,
        base_confidence: float,
        confidence_basis: ConfidenceBasis,
        runner: KmsRunner,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """`base_confidence` is injected, never defaulted: no cited row
        exists for this surface in data/base_confidence.yaml
        (usable_row_count is 0), so the caller supplies a value together
        with its own justification, exactly as every other adapter here
        requires."""
        super().__init__(**({"clock": clock} if clock else {}))
        self._base_confidence = base_confidence
        self._confidence_basis = confidence_basis
        self._runner = runner

    # --- emission --------------------------------------------------------

    def _fields(
        self, key: ParsedKmsKey, evidence_id: str, spki_sha256: str | None
    ) -> dict[str, FieldValue]:
        refs = (evidence_id,)

        def known(value) -> FieldValue:
            return FieldValue(value=value, state=EpistemicState.KNOWN, evidence_refs=refs)

        def known_or_unknown(value) -> FieldValue:
            if value in (None, (), ""):
                return FieldValue(value=None, state=EpistemicState.UNKNOWN)
            return known(value)

        fields = {
            "description": known_or_unknown(key.description),
            "enabled": known(key.enabled),
            "key_state": known(key.key_state),
            "key_usage": known(key.key_usage),
            "key_spec": known(key.key_spec),
            "origin": known(key.origin),
            "key_manager": known(key.key_manager),
            "creation_date": known_or_unknown(
                key.creation_date.isoformat() if key.creation_date else None
            ),
            "signing_algorithms": known_or_unknown(key.signing_algorithms),
            "encryption_algorithms": known_or_unknown(key.encryption_algorithms),
        }
        if spki_sha256 is not None:
            # Named identically to certs-x509's own spki_sha256 field for
            # the same reason tls/adapter.py and images/adapter.py give:
            # correlation/engine.py's shares_public_key_unclaimed match
            # looks for exactly this field name. No der_sha256 exists on
            # this surface -- there is no certificate here, only a raw key.
            fields["spki_sha256"] = known(spki_sha256)
        return fields

    def _scan(self, target: ScanTarget) -> AdapterRunResult:
        observed_at = self._clock()
        bundle = self._runner(target)

        if not bundle.list_keys_text:
            raise KmsInvocationError("aws kms list-keys produced no output for this target")

        raw_captures: list[RawCapture] = [
            RawCapture(
                raw_ref=f"aws-kms-list-keys://{target.locator}",
                source_tool="aws-cli",
                tool_version="unknown",
                sha256=hashlib.sha256(bundle.list_keys_text.encode("utf-8")).hexdigest(),
                captured_at=observed_at,
            )
        ]

        # Public keys are matched to their describe-key entry by KeyId --
        # both responses carry it, and this is the only reliable join key
        # (the two calls are not guaranteed to be in the same order once
        # more than one thing can fail independently).
        public_key_by_key_id: dict[str, str] = {}
        for text in bundle.public_key_texts:
            document = json.loads(text)
            key_arn_or_id = str(document.get("KeyId", ""))
            key_id = key_arn_or_id.rsplit("/", 1)[-1]
            try:
                public_key_by_key_id[key_id] = parse_get_public_key_spki_sha256(document)
            except KmsParseError:
                continue
            raw_captures.append(
                RawCapture(
                    raw_ref=f"aws-kms-get-public-key://{target.locator}/{key_id}",
                    source_tool="aws-cli",
                    tool_version="unknown",
                    sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
                    captured_at=observed_at,
                )
            )

        surface = f"kms:{target.locator}"
        evidence: list[Evidence] = []
        findings: list[Finding] = []
        scanned: list[str] = []
        skipped: list[str] = []

        for text in bundle.describe_key_texts:
            try:
                key = parse_describe_key(json.loads(text))
            except KmsParseError as exc:
                skipped.append(f"unreadable describe-key response: {exc}")
                continue
            scanned.append(key.key_id)
            raw_captures.append(
                RawCapture(
                    raw_ref=f"aws-kms-describe-key://{target.locator}/{key.key_id}",
                    source_tool="aws-cli",
                    tool_version="unknown",
                    sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
                    captured_at=observed_at,
                )
            )
            evidence_id = f"{self.adapter_id}:{len(evidence)}"
            evidence.append(
                Evidence(
                    evidence_id=evidence_id,
                    source_tool="aws-cli",
                    tool_version="unknown",
                    location=f"{target.locator}/{key.key_id}",
                    base_confidence=self._base_confidence,
                    confidence_basis=self._confidence_basis,
                    raw_ref=f"aws-kms-describe-key://{target.locator}/{key.key_id}",
                )
            )
            findings.append(
                Finding(
                    finding_id=f"{self.adapter_id}:{key.key_id}",
                    surface=surface,
                    evidence_refs=(evidence_id,),
                    fields=self._fields(key, evidence_id, public_key_by_key_id.get(key.key_id)),
                )
            )

        detail = (
            f"{target.target_id}: aws kms list-keys + describe-key against {target.locator!r}, "
            f"{len(scanned)} key(s) described. Metadata only -- key existence, spec, usage and "
            "state, never key material (AWS's own API refuses to export a CUSTOMER-managed "
            "private key; a symmetric key has no public half). No usage observation: a key "
            "existing says nothing about whether anything actually calls Encrypt/Sign with it. "
            "AWS KMS only -- no other cloud provider's key service is covered by this adapter."
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

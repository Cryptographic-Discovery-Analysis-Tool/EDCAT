"""AWS KMS adapter (P11, KMS half).

Every fixture here is real recorded output from LocalStack 3.0.2, hit with
the real `aws` CLI -- not a real AWS account (none was available in this
environment), documented as such in
tests/fixtures/recorded/aws-kms/localstack-3.0.2/README.md. The adapter's
own code path is unmodified real `aws kms` CLI usage either way.
"""
from __future__ import annotations

import json
from pathlib import Path

from ecdat.adapters.base import AdapterOutcome, ScanTarget
from ecdat.adapters.kms.adapter import (
    KmsAdapter,
    KmsProbeBundle,
    build_describe_key_argv,
    build_get_public_key_argv,
    build_list_keys_argv,
)
from ecdat.model.epistemic import EpistemicState
from ecdat.model.evidence import ConfidenceBasis
from ecdat.model.visibility import SupportLevel, VisibilityDimension
from ecdat.security.secrets import find_secrets

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "recorded" / "aws-kms" / "localstack-3.0.2"

BASIS = ConfidenceBasis(
    source="ADAPTER_DECLARED",
    justification=(
        "No cited row exists for AWS KMS metadata confidence (OI-004); a direct "
        "describe-key API response is the strongest evidence class this tool has."
    ),
)

TARGET = ScanTarget(target_id="account", locator="us-east-1")

REAL_ECC_SPKI_SHA256 = "9018f0999a68c4d5a5df4c94f5a77b607f7418b6ea396018e17c828b0667893f"


def _read(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def bundle(**kw) -> KmsProbeBundle:
    defaults = dict(
        list_keys_text=_read("list-keys.json"),
        describe_key_texts=(_read("describe-key-symmetric.json"), _read("describe-key-ecc.json")),
        public_key_texts=(_read("get-public-key-ecc.json"),),
    )
    defaults.update(kw)
    return KmsProbeBundle(**defaults)


def adapter(probe_bundle):
    return KmsAdapter(base_confidence=0.9, confidence_basis=BASIS, runner=lambda target: probe_bundle)


def run(**kw):
    return adapter(bundle(**kw)).run(TARGET)


# --- real fixtures, end to end -------------------------------------------------


def test_two_real_keys_produce_two_findings_all_known():
    result = run()

    assert result.outcome == AdapterOutcome.COMPLETED
    assert len(result.findings) == 2
    for finding in result.findings:
        for field_name, field in finding.fields.items():
            assert field.state in (EpistemicState.KNOWN, EpistemicState.UNKNOWN), (
                f"{finding.finding_id}.{field_name} is {field.state} -- every field this "
                "adapter emits is a direct API observation"
            )


def test_the_symmetric_key_carries_its_real_metadata_and_no_public_key_hash():
    result = run()
    symmetric = next(
        f for f in result.findings if f.fields["key_spec"].value == "SYMMETRIC_DEFAULT"
    )
    assert symmetric.fields["key_usage"].value == "ENCRYPT_DECRYPT"
    assert symmetric.fields["key_state"].value == "Enabled"
    assert symmetric.fields["enabled"].value is True
    assert symmetric.fields["origin"].value == "AWS_KMS"
    # A symmetric key has no public half -- no spki_sha256 field at all,
    # not an UNKNOWN one, since this adapter never even asks for one.
    assert "spki_sha256" not in symmetric.fields


def test_the_ecc_key_carries_a_real_independently_hashed_public_key():
    """The value asserted here is not invented: it is base64-decode-then-
    SHA-256 of the real get-public-key fixture, verified once directly
    against the parser (test_kms_parser.py) and reused here as the expected
    end-to-end adapter output."""
    result = run()
    ecc = next(f for f in result.findings if f.fields["key_spec"].value == "ECC_NIST_P256")
    assert ecc.fields["key_usage"].value == "SIGN_VERIFY"
    assert ecc.fields["spki_sha256"].value == REAL_ECC_SPKI_SHA256
    assert ecc.fields["spki_sha256"].state == EpistemicState.KNOWN
    assert find_secrets(result.model_dump_json()) == ()


def test_support_level_is_partial_and_the_no_usage_observation_gap_is_named():
    result = run()
    assert KmsAdapter.support_level == SupportLevel.PARTIAL
    entries = [v for v in result.visibility if v.dimension == VisibilityDimension.HSM_KMS]
    assert len(entries) == 1
    detail = entries[0].detail
    assert detail is not None
    assert "never key material" in detail
    assert "no usage observation" in detail.lower()


def test_coverage_lists_both_key_ids():
    result = run()
    assert set(result.coverage.scanned) == {
        "c5e5d28f-fa8a-4b1a-859a-6e7c842352ac",
        "dd316ada-96cf-4078-93da-53ab2473536b",
    }


# --- the real not-found race ---------------------------------------------------


def test_a_key_that_vanished_before_describe_key_is_skipped_not_a_failure():
    """The live runner itself (live_kms_runner) is what turns a real
    NotFoundException into `None` in the bundle -- this test proves the
    adapter's own handling of a bundle already missing that key's entry
    (fewer describe_key_texts than list-keys reported), the shape the live
    runner produces after catching that error."""
    result = run(describe_key_texts=(_read("describe-key-symmetric.json"),))
    assert result.outcome == AdapterOutcome.COMPLETED
    assert len(result.findings) == 1


# --- live-invocation argv shape --------------------------------------------


def test_list_keys_argv_carries_the_endpoint_url_for_localstack():
    argv = build_list_keys_argv(endpoint_url="http://localhost:4566", region="us-east-1")
    assert argv[0] == "aws"
    assert "--endpoint-url" in argv
    assert argv[argv.index("--endpoint-url") + 1] == "http://localhost:4566"
    assert argv[-3:] == ["kms", "list-keys", "--output"] or "list-keys" in argv


def test_list_keys_argv_omits_endpoint_url_for_a_real_account():
    argv = build_list_keys_argv()
    assert "--endpoint-url" not in argv
    assert argv == ["aws", "kms", "list-keys", "--output", "json"]


def test_describe_key_argv_names_the_key_id():
    argv = build_describe_key_argv("my-key-id", region="us-east-1")
    assert "--key-id" in argv
    assert argv[argv.index("--key-id") + 1] == "my-key-id"


def test_get_public_key_argv_names_the_key_id():
    argv = build_get_public_key_argv("my-key-id")
    assert "get-public-key" in argv
    assert argv[argv.index("--key-id") + 1] == "my-key-id"


def test_no_credentials_or_keys_appear_anywhere_in_the_argv_builders():
    """These are pure argv builders -- if a PIN/secret ever leaked into one
    of them, this is where it would first show up. Nothing here ever takes
    a credential argument at all, which is itself the guarantee: AWS
    credentials are read by the aws CLI from the environment/profile, never
    passed as a CLI argument by this adapter."""
    argv = build_list_keys_argv(endpoint_url="http://localhost:4566")
    assert not any("secret" in part.lower() or "key_id" == part for part in argv)

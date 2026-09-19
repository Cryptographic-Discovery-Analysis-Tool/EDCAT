"""Certificate adapter (P4; spec §3 row "Certificates").

Runs against the real Tier A PKI in the sibling harness checkout when it is
present, and against synthetic certificates otherwise, so the suite is green
on a clean clone.
"""
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from ecdat.adapters.base import AdapterOutcome, ScanTarget
from ecdat.adapters.certs.adapter import CertificateAdapter
from ecdat.adapters.certs.parser import CertificateParseError, load_pem_or_der, load_path
from ecdat.model.epistemic import EpistemicState
from ecdat.model.evidence import ConfidenceBasis
from ecdat.security.secrets import SecretLeakError

HARNESS_PKI = Path(__file__).resolve().parents[4] / "ecdat-harness" / "harness" / "build" / "out"

BASIS = ConfidenceBasis(
    source="ADAPTER_DECLARED",
    justification=(
        "No cited row exists for certificate parsing (OI-004); a certificate read "
        "directly from an artefact is the strongest evidence class this tool has."
    ),
)


def adapter(**kw):
    return CertificateAdapter(base_confidence=0.95, confidence_basis=BASIS, **kw)


# --- synthetic certificates -------------------------------------------------


def _make_certificate(tmp_path: Path, *, name: str, key=None, usage=None) -> Path:
    key = key or ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
    )
    if usage is not None:
        builder = builder.add_extension(usage, critical=True)
    certificate = builder.sign(key, hashes.SHA256())
    path = tmp_path / f"{name}.pem"
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return path


def test_pem_and_der_of_one_certificate_hash_identically(tmp_path):
    """'Canonicalised' means the hash is over re-encoded DER, so the same
    certificate in two containers is one object."""
    pem_path = _make_certificate(tmp_path, name="same-object")
    (parsed_pem,) = load_pem_or_der(pem_path.read_bytes(), location="pem")

    certificate = x509.load_pem_x509_certificate(pem_path.read_bytes())
    der = certificate.public_bytes(serialization.Encoding.DER)
    (parsed_der,) = load_pem_or_der(der, location="der")

    assert parsed_pem.der_sha256 == parsed_der.der_sha256
    assert parsed_pem.spki_sha256 == parsed_der.spki_sha256
    assert parsed_pem.source_format == "PEM"
    assert parsed_der.source_format == "DER"


def test_two_certificates_over_one_key_share_spki_but_not_der(tmp_path):
    """The distinction the two hashes exist for: a reissued certificate is a
    different object over the same key."""
    key = ec.generate_private_key(ec.SECP256R1())
    first = _make_certificate(tmp_path, name="first", key=key)
    second = _make_certificate(tmp_path, name="second", key=key)
    (a,) = load_path(first)
    (b,) = load_path(second)
    assert a.spki_sha256 == b.spki_sha256, "same key"
    assert a.der_sha256 != b.der_sha256, "different object"


def test_key_usage_bits_use_x509_spellings(tmp_path):
    """The classifier matches on X.509 field names, so the parser must emit
    them, not cryptography's snake_case attribute names."""
    path = _make_certificate(
        tmp_path,
        name="usage",
        key=rsa.generate_private_key(public_exponent=65537, key_size=2048),
        usage=x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
    )
    (parsed,) = load_path(path)
    assert parsed.key_usage == ("digitalSignature", "keyEncipherment")
    assert parsed.public_key_algorithm == "RSA"
    assert parsed.public_key_size == 2048


def test_a_private_key_file_is_refused_without_echoing_it(tmp_path):
    """The failure path must not put key bytes in an exception message."""
    key = ec.generate_private_key(ec.SECP256R1())
    path = tmp_path / "key.pem"
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    with pytest.raises(CertificateParseError) as caught:
        load_path(path)
    assert "PRIVATE KEY" not in str(caught.value)
    assert "MII" not in str(caught.value)


def test_an_unopenable_keystore_raises_rather_than_reporting_empty(tmp_path):
    path = tmp_path / "locked.p12"
    path.write_bytes(b"not actually a pkcs12 file")
    with pytest.raises(CertificateParseError, match="could not be opened"):
        load_path(path, password=b"wrong")


# --- the adapter ------------------------------------------------------------


def test_adapter_reports_what_it_skipped(tmp_path):
    _make_certificate(tmp_path, name="real")
    (tmp_path / "notes.txt").write_text("not a certificate")
    result = adapter().run(ScanTarget(target_id="dir", locator=str(tmp_path)))

    assert result.outcome == AdapterOutcome.COMPLETED
    assert len(result.findings) == 1
    assert any("notes.txt" in s for s in result.coverage.skipped)
    assert "JKS" in result.visibility[0].detail, "unsupported formats are named"


def test_adapter_emits_no_purpose(tmp_path):
    """Purpose is the classifier's job and is INFERRED there. An adapter that
    emitted it would launder a capability into an observation."""
    _make_certificate(tmp_path, name="plain")
    (finding,) = adapter().run(ScanTarget(target_id="d", locator=str(tmp_path))).findings
    assert "purpose" not in finding.fields
    assert "function" not in finding.fields


def test_adapter_emits_no_verdict_on_expiry(tmp_path):
    """§6: 'Expired certificate on live endpoint | ledger unaffected;
    lifecycle EXPIRED flagged separately.'"""
    _make_certificate(tmp_path, name="dates")
    (finding,) = adapter().run(ScanTarget(target_id="d", locator=str(tmp_path))).findings
    assert finding.fields["not_after"].state == EpistemicState.KNOWN
    assert not any(
        key in finding.fields for key in ("expired", "is_expired", "lifecycle", "valid")
    )


def test_absent_extension_is_unknown_not_empty(tmp_path):
    """'States no keyUsage' and 'we did not look' must not collapse."""
    _make_certificate(tmp_path, name="no-usage")
    (finding,) = adapter().run(ScanTarget(target_id="d", locator=str(tmp_path))).findings
    assert finding.fields["key_usage"].state == EpistemicState.UNKNOWN


def test_a_directory_of_only_private_keys_yields_no_findings_but_says_it_looked(tmp_path):
    """TRAP-07: zero findings plus coverage proving the target was examined."""
    key = ec.generate_private_key(ec.SECP256R1())
    (tmp_path / "id.pem").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    result = adapter().run(ScanTarget(target_id="keys", locator=str(tmp_path)))
    assert result.findings == ()
    assert result.coverage.skipped, "the file was seen and rejected, not ignored"
    assert result.visibility


def test_the_secret_guard_runs_on_the_way_out(tmp_path, monkeypatch):
    """The gate must be on the emission path, not a separate lint."""
    _make_certificate(tmp_path, name="guarded")
    import ecdat.adapters.certs.adapter as module

    def leaky(*args, **kwargs):
        raise SecretLeakError("guard fired")

    monkeypatch.setattr(module, "scan_for_secrets", leaky)
    with pytest.raises(SecretLeakError):
        adapter()._scan(ScanTarget(target_id="d", locator=str(tmp_path)))


def test_missing_path_is_a_failed_outcome_not_a_crash(tmp_path):
    result = adapter().run(
        ScanTarget(target_id="gone", locator=str(tmp_path / "nope"))
    )
    assert result.outcome == AdapterOutcome.FAILED
    assert result.findings == ()
    assert result.failure_reason == "FileNotFoundError"


# --- against the real Tier A PKI --------------------------------------------

pytestmark_harness = pytest.mark.skipif(
    not HARNESS_PKI.exists(), reason="sibling harness checkout not present"
)


@pytestmark_harness
def test_real_pki_parses_and_finds_the_edge_certificate():
    result = adapter(keystore_password=b"changeit").run(
        ScanTarget(target_id="tier-a-pki", locator=str(HARNESS_PKI))
    )
    assert result.outcome == AdapterOutcome.COMPLETED
    subjects = {f.fields["subject"].value for f in result.findings}
    assert any("pay-edge" in s for s in subjects)
    assert any("Harness Root CA" in s for s in subjects)


@pytestmark_harness
def test_the_same_certificate_in_two_files_is_one_object():
    """cert.pem and the bundled pay-edge.pem hold the same leaf."""
    result = adapter(keystore_password=b"changeit").run(
        ScanTarget(target_id="tier-a-pki", locator=str(HARNESS_PKI))
    )
    edge = [
        f for f in result.findings if "pay-edge" in (f.fields["subject"].value or "")
    ]
    assert len(edge) >= 2
    assert len({f.fields["der_sha256"].value for f in edge}) == 1


@pytestmark_harness
def test_a_keystore_yields_certificates_and_never_the_key():
    result = adapter(keystore_password=b"changeit").run(
        ScanTarget(target_id="p12", locator=str(HARNESS_PKI / "gateway-p12" / "gateway.p12"))
    )
    assert result.outcome == AdapterOutcome.COMPLETED
    assert result.findings
    assert all(f.fields["source_format"].value == "PKCS12" for f in result.findings)
    # The guard already ran inside _scan; assert the serialised result directly.
    from ecdat.security.secrets import find_secrets

    assert find_secrets(result.model_dump_json()) == ()

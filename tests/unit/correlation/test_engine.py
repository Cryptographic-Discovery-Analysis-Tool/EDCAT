"""The correlation engine (correlate()): one asset view across adapters.

Runs the REAL CertificateAdapter against synthetic certificates (not a
hand-built Finding) so the DER-hash identity path is exercised the same way
it would be from `ecdat correlate`, not just against a mocked shape.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from ecdat.adapters.base import ScanTarget
from ecdat.adapters.certs.adapter import CertificateAdapter
from ecdat.adapters.tls.adapter import TlsEndpointAdapter, TlsProbeBundle
from ecdat.correlation.engine import ForbiddenEdgeError, correlate
from ecdat.model.epistemic import EpistemicState
from ecdat.model.evidence import ConfidenceBasis
from ecdat.model.relationship import EvidenceBasis, Relationship
from ecdat.model.topology import ProbeTargetIdentity

BASIS = ConfidenceBasis(source="ADAPTER_DECLARED", justification="test invocation, no cited table exists")

# Real recorded material, both already committed in this repo.
FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "recorded"
SSLYZE_JSON = FIXTURES / "sslyze" / "6.2.0" / "tier_a_edge_lb.raw.json"
# The sibling harness repo's real Tier A PKI -- the file `cert.pem` here is
# the exact certificate the sslyze fixture above recorded live from the wire.
HARNESS_PKI = Path(__file__).resolve().parents[4] / "ecdat-harness" / "harness" / "build" / "out"
pytestmark_harness = pytest.mark.skipif(
    not HARNESS_PKI.exists(), reason="sibling harness checkout not present"
)


def _write_cert(path, *, key=None, name="test-cert"):
    key = key or ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return key


def _certs_adapter():
    return CertificateAdapter(base_confidence=0.9, confidence_basis=BASIS)


def test_correlate_with_no_results_is_empty():
    report = correlate([])
    assert report.assets == ()
    assert report.relationships == ()
    assert report.source_adapter_ids == ()


def test_single_adapter_result_produces_assets_and_no_relationships(tmp_path):
    _write_cert(tmp_path / "a.pem")
    result = _certs_adapter().run(ScanTarget(target_id="d", locator=str(tmp_path)))

    report = correlate([result])

    assert len(report.assets) == 1
    assert report.relationships == ()
    assert report.source_adapter_ids == ("certs-x509",)


def test_the_same_certificate_in_two_different_directories_is_linked_by_der_hash(tmp_path):
    """The core cross-surface case: the identical certificate -- the exact
    same DER bytes, e.g. the same file copied into two services' cert
    directories -- produces two separate CryptoAssets (never merged:
    different scope_anchor) linked by a real same-object Relationship, using
    the one registered identity rule. (Two INDEPENDENTLY generated
    certificates over the same key are NOT byte-identical DER -- serial
    number and validity timestamps differ -- so this test copies one real
    certificate's bytes, not "generate twice with the same key".)"""
    dir_a = tmp_path / "service-a"
    dir_b = tmp_path / "service-b"
    dir_a.mkdir()
    dir_b.mkdir()
    _write_cert(dir_a / "cert.pem", name="shared-cert")
    (dir_b / "cert.pem").write_bytes((dir_a / "cert.pem").read_bytes())

    result_a = _certs_adapter().run(ScanTarget(target_id="a", locator=str(dir_a)))
    result_b = _certs_adapter().run(ScanTarget(target_id="b", locator=str(dir_b)))

    report = correlate([result_a, result_b])

    assert len(report.assets) == 2
    assert {asset.scope_anchor for asset in report.assets} == {f"certdir:{dir_a}", f"certdir:{dir_b}"}

    (relationship,) = report.relationships
    assert relationship.type == "same-object"
    assert relationship.evidence_basis == EvidenceBasis.CONTENT_IDENTITY
    assert relationship.rule_id == "IDENTITY-CERT-DER-001"
    assert relationship.epistemic_state == EpistemicState.KNOWN
    assert {relationship.source_entity, relationship.target_entity} == {a.asset_id for a in report.assets}
    assert relationship.evidence_refs


def test_two_different_certificates_are_not_linked(tmp_path):
    dir_a = tmp_path / "service-a"
    dir_b = tmp_path / "service-b"
    dir_a.mkdir()
    dir_b.mkdir()
    _write_cert(dir_a / "cert.pem", name="cert-a")
    _write_cert(dir_b / "cert.pem", name="cert-b")

    result_a = _certs_adapter().run(ScanTarget(target_id="a", locator=str(dir_a)))
    result_b = _certs_adapter().run(ScanTarget(target_id="b", locator=str(dir_b)))

    report = correlate([result_a, result_b])

    assert len(report.assets) == 2
    assert report.relationships == ()


def test_two_certificates_sharing_a_key_but_different_der_are_unclaimed_not_related(tmp_path):
    """Same public key, reissued certificate (different DER -- different
    serial/subject) -- a real 'shares-public-key' signal this engine
    deliberately does not turn into a Relationship (no registered rule_id
    for it). It must show up as an explicit unclaimed pair, not vanish."""
    key = ec.generate_private_key(ec.SECP256R1())
    dir_a = tmp_path / "service-a"
    dir_b = tmp_path / "service-b"
    dir_a.mkdir()
    dir_b.mkdir()
    _write_cert(dir_a / "cert.pem", key=key, name="first-issue")
    _write_cert(dir_b / "cert.pem", key=key, name="second-issue")

    result_a = _certs_adapter().run(ScanTarget(target_id="a", locator=str(dir_a)))
    result_b = _certs_adapter().run(ScanTarget(target_id="b", locator=str(dir_b)))

    report = correlate([result_a, result_b])

    assert report.relationships == ()
    assert len(report.shares_public_key_unclaimed) == 1
    (pair,) = report.shares_public_key_unclaimed
    assert set(pair) == {a.asset_id for a in report.assets}


def test_forbidden_edge_raises_rather_than_silently_dropping(monkeypatch, tmp_path):
    """If some future change to _identity_relationships ever produced a
    structurally-forbidden edge, the engine must fail loudly, not return a
    report that looks clean. Simulated here by monkeypatching the gate to
    always object, proving the engine actually wires the gate's answer to
    a real failure mode rather than ignoring it."""
    import ecdat.correlation.engine as engine_module

    def always_reject(relationships):
        return ("simulated rejection",) if relationships else ()

    dir_a = tmp_path / "service-a"
    dir_b = tmp_path / "service-b"
    dir_a.mkdir()
    dir_b.mkdir()
    _write_cert(dir_a / "cert.pem", name="shared")
    (dir_b / "cert.pem").write_bytes((dir_a / "cert.pem").read_bytes())
    result_a = _certs_adapter().run(ScanTarget(target_id="a", locator=str(dir_a)))
    result_b = _certs_adapter().run(ScanTarget(target_id="b", locator=str(dir_b)))

    monkeypatch.setattr(engine_module, "check_forbidden_edges", always_reject)
    with pytest.raises(ForbiddenEdgeError) as caught:
        correlate([result_a, result_b])
    assert caught.value.violations == ("simulated rejection",)


def test_a_self_edge_never_slips_through_even_with_one_asset_group():
    """Defensive: _identity_relationships must never propose source==target
    even in a degenerate grouping. Exercised directly since building a real
    single-asset duplicate through the adapter is awkward to construct."""
    from ecdat.correlation.engine import _identity_relationships
    from ecdat.model.asset import CryptoAsset
    from ecdat.model.field_value import FieldValue

    field = FieldValue(value="deadbeef", state=EpistemicState.KNOWN, evidence_refs=("e1",))
    asset = CryptoAsset(asset_id="asset:only-one", fields={"der_sha256": field})

    relationships, unclaimed = _identity_relationships((asset,))
    assert relationships == ()
    assert unclaimed == ()


# --- real cross-surface case: the same certificate, TLS wire vs. disk --------


@pytestmark_harness
def test_the_wire_certificate_and_the_on_disk_certificate_are_the_same_object():
    """The case this whole extension exists for: `tls-endpoint`'s live-
    recorded handshake (sslyze fixture, committed in this repo) presented
    the exact certificate that sits on disk in the real Tier A PKI (sibling
    harness checkout) as `pay-edge/cert.pem`. Two completely different
    surfaces -- a wire capture and a filesystem read -- correlate to one
    real-world object with no synthetic data anywhere in this test."""
    tls_probe = TlsProbeBundle(sslyze_json=SSLYZE_JSON.read_text(encoding="utf-8"))
    tls_adapter = TlsEndpointAdapter(
        base_confidence=0.95, confidence_basis=BASIS, probe_runner=lambda target: tls_probe
    )
    tls_target = ScanTarget(
        target_id="tier-a-edge-lb",
        locator="172.18.0.3:8443",
        consent=True,
        probe=ProbeTargetIdentity(
            requested_host="172.18.0.3", port=8443, sni_sent="pay-edge", probe_vantage="docker:payments-internal"
        ),
    )
    tls_result = tls_adapter.run(tls_target)

    certs_adapter = CertificateAdapter(base_confidence=0.95, confidence_basis=BASIS)
    certs_result = certs_adapter.run(
        ScanTarget(target_id="pay-edge-pki", locator=str(HARNESS_PKI / "pay-edge" / "cert.pem"))
    )

    report = correlate([tls_result, certs_result])

    assert set(report.source_adapter_ids) == {"tls-endpoint", "certs-x509"}
    (relationship,) = report.relationships
    assert relationship.type == "same-object"
    assert relationship.rule_id == "IDENTITY-CERT-DER-001"
    assert relationship.evidence_basis == EvidenceBasis.CONTENT_IDENTITY
    tls_asset = next(a for a in report.assets if a.scope_anchor == "tls:172.18.0.3:8443")
    certs_asset = next(a for a in report.assets if a.scope_anchor != "tls:172.18.0.3:8443")
    assert {relationship.source_entity, relationship.target_entity} == {
        tls_asset.asset_id,
        certs_asset.asset_id,
    }

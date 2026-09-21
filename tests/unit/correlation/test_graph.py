"""The evidence graph view (build-plan.md P15).

Runs the REAL CertificateAdapter against synthetic certificates, the same
way test_engine.py does, so every claimed and unclaimed edge here is read
off a real correlate() report -- nothing hand-built to match graph.py.
"""
from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, timezone

from ecdat.adapters.base import ScanTarget
from ecdat.adapters.certs.adapter import CertificateAdapter
from ecdat.correlation.engine import correlate
from ecdat.correlation.graph import CHAIN_GAPS, EdgeStrength, build_graph
from ecdat.model.evidence import ConfidenceBasis

BASIS = ConfidenceBasis(source="ADAPTER_DECLARED", justification="test invocation, no cited table exists")


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


def test_empty_report_produces_an_empty_graph_with_named_gaps():
    graph = build_graph(correlate([]))
    assert graph.nodes == ()
    assert graph.edges == ()
    assert graph.gaps == CHAIN_GAPS
    assert len(graph.gaps) == 2


def test_same_object_relationship_becomes_a_claimed_edge(tmp_path):
    dir_a, dir_b = tmp_path / "a", tmp_path / "b"
    dir_a.mkdir()
    dir_b.mkdir()
    _write_cert(dir_a / "cert.pem", name="shared-cert")
    (dir_b / "cert.pem").write_bytes((dir_a / "cert.pem").read_bytes())

    result_a = _certs_adapter().run(ScanTarget(target_id="a", locator=str(dir_a)))
    result_b = _certs_adapter().run(ScanTarget(target_id="b", locator=str(dir_b)))
    report = correlate([result_a, result_b])

    graph = build_graph(report)
    assert len(graph.nodes) == 2
    (edge,) = graph.edges
    assert edge.strength == EdgeStrength.CLAIMED
    assert edge.type == "same-object"
    assert edge.rule_id == "IDENTITY-CERT-DER-001"
    assert edge.evidence_basis == "content_identity"
    assert edge.epistemic_state is not None
    assert graph.claimed_edges == (edge,)
    assert graph.unclaimed_edges == ()


def test_shares_public_key_unclaimed_becomes_a_visibly_weaker_edge_never_claimed(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    dir_a, dir_b = tmp_path / "a", tmp_path / "b"
    dir_a.mkdir()
    dir_b.mkdir()
    _write_cert(dir_a / "cert.pem", key=key, name="first-issue")
    _write_cert(dir_b / "cert.pem", key=key, name="second-issue")

    result_a = _certs_adapter().run(ScanTarget(target_id="a", locator=str(dir_a)))
    result_b = _certs_adapter().run(ScanTarget(target_id="b", locator=str(dir_b)))
    report = correlate([result_a, result_b])

    graph = build_graph(report)
    (edge,) = graph.edges
    assert edge.strength == EdgeStrength.UNCLAIMED
    assert edge.strength != EdgeStrength.CLAIMED, "must never collapse into same-object"
    assert edge.type == "shares_public_key_unclaimed"
    assert edge.rule_id is None, "OI-006: no registered rule_id exists for this claim"
    assert graph.claimed_edges == ()
    assert graph.unclaimed_edges == (edge,)


def test_every_edge_states_its_type_and_epistemic_basis(tmp_path):
    """Hard requirement, checked structurally: no edge this module can
    produce is missing its type or its basis, whichever strength it is."""
    dir_a, dir_b = tmp_path / "a", tmp_path / "b"
    dir_a.mkdir()
    dir_b.mkdir()
    _write_cert(dir_a / "cert.pem", name="shared")
    (dir_b / "cert.pem").write_bytes((dir_a / "cert.pem").read_bytes())
    result_a = _certs_adapter().run(ScanTarget(target_id="a", locator=str(dir_a)))
    result_b = _certs_adapter().run(ScanTarget(target_id="b", locator=str(dir_b)))
    graph = build_graph(correlate([result_a, result_b]))

    for edge in graph.edges:
        assert edge.type
        assert edge.note
        if edge.strength == EdgeStrength.CLAIMED:
            assert edge.evidence_basis is not None
            assert edge.epistemic_state is not None
            assert edge.rule_id is not None
        else:
            assert edge.rule_id is None


def test_refused_chain_links_are_named_gaps_not_blank_space():
    graph = build_graph(correlate([]))
    layers = {(g.from_layer, g.to_layer) for g in graph.gaps}
    assert ("library", "usage") in layers
    assert ("service", "protected data") in layers
    for gap in graph.gaps:
        assert gap.why

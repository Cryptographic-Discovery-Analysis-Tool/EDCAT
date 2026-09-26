"""Scan -> ledger bridge (build-plan.md P21).

Every input is a real adapter run over a recorded fixture (the live Tier A
TLS probe, our own semgrep rules over the Tier A Java tree) or a certificate
generated here -- never a hand-built Finding shaped to fit the bridge.
"""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from ecdat.adapters.base import ScanTarget
from ecdat.adapters.certs.adapter import CertificateAdapter
from ecdat.adapters.source.semgrep import SemgrepSourceAdapter
from ecdat.adapters.tls.adapter import TlsEndpointAdapter, TlsProbeBundle
from ecdat.assemble import BindingDeclaration, Declarations, assemble
from ecdat.context.binding import Lifetime
from ecdat.model.epistemic import EpistemicState
from ecdat.model.evidence import ConfidenceBasis
from ecdat.model.topology import ProbeTargetIdentity
from ecdat.model.usage_context import CryptoFunction
from ecdat.risk.record import ExposureBand, Qualifier
from ecdat.risk.run import evaluate_run
from ecdat.risk.scenarios import CaptureAssumption, CaptureMode, Policy, Scenario

BASIS = ConfidenceBasis(source="ADAPTER_DECLARED", justification="test value; no cited confidence table (OI-004)")
F = Path(__file__).resolve().parents[2] / "fixtures" / "recorded"
SURFACE = "tls:172.18.0.3:8443"
AS_OF = date(2026, 9, 23)
POLICY = Policy(
    capture_assumption=CaptureAssumption(mode=CaptureMode.SINCE_CONFIRMED),
    rollout_Y_default=Lifetime(days=365),
)


def _tls(*, classical: bool = True, negotiated: bool = True):
    probe = ProbeTargetIdentity(
        requested_host="172.18.0.3", port=8443, sni_sent="pay-edge", probe_vantage="docker:payments-internal"
    )
    bundle = TlsProbeBundle(
        sslyze_json=(F / "sslyze/6.2.0/tier_a_edge_lb.raw.json").read_text(encoding="utf-8"),
        negotiated_text=(
            (F / "openssl/3.5.8/tier_a_edge_lb.negotiated.txt").read_text(encoding="utf-8")
            if negotiated
            else ""
        ),
        classical_only_text=(
            (F / "openssl/3.5.8/tier_a_edge_lb.classical_only.txt").read_text(encoding="utf-8")
            if classical
            else ""
        ),
    )
    adapter = TlsEndpointAdapter(base_confidence=0.95, confidence_basis=BASIS, probe_runner=lambda t: bundle)
    return adapter.run(ScanTarget(target_id="edge", locator="172.18.0.3:8443", consent=True, probe=probe))


GROUP_PROBE_DIR = F / "openssl" / "3.5.4" / "hybrid_groups_probe" / "hybrid_server"
GROUP_PROBE_VERSION = (
    F / "openssl" / "3.5.4" / "hybrid_groups_probe" / "openssl_version.txt"
).read_text(encoding="utf-8")


def _tls_with_group_probe(groups: tuple[str, ...]):
    """Same recorded Tier A full-offer/classical-only probes as `_tls()`,
    plus real DEV-013 individual-group recordings from the throwaway local
    hybrid-enabled `s_server` (a different, unrelated endpoint from the
    Tier A one -- only the group-probe fields from this bundle are under
    test here, not cross-endpoint consistency)."""
    probe = ProbeTargetIdentity(
        requested_host="172.18.0.3", port=8443, sni_sent="pay-edge", probe_vantage="docker:payments-internal"
    )
    bundle = TlsProbeBundle(
        sslyze_json=(F / "sslyze/6.2.0/tier_a_edge_lb.raw.json").read_text(encoding="utf-8"),
        negotiated_text=(F / "openssl/3.5.8/tier_a_edge_lb.negotiated.txt").read_text(encoding="utf-8"),
        classical_only_text=(F / "openssl/3.5.8/tier_a_edge_lb.classical_only.txt").read_text(encoding="utf-8"),
        group_probe_texts={
            g: (GROUP_PROBE_DIR / f"probe_{g}.txt").read_text(encoding="utf-8") for g in groups
        },
        group_probe_openssl_version=GROUP_PROBE_VERSION,
    )
    adapter = TlsEndpointAdapter(base_confidence=0.95, confidence_basis=BASIS, probe_runner=lambda t: bundle)
    return adapter.run(ScanTarget(target_id="edge", locator="172.18.0.3:8443", consent=True, probe=probe))


def _source():
    adapter = SemgrepSourceAdapter(base_confidence=0.5, confidence_basis=BASIS)
    path = F / "semgrep/1.99.0/ecdat-rules/tier-a-java.raw.json"
    return adapter.run(ScanTarget(target_id="src", locator=str(path)))


def _certs(tmp_path, *, key_usage: bool = True):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "bridge-test")])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2024, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
    )
    if key_usage:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
    (tmp_path / "cert.pem").write_bytes(
        builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)
    )
    adapter = CertificateAdapter(base_confidence=0.9, confidence_basis=BASIS)
    return adapter.run(ScanTarget(target_id="certs", locator=str(tmp_path)))


def _by_suffix(assembly, suffix):
    return [s for s in assembly.subjects if s.usage_context.usage_context_id.endswith(suffix)]


# --- TLS ----------------------------------------------------------------------


def test_a_tls_probe_yields_observed_kex_and_auth_contexts():
    assembly = assemble([_tls()])
    (kex,) = _by_suffix(assembly, "|kex")
    (auth,) = _by_suffix(assembly, "|auth")
    assert kex.usage_context.function.value == CryptoFunction.HYBRID_KEX
    assert kex.usage_context.function.state == EpistemicState.KNOWN
    assert auth.usage_context.function.value == CryptoFunction.SIGNATURE_AUTH


def test_first_observed_is_the_probe_date_and_is_known():
    result = _tls()
    (kex,) = _by_suffix(assemble([result]), "|kex")
    assert kex.temporal.first_observed.value == result.context.observed_at.date()
    assert kex.temporal.first_observed.state == EpistemicState.KNOWN


def test_classical_still_accepted_becomes_its_own_banded_row():
    """The recorded Tier A classical-only probe succeeded: a client with no
    hybrid group still gets classical key establishment. That is an observed
    exposure and must not be hidden behind the hybrid row."""
    declarations = Declarations(
        bindings=(BindingDeclaration(surface=SURFACE, data_class="TEST.X_7Y", declared_by="test"),)
    )
    assembly = assemble([_tls()], declarations=declarations)
    (classical,) = _by_suffix(assembly, "|classical-client")
    assert classical.usage_context.function.value == CryptoFunction.KEY_ESTABLISHMENT

    run = evaluate_run(list(assembly.subjects), scenario=Scenario.load("Z_aggressive"), policy=POLICY, as_of=AS_OF)
    by_suffix = {r.usage_context_id.rsplit("|", 1)[-1]: r for r in run.records}
    assert by_suffix["classical-client"].band == ExposureBand.BLEEDING
    assert Qualifier.PARTIAL in by_suffix["classical-client"].qualifiers
    assert by_suffix["kex"].band == ExposureBand.SAFE


def test_no_classical_probe_means_no_classical_row():
    assembly = assemble([_tls(classical=False)])
    assert _by_suffix(assembly, "|classical-client") == []


def test_no_negotiated_handshake_is_unassembled_not_invented():
    assembly = assemble([_tls(negotiated=False)])
    assert assembly.subjects == ()
    assert any("not observed" in u.reason for u in assembly.unassembled)


def test_migration_evidence_rides_on_kex_rows_only():
    assembly = assemble([_tls()])
    assert all(len(s.migrations) == 1 for s in _by_suffix(assembly, "|kex"))
    assert all(s.migrations == () for s in _by_suffix(assembly, "|auth"))


# --- DEV-013: individual group-probe subjects --------------------------------


def test_an_accepted_hybrid_group_other_than_the_preferred_one_gets_its_own_subject():
    """The Tier A full-offer probe prefers X25519MLKEM768; the group-probe
    fixture also shows SecP256r1MLKEM768 individually accepted. That is
    migration evidence the full-offer probe alone would never produce, and
    the recommendation engine / ledger must see it as its own row."""
    assembly = assemble([_tls_with_group_probe(("X25519MLKEM768", "SecP256r1MLKEM768"))])
    rows = _by_suffix(assembly, "|group-probe-SecP256r1MLKEM768")
    assert len(rows) == 1
    assert rows[0].usage_context.function.value == CryptoFunction.HYBRID_KEX
    assert rows[0].usage_context.function.state == EpistemicState.KNOWN
    assert len(rows[0].migrations) == 1
    assert rows[0].migrations[0].negotiated_group == "SecP256r1MLKEM768"


def test_the_preferred_group_is_not_duplicated_as_a_group_probe_subject():
    """X25519MLKEM768 is both the full-offer preference AND individually
    accepted -- it must appear once (the main |kex row), not twice."""
    assembly = assemble([_tls_with_group_probe(("X25519MLKEM768",))])
    assert _by_suffix(assembly, "|group-probe-X25519MLKEM768") == []
    assert len(_by_suffix(assembly, "|kex")) == 1


def test_a_refused_group_produces_no_group_probe_subject():
    """secp256r1 was refused by the fixture's hybrid server (it was not in
    that server's -groups list) -- refused is not migration evidence."""
    assembly = assemble([_tls_with_group_probe(("X25519MLKEM768", "secp256r1"))])
    assert _by_suffix(assembly, "|group-probe-secp256r1") == []


def test_no_group_probe_bundle_produces_no_group_probe_subjects_at_all():
    assembly = assemble([_tls()])
    assert [s for s in assembly.subjects if "group-probe" in s.usage_context.usage_context_id] == []


# --- declarations -------------------------------------------------------------


def test_undeclared_surfaces_carry_no_binding_and_stay_unbounded():
    assembly = assemble([_tls()])
    assert all(s.binding_key is None for s in assembly.subjects)
    run = evaluate_run(list(assembly.subjects), scenario=Scenario.load("Z_central"), policy=POLICY, as_of=AS_OF)
    assert all(r.band == ExposureBand.UNBOUNDED for r in run.records)


def test_an_asset_declaration_beats_a_surface_declaration():
    result = _tls()
    (auth,) = _by_suffix(assemble([result]), "|auth")
    declarations = Declarations(
        bindings=(
            BindingDeclaration(surface=SURFACE, data_class="TEST.X_7Y", declared_by="team"),
            BindingDeclaration(asset=auth.usage_context.asset_id, data_class="TEST.A_SESSION", declared_by="pki"),
        )
    )
    assembly = assemble([result], declarations=declarations)
    (auth,) = _by_suffix(assembly, "|auth")
    (kex,) = _by_suffix(assembly, "|kex")
    assert auth.binding_key == "TEST.A_SESSION"
    assert kex.binding_key == "TEST.X_7Y"
    assert "declared by pki" in auth.binding_source_ref


def test_a_declaration_must_name_a_target_and_an_author():
    with pytest.raises(ValueError):
        BindingDeclaration(data_class="TEST.X_7Y", declared_by="x")
    with pytest.raises(ValueError):
        BindingDeclaration(surface=SURFACE, data_class="TEST.X_7Y", declared_by=" ")


def test_declarations_load_from_yaml(tmp_path):
    path = tmp_path / "declarations.yaml"
    path.write_text(
        "bindings:\n  - surface: tls:172.18.0.3:8443\n    data_class: TEST.X_7Y\n    declared_by: team\n",
        encoding="utf-8",
    )
    declarations = Declarations.load(path)
    assert declarations.binding_for(surface_id=SURFACE, asset_id="x").data_class == "TEST.X_7Y"


# --- certificates -------------------------------------------------------------


def test_certificate_key_usage_yields_inferred_capability_with_possible_start(tmp_path):
    assembly = assemble([_certs(tmp_path)])
    (subject,) = assembly.subjects
    assert subject.usage_context.function.value == CryptoFunction.SIGNATURE_AUTH
    assert subject.usage_context.function.state == EpistemicState.INFERRED
    assert subject.temporal.not_before.value == date(2024, 1, 1)
    assert subject.temporal.first_observed is None, "notBefore bounds possibility, never confirmation"


def test_a_certificate_with_no_key_usage_is_named_not_dropped(tmp_path):
    assembly = assemble([_certs(tmp_path, key_usage=False)])
    assert assembly.subjects == ()
    assert any("no keyUsage" in u.reason for u in assembly.unassembled)


# --- source -------------------------------------------------------------------


def test_every_call_site_becomes_a_subject_and_the_binding_declaration_does_not():
    assembly = assemble([_source()])
    locations = {s.usage_context.asset_id.rsplit("/", 1)[-1] for s in assembly.subjects}
    assert locations == {
        "KeyWrapService.java:25", "LegacyCardHash.java:21", "TokenVault.java:22", "WebhookSigner.java:17"
    }
    assert any("not a crypto call site" in u.reason for u in assembly.unassembled)


def test_a_call_site_invents_no_start_date():
    for subject in assemble([_source()]).subjects:
        assert subject.temporal.first_observed is None
        assert subject.temporal.possible_since is None


# --- whole pipeline -----------------------------------------------------------


def test_packages_are_named_as_no_context_by_design():
    class _Stub:
        adapter_id = "packages-trivy"
        findings = ()

    assembly = assemble([_Stub()])
    assert "capability, never usage" in assembly.unassembled[0].reason


def test_assembled_subjects_round_trip_through_the_fixture_shape(tmp_path):
    import json

    from ecdat.api.app import load_subjects

    assembly = assemble([_tls(), _source()])
    path = tmp_path / "subjects.json"
    path.write_text(json.dumps(assembly.to_subjects_document()), encoding="utf-8")
    loaded = load_subjects(path)
    assert [s.usage_context.usage_context_id for s in loaded] == [
        s.usage_context.usage_context_id for s in assembly.subjects
    ]


def test_every_assembled_subject_evaluates_without_error():
    assembly = assemble([_tls(), _source()])
    for scenario in Scenario.load_all():
        run = evaluate_run(list(assembly.subjects), scenario=scenario, policy=POLICY, as_of=AS_OF)
        assert len(run.records) + len(run.grover_flags) + len(run.skipped) == len(assembly.subjects)

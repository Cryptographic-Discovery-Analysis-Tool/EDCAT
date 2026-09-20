"""The CLI wiring (cli.py) for all eight adapters.

Every test here drives `main()` the way a real invocation would (an argv
list), against REAL recorded fixtures already committed under
tests/fixtures/recorded/ -- not synthesised JSON -- so a broken builder
(wrong bundle field, wrong runner signature) fails here the same way it
would on the command line, not just when called directly from Python as the
adapters' own unit tests do.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, timezone

from ecdat.cli import ADAPTERS, BUILDERS, main

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "recorded"

SEMGREP_INPUT = FIXTURES / "semgrep" / "1.99.0" / "ecdat-rules" / "tier-a-java.raw.json"
TRIVY_INPUT = FIXTURES / "trivy" / "0.74.0" / "e1_supplemental_payment-gateway-fatjar.raw.json"
THEIA_INPUT = FIXTURES / "theia" / "edge-2026-09-19" / "edge-lb.sample.json"
YARA_INPUT = FIXTURES / "yara" / "4.5.0" / "libcrypto.match.verbose.txt"
READELF_HEADER_INPUT = FIXTURES / "readelf" / "tier_a_edge_lb.libcrypto.header.txt"
READELF_DYNAMIC_INPUT = FIXTURES / "readelf" / "tier_a_edge_lb.libcrypto.soname.txt"
PKCS11_SLOTS_INPUT = FIXTURES / "pkcs11-tool" / "opensc-0.25.0" / "list-slots.txt"
PKCS11_OBJECTS_INPUT = FIXTURES / "pkcs11-tool" / "opensc-0.25.0" / "list-objects-authenticated.txt"
PKCS11_MECHANISMS_INPUT = FIXTURES / "pkcs11-tool" / "opensc-0.25.0" / "list-mechanisms.txt"
SSLYZE_INPUT = FIXTURES / "sslyze" / "6.2.0" / "tier_a_edge_lb.raw.json"
NEGOTIATED_INPUT = FIXTURES / "openssl" / "3.5.8" / "tier_a_edge_lb.negotiated.txt"
CLASSICAL_ONLY_INPUT = FIXTURES / "openssl" / "3.5.8" / "tier_a_edge_lb.classical_only.txt"

COMMON = [
    "--target-id", "t", "--confidence", "0.9",
    "--confidence-justification", "test invocation, no cited table exists yet",
]


def _run(argv: list[str], out_path: Path, capsys) -> dict:
    exit_code = main(["scan", *COMMON, "--out", str(out_path), *argv])
    assert exit_code == 0, capsys.readouterr().err
    return json.loads(out_path.read_text(encoding="utf-8"))


# --- registry completeness ----------------------------------------------------


def test_every_declared_adapter_has_a_cli_builder():
    """The whole point of this task: no adapter exists that the CLI cannot
    reach. If a ninth adapter is ever added without a BUILDERS entry, this
    fails immediately instead of silently leaving it unreachable."""
    assert set(ADAPTERS) == set(BUILDERS)
    assert len(ADAPTERS) == 8


# --- adapters that read a local path directly ----------------------------------


def test_semgrep_via_cli(tmp_path, capsys):
    document = _run(
        ["--adapter", "source-semgrep", "--input", str(SEMGREP_INPUT)],
        tmp_path / "out.json",
        capsys,
    )
    assert document["adapter_id"] == "source-semgrep"
    assert document["outcome"] == "completed"
    assert document["findings"]


def test_certs_via_cli(tmp_path, capsys):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "cli-test")])
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
    cert_path = tmp_path / "cert.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))

    document = _run(
        ["--adapter", "certs-x509", "--input", str(cert_path)], tmp_path / "out.json", capsys
    )
    assert document["adapter_id"] == "certs-x509"
    assert document["outcome"] == "completed"
    assert len(document["findings"]) == 1


def test_config_via_cli(tmp_path, capsys):
    resources = tmp_path / "src" / "main" / "resources"
    resources.mkdir(parents=True)
    (resources / "application.yml").write_text(
        "pay:\n  keywrap:\n    transformation: RSA/ECB/OAEPWithSHA-256AndMGF1Padding\n",
        encoding="utf-8",
    )
    document = _run(
        [
            "--adapter", "config-chain-spring",
            "--input", str(tmp_path),
            "--property-key", "pay.keywrap.transformation",
        ],
        tmp_path / "out.json",
        capsys,
    )
    assert document["adapter_id"] == "config-chain-spring"
    (finding,) = document["findings"]
    resolved = next(f for f in finding["fields"] if f["field"] == "resolved_value")
    assert resolved["epistemic_state"] == "INFERRED"
    assert resolved["value"] == "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"


def test_config_without_property_key_is_a_usage_error(tmp_path):
    assert main(["scan", *COMMON, "--adapter", "config-chain-spring", "--input", str(tmp_path)]) == 2


# --- adapters that wrap a tool behind a runner (replay mode) -------------------


def test_packages_replay_via_cli(tmp_path, capsys):
    document = _run(
        ["--adapter", "packages-trivy", "--input", str(TRIVY_INPUT)], tmp_path / "out.json", capsys
    )
    assert document["adapter_id"] == "packages-trivy"
    assert document["outcome"] == "completed"
    assert document["findings"]
    assert all(
        f not in field["field"]
        for field in document["findings"][0]["fields"]
        for f in ("purpose", "function", "in_use")
    )


def test_images_replay_via_cli(tmp_path, capsys):
    document = _run(
        ["--adapter", "images-cbomkit-theia", "--input", str(THEIA_INPUT)], tmp_path / "out.json", capsys
    )
    assert document["adapter_id"] == "images-cbomkit-theia"
    assert document["outcome"] == "completed"
    states = {f["epistemic_state"] for finding in document["findings"] for f in finding["fields"]}
    assert "KNOWN" not in states


def test_binary_replay_via_cli(tmp_path, capsys):
    document = _run(
        [
            "--adapter", "binary-yara-readelf",
            "--yara-input", str(YARA_INPUT),
            "--readelf-header-input", str(READELF_HEADER_INPUT),
            "--readelf-dynamic-input", str(READELF_DYNAMIC_INPUT),
        ],
        tmp_path / "out.json",
        capsys,
    )
    assert document["adapter_id"] == "binary-yara-readelf"
    assert document["outcome"] == "completed"
    (finding,) = document["findings"]
    fields = {f["field"]: f for f in finding["fields"]}
    assert "AES" in str(fields["embedded_constant_families"]["value"])


def test_binary_replay_requires_at_least_one_input(tmp_path):
    assert main(["scan", *COMMON, "--adapter", "binary-yara-readelf"]) == 2


def test_hsm_replay_via_cli(tmp_path, capsys):
    document = _run(
        [
            "--adapter", "hsm-pkcs11",
            "--pkcs11-slots-input", str(PKCS11_SLOTS_INPUT),
            "--pkcs11-objects-input", str(PKCS11_OBJECTS_INPUT),
            "--pkcs11-mechanisms-input", str(PKCS11_MECHANISMS_INPUT),
            "--authenticated",
        ],
        tmp_path / "out.json",
        capsys,
    )
    assert document["adapter_id"] == "hsm-pkcs11"
    assert document["outcome"] == "completed"
    assert document["findings"]


def test_tls_replay_via_cli(tmp_path, capsys):
    document = _run(
        [
            "--adapter", "tls-endpoint",
            "--host", "172.18.0.3",
            "--port", "8443",
            "--sni", "pay-edge",
            "--vantage", "cli-test",
            "--consent",
            "--sslyze-input", str(SSLYZE_INPUT),
            "--negotiated-input", str(NEGOTIATED_INPUT),
            "--classical-only-input", str(CLASSICAL_ONLY_INPUT),
        ],
        tmp_path / "out.json",
        capsys,
    )
    assert document["adapter_id"] == "tls-endpoint"
    assert document["outcome"] == "completed"
    (finding,) = document["findings"]
    group = next(f for f in finding["fields"] if f["field"] == "negotiated_group")
    assert group["value"] == "X25519MLKEM768"


def test_tls_without_vantage_is_a_usage_error():
    assert main(
        [
            "scan", *COMMON, "--adapter", "tls-endpoint",
            "--host", "h", "--sslyze-input", str(SSLYZE_INPUT),
        ]
    ) == 2


def test_tls_live_is_not_supported_from_the_cli():
    assert main(
        [
            "scan", *COMMON, "--adapter", "tls-endpoint",
            "--host", "h", "--vantage", "v", "--live",
        ]
    ) == 2


# --- live-mode argument requirements (no real subprocess touched) --------------


def test_packages_live_requires_input(tmp_path):
    assert main(["scan", *COMMON, "--adapter", "packages-trivy", "--live"]) == 2


def test_hsm_live_requires_pkcs11_module(tmp_path):
    assert main(["scan", *COMMON, "--adapter", "hsm-pkcs11", "--live"]) == 2


def test_binary_live_requires_input(tmp_path):
    assert main(["scan", *COMMON, "--adapter", "binary-yara-readelf", "--live"]) == 2


def test_images_live_requires_input(tmp_path):
    assert main(["scan", *COMMON, "--adapter", "images-cbomkit-theia", "--live"]) == 2


def test_unknown_adapter_is_rejected():
    with pytest.raises(SystemExit):
        main(["scan", *COMMON, "--adapter", "not-a-real-adapter"])

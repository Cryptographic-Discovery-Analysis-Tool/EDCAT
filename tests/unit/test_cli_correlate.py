"""`ecdat correlate`: a JSON plan of several scans -> one asset view.

Drives `main()` with a real plan file on disk, against real certificate
material (the same synthetic-cert pattern test_cli.py uses), so the whole
path -- plan parsing, re-using BUILDERS, running N adapters in one process,
correlate() -- is exercised the way a real invocation would be.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from ecdat.cli import main

COMMON_ENTRY = {
    "confidence": 0.9,
    "confidence_justification": "test invocation, no cited table exists yet",
}


def _write_cert(path: Path, *, name: str = "cli-correlate-test") -> None:
    key = ec.generate_private_key(ec.SECP256R1())
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


def _write_plan(path: Path, entries: list[dict]) -> None:
    path.write_text(json.dumps(entries), encoding="utf-8")


def test_correlate_two_scans_with_the_same_certificate_links_them(tmp_path, capsys):
    dir_a = tmp_path / "a"
    dir_b = tmp_path / "b"
    dir_a.mkdir()
    dir_b.mkdir()
    _write_cert(dir_a / "cert.pem")
    (dir_b / "cert.pem").write_bytes((dir_a / "cert.pem").read_bytes())

    plan_path = tmp_path / "plan.json"
    _write_plan(
        plan_path,
        [
            {**COMMON_ENTRY, "adapter": "certs-x509", "target_id": "a", "input": str(dir_a)},
            {**COMMON_ENTRY, "adapter": "certs-x509", "target_id": "b", "input": str(dir_b)},
        ],
    )

    out_path = tmp_path / "report.json"
    exit_code = main(["correlate", "--plan", str(plan_path), "--out", str(out_path)])
    assert exit_code == 0, capsys.readouterr().err

    report = json.loads(out_path.read_text(encoding="utf-8"))
    assert report["source_adapter_ids"] == ["certs-x509"]
    assert len(report["assets"]) == 2
    (relationship,) = report["relationships"]
    assert relationship["type"] == "same-object"
    assert relationship["rule_id"] == "IDENTITY-CERT-DER-001"
    assert relationship["epistemic_state"] == "KNOWN"


def test_correlate_single_scan_produces_assets_no_relationships(tmp_path, capsys):
    _write_cert(tmp_path / "cert.pem")
    plan_path = tmp_path / "plan.json"
    _write_plan(plan_path, [{**COMMON_ENTRY, "adapter": "certs-x509", "target_id": "a", "input": str(tmp_path)}])

    out_path = tmp_path / "report.json"
    assert main(["correlate", "--plan", str(plan_path), "--out", str(out_path)]) == 0
    report = json.loads(out_path.read_text(encoding="utf-8"))
    assert len(report["assets"]) == 1
    assert report["relationships"] == []


def test_correlate_plan_entry_missing_required_key_is_a_usage_error(tmp_path):
    plan_path = tmp_path / "plan.json"
    _write_plan(plan_path, [{"adapter": "certs-x509", "target_id": "a"}])  # no confidence fields
    assert main(["correlate", "--plan", str(plan_path)]) == 2


def test_correlate_empty_plan_is_a_usage_error(tmp_path):
    plan_path = tmp_path / "plan.json"
    _write_plan(plan_path, [])
    assert main(["correlate", "--plan", str(plan_path)]) == 2


def test_correlate_unknown_adapter_in_plan_is_a_usage_error(tmp_path):
    plan_path = tmp_path / "plan.json"
    _write_plan(plan_path, [{**COMMON_ENTRY, "adapter": "not-real", "target_id": "a"}])
    assert main(["correlate", "--plan", str(plan_path)]) == 2


def test_correlate_missing_plan_file_is_a_usage_error(tmp_path):
    assert main(["correlate", "--plan", str(tmp_path / "does-not-exist.json")]) == 2


def test_correlate_requires_plan_flag():
    with pytest.raises(SystemExit):
        main(["correlate"])

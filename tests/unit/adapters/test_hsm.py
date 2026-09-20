"""PKCS#11/SoftHSM2 metadata adapter (P11, HSM half; spec §3 row "HSM/KMS").

Every fixture here was recorded from a real, freshly-initialised SoftHSM2
2.6.1 token with a real RSA-2048 and a real EC P-256 key pair generated ON
the token via pkcs11-tool/OpenSC 0.25.0 -- see
tests/fixtures/recorded/pkcs11-tool/opensc-0.25.0/README.md for full
provenance. This suite does not run pkcs11-tool itself (CLAUDE.md: parsers
are written only against tests/fixtures/recorded/); the live-invocation
shape is exercised through the pure `build_pkcs11_argv` function only.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from ecdat.adapters.base import AdapterOutcome, ScanTarget
from ecdat.adapters.hsm.adapter import (
    HsmPkcs11Adapter,
    Pkcs11ProbeBundle,
    build_pkcs11_argv,
)
from ecdat.model.epistemic import EpistemicState
from ecdat.model.evidence import ConfidenceBasis
from ecdat.model.visibility import SupportLevel, VisibilityDimension
from ecdat.security.secrets import find_secrets

FIXTURES = (
    Path(__file__).resolve().parents[2]
    / "fixtures"
    / "recorded"
    / "pkcs11-tool"
    / "opensc-0.25.0"
)
SLOTS = FIXTURES / "list-slots.txt"
OBJECTS_AUTHENTICATED = FIXTURES / "list-objects-authenticated.txt"
OBJECTS_PUBLIC = FIXTURES / "list-objects-public.txt"
MECHANISMS = FIXTURES / "list-mechanisms.txt"

BASIS = ConfidenceBasis(
    source="ADAPTER_DECLARED",
    justification=(
        "No cited row exists for pkcs11-tool metadata confidence (OI-004; "
        "data/base_confidence.yaml usable_row_count is 0); object metadata "
        "read directly off the token via a real PKCS#11 call is the "
        "strongest evidence class this tool has, matching certs/adapter.py."
    ),
)

TARGET = ScanTarget(target_id="softhsm-token", locator="/usr/lib/softhsm/libsofthsm2.so")


def adapter(**kw):
    return HsmPkcs11Adapter(base_confidence=0.9, confidence_basis=BASIS, **kw)


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def run_with(**bundle_kw):
    bundle_kw.setdefault("slots_text", _text(SLOTS))
    bundle = Pkcs11ProbeBundle(**bundle_kw)
    return adapter(probe_runner=lambda target: bundle).run(TARGET)


# --- (a) authenticated listing: both private key objects, never-extractable ---


def test_authenticated_listing_shows_both_private_keys_as_never_extractable():
    result = run_with(
        objects_text=_text(OBJECTS_AUTHENTICATED),
        authenticated=True,
    )

    assert result.outcome == AdapterOutcome.COMPLETED
    assert result.support_level == SupportLevel.PARTIAL

    # One Finding per PKCS#11 object: two public, two private.
    object_kinds = [f.fields["object_kind"].value for f in result.findings if "object_kind" in f.fields]
    assert object_kinds.count("Public Key Object") == 2
    assert object_kinds.count("Private Key Object") == 2

    private_findings = [
        f for f in result.findings if f.fields.get("object_kind") and f.fields["object_kind"].value == "Private Key Object"
    ]
    # One per key pair: the RSA-2048 private half and the EC P-256 private half.
    assert len(private_findings) == 2
    families = {f.fields["algorithm_family"].value for f in private_findings}
    assert families == {"RSA", "EC"}

    for finding in private_findings:
        never_extractable = finding.fields["never_extractable"]
        assert never_extractable.value is True
        assert never_extractable.state == EpistemicState.KNOWN
        # The headline fact must never be modelled as an ambiguous UNKNOWN --
        # it is read straight off the token's own Access: line either way.
        assert never_extractable.state != EpistemicState.UNKNOWN
        # No field on a private-key Finding may hold key material or even a
        # size/curve inferred from its public counterpart -- only what
        # pkcs11-tool actually printed for that block.
        assert "key_size_bits" not in finding.fields
        assert "curve_oid" not in finding.fields

    assert find_secrets(result.model_dump_json()) == ()


def test_authenticated_public_findings_carry_size_and_curve():
    result = run_with(objects_text=_text(OBJECTS_AUTHENTICATED), authenticated=True)
    public_findings = [
        f for f in result.findings if f.fields.get("object_kind") and f.fields["object_kind"].value == "Public Key Object"
    ]
    assert len(public_findings) == 2

    rsa = next(f for f in public_findings if f.fields["algorithm_family"].value == "RSA")
    assert rsa.fields["key_size_bits"].value == 2048
    assert rsa.fields["key_size_bits"].state == EpistemicState.KNOWN
    assert "never_extractable" not in rsa.fields

    ec = next(f for f in public_findings if f.fields["algorithm_family"].value == "EC")
    assert ec.fields["curve_oid"].value == "1.2.840.10045.3.1.7"
    assert ec.fields["curve_oid"].state == EpistemicState.KNOWN
    assert "never_extractable" not in ec.fields


# --- (b) unauthenticated listing: honest reduced-visibility ceiling ----------


def test_unauthenticated_listing_shows_only_public_keys_and_says_so():
    result = run_with(objects_text=_text(OBJECTS_PUBLIC), authenticated=False)

    assert result.outcome == AdapterOutcome.COMPLETED
    assert len(result.findings) == 2
    assert all(f.fields["object_kind"].value == "Public Key Object" for f in result.findings)

    # No trace of a private key anywhere -- not a Finding, not a field, not
    # even an UNKNOWN placeholder implying one was looked for.
    for finding in result.findings:
        assert "never_extractable" not in finding.fields
        for name in finding.fields:
            assert "private" not in name.lower()
    for finding in result.findings:
        for field_value in finding.fields.values():
            text = str(field_value.value)
            assert "private" not in text.lower()

    # The visibility entry must state the reduced/unauthenticated scope
    # explicitly, in words -- not silently report "found 2 public keys" as
    # though that were the complete picture.
    (entry,) = result.visibility
    assert entry.dimension == VisibilityDimension.HSM_KMS
    detail = entry.detail.lower()
    assert "unauthenticated" in detail
    assert "no pin" in detail
    assert "private" in detail  # names what it could not see, in words

    assert find_secrets(result.model_dump_json()) == ()


# --- (c) mechanism capability list --------------------------------------------


def test_mechanism_listing_is_surfaced_as_token_capability_not_usage():
    result = run_with(mechanisms_text=_text(MECHANISMS))

    assert result.outcome == AdapterOutcome.COMPLETED
    (finding,) = [f for f in result.findings if "supported_mechanisms" in f.fields]
    mechanisms = finding.fields["supported_mechanisms"].value

    assert len(mechanisms) > 40, "a reasonable number of mechanisms parsed"
    assert "AES-GCM" in mechanisms
    assert "RSA-PKCS" in mechanisms
    assert "ECDSA" in mechanisms
    assert finding.fields["mechanism_count"].value == len(mechanisms)

    (entry,) = result.visibility
    detail = entry.detail.lower()
    assert "capability" in detail
    assert "not observed usage" in detail

    assert find_secrets(result.model_dump_json()) == ()


# --- surface / coverage / secret-guard plumbing -------------------------------


def test_surface_identifies_the_token_from_list_slots():
    result = run_with(objects_text=_text(OBJECTS_AUTHENTICATED), authenticated=True)
    (finding, *_rest) = result.findings
    assert "pkcs11:" in finding.surface
    assert "531673ac2dfdad71" in finding.surface  # serial num from list-slots.txt


def test_a_run_with_only_slots_completes_with_no_findings_but_proves_it_looked():
    """TRAP-07: zero findings plus coverage proving the target was examined."""
    result = run_with()
    assert result.outcome == AdapterOutcome.COMPLETED
    assert result.findings == ()
    assert result.coverage.scanned
    assert result.visibility


def test_the_secret_guard_runs_on_the_way_out(monkeypatch):
    import ecdat.adapters.hsm.adapter as module
    from ecdat.security.secrets import SecretLeakError

    def leaky(*args, **kwargs):
        raise SecretLeakError("guard fired")

    monkeypatch.setattr(module, "scan_for_secrets", leaky)
    bundle = Pkcs11ProbeBundle(slots_text=_text(SLOTS), objects_text=_text(OBJECTS_AUTHENTICATED), authenticated=True)
    with pytest.raises(SecretLeakError):
        adapter(probe_runner=lambda target: bundle)._scan(TARGET)


def test_no_slot_listing_at_all_is_a_failed_outcome_not_a_crash():
    bundle = Pkcs11ProbeBundle(slots_text=None)
    result = adapter(probe_runner=lambda target: bundle).run(TARGET)
    assert result.outcome == AdapterOutcome.FAILED
    assert result.findings == ()


# --- live-invocation argv shape: no PIN ever leaves this function's return ---


def test_live_argv_pins_module_flag_and_action():
    argv = build_pkcs11_argv("/usr/lib/softhsm/libsofthsm2.so", action="list-objects")
    assert argv[0] == "pkcs11-tool"
    assert "--module" in argv
    assert argv[argv.index("--module") + 1] == "/usr/lib/softhsm/libsofthsm2.so"
    assert "--list-objects" in argv
    assert "--login" not in argv


def test_live_argv_carries_login_and_pin_only_when_authenticating():
    argv = build_pkcs11_argv(
        "/usr/lib/softhsm/libsofthsm2.so", action="list-objects", login=True, pin="1234"
    )
    assert "--login" in argv
    assert "--pin" in argv
    assert argv[argv.index("--pin") + 1] == "1234"

    # A PIN must never leak into an action string or be duplicated anywhere
    # outside the single --pin argument.
    assert argv.count("1234") == 1


def test_live_argv_omits_pin_entirely_when_none_supplied():
    argv = build_pkcs11_argv(
        "/usr/lib/softhsm/libsofthsm2.so", action="list-objects", login=False
    )
    assert "--pin" not in argv
    assert "--login" not in argv


def test_live_argv_rejects_an_unknown_action():
    with pytest.raises(ValueError):
        build_pkcs11_argv("/mod.so", action="list-nonsense")

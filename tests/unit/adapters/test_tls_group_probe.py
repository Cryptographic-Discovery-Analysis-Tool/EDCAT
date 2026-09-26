"""TLS individual group-probe path (DEV-013; resolves OI-016/OI-017).

Real recordings from two throwaway local `openssl s_server` instances
(OpenSSL 3.5.4), one hybrid-enabled and one classical-only -- see
tests/fixtures/recorded/openssl/3.5.4/hybrid_groups_probe/README.md for the
exact commands. The one exception is the deprecated-draft-group test, which
uses a hand-authored `Negotiated TLS1.3 group:` line (documented at the test
site) because no OpenSSL on the recording machine implements the
pre-standardisation `X25519Kyber768Draft00` group at all -- there is nothing
live to record it from.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from ecdat.adapters.base import ScanTarget
from ecdat.adapters.tls.adapter import (
    TlsEndpointAdapter,
    TlsProbeBundle,
    build_group_probe_argv,
    build_openssl_version_argv,
    default_group_probe_list,
    resolve_openssl_bin,
)
from ecdat.adapters.tls.parser import (
    MIN_OPENSSL_VERSION,
    meets_min_openssl_version,
    parse_group_probe,
    parse_openssl_version,
)
from ecdat.data.crypto_families import canonical_family
from ecdat.model.epistemic import EpistemicState
from ecdat.model.evidence import ConfidenceBasis
from ecdat.model.topology import ProbeTargetIdentity

FIXTURES = (
    Path(__file__).resolve().parents[2]
    / "fixtures"
    / "recorded"
    / "openssl"
    / "3.5.4"
    / "hybrid_groups_probe"
)
HYBRID_SERVER = FIXTURES / "hybrid_server"
CLASSICAL_SERVER = FIXTURES / "classical_server"
OPENSSL_VERSION_TEXT = (FIXTURES / "openssl_version.txt").read_text(encoding="utf-8")

BASIS = ConfidenceBasis(
    source="ADAPTER_DECLARED",
    justification=(
        "No cited row exists for TLS probe confidence (OI-004); an observed "
        "handshake is the strongest evidence class for a network surface."
    ),
)

PROBE = ProbeTargetIdentity(
    requested_host="127.0.0.1", port=14443, sni_sent=None, probe_vantage="local:fixture-gen"
)
TARGET = ScanTarget(
    target_id="fixture-gen", locator="127.0.0.1:14443", consent=True, probe=PROBE
)


def _read(directory: Path, group: str) -> str:
    return (directory / f"probe_{group}.txt").read_text(encoding="utf-8")


def bundle_from(directory: Path, groups: tuple[str, ...]) -> TlsProbeBundle:
    return TlsProbeBundle(
        group_probe_texts={g: _read(directory, g) for g in groups},
        group_probe_openssl_version=OPENSSL_VERSION_TEXT,
    )


def adapter(probes: TlsProbeBundle) -> TlsEndpointAdapter:
    return TlsEndpointAdapter(
        base_confidence=0.95,
        confidence_basis=BASIS,
        probe_runner=lambda target: probes,
    )


GROUPS = ("X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "X25519", "secp256r1")


# --- parser: individual group probes ----------------------------------------


def test_the_hybrid_server_accepts_every_group_it_was_configured_with():
    for group in ("X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "X25519"):
        result = parse_group_probe(group, _read(HYBRID_SERVER, group))
        assert result.accepted is True, group


def test_the_hybrid_server_refuses_a_group_it_was_not_configured_with():
    """secp256r1 was deliberately left out of server (a)'s -groups list."""
    result = parse_group_probe("secp256r1", _read(HYBRID_SERVER, "secp256r1"))
    assert result.accepted is False
    assert result.handshake.established is False


def test_the_classical_only_server_refuses_every_hybrid_group():
    for group in ("X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024"):
        result = parse_group_probe(group, _read(CLASSICAL_SERVER, group))
        assert result.accepted is False, group


def test_the_classical_only_server_still_accepts_classical_groups():
    for group in ("X25519", "secp256r1"):
        result = parse_group_probe(
            group, _read(CLASSICAL_SERVER, group), canonicalize=canonical_family
        )
        assert result.accepted is True, group


def test_ecdh_shaped_peer_temp_key_is_parsed_correctly_not_as_ecdh():
    """Regression: `Peer Temp Key: ECDH, prime256v1, 256 bits` used to be
    parsed as group "ECDH" (everything before the first comma) -- wrong,
    ECDH is a kind token, not a group name. Recorded live against the
    classical-only server. OpenSSL reports the negotiated group back as
    `prime256v1`, a different spelling of the SAME curve than the
    `secp256r1` name this probe offered -- accepted only resolves through
    `canonical_family` (data/crypto_families.yaml's `family_aliases`
    naming-identity rows), never by exact string match."""
    result = parse_group_probe(
        "secp256r1", _read(CLASSICAL_SERVER, "secp256r1"), canonicalize=canonical_family
    )
    assert result.handshake.group == "prime256v1"
    assert result.accepted is True


def test_without_canonicalization_the_alias_spelling_looks_unaccepted():
    """The default (no `canonicalize`) is exact-string comparison -- this
    documents why the adapter always passes `canonical_family`, not that
    exact matching is wrong in general."""
    result = parse_group_probe("secp256r1", _read(CLASSICAL_SERVER, "secp256r1"))
    assert result.accepted is False


def test_an_accepted_result_requires_the_reported_group_to_match_what_was_offered():
    """Accepted is never inferred from `established` alone -- a handshake
    that established but reports back a DIFFERENT group than the one this
    probe claims to be testing must not read as acceptance of the group it
    claims. (This cannot happen from a real single-group `-groups` offer --
    it guards a caller that mislabels which recording goes with which
    group.)"""
    real_x25519_text = _read(HYBRID_SERVER, "X25519")  # negotiates plain X25519
    mislabelled = parse_group_probe("X25519MLKEM768", real_x25519_text)
    assert mislabelled.handshake.established is True
    assert mislabelled.accepted is False


# --- parser: openssl version gating -----------------------------------------


def test_the_recorded_openssl_version_meets_the_minimum():
    assert parse_openssl_version(OPENSSL_VERSION_TEXT) == (3, 5, 4)
    assert meets_min_openssl_version(OPENSSL_VERSION_TEXT) is True


def test_an_older_openssl_does_not_meet_the_minimum():
    assert meets_min_openssl_version("OpenSSL 3.0.13 30 Jan 2024") is False
    assert meets_min_openssl_version("OpenSSL 3.4.9 1 Jan 2025") is False


def test_a_missing_or_unparseable_version_is_never_assumed_capable():
    assert meets_min_openssl_version(None) is False
    assert meets_min_openssl_version("") is False
    assert meets_min_openssl_version("not an openssl banner at all") is False
    assert parse_openssl_version("garbage") is None


def test_the_minimum_version_constant_is_3_5():
    assert MIN_OPENSSL_VERSION == (3, 5, 0)


# --- live-invocation shape (pure argv builders; no subprocess in tests) -----


def test_group_probe_argv_offers_exactly_one_group():
    argv = build_group_probe_argv("openssl", host="10.0.0.1", port=8443, group="X25519MLKEM768")
    assert argv == [
        "openssl",
        "s_client",
        "-connect",
        "10.0.0.1:8443",
        "-groups",
        "X25519MLKEM768",
        "-brief",
    ]


def test_group_probe_argv_carries_sni_when_given():
    argv = build_group_probe_argv(
        "openssl", host="10.0.0.1", port=8443, group="X25519", sni="pay-edge"
    )
    assert argv[-2:] == ["-servername", "pay-edge"]


def test_version_argv_is_just_version():
    assert build_openssl_version_argv("openssl") == ["openssl", "version"]


def test_resolve_openssl_bin_prefers_the_explicit_argument(monkeypatch):
    monkeypatch.setenv("ECDAT_OPENSSL_BIN", "/opt/openssl35/bin/openssl")
    assert resolve_openssl_bin(openssl_bin="/custom/openssl") == "/custom/openssl"


def test_resolve_openssl_bin_falls_back_to_the_env_var(monkeypatch):
    monkeypatch.setenv("ECDAT_OPENSSL_BIN", "/opt/openssl35/bin/openssl")
    assert resolve_openssl_bin() == "/opt/openssl35/bin/openssl"


def test_resolve_openssl_bin_falls_back_to_bare_openssl(monkeypatch):
    monkeypatch.delenv("ECDAT_OPENSSL_BIN", raising=False)
    assert resolve_openssl_bin() == "openssl"


def test_default_group_probe_list_is_sourced_from_the_registry_not_hardcoded():
    groups = default_group_probe_list()
    assert "X25519MLKEM768" in groups
    assert "SecP256r1MLKEM768" in groups
    assert "SecP384r1MLKEM1024" in groups
    assert "X25519Kyber768Draft00" in groups  # deprecated, still probed
    assert "X25519" in groups
    assert "secp256r1" in groups


# --- the adapter: emitting group-probe fields into the finding/evidence model


def test_the_hybrid_server_finding_reports_each_group_accepted_or_not():
    bundle = bundle_from(HYBRID_SERVER, GROUPS)
    (finding,) = adapter(bundle)._scan(TARGET).findings
    assert finding.fields["group_accepted_X25519MLKEM768"].value is True
    assert finding.fields["group_accepted_SecP256r1MLKEM768"].value is True
    assert finding.fields["group_accepted_SecP384r1MLKEM1024"].value is True
    assert finding.fields["group_accepted_X25519"].value is True
    assert finding.fields["group_accepted_secp256r1"].value is False


def test_the_hybrid_server_reports_hybrid_kex_supported_true():
    bundle = bundle_from(HYBRID_SERVER, GROUPS)
    (finding,) = adapter(bundle)._scan(TARGET).findings
    supported = finding.fields["hybrid_kex_supported"]
    assert supported.value is True
    assert supported.state == EpistemicState.KNOWN
    accepted = set(finding.fields["hybrid_kex_accepted_groups"].value)
    assert accepted == {"X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024"}


def test_the_classical_only_server_reports_hybrid_kex_supported_false_known_not_unknown():
    """The case task 3 calls out explicitly: a classical-only server must
    report hybrid support as KNOWN false, never UNKNOWN -- the probes ran,
    they all came back refused, and that is a real, cited answer."""
    bundle = bundle_from(CLASSICAL_SERVER, GROUPS)
    (finding,) = adapter(bundle)._scan(TARGET).findings
    supported = finding.fields["hybrid_kex_supported"]
    assert supported.value is False
    assert supported.state == EpistemicState.KNOWN
    assert supported.evidence_refs
    assert "hybrid_kex_accepted_groups" not in finding.fields


def test_group_probe_unavailable_reports_unknown_not_false():
    """Distinguish 'we checked and it does not support hybrid' from 'we
    could not check' -- the latter must never collapse into False."""
    bundle = TlsProbeBundle(
        group_probe_unavailable_reason=(
            "'openssl' reports 'OpenSSL 3.0.13 30 Jan 2024'; group probe "
            "requires openssl >= 3.5.0"
        ),
        sslyze_json=None,
        negotiated_text=None,
        classical_only_text=None,
    )
    # A group-probe-only bundle produces no finding unless something else
    # also ran; pair it with a minimal negotiated probe so the finding
    # exists to carry the field.
    negotiated = FIXTURES.parents[1] / "3.5.8" / "tier_a_edge_lb.negotiated.txt"
    bundle = TlsProbeBundle(
        negotiated_text=negotiated.read_text(encoding="utf-8"),
        group_probe_unavailable_reason=bundle.group_probe_unavailable_reason,
    )
    result = adapter(bundle)._scan(TARGET)
    (finding,) = result.findings
    supported = finding.fields["hybrid_kex_supported"]
    assert supported.state == EpistemicState.UNKNOWN
    assert any("group probe" in s for s in result.coverage.skipped)
    assert any("3.5.0" in d or "requires openssl" in d for d in (result.visibility[0].detail,))


def test_deprecated_group_accepted_is_flagged_not_silently_folded_into_hybrid_kex_supported():
    """No live OpenSSL on the recording machine implements the
    pre-standardisation X25519Kyber768Draft00 group (`Call to
    SSL_CONF_cmd(-groups, X25519Kyber768Draft00) failed`) -- there is
    nothing to record a real negotiation of it from. This is the one
    hand-authored probe text in this suite: the SAME line shape
    (`Negotiated TLS1.3 group: <name>`) the real recordings above establish,
    only the group name substituted, to exercise the deprecated-flag path
    the data alone (data/crypto_families.yaml) cannot exercise on its own."""
    legacy_negotiated = (
        "Connecting to 127.0.0.1\n"
        "CONNECTION ESTABLISHED\n"
        "Protocol version: TLSv1.3\n"
        "Ciphersuite: TLS_AES_256_GCM_SHA384\n"
        "Negotiated TLS1.3 group: X25519Kyber768Draft00\n"
        "DONE\n"
    )
    bundle = TlsProbeBundle(
        group_probe_texts={"X25519Kyber768Draft00": legacy_negotiated},
        group_probe_openssl_version=OPENSSL_VERSION_TEXT,
    )
    (finding,) = adapter(bundle)._scan(TARGET).findings
    assert finding.fields["group_accepted_X25519Kyber768Draft00"].value is True
    assert finding.fields["hybrid_kex_supported"].value is True
    assert finding.fields["hybrid_kex_deprecated_groups_accepted"].value == (
        "X25519Kyber768Draft00",
    )
    assert finding.fields["group_codepoint_X25519Kyber768Draft00"].value == "0x6399"


def test_the_visibility_entry_names_a_deprecated_group_when_accepted():
    legacy_negotiated = (
        "Connecting to 127.0.0.1\n"
        "CONNECTION ESTABLISHED\n"
        "Protocol version: TLSv1.3\n"
        "Ciphersuite: TLS_AES_256_GCM_SHA384\n"
        "Negotiated TLS1.3 group: X25519Kyber768Draft00\n"
        "DONE\n"
    )
    bundle = TlsProbeBundle(
        group_probe_texts={"X25519Kyber768Draft00": legacy_negotiated},
        group_probe_openssl_version=OPENSSL_VERSION_TEXT,
    )
    result = adapter(bundle)._scan(TARGET)
    detail = result.visibility[0].detail
    assert "DEPRECATED" in detail
    assert "X25519Kyber768Draft00" in detail
    assert "RFC 10024" in detail


def test_group_codepoints_are_carried_on_the_finding():
    bundle = bundle_from(HYBRID_SERVER, ("X25519MLKEM768",))
    (finding,) = adapter(bundle)._scan(TARGET).findings
    assert finding.fields["group_codepoint_X25519MLKEM768"].value == "0x11EC"


def test_the_result_passes_the_secret_guard():
    from ecdat.security.secrets import find_secrets

    bundle = bundle_from(HYBRID_SERVER, GROUPS)
    assert find_secrets(adapter(bundle)._scan(TARGET).model_dump_json()) == ()

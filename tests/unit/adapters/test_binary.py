"""Compiled-binary adapter tests (P12).

Every fixture here is a REAL recorded capture: `yara -s -w
rules/yara/crypto-constants.yar` and `readelf -h`/`readelf -d` run against
two binaries copied out of the live Tier A `edge-lb` container (HAProxy
3.0.27 on Alpine 3.24.2) -- see tests/fixtures/recorded/yara/4.5.0/README.md
and tests/fixtures/recorded/readelf/README.md. Nothing here is synthesised.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from ecdat.adapters.base import AdapterOutcome, ScanTarget
from ecdat.adapters.binary.adapter import (
    RSA_ECDSA_GAP_NOTE,
    BinaryAdapter,
    BinaryScanBundle,
    build_readelf_dynamic_argv,
    build_readelf_header_argv,
    build_yara_argv,
)
from ecdat.adapters.binary.parser import (
    RULE_FAMILY,
    parse_readelf_dynamic,
    parse_readelf_header,
    parse_yara,
)
from ecdat.model.epistemic import EpistemicState
from ecdat.model.evidence import ConfidenceBasis
from ecdat.model.visibility import SupportLevel, VisibilityDimension
from ecdat.security.secrets import find_secrets

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "recorded"
YARA_DIR = FIXTURES / "yara" / "4.5.0"
READELF_DIR = FIXTURES / "readelf"

HAPROXY_NO_MATCH = YARA_DIR / "haproxy.no-match.txt"
LIBCRYPTO_MATCH = YARA_DIR / "libcrypto.match.txt"
LIBCRYPTO_MATCH_VERBOSE = YARA_DIR / "libcrypto.match.verbose.txt"

HAPROXY_HEADER = READELF_DIR / "tier_a_edge_lb.haproxy.header.txt"
HAPROXY_DEPS = READELF_DIR / "tier_a_edge_lb.haproxy.dynamic-deps.txt"
LIBCRYPTO_HEADER = READELF_DIR / "tier_a_edge_lb.libcrypto.header.txt"
LIBCRYPTO_SONAME = READELF_DIR / "tier_a_edge_lb.libcrypto.soname.txt"

BASIS = ConfidenceBasis(
    source="ADAPTER_DECLARED",
    justification=(
        "No cited row exists for yara/readelf binary confidence (OI-004); "
        "data/base_confidence.yaml's one binary.* row is usable:false, so "
        "a moderate declared value is used pending a cited table."
    ),
)


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def adapter(**kw):
    kw.setdefault("scan_runner", lambda target: BinaryScanBundle())
    return BinaryAdapter(base_confidence=0.6, confidence_basis=BASIS, **kw)


def run_against(target_id: str, locator: str, **bundle_kw):
    bundle = BinaryScanBundle(**bundle_kw)
    return adapter(scan_runner=lambda target: bundle).run(
        ScanTarget(target_id=target_id, locator=locator)
    )


def libcrypto_result():
    """The real positive-match scenario: libcrypto.so.3, AES embedded."""
    return run_against(
        "tier-a-libcrypto",
        "libcrypto.so.3",
        yara_output=_text(LIBCRYPTO_MATCH_VERBOSE),
        readelf_header_output=_text(LIBCRYPTO_HEADER),
        readelf_dynamic_output=_text(LIBCRYPTO_SONAME),
    )


def haproxy_result():
    """The real negative-embedding / positive-linkage scenario: haproxy
    itself never matches, but dynamically links libcrypto.so.3."""
    return run_against(
        "tier-a-haproxy",
        "haproxy",
        yara_output=_text(HAPROXY_NO_MATCH),
        readelf_header_output=_text(HAPROXY_HEADER),
        readelf_dynamic_output=_text(HAPROXY_DEPS),
    )


# --- parsers, against recorded live output -----------------------------------


def test_parse_yara_reads_the_real_libcrypto_verbose_match():
    matches = parse_yara(_text(LIBCRYPTO_MATCH_VERBOSE))
    assert len(matches) == 1
    (match,) = matches
    assert match.rule_name == "Pramana_AES_Rijndael_Sbox"
    assert match.family == "AES"
    assert match.offsets == ("0x320800", "0x320900", "0x320a00", "0x320b00")


def test_parse_yara_reads_the_bare_non_verbose_match_line():
    matches = parse_yara(_text(LIBCRYPTO_MATCH))
    assert len(matches) == 1
    assert matches[0].family == "AES"
    assert matches[0].offsets == ()


def test_parse_yara_is_tolerant_of_the_real_zero_match_fixture():
    """The exact real recorded haproxy fixture: no rule matched. The
    surrounding commentary in the file must not be mistaken for a match."""
    matches = parse_yara(_text(HAPROXY_NO_MATCH))
    assert matches == ()


def test_parse_yara_is_tolerant_of_a_genuinely_empty_string():
    assert parse_yara("") == ()


def test_rule_family_mapping_matches_the_rule_files_own_meta():
    """Not asserting the rule file's contents here (it is read-only), just
    that this module's mapping names exactly the two families the header
    comment of rules/yara/crypto-constants.yar documents."""
    assert set(RULE_FAMILY.values()) == {"AES", "SHA-256"}


def test_parse_readelf_header_reads_the_real_libcrypto_header():
    header = parse_readelf_header(_text(LIBCRYPTO_HEADER))
    assert header.elf_class == "ELF64"
    assert header.elf_type == "DYN (Shared object file)"
    assert header.machine == "Advanced Micro Devices X86-64"


def test_parse_readelf_header_reads_the_real_haproxy_header():
    header = parse_readelf_header(_text(HAPROXY_HEADER))
    assert header.elf_class == "ELF64"
    assert header.elf_type == "DYN (Position-Independent Executable file)"


def test_parse_readelf_dynamic_reads_the_real_haproxy_needed_entries():
    dynamic = parse_readelf_dynamic(_text(HAPROXY_DEPS))
    assert dynamic.needed == (
        "libssl.so.3",
        "libcrypto.so.3",
        "liblua-5.4.so.0",
        "libpcre2-8.so.0",
        "libc.musl-x86_64.so.1",
    )
    assert dynamic.soname is None


def test_parse_readelf_dynamic_reads_the_real_libcrypto_soname():
    dynamic = parse_readelf_dynamic(_text(LIBCRYPTO_SONAME))
    assert dynamic.soname == "libcrypto.so.3"
    assert dynamic.needed == ()


def test_the_soname_round_trips_into_one_of_haproxys_needed_entries():
    """The core cross-fixture fact the README calls out: libcrypto's own
    SONAME string matches one of haproxy's NEEDED entries byte-for-byte."""
    soname = parse_readelf_dynamic(_text(LIBCRYPTO_SONAME)).soname
    needed = parse_readelf_dynamic(_text(HAPROXY_DEPS)).needed
    assert soname in needed


# --- (a) the real positive AES match, end to end -----------------------------


def test_libcrypto_aes_match_is_known_with_the_real_offsets():
    result = libcrypto_result()
    assert result.outcome == AdapterOutcome.COMPLETED
    assert result.support_level == SupportLevel.DETECT_ONLY
    (finding,) = result.findings

    families = finding.fields["embedded_constant_families"]
    assert families.state == EpistemicState.KNOWN
    assert families.value == ("AES",)

    offsets = finding.fields["embedded_constant_offsets_AES"]
    assert offsets.state == EpistemicState.KNOWN
    assert set(offsets.value) >= {"0x320800", "0x320900", "0x320a00", "0x320b00"}


def test_libcrypto_elf_header_fields_are_known():
    (finding,) = libcrypto_result().findings
    assert finding.fields["elf_class"].state == EpistemicState.KNOWN
    assert finding.fields["elf_class"].value == "ELF64"
    assert finding.fields["elf_type"].state == EpistemicState.KNOWN
    assert "Shared object file" in finding.fields["elf_type"].value
    assert finding.fields["elf_machine"].state == EpistemicState.KNOWN
    assert "X86-64" in finding.fields["elf_machine"].value


# --- (b) the real haproxy negative-embedding / positive-linkage case ---------


def test_haproxy_reports_no_embedded_constant_family():
    (finding,) = haproxy_result().findings
    families = finding.fields["embedded_constant_families"]
    # A completed, honest negative -- KNOWN, not UNKNOWN (this adapter did
    # look; see adapter.py's KNOWN-empty-vs-UNKNOWN note).
    assert families.state == EpistemicState.KNOWN
    assert families.value == ()
    assert not any(k.startswith("embedded_constant_offsets_") for k in finding.fields)


def test_haproxy_linked_libraries_lists_libcrypto_separately_from_embedding():
    """The whole point of the fixture pair: haproxy's crypto capability is
    real (it is there in linked_libraries) but is NEVER folded into the
    embedded_constant_families claim, which stays an honest empty tuple."""
    (finding,) = haproxy_result().findings
    linked = finding.fields["linked_libraries"]
    assert linked.state == EpistemicState.KNOWN
    assert "libcrypto.so.3" in linked.value
    assert len(linked.value) == 5
    assert finding.fields["embedded_constant_families"].value == ()


# --- (c) the RSA/ECDSA capability gap, stated on every run --------------------


def test_rsa_ecdsa_capability_gap_is_stated_on_the_positive_match_run():
    result = libcrypto_result()
    assert RSA_ECDSA_GAP_NOTE in result.visibility[0].detail


def test_rsa_ecdsa_capability_gap_is_stated_on_the_negative_match_run():
    result = haproxy_result()
    assert RSA_ECDSA_GAP_NOTE in result.visibility[0].detail


def test_rsa_ecdsa_capability_gap_is_stated_even_when_nothing_was_run():
    result = adapter(scan_runner=lambda target: BinaryScanBundle()).run(
        ScanTarget(target_id="t", locator="nowhere")
    )
    assert RSA_ECDSA_GAP_NOTE in result.visibility[0].detail


# --- (d) the secret guard on the way out --------------------------------------


def test_secret_guard_passes_on_the_positive_match_result():
    assert find_secrets(libcrypto_result().model_dump_json()) == ()


def test_secret_guard_passes_on_the_negative_match_result():
    assert find_secrets(haproxy_result().model_dump_json()) == ()


def test_the_secret_guard_actually_runs_on_the_emission_path(monkeypatch):
    """Mirrors certs/adapter.py's and packages/adapter.py's own test of the
    same invariant: the gate is on the path, not a separate lint step."""
    import ecdat.adapters.binary.adapter as module
    from ecdat.security.secrets import SecretLeakError

    def leaky(*args, **kwargs):
        raise SecretLeakError("guard fired")

    monkeypatch.setattr(module, "scan_for_secrets", leaky)
    bundle = BinaryScanBundle(yara_output=_text(HAPROXY_NO_MATCH))
    with pytest.raises(SecretLeakError):
        adapter(scan_runner=lambda target: bundle)._scan(
            ScanTarget(target_id="t", locator="haproxy")
        )


# --- supporting behaviour: KNOWN-empty vs UNKNOWN, coverage, evidence --------


def test_when_yara_never_runs_the_field_is_unknown_not_empty():
    """`None` (never run) must read differently from "" (ran, empty
    output) -- see adapter.py's `is not None` check."""
    result = run_against(
        "t",
        "haproxy",
        yara_output=None,
        readelf_header_output=_text(HAPROXY_HEADER),
        readelf_dynamic_output=_text(HAPROXY_DEPS),
    )
    (finding,) = result.findings
    assert finding.fields["embedded_constant_families"].state == EpistemicState.UNKNOWN
    assert any("yara: not run" in s for s in result.coverage.skipped)


def test_a_genuinely_empty_yara_capture_still_counts_as_scanned():
    """A live run that legitimately returns empty stdout is a scan, not a
    skip -- distinct from the never-run case above."""
    result = run_against("t", "haproxy", yara_output="")
    (finding,) = result.findings
    assert finding.fields["embedded_constant_families"].state == EpistemicState.KNOWN
    assert finding.fields["embedded_constant_families"].value == ()
    assert any(s.startswith("yara ") for s in result.coverage.scanned)


def test_no_probe_run_at_all_yields_no_finding_but_still_a_visibility_entry():
    result = adapter(scan_runner=lambda target: BinaryScanBundle()).run(
        ScanTarget(target_id="t", locator="nowhere")
    )
    assert result.outcome == AdapterOutcome.COMPLETED
    assert result.findings == ()
    assert len(result.visibility) == 1
    assert result.visibility[0].dimension == VisibilityDimension.ARTIFACT
    assert len(result.coverage.skipped) == 3


def test_evidence_is_referenced_and_scoped_to_the_declared_dimension():
    result = libcrypto_result()
    assert result.evidence
    assert {e.source_tool for e in result.evidence} == {"yara", "readelf"}
    for entry in result.visibility:
        assert entry.dimension == VisibilityDimension.ARTIFACT
        assert entry.support_level == SupportLevel.DETECT_ONLY


# --- live-invocation argv shape (never actually shells out) ------------------


def test_yara_argv_uses_dash_s_and_dash_w_with_the_pinned_rules_file():
    argv = build_yara_argv("rules/yara/crypto-constants.yar", "/bin/target")
    assert argv[0] == "yara"
    assert "-s" in argv
    assert "-w" in argv
    assert argv[-2] == "rules/yara/crypto-constants.yar"
    assert argv[-1] == "/bin/target"


def test_readelf_header_argv_uses_dash_h():
    assert build_readelf_header_argv("/bin/target") == ["readelf", "-h", "/bin/target"]


def test_readelf_dynamic_argv_uses_dash_d():
    assert build_readelf_dynamic_argv("/bin/target") == ["readelf", "-d", "/bin/target"]

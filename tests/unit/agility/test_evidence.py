"""Agility evidence (build-plan.md P14; DEV-012, OI-018).

Reuses the real recorded fixtures test_source_semgrep.py and test_tls.py
already run adapters against, so every case here is a real Finding's
`.fields`, not a hand-built dict shaped to match `agility/evidence.py`.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from ecdat.adapters.base import ScanTarget
from ecdat.adapters.source.semgrep import SemgrepSourceAdapter
from ecdat.adapters.tls.adapter import TlsEndpointAdapter, TlsProbeBundle
from ecdat.agility.evidence import (
    AlgorithmSelection,
    agility_evidence_for,
    algorithm_selection_for,
    hybrid_capable_for,
    provider_pluggable_for,
)
from ecdat.model.epistemic import EpistemicState
from ecdat.model.evidence import ConfidenceBasis
from ecdat.model.topology import ProbeTargetIdentity

SOURCE_FIXTURES = Path(__file__).resolve().parents[2] / "fixtures/recorded/semgrep/1.99.0/ecdat-rules"
TIER_A = SOURCE_FIXTURES / "tier-a-java.raw.json"
ARGUMENT_FORMS = SOURCE_FIXTURES / "argument-forms.raw.json"

TLS_FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "recorded"
SSLYZE_JSON = TLS_FIXTURES / "sslyze" / "6.2.0" / "tier_a_edge_lb.raw.json"
NEGOTIATED = TLS_FIXTURES / "openssl" / "3.5.8" / "tier_a_edge_lb.negotiated.txt"
CLASSICAL = TLS_FIXTURES / "openssl" / "3.5.8" / "tier_a_edge_lb.classical_only.txt"

SOURCE_BASIS = ConfidenceBasis(
    source="ADAPTER_DECLARED",
    justification="test value; no cited confidence table exists for semgrep (OI-004)",
)
TLS_BASIS = ConfidenceBasis(
    source="ADAPTER_DECLARED",
    justification="test value; no cited row exists for TLS probe confidence (OI-004)",
)


def _source_run(path: Path):
    adapter = SemgrepSourceAdapter(base_confidence=0.5, confidence_basis=SOURCE_BASIS)
    return adapter.run(ScanTarget(target_id=path.stem, locator=str(path)))


def _by_file(result, filename: str):
    return [f for f in result.findings if f.fields["path"].value.endswith(filename)]


@pytest.fixture(scope="module")
def tier_a():
    return _source_run(TIER_A)


@pytest.fixture(scope="module")
def argument_forms():
    return _source_run(ARGUMENT_FORMS)


def _tls_finding(*, with_openssl: bool):
    probe = ProbeTargetIdentity(
        requested_host="172.18.0.3", port=8443, sni_sent="pay-edge", probe_vantage="docker:payments-internal"
    )
    target = ScanTarget(target_id="tier-a-edge-lb", locator="172.18.0.3:8443", consent=True, probe=probe)
    bundle = TlsProbeBundle(
        sslyze_json=SSLYZE_JSON.read_text(encoding="utf-8"),
        negotiated_text=NEGOTIATED.read_text(encoding="utf-8") if with_openssl else "",
        classical_only_text=CLASSICAL.read_text(encoding="utf-8") if with_openssl else "",
    )
    adapter = TlsEndpointAdapter(base_confidence=0.95, confidence_basis=TLS_BASIS, probe_runner=lambda t: bundle)
    result = adapter.run(target)
    return result.findings[0]


# --- algorithm_selection -----------------------------------------------------


def test_pay001_configuration_driven_algorithm_selection(tier_a):
    """PAY-001: KeyWrapService.java resolves through props.getTransformation()."""
    finding = _by_file(tier_a, "KeyWrapService.java")[0]
    selection = algorithm_selection_for(finding.fields)
    assert selection.value == AlgorithmSelection.CONFIGURATION_DRIVEN
    assert selection.state == EpistemicState.KNOWN
    assert selection.evidence_refs == finding.fields["algorithm_argument"].evidence_refs


def test_pay003_hardcoded_algorithm_selection(tier_a):
    """PAY-003: TokenVault.java's literal Cipher.getInstance("AES/GCM/NoPadding")."""
    finding = _by_file(tier_a, "TokenVault.java")[0]
    selection = algorithm_selection_for(finding.fields)
    assert selection.value == AlgorithmSelection.HARDCODED
    assert selection.state == EpistemicState.KNOWN
    assert selection.evidence_refs == finding.fields["algorithm"].evidence_refs


def test_pay002_hardcoded_algorithm_selection_for_a_mac(tier_a):
    """PAY-002: WebhookSigner.java's literal Mac.getInstance(...)."""
    finding = _by_file(tier_a, "WebhookSigner.java")[0]
    selection = algorithm_selection_for(finding.fields)
    assert selection.value == AlgorithmSelection.HARDCODED


def test_algorithm_selection_is_unknown_when_neither_rule_fires():
    selection = algorithm_selection_for({})
    assert selection.value == AlgorithmSelection.UNKNOWN
    assert selection.state == EpistemicState.UNKNOWN


def test_algorithm_selection_never_returns_a_fourth_value(tier_a, argument_forms):
    """Closed set, checked structurally over every real finding these two
    fixtures produce, not just the ones named above."""
    for result in (tier_a, argument_forms):
        for finding in result.findings:
            selection = algorithm_selection_for(finding.fields)
            assert selection.value in (
                AlgorithmSelection.HARDCODED,
                AlgorithmSelection.CONFIGURATION_DRIVEN,
                AlgorithmSelection.UNKNOWN,
            )


# --- hybrid_capable -----------------------------------------------------------


def test_hybrid_capable_is_known_true_when_a_group_was_observed():
    finding = _tls_finding(with_openssl=True)
    result = hybrid_capable_for(finding.fields)
    assert result.value is True
    assert result.state == EpistemicState.KNOWN
    assert result.evidence_refs == finding.fields["negotiated_group"].evidence_refs


def test_hybrid_capable_is_unknown_without_the_openssl_probe():
    """A configured cipher list alone must never promote this past
    UNKNOWN -- there is no configured-list case tested elsewhere in the
    adapter, and this field must not invent one either."""
    finding = _tls_finding(with_openssl=False)
    assert finding.fields["negotiated_group"].state == EpistemicState.UNKNOWN
    result = hybrid_capable_for(finding.fields)
    assert result.value is None
    assert result.state == EpistemicState.UNKNOWN


def test_hybrid_capable_is_unknown_when_the_field_is_absent():
    result = hybrid_capable_for({})
    assert result.value is None
    assert result.state == EpistemicState.UNKNOWN


# --- provider_pluggable --------------------------------------------------------


def test_provider_pluggable_is_capped_to_inferred_never_known(argument_forms):
    """DEV-012 / OI-018: the source text is KNOWN, the pluggability claim is
    not -- the whole point of this field."""
    at_line_47 = [f for f in argument_forms.findings if f.fields["line"].value == 47]
    finding = at_line_47[0]
    assert finding.fields["provider_argument"].state == EpistemicState.KNOWN

    result = provider_pluggable_for(finding.fields)
    assert result.value is True
    assert result.state == EpistemicState.INFERRED
    assert result.state != EpistemicState.KNOWN
    assert result.evidence_refs == finding.fields["provider_argument"].evidence_refs


def test_provider_pluggable_is_unknown_when_no_provider_argument_observed(tier_a):
    finding = _by_file(tier_a, "TokenVault.java")[0]
    assert "provider_argument" not in finding.fields
    result = provider_pluggable_for(finding.fields)
    assert result.value is None
    assert result.state == EpistemicState.UNKNOWN


def test_provider_pluggable_never_returns_known(tier_a, argument_forms):
    for result in (tier_a, argument_forms):
        for finding in result.findings:
            assert provider_pluggable_for(finding.fields).state != EpistemicState.KNOWN


# --- AgilityEvidence, all three together --------------------------------------


def test_agility_evidence_for_bundles_all_three(tier_a):
    finding = _by_file(tier_a, "TokenVault.java")[0]
    evidence = agility_evidence_for("PAY-003", finding.fields)
    assert evidence.asset_id == "PAY-003"
    assert evidence.algorithm_selection.value == AlgorithmSelection.HARDCODED
    assert evidence.provider_pluggable.state == EpistemicState.UNKNOWN

import pytest
from pydantic import ValidationError

from ecdat.model.evidence import ConfidenceBasis, Evidence


def declared_basis(**overrides):
    fields = dict(
        source="ADAPTER_DECLARED",
        justification="no cited table exists for this tool yet; see OI-004 and ADR-002",
    )
    fields.update(overrides)
    return ConfidenceBasis(**fields)


def make(**overrides):
    fields = dict(
        evidence_id="ev-1",
        source_tool="sslyze",
        tool_version="6.2.0",
        location="payments/edge-lb/haproxy.cfg:12",
        base_confidence=0.8,
        confidence_basis=declared_basis(),
        raw_ref="tests/fixtures/recorded/sslyze/6.x/edge-lb.json",
    )
    fields.update(overrides)
    return Evidence(**fields)


def test_valid_evidence():
    ev = make()
    assert ev.base_confidence == 0.8
    assert ev.tool_version == "6.2.0"


@pytest.mark.parametrize("bad_confidence", [-0.01, 1.01, 2.0, -5.0])
def test_base_confidence_out_of_range_rejected(bad_confidence):
    with pytest.raises(ValidationError):
        make(base_confidence=bad_confidence)


@pytest.mark.parametrize(
    "field", ["evidence_id", "source_tool", "tool_version", "location", "raw_ref"]
)
def test_blank_string_fields_rejected(field):
    with pytest.raises(ValidationError):
        make(**{field: "   "})


def test_evidence_requires_a_confidence_basis():
    """OI-004: no source-tool confidence table exists, so every confidence value
    must arrive with its own provenance rather than looking authoritative."""
    with pytest.raises(ValidationError):
        Evidence(
            evidence_id="ev-2",
            source_tool="sslyze",
            tool_version="6.2.0",
            location="l",
            base_confidence=0.8,
            raw_ref="r",
        )


def test_an_uncited_confidence_must_be_justified_in_words():
    with pytest.raises(ValidationError, match="justification"):
        declared_basis(justification="because")


def test_an_uncited_confidence_may_not_claim_a_citation():
    with pytest.raises(ValidationError, match="must not claim"):
        declared_basis(citation="ECDAT_Final_Architecture.md Part 3")


def test_a_cited_confidence_must_name_its_row_and_source():
    with pytest.raises(ValidationError, match="requires table_key"):
        ConfidenceBasis(
            source="CITED_TABLE",
            justification="value taken from the cited base-confidence registry",
        )
    with pytest.raises(ValidationError, match="requires citation"):
        ConfidenceBasis(
            source="CITED_TABLE",
            table_key="some.key",
            justification="value taken from the cited base-confidence registry",
        )

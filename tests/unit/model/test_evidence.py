import pytest
from pydantic import ValidationError

from ecdat.model.evidence import Evidence


def make(**overrides):
    fields = dict(
        evidence_id="ev-1",
        source_tool="sslyze",
        location="payments/edge-lb/haproxy.cfg:12",
        base_confidence=0.8,
        raw_ref="tests/fixtures/recorded/sslyze/6.x/edge-lb.json",
    )
    fields.update(overrides)
    return Evidence(**fields)


def test_valid_evidence():
    ev = make()
    assert ev.base_confidence == 0.8


@pytest.mark.parametrize("bad_confidence", [-0.01, 1.01, 2.0, -5.0])
def test_base_confidence_out_of_range_rejected(bad_confidence):
    with pytest.raises(ValidationError):
        make(base_confidence=bad_confidence)


@pytest.mark.parametrize("field", ["evidence_id", "source_tool", "location", "raw_ref"])
def test_blank_string_fields_rejected(field):
    with pytest.raises(ValidationError):
        make(**{field: "   "})

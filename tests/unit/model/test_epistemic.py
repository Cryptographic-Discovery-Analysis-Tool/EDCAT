import pytest
from pydantic import ValidationError

from ecdat.model.epistemic import Resolution, ResolutionStatus


def test_unresolved_requires_reason():
    with pytest.raises(ValidationError):
        Resolution(status=ResolutionStatus.UNRESOLVED)


def test_unresolved_with_blank_reason_rejected():
    with pytest.raises(ValidationError):
        Resolution(status=ResolutionStatus.UNRESOLVED, reason="   ")


def test_unresolved_with_reason_ok():
    r = Resolution(status=ResolutionStatus.UNRESOLVED, reason="no binding value found")
    assert r.reason == "no binding value found"


def test_resolved_without_reason_ok():
    r = Resolution(status=ResolutionStatus.RESOLVED)
    assert r.reason is None

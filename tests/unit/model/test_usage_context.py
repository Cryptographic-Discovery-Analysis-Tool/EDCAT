"""Pramana_Ledger_Spec.md §5.1 -- function lives on the usage context."""
import pytest
from pydantic import ValidationError

from ecdat.model.epistemic import EpistemicState
from ecdat.model.field_value import FieldValue
from ecdat.model.usage_context import CryptoFunction, UsageContext


def _fn(state, value=None, *, refs=(), rule_id=None):
    return FieldValue[CryptoFunction](
        value=value, state=state, evidence_refs=refs, rule_id=rule_id
    )


def _ctx(function, **kw):
    return UsageContext(
        usage_context_id=kw.pop("uid", "UC-1"),
        asset_id=kw.pop("asset_id", "PAY-005"),
        surface_id=kw.pop("surface_id", "tls:pay:443"),
        protocol_context=kw.pop("protocol_context", "TLS1.2 handshake"),
        function=function,
        **kw,
    )


def test_observed_function_requires_evidence():
    with pytest.raises(ValidationError, match="evidence_ref"):
        _ctx(
            _fn(
                EpistemicState.KNOWN,
                CryptoFunction.KEY_ESTABLISHMENT,
                rule_id="FUNC-TLS-KEX-001",
            )
        )


def test_classified_function_requires_rule_id():
    with pytest.raises(ValidationError, match="rule_id"):
        _ctx(_fn(EpistemicState.KNOWN, CryptoFunction.KEY_ESTABLISHMENT, refs=("E1",)))


def test_unknown_function_carries_no_value():
    with pytest.raises(ValidationError, match="no default"):
        _ctx(_fn(EpistemicState.UNKNOWN, CryptoFunction.KEY_TRANSPORT))


def test_unknown_member_may_not_be_claimed_as_observed():
    with pytest.raises(ValidationError, match="false certainty"):
        _ctx(
            _fn(
                EpistemicState.KNOWN,
                CryptoFunction.UNKNOWN,
                refs=("E1",),
                rule_id="FUNC-TLS-KEX-001",
            )
        )


def test_observed_kex_context_is_confidentiality_not_authentication():
    ctx = _ctx(
        _fn(
            EpistemicState.KNOWN,
            CryptoFunction.KEY_ESTABLISHMENT,
            refs=("E1",),
            rule_id="FUNC-TLS-KEX-001",
        )
    )
    assert ctx.is_confidentiality and not ctx.is_authentication


def test_algorithm_may_be_unknown_while_function_is_observed():
    """§5.1: 'algorithm may be Unknown while function is Observed'."""
    ctx = _ctx(
        _fn(
            EpistemicState.KNOWN,
            CryptoFunction.KEY_TRANSPORT,
            refs=("E1",),
            rule_id="FUNC-SRC-KEYTRANSPORT-001",
        ),
        algorithm=FieldValue[str](value=None, state=EpistemicState.UNKNOWN),
    )
    assert ctx.function.state == EpistemicState.KNOWN
    assert ctx.algorithm.state == EpistemicState.UNKNOWN


def test_one_asset_carries_two_contexts_with_different_functions():
    """The red-team fix: one RSA key, two functions, two clocks."""
    kex = _ctx(
        _fn(
            EpistemicState.INFERRED,
            CryptoFunction.KEY_TRANSPORT,
            rule_id="FUNC-TLS-OFFERED-001",
        ),
        uid="UC-kt",
    )
    auth = _ctx(
        _fn(
            EpistemicState.KNOWN,
            CryptoFunction.SIGNATURE_AUTH,
            refs=("E1",),
            rule_id="FUNC-CERT-AUTH-001",
        ),
        uid="UC-auth",
    )
    assert kex.asset_id == auth.asset_id
    assert {kex.function.value, auth.function.value} == {
        CryptoFunction.KEY_TRANSPORT,
        CryptoFunction.SIGNATURE_AUTH,
    }

import pytest
from hypothesis import given, strategies as st
from pydantic import ValidationError

from ecdat.model.epistemic import EpistemicState, derivation_strength
from ecdat.model.field_value import FieldValue, derive
from ecdat.rules import registry

RULE = "TLS-FRONT-001"  # any registered rule_id; content is irrelevant here
NON_KNOWN_STATES = [s for s in EpistemicState if s != EpistemicState.KNOWN]


def plain(state: EpistemicState, evidence_refs: tuple[str, ...] = ()) -> FieldValue:
    return FieldValue(value="x", state=state, evidence_refs=evidence_refs)


# --- validator tests ---------------------------------------------------


def test_derived_from_without_rule_id_rejected():
    with pytest.raises(ValidationError):
        FieldValue(value="x", state=EpistemicState.INFERRED, derived_from=("a",))


def test_rule_id_not_in_registry_rejected():
    with pytest.raises(ValidationError):
        FieldValue(
            value="x",
            state=EpistemicState.INFERRED,
            derived_from=("a",),
            rule_id="NOT-A-REAL-RULE",
        )


def test_derived_field_cannot_be_known():
    with pytest.raises(ValidationError):
        FieldValue(
            value="x",
            state=EpistemicState.KNOWN,
            derived_from=("a",),
            rule_id=RULE,
        )


def test_plain_known_field_without_derivation_ok():
    fv = FieldValue(value="x", state=EpistemicState.KNOWN)
    assert fv.state == EpistemicState.KNOWN
    assert fv.derived_from == ()
    assert fv.rule_id is None


def test_rule_id_without_derived_from_is_allowed():
    # a field can cite a rule_id (e.g. an identity check) without being a
    # R-DERIVE-style derived value; only derived_from implies rule_id is
    # mandatory, not the reverse.
    fv = FieldValue(value="x", state=EpistemicState.INFERRED, rule_id=RULE)
    assert fv.rule_id == RULE


# --- derive() validator tests -------------------------------------------


def test_derive_requires_at_least_one_input():
    with pytest.raises(ValueError):
        derive(value="x", inputs=[], rule_id=RULE, derived_from=[])


def test_derive_rejects_unregistered_rule_id():
    with pytest.raises(KeyError):
        derive(
            value="x",
            inputs=[plain(EpistemicState.INFERRED)],
            rule_id="NOT-A-REAL-RULE",
            derived_from=["a"],
        )


def test_derive_result_is_never_known_even_if_all_inputs_known():
    result = derive(
        value="x",
        inputs=[plain(EpistemicState.KNOWN), plain(EpistemicState.KNOWN)],
        rule_id=RULE,
        derived_from=["a", "b"],
    )
    assert result.state == EpistemicState.INFERRED


def test_derive_matches_harness_14_3_state_d():
    # harness §14.3 state D: family/primitive/purpose/quantum tier stay
    # INFERRED while padding is CONFLICTING, because padding is not a
    # required input of the tier-derivation rule.
    family = plain(EpistemicState.INFERRED, evidence_refs=("ev-family",))
    # padding is deliberately NOT passed to derive() -- it is not a required
    # input of this rule, per harness §14.3's own explanation.
    tier = derive(value="shor-broken", inputs=[family], rule_id=RULE, derived_from=["family"])
    assert tier.state == EpistemicState.INFERRED


def test_derive_records_derived_from_and_rule_id():
    result = derive(
        value="x",
        inputs=[plain(EpistemicState.INFERRED)],
        rule_id=RULE,
        derived_from=["family"],
    )
    assert result.derived_from == ("family",)
    assert result.rule_id == RULE


def test_derive_unions_evidence_refs_without_duplicates():
    a = plain(EpistemicState.INFERRED, evidence_refs=("ev-1", "ev-2"))
    b = plain(EpistemicState.INFERRED, evidence_refs=("ev-2", "ev-3"))
    result = derive(value="x", inputs=[a, b], rule_id=RULE, derived_from=["a", "b"])
    assert result.evidence_refs == ("ev-1", "ev-2", "ev-3")


# --- hypothesis property tests: R-DERIVE ---------------------------------


state_strategy = st.sampled_from(list(EpistemicState))


@given(states=st.lists(state_strategy, min_size=1, max_size=6))
def test_property_r_derive_weakest_input_wins(states):
    """R-DERIVE (Lock §3): the derived state is the weakest required input,
    except that a weakest-of-KNOWN result is capped to INFERRED (CFG-001)."""
    inputs = [plain(s) for s in states]
    result = derive(value="x", inputs=inputs, rule_id=RULE, derived_from=[f"f{i}" for i in range(len(inputs))])

    expected = min(states, key=derivation_strength)
    if expected == EpistemicState.KNOWN:
        expected = EpistemicState.INFERRED

    assert result.state == expected


@given(states=st.lists(state_strategy, min_size=1, max_size=6))
def test_property_r_monotone_never_produces_known(states):
    """R-MONOTONE (Lock §3): derivation must never create certainty the
    evidence does not support -- a derived field is never KNOWN, regardless
    of how many/which inputs are supplied."""
    inputs = [plain(s) for s in states]
    result = derive(value="x", inputs=inputs, rule_id=RULE, derived_from=[f"f{i}" for i in range(len(inputs))])
    assert result.state != EpistemicState.KNOWN


@given(
    states=st.lists(st.sampled_from(NON_KNOWN_STATES), min_size=1, max_size=6),
    upgrade_index=st.integers(min_value=0),
)
def test_property_r_monotone_stronger_input_never_weakens_result(states, upgrade_index):
    """R-MONOTONE: 'stronger evidence may reduce uncertainty' -- strictly
    strengthening one required input (within the non-KNOWN states, where the
    KNOWN-downgrade rule can't interfere -- see ADR-001) never makes the
    derived result weaker than before."""
    idx = upgrade_index % len(states)
    current_rank = derivation_strength(states[idx])
    stronger_states = [s for s in NON_KNOWN_STATES if derivation_strength(s) > current_rank]
    if not stronger_states:
        return  # already the strongest non-KNOWN state; nothing to upgrade to

    before_inputs = [plain(s) for s in states]
    after_states = list(states)
    after_states[idx] = stronger_states[-1]  # upgrade to the strongest available
    after_inputs = [plain(s) for s in after_states]

    names = [f"f{i}" for i in range(len(states))]
    before = derive(value="x", inputs=before_inputs, rule_id=RULE, derived_from=names)
    after = derive(value="x", inputs=after_inputs, rule_id=RULE, derived_from=names)

    assert derivation_strength(after.state) >= derivation_strength(before.state)

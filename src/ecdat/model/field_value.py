"""FieldValue[T] and derive() (Lock §2 principle 8, §3 R-DERIVE / R-MONOTONE).

Epistemic state is assigned per field, not per asset (principle 8) -- this is
that per-field container.
"""
from __future__ import annotations

from typing import Generic, Sequence, TypeVar

from pydantic import BaseModel, ConfigDict, model_validator

from ecdat.model.epistemic import EpistemicState, derivation_strength
from ecdat.rules.registry import is_registered

T = TypeVar("T")


class FieldValue(BaseModel, Generic[T]):
    value: T | None = None
    state: EpistemicState
    evidence_refs: tuple[str, ...] = ()
    derived_from: tuple[str, ...] = ()
    rule_id: str | None = None

    model_config = ConfigDict(frozen=True)

    @model_validator(mode="after")
    def _validate(self) -> "FieldValue[T]":
        if self.derived_from and self.rule_id is None:
            raise ValueError(
                "R-DERIVE (Lock §3): a field with derived_from set requires rule_id"
            )
        if self.rule_id is not None and not is_registered(self.rule_id):
            raise ValueError(
                f"rule_id {self.rule_id!r} is not registered in "
                "src/ecdat/rules/registry.py"
            )
        if self.derived_from and self.state == EpistemicState.KNOWN:
            raise ValueError(
                "a derived field is never KNOWN (CFG-001, Lock §4: "
                "'Effective' does not mean 'observed'; harness §14 W2)"
            )
        return self


def derive(
    *,
    value: T,
    inputs: Sequence[FieldValue],
    rule_id: str,
    derived_from: Sequence[str],
) -> FieldValue[T]:
    """R-DERIVE (Lock §3): a derived field is never more certain than its
    weakest required input. `inputs` must be exactly the fields this rule
    depends on -- fields the rule does not use must not be passed in (harness
    §14.3 state D: padding is CONFLICTING but is not a required input of the
    tier-derivation rule, so tier stays INFERRED).

    `derived_from` is caller-supplied identifiers for the input fields (e.g.
    "asset:PAY-001.family"), recorded as derivation metadata per CFG-001 /
    harness §14.6 W2 ("derived_from" + "rule_id", never a new state).
    """
    if not inputs:
        raise ValueError(
            "derive() requires at least one input (R-DERIVE has nothing to "
            "bound the result by otherwise)"
        )
    if not is_registered(rule_id):
        raise KeyError(f"rule_id {rule_id!r} is not registered in src/ecdat/rules/registry.py")

    weakest_input = min(inputs, key=lambda f: derivation_strength(f.state))
    state = weakest_input.state
    if state == EpistemicState.KNOWN:
        # CFG-001 (Lock §4): a derived value is never KNOWN, even when every
        # required input happens to be KNOWN. Derivation itself caps
        # certainty; this is independent of ADR-001's ordering choice.
        state = EpistemicState.INFERRED

    evidence_refs = tuple(dict.fromkeys(ref for f in inputs for ref in f.evidence_refs))

    return FieldValue[T](
        value=value,
        state=state,
        evidence_refs=evidence_refs,
        derived_from=tuple(derived_from),
        rule_id=rule_id,
    )

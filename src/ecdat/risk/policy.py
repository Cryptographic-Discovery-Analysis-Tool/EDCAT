"""Policy deadlines laid over ledger rows (build-plan.md P22).

A regulator's migration deadline is not Z. Z is when a quantum computer is
assumed to arrive (data/scenarios.yaml); a policy deadline is when an
authority says migration must be done regardless. So this module never
touches a band: it annotates a finished `CalculationRecord` with, for each
cited policy milestone (data/policy_deadlines.yaml), one of three answers:

* `met`          -- an OBSERVED migration stopped this row's clock on or
                    before the deadline (the record's own `M`, which §5.7
                    only sets from a KNOWN negotiation with classical off);
* `open`         -- the row's algorithm family is quantum-vulnerable per a
                    cited row and no such stop has been observed;
* `undetermined` -- the family is unknown, or has no cited classification,
                    so whether the policy applies at all cannot be said.

Rows whose family is cited as not Shor-broken (ML-KEM, a hybrid group) are
`not_applicable`. Nothing is weighted or scored; `days_remaining` is plain
date arithmetic from the record's own `as_of`.
"""
from __future__ import annotations

from datetime import date
from enum import Enum
from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict

from ecdat.data.crypto_families import (
    NoCitedFamilyError,
    canonical_family,
    is_hybrid_group,
    is_shor_broken,
)
from ecdat.risk.record import CalculationRecord, Qualifier


class PolicyStatus(str, Enum):
    MET = "met"
    OPEN = "open"
    UNDETERMINED = "undetermined"
    NOT_APPLICABLE = "not_applicable"


class Milestone(BaseModel):
    model_config = ConfigDict(frozen=True)

    key: str
    label: str
    date: date
    quote: str
    #: "row" -- a key/row meets or misses it by migrating; "programme" -- an
    #: organisation-level milestone (inventory, CBOM requests) that no single
    #: row can meet, so it is never laid over a row.
    scope: str = "row"
    #: Set when a milestone binds only at one classical strength (NIST IR
    #: 8547's "Deprecated after 2030" is 112-bit only). None = every strength.
    applies_at_strength: int | None = None


class PolicyDeadlines(BaseModel):
    model_config = ConfigDict(frozen=True)

    key: str
    label: str
    citation: str
    milestones: tuple[Milestone, ...]


class PolicyAnnotation(BaseModel):
    model_config = ConfigDict(frozen=True)

    policy_key: str
    policy_label: str
    milestone_key: str
    milestone_label: str
    deadline: date
    status: PolicyStatus
    days_remaining: int
    reason: str
    citation: str


def _data_path() -> Path:
    return Path(__file__).resolve().parents[3] / "data" / "policy_deadlines.yaml"


@lru_cache(maxsize=1)
def _fixed_strengths() -> dict[str, int]:
    """Families whose classical strength is fixed by the name (SP 800-186
    Table 1). RSA / finite-field DH are sized by key length and are absent on
    purpose until a row carries one."""
    path = _data_path().with_name("security_strength.yaml")
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    return {
        row["key"]: int(row["strength_bits"])
        for row in document.get("families") or ()
        if row.get("usable") is True
    }


def security_strength(record: CalculationRecord) -> int | None:
    algorithm = record.inputs.usage_context.algorithm
    if algorithm is None or algorithm.value is None:
        return None
    return _fixed_strengths().get(canonical_family(algorithm.value) or "")


@lru_cache(maxsize=1)
def load_policies() -> tuple[PolicyDeadlines, ...]:
    """Usable rows only. A row marked `usable: false` (the 112-bit
    deprecation, the unvendored EU roadmap) never becomes a deadline."""
    document = yaml.safe_load(_data_path().read_text(encoding="utf-8"))
    return tuple(
        PolicyDeadlines(
            key=row["key"],
            label=row["label"],
            citation=row["citation"],
            milestones=tuple(Milestone(**m) for m in row["milestones"]),
        )
        for row in document.get("policies") or ()
        if row.get("usable") is True
    )


def _vulnerability(record: CalculationRecord) -> tuple[bool | None, str]:
    """(quantum-vulnerable?, why). None when it cannot be said."""
    algorithm = record.inputs.usage_context.algorithm
    if algorithm is None or algorithm.value is None:
        return None, "algorithm family unknown for this row"
    if is_hybrid_group(algorithm.value):
        return False, f"{algorithm.value} is a hybrid PQ group"
    family = canonical_family(algorithm.value)
    try:
        return is_shor_broken(family), f"{family} per data/crypto_families.yaml"
    except NoCitedFamilyError:
        return None, f"{family!r} has no cited classification"


def annotate(
    record: CalculationRecord, policies: tuple[PolicyDeadlines, ...] | None = None
) -> tuple[PolicyAnnotation, ...]:
    policies = load_policies() if policies is None else policies
    vulnerable, why = _vulnerability(record)
    annotations: list[PolicyAnnotation] = []
    for policy in policies:
        for milestone in policy.milestones:
            if milestone.scope != "row":
                continue
            strength = security_strength(record)
            if vulnerable is None:
                status, reason = PolicyStatus.UNDETERMINED, why
            elif vulnerable is False:
                status, reason = PolicyStatus.NOT_APPLICABLE, why
            elif milestone.applies_at_strength is not None and strength is None:
                status = PolicyStatus.UNDETERMINED
                reason = (
                    f"binds only at {milestone.applies_at_strength}-bit strength; this row's "
                    "strength is unknown (no key size on the row)"
                )
            elif milestone.applies_at_strength is not None and strength != milestone.applies_at_strength:
                status = PolicyStatus.NOT_APPLICABLE
                reason = (
                    f"binds only at {milestone.applies_at_strength}-bit strength; "
                    f"this row is {strength}-bit (data/security_strength.yaml)"
                )
            elif (
                record.M is not None
                and record.M <= milestone.date
                and Qualifier.REOPENED not in record.qualifiers
            ):
                status = PolicyStatus.MET
                reason = f"observed migration stopped the clock on {record.M.isoformat()}"
            else:
                status = PolicyStatus.OPEN
                reason = f"{why}; no observed migration stops this row"
            annotations.append(
                PolicyAnnotation(
                    policy_key=policy.key,
                    policy_label=policy.label,
                    milestone_key=milestone.key,
                    milestone_label=milestone.label,
                    deadline=milestone.date,
                    status=status,
                    days_remaining=(milestone.date - record.as_of).days,
                    reason=reason,
                    citation=policy.citation,
                )
            )
    return tuple(annotations)

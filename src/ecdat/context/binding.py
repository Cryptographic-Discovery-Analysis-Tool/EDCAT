"""Lifetime and DataClassBinding (Pramana_Ledger_Spec.md §5.3).

X is the only quantity in the whole ledger that does not come from an
observation. It comes from the operator: how long this data must stay secret.
That makes it DECLARED by construction -- there is no way to observe a
retention requirement off a wire -- and every binding therefore names the
table row it came from, so a band can be traced back to the sentence that set
its deadline.

Units: see docs/deviations.md DEV-003. §5.3 names the field
`secrecy_lifetime_X_days`; §6's expected dates are calendar-year arithmetic,
and a fixed day count cannot reproduce them (7 years before 2031-01-01 is
2024-01-01, but 2556 days before it is 2024-01-02, because 2024-2031 carries
two leap days and 2029-2036 carries one). Lifetime therefore holds whichever
unit the policy was actually written in and subtracts in that unit.
"""
from __future__ import annotations

from datetime import date, timedelta

from pydantic import BaseModel, ConfigDict, model_validator

from ecdat.model.epistemic import EpistemicState


def _shift_years(anchor: date, years: int) -> date:
    """Calendar-year shift, clamping 29 February to 28 February in a
    non-leap target year. No other calendar subtlety exists for whole-year
    offsets."""
    target_year = anchor.year + years
    try:
        return anchor.replace(year=target_year)
    except ValueError:
        # anchor is 29 February and target_year is not a leap year.
        return anchor.replace(year=target_year, day=28)


class Lifetime(BaseModel):
    """A duration written in the unit its policy was written in.

    Exactly one of `years` / `days`. A policy that says "seven years" means
    seven calendar years; storing that as 2556 days silently re-dates every
    deadline that crosses a different number of leap days.
    """

    model_config = ConfigDict(frozen=True)

    years: int | None = None
    days: int | None = None

    @model_validator(mode="after")
    def _exactly_one_unit(self) -> "Lifetime":
        if (self.years is None) == (self.days is None):
            raise ValueError("Lifetime takes exactly one of years / days")
        if (self.years if self.years is not None else self.days) < 0:
            raise ValueError("Lifetime must not be negative")
        return self

    @property
    def is_zero(self) -> bool:
        """§5.6: `A == 0` (session) is a distinct case, not a short lifetime."""
        return (self.years or 0) == 0 and (self.days or 0) == 0

    def before(self, anchor: date) -> date:
        """anchor - self. Used for the deadline Z - X."""
        if self.years is not None:
            return _shift_years(anchor, -self.years)
        return anchor - timedelta(days=self.days)

    def after(self, anchor: date) -> date:
        """anchor + self. Used for required_until = signed_at + A."""
        if self.years is not None:
            return _shift_years(anchor, self.years)
        return anchor + timedelta(days=self.days)

    def __str__(self) -> str:
        return f"{self.years}y" if self.years is not None else f"{self.days}d"


class DataClassBinding(BaseModel):
    """§5.3. Binds a target to the lifetimes its data class requires.

    `status` is DECLARED and only DECLARED: a lifetime is an operator's
    statement, and no amount of scanning turns it into an observation. It is
    not weakened to INFERRED either -- inferring a retention requirement from
    a file path is exactly the kind of guess that produces a confident wrong
    deadline.

    `authenticity_lifetime_A` is None when the target carries no signed
    artefact whose trustworthiness must outlive it; that is NOT the same as
    A == 0 (a session signature), which §5.6 routes to ROTATE_BEFORE_Z.
    """

    model_config = ConfigDict(frozen=True)

    target_id: str
    classification: str
    secrecy_lifetime_X: Lifetime
    source_ref: str
    cited_table_row: str
    authenticity_lifetime_A: Lifetime | None = None
    status: EpistemicState = EpistemicState.DECLARED

    @model_validator(mode="after")
    def _validate(self) -> "DataClassBinding":
        if self.status != EpistemicState.DECLARED:
            raise ValueError(
                "§5.3 fixes status=DECLARED: a data-class lifetime is stated "
                "by an operator, never observed and never inferred"
            )
        for name in ("target_id", "classification", "source_ref", "cited_table_row"):
            if not getattr(self, name).strip():
                raise ValueError(f"{name} must not be blank")
        return self

    def deadline(self, z_date: date) -> date:
        """§5.5: `deadline = Z - X`. The last day on which sending this data
        over a Shor-broken confidentiality channel is still savable."""
        return self.secrecy_lifetime_X.before(z_date)

    def required_until(self, signed_at: date) -> date | None:
        """§5.6: `required_until = signed_at + A`."""
        if self.authenticity_lifetime_A is None:
            return None
        return self.authenticity_lifetime_A.after(signed_at)

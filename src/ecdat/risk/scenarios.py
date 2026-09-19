"""Scenario and Policy (Pramana_Ledger_Spec.md §5.4).

Two objects, both of them assumptions the operator owns rather than findings
this tool produces:

* `Scenario` fixes Z, the date a cryptographically relevant quantum computer
  is assumed available. Three of them ship, every ledger row names the one it
  used, and the dashboard switches between them live. There is no
  probabilistic Z (§5.12): a distribution over Z is a weighted score wearing a
  different hat.
* `Policy` fixes what counts as admissible evidence, and -- the one a hostile
  judge will push on -- `capture_assumption`: since when do we assume an
  adversary was recording. Every row states its answer in words, because the
  honest reply to "you are assuming capture" is "yes, since this date, because
  you told me to, and here is the switch".

§5.4: "Pure date arithmetic; no hidden constants." Nothing in this module
rounds, weights, or interpolates.
"""
from __future__ import annotations

from datetime import date
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, model_validator

from ecdat.context.binding import DataClassBinding, Lifetime

_SCENARIOS_FILE = "scenarios.yaml"
_LIFETIME_FILE = "data_lifetime.yaml"


class NoCitedScenarioError(LookupError):
    """No usable row defines this scenario or policy constant."""


class NoCitedLifetimeError(LookupError):
    """No usable row defines this data-class lifetime."""


def _data_dir() -> Path:
    # src/ecdat/risk/scenarios.py -> repository root -> data/
    return Path(__file__).resolve().parents[3] / "data"


@lru_cache(maxsize=2)
def _load(filename: str) -> dict[str, Any]:
    data = yaml.safe_load((_data_dir() / filename).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"malformed registry at {_data_dir() / filename}")
    return data


class Scenario(BaseModel):
    """§5.4. `{id, Z_date, basis_citation, label}`."""

    model_config = ConfigDict(frozen=True)

    id: str
    label: str
    z_date: date
    basis_citation: str

    @classmethod
    def load(cls, scenario_id: str) -> "Scenario":
        for row in _load(_SCENARIOS_FILE).get("scenarios") or ():
            if row.get("id") != scenario_id:
                continue
            if row.get("usable") is not True:
                raise NoCitedScenarioError(f"scenario {scenario_id!r} is recorded but not usable")
            return cls(
                id=row["id"],
                label=row["label"],
                z_date=row["z_date"],
                basis_citation=row["citation"],
            )
        raise NoCitedScenarioError(f"scenario {scenario_id!r} has no row in {_SCENARIOS_FILE}")

    @classmethod
    def load_all(cls) -> tuple["Scenario", ...]:
        return tuple(
            cls.load(row["id"])
            for row in _load(_SCENARIOS_FILE).get("scenarios") or ()
            if row.get("usable") is True
        )


class CaptureMode(str, Enum):
    """§5.4: `capture_assumption in {SINCE_CONFIRMED, SINCE_POSSIBLE,
    SINCE_DATE(d)}`.

    This is the scenario assumption a hostile judge pushes on, so it is a
    first-class switchable input rather than a constant buried in a formula.
    SINCE_CONFIRMED is the conservative reading (assume capture only from the
    date we can prove traffic flowed); SINCE_POSSIBLE is the pessimistic one.
    """

    SINCE_CONFIRMED = "SINCE_CONFIRMED"
    SINCE_POSSIBLE = "SINCE_POSSIBLE"
    SINCE_DATE = "SINCE_DATE"


class CaptureAssumption(BaseModel):
    model_config = ConfigDict(frozen=True)

    mode: CaptureMode
    since: date | None = None

    @model_validator(mode="after")
    def _date_mode_carries_a_date(self) -> "CaptureAssumption":
        if self.mode == CaptureMode.SINCE_DATE and self.since is None:
            raise ValueError("CaptureMode.SINCE_DATE requires `since`")
        if self.mode != CaptureMode.SINCE_DATE and self.since is not None:
            raise ValueError(f"`since` is meaningless for {self.mode.value}")
        return self

    def __str__(self) -> str:
        return (
            f"{self.mode.value}({self.since.isoformat()})"
            if self.since is not None
            else self.mode.value
        )


class Policy(BaseModel):
    """§5.4. `{accept_inferred_inputs=false, accept_declared_go_live=true,
    capture_assumption, rollout_Y_default}`.

    `rollout_Y_default` has no default here on purpose: data/scenarios.yaml
    records that §5.4 names the knob and states no number, so a value picked
    in code would silently move every ROTATE_BEFORE_Z deadline in the system.
    """

    model_config = ConfigDict(frozen=True)

    capture_assumption: CaptureAssumption
    rollout_Y_default: Lifetime
    accept_inferred_inputs: bool = False
    accept_declared_go_live: bool = True


def lifetime_row(key: str) -> dict[str, Any]:
    """The raw cited row for `key`, or raise. Callers that want a binding use
    `binding_for`."""
    for row in _load(_LIFETIME_FILE).get("rows") or ():
        if row.get("key") != key:
            continue
        if row.get("usable") is not True:
            raise NoCitedLifetimeError(
                f"{key!r} is recorded but not usable: "
                f"{row.get('why_not_usable', 'no reason recorded')}"
            )
        return row
    raise NoCitedLifetimeError(f"{key!r} has no row in {_LIFETIME_FILE}")


def binding_for(*, target_id: str, key: str, source_ref: str) -> DataClassBinding:
    """Build a DataClassBinding from a cited lifetime row (§5.3).

    `cited_table_row` is filled with the row key, so a band carries its
    lifetime's provenance all the way to the export.
    """
    row = lifetime_row(key)
    authenticity = row.get("authenticity_lifetime_A")
    return DataClassBinding(
        target_id=target_id,
        classification=row["classification"],
        secrecy_lifetime_X=Lifetime(**row["secrecy_lifetime_X"]),
        authenticity_lifetime_A=Lifetime(**authenticity) if authenticity is not None else None,
        source_ref=source_ref,
        cited_table_row=f"{_LIFETIME_FILE}#{key}",
    )

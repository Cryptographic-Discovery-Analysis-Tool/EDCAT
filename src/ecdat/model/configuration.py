"""ConfigurationCandidate / EffectiveConfigurationInference (CFG-001, Lock §4;
harness §14.2, verbatim conceptual schema):

    ConfigurationCandidate
      property_key            pay.keywrap.transformation
      value                   RSA/ECB/OAEPWithSHA-256AndMGF1Padding
      source_kind             spring-config-data | os-env | cli-arg | system-prop | spring-app-json
      source_location         file:path:line
      precedence_rank         per Spring reference order
      applicability           APPLICABLE | CONDITIONAL(profile=prod) | UNKNOWN

    EffectiveConfigurationInference
      property_key
      winning_candidate       -> ConfigurationCandidate
      losing_candidates       [ ... ]
      rule_applied            "Spring Boot property-source order"
      sources_inspected       [ ... ]
      higher_precedence_not_inspected [ ... ]      (A1)
      epistemic_state         INFERRED | CONFLICTING | UNKNOWN
      resolution_status       RESOLVED | OVERRIDDEN | UNRESOLVED(reason)
      runtime_observation     NOT_OBSERVED
"""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from ecdat.model.epistemic import EpistemicState, Resolution, ResolutionStatus


class SourceKind(str, Enum):
    SPRING_CONFIG_DATA = "spring-config-data"
    OS_ENV = "os-env"
    CLI_ARG = "cli-arg"
    SYSTEM_PROP = "system-prop"
    SPRING_APP_JSON = "spring-app-json"


class Applicability(str, Enum):
    APPLICABLE = "APPLICABLE"
    CONDITIONAL = "CONDITIONAL"
    UNKNOWN = "UNKNOWN"


class ConfigurationCandidate(BaseModel):
    model_config = ConfigDict(frozen=True)

    property_key: str
    value: str
    source_kind: SourceKind
    source_location: str
    precedence_rank: int
    applicability: Applicability
    # e.g. "profile=prod" -- only meaningful when applicability=CONDITIONAL
    condition: str | None = None

    @field_validator("property_key", "value", "source_location")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be blank")
        return value

    @model_validator(mode="after")
    def _condition_matches_applicability(self) -> "ConfigurationCandidate":
        if self.applicability == Applicability.CONDITIONAL and not self.condition:
            raise ValueError(
                "CONDITIONAL applicability requires a condition, e.g. "
                "'profile=prod' (harness §14.2)"
            )
        if self.applicability != Applicability.CONDITIONAL and self.condition is not None:
            raise ValueError("condition is only meaningful when applicability=CONDITIONAL")
        return self


# harness §14.2: EffectiveConfigurationInference.epistemic_state is a
# strict subset of the full closed enum -- validated below, not modelled as
# a separate enum, so the single closed EpistemicState set (Lock principle 7)
# stays the only enum in the codebase.
_ALLOWED_EFFECTIVE_STATES = frozenset(
    {EpistemicState.INFERRED, EpistemicState.CONFLICTING, EpistemicState.UNKNOWN}
)


class EffectiveConfigurationInference(BaseModel):
    model_config = ConfigDict(frozen=True)

    property_key: str
    winning_candidate: ConfigurationCandidate | None = None
    losing_candidates: tuple[ConfigurationCandidate, ...] = ()
    rule_applied: str
    sources_inspected: tuple[str, ...] = ()
    higher_precedence_not_inspected: tuple[str, ...] = ()
    epistemic_state: EpistemicState
    resolution: Resolution
    # CFG-001 (Lock §4): "Effective" does not mean "observed"; the runtime is
    # NOT_OBSERVED absent a runtime sensor. Always this value in MVP.
    runtime_observation: EpistemicState = EpistemicState.NOT_OBSERVED

    @field_validator("property_key", "rule_applied")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be blank")
        return value

    @model_validator(mode="after")
    def _validate(self) -> "EffectiveConfigurationInference":
        if self.epistemic_state not in _ALLOWED_EFFECTIVE_STATES:
            raise ValueError(
                "EffectiveConfigurationInference.epistemic_state must be one "
                "of INFERRED, CONFLICTING, UNKNOWN (harness §14.2)"
            )
        if self.runtime_observation != EpistemicState.NOT_OBSERVED:
            raise ValueError(
                "runtime_observation must be NOT_OBSERVED absent a runtime "
                "sensor (CFG-001, Lock §4: \"'Effective' does not mean "
                "'observed'\")"
            )
        if self.resolution.status == ResolutionStatus.RESOLVED and self.winning_candidate is None:
            raise ValueError("resolution_status=RESOLVED requires a winning_candidate")
        if self.resolution.status == ResolutionStatus.UNRESOLVED and self.winning_candidate is not None:
            raise ValueError(
                "resolution_status=UNRESOLVED must not carry a winning_candidate "
                "(harness §14.3 states F/G: never report an unsupported value "
                "as effective)"
            )
        return self

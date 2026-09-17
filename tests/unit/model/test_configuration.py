import pytest
from pydantic import ValidationError

from ecdat.model.configuration import (
    Applicability,
    ConfigurationCandidate,
    EffectiveConfigurationInference,
    SourceKind,
)
from ecdat.model.epistemic import EpistemicState, Resolution, ResolutionStatus


def candidate(**overrides):
    fields = dict(
        property_key="pay.keywrap.transformation",
        value="RSA/ECB/OAEPWithSHA-256AndMGF1Padding",
        source_kind=SourceKind.SPRING_CONFIG_DATA,
        source_location="payments/payment-gateway/src/main/resources/application.yml:1",
        precedence_rank=3,
        applicability=Applicability.APPLICABLE,
    )
    fields.update(overrides)
    return ConfigurationCandidate(**fields)


def test_conditional_without_condition_rejected():
    with pytest.raises(ValidationError):
        candidate(applicability=Applicability.CONDITIONAL)


def test_condition_without_conditional_applicability_rejected():
    with pytest.raises(ValidationError):
        candidate(applicability=Applicability.APPLICABLE, condition="profile=prod")


def test_conditional_with_condition_ok():
    c = candidate(applicability=Applicability.CONDITIONAL, condition="profile=prod")
    assert c.condition == "profile=prod"


# --- harness §14.3 PAY-001 state matrix, as EffectiveConfigurationInference ---


def test_state_b_resolved_inferred():
    # State B: application.yml = OAEP -> INFERRED RSA-OAEP-SHA256; RESOLVED
    winning = candidate()
    result = EffectiveConfigurationInference(
        property_key="pay.keywrap.transformation",
        winning_candidate=winning,
        rule_applied="Spring Boot property-source order",
        sources_inspected=["application.yml"],
        higher_precedence_not_inspected=["os-env", "cli-arg", "system-prop", "spring-app-json"],
        epistemic_state=EpistemicState.INFERRED,
        resolution=Resolution(status=ResolutionStatus.RESOLVED),
    )
    assert result.resolution.status == ResolutionStatus.RESOLVED
    assert result.runtime_observation == EpistemicState.NOT_OBSERVED


def test_state_c_overridden_keeps_losing_candidate():
    # State C: env override wins; yml value kept as losing candidate; OVERRIDDEN
    yml = candidate()
    env_override = candidate(
        value="RSA/ECB/PKCS1Padding",
        source_kind=SourceKind.OS_ENV,
        source_location="k8s Deployment env PAY_KEYWRAP_TRANSFORMATION",
        precedence_rank=5,
    )
    result = EffectiveConfigurationInference(
        property_key="pay.keywrap.transformation",
        winning_candidate=env_override,
        losing_candidates=[yml],
        rule_applied="Spring Boot property-source order",
        epistemic_state=EpistemicState.INFERRED,
        resolution=Resolution(status=ResolutionStatus.OVERRIDDEN),
    )
    assert result.losing_candidates == (yml,)
    assert result.resolution.status == ResolutionStatus.OVERRIDDEN


def test_state_d_conflicting_requires_no_winning_candidate_is_still_allowed_but_state_conflicting():
    # State D: CONFLICTING {OAEP, PKCS1} -- no active-profile evidence.
    yml = candidate()
    prod_yml = candidate(value="RSA/ECB/PKCS1Padding", source_location="application-prod.yml:1")
    result = EffectiveConfigurationInference(
        property_key="pay.keywrap.transformation",
        losing_candidates=[yml, prod_yml],
        rule_applied="Spring Boot property-source order",
        epistemic_state=EpistemicState.CONFLICTING,
        resolution=Resolution(status=ResolutionStatus.UNRESOLVED, reason="active profile unknown"),
    )
    assert result.winning_candidate is None
    assert result.epistemic_state == EpistemicState.CONFLICTING


def test_state_f_unresolved_must_not_report_a_winning_candidate():
    # State F (A1): higher-precedence source present but unsupported -- must
    # not report B's or C's value as effective.
    with pytest.raises(ValidationError):
        EffectiveConfigurationInference(
            property_key="pay.keywrap.transformation",
            winning_candidate=candidate(),
            rule_applied="Spring Boot property-source order",
            epistemic_state=EpistemicState.UNKNOWN,
            resolution=Resolution(
                status=ResolutionStatus.UNRESOLVED,
                reason="higher-precedence source present, unsupported",
            ),
        )


def test_resolved_without_winning_candidate_rejected():
    with pytest.raises(ValidationError):
        EffectiveConfigurationInference(
            property_key="pay.keywrap.transformation",
            rule_applied="Spring Boot property-source order",
            epistemic_state=EpistemicState.INFERRED,
            resolution=Resolution(status=ResolutionStatus.RESOLVED),
        )


def test_effective_epistemic_state_restricted_to_subset():
    with pytest.raises(ValidationError):
        EffectiveConfigurationInference(
            property_key="pay.keywrap.transformation",
            rule_applied="Spring Boot property-source order",
            epistemic_state=EpistemicState.KNOWN,
            resolution=Resolution(status=ResolutionStatus.UNRESOLVED, reason="x"),
        )


def test_runtime_observation_must_be_not_observed():
    with pytest.raises(ValidationError):
        EffectiveConfigurationInference(
            property_key="pay.keywrap.transformation",
            rule_applied="Spring Boot property-source order",
            epistemic_state=EpistemicState.UNKNOWN,
            resolution=Resolution(status=ResolutionStatus.UNRESOLVED, reason="x"),
            runtime_observation=EpistemicState.KNOWN,
        )

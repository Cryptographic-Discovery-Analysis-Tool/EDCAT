"""The configuration-chain resolver (CFG-001; harness §14, FROZEN).

Answers one question: *given everything we could read, what value would Spring
actually bind to this property, and how sure can we honestly be?*

The answer is **never KNOWN**. CFG-001's DECISION says so outright —
"Successful resolution is INFERRED, never KNOWN" — because reading files is
not watching a process. `runtime_observation` stays NOT_OBSERVED until a
runtime sensor exists, and the model refuses any other value.

Three rules from §14.5 do the real work here, and each one is a guard against
a specific way of being confidently wrong:

* **R-UNSEEN** — a *possible* unseen source does not invalidate an inference;
  an *identified, present, unsupported* one does. Without the first half,
  nothing could ever be inferred (something could always be overriding it).
  Without the second half, we would report a value as effective while a
  command-line argument overriding it sits two lines below in the same file.
* **R-DERIVE** — a derived field is never more certain than its weakest input.
* **R-MONOTONE** — more evidence may reduce uncertainty, never manufacture it.
  The D→E transition is the test: adding an env override to a conflicting pair
  resolves it, because env genuinely outranks both.

And one refinement CFG-001 explicitly accepted: **two values with an
established precedence is an override, not a conflict.** CONFLICTING is
reserved for candidates we cannot order — two profile-specific files with no
known active profile.
"""
from __future__ import annotations

from dataclasses import dataclass

from ecdat.model.configuration import (
    Applicability,
    ConfigurationCandidate,
    EffectiveConfigurationInference,
    SourceKind,
)
from ecdat.model.epistemic import EpistemicState, Resolution, ResolutionStatus

#: Spring Boot property-source order, from CFG-001's VERIFIED FACTS (Spring
#: Boot reference 4.1.1). Later sources override earlier ones, so a HIGHER
#: rank wins. These five numbers are quoted from the decision text; none is
#: interpolated.
PRECEDENCE: dict[SourceKind, int] = {
    SourceKind.SPRING_CONFIG_DATA: 3,
    SourceKind.OS_ENV: 5,
    SourceKind.SYSTEM_PROP: 6,
    SourceKind.SPRING_APP_JSON: 10,
    SourceKind.CLI_ARG: 11,
}

#: External config data (a ConfigMap-mounted application.yml) sits between the
#: repository's packaged file and the environment. W1: "config data outside
#: the jar overrides the packaged file — lower than env, higher than the repo
#: yml". Spring lists both as position 3; this rank encodes the ordering W1
#: states WITHIN that position and is not a claim about Spring's own list.
EXTERNAL_CONFIG_DATA_RANK = 4

#: Sources that v1 DETECTS but does not RESOLVE (A1). Finding the property key
#: in one of these degrades the whole result to UNRESOLVED, because claiming
#: an effective value beneath an unparsed higher-precedence source is exactly
#: the false certainty CFG-001 was written to prevent.
DETECT_ONLY: frozenset[SourceKind] = frozenset(
    {SourceKind.CLI_ARG, SourceKind.SYSTEM_PROP, SourceKind.SPRING_APP_JSON}
)

RULE_APPLIED = "Spring Boot property-source order"

#: Sources that exist but static scanning cannot see at all (W1): a runtime
#: `kubectl patch`, an admission webhook, an operator injecting env, a
#: launcher adding -D flags. Listed rather than allowed to collapse every
#: result to UNKNOWN -- that is W1's whole point.
NOT_INSPECTABLE_STATICALLY: tuple[str, ...] = (
    "runtime kubectl patch / admission webhook",
    "operator-injected environment variables",
    "launcher-added -D flags outside the manifest",
    "image ENTRYPOINT/CMD not present in scanned build config",
)


@dataclass(frozen=True)
class Blocker:
    """An identified, present, unsupported source (R-UNSEEN, second half).

    `reason` is the literal wording CFG-001 requires, because these strings
    are the scored output: §14.3 grades states F and G on reporting UNRESOLVED
    with the right reason, not merely on declining to answer.
    """

    reason: str
    source_kind: SourceKind | None = None
    location: str | None = None


def _rank(candidate: ConfigurationCandidate) -> int:
    return candidate.precedence_rank


def resolve(
    property_key: str,
    candidates: tuple[ConfigurationCandidate, ...],
    *,
    blockers: tuple[Blocker, ...] = (),
    sources_inspected: tuple[str, ...] = (),
    active_profile: str | None = None,
    higher_precedence_not_inspected: tuple[str, ...] = NOT_INSPECTABLE_STATICALLY,
) -> EffectiveConfigurationInference:
    """Resolve one property key. See the module docstring for the rules."""

    def inference(
        *,
        state: EpistemicState,
        resolution: Resolution,
        winning: ConfigurationCandidate | None = None,
        losing: tuple[ConfigurationCandidate, ...] = (),
    ) -> EffectiveConfigurationInference:
        return EffectiveConfigurationInference(
            property_key=property_key,
            winning_candidate=winning,
            losing_candidates=losing,
            rule_applied=RULE_APPLIED,
            sources_inspected=sources_inspected,
            higher_precedence_not_inspected=higher_precedence_not_inspected,
            epistemic_state=state,
            resolution=resolution,
        )

    # --- R-UNSEEN, second half: a present, unsupported source wins over any
    # inference we might otherwise have made. Checked FIRST, before looking at
    # candidates at all, so no path can accidentally report a value beneath a
    # blocker (§14.3 states F, G, H-unattached; A1; A2).
    if blockers:
        return inference(
            state=EpistemicState.UNKNOWN,
            resolution=Resolution(
                status=ResolutionStatus.UNRESOLVED,
                reason="; ".join(b.reason for b in blockers),
            ),
            # Every candidate becomes a losing one: they are real observations,
            # and dropping them would lose the evidence chain CFG-001 requires
            # be preserved. None of them is winning.
            losing=tuple(sorted(candidates, key=_rank, reverse=True)),
        )

    if not candidates:
        return inference(
            state=EpistemicState.UNKNOWN,
            resolution=Resolution(
                status=ResolutionStatus.UNRESOLVED, reason="no binding value found"
            ),
        )

    # --- applicability. A conditional candidate (profile-specific file) only
    # applies when we know that profile is active.
    def applies(candidate: ConfigurationCandidate) -> bool:
        if candidate.applicability == Applicability.APPLICABLE:
            return True
        if candidate.applicability == Applicability.CONDITIONAL:
            return active_profile is not None and candidate.condition == f"profile={active_profile}"
        return False

    applicable = tuple(c for c in candidates if applies(c))
    undecidable = tuple(
        c
        for c in candidates
        if c.applicability == Applicability.CONDITIONAL and not applies(c)
    )

    ranked = sorted(applicable, key=_rank, reverse=True)
    top = ranked[0] if ranked else None

    # --- state D: profile-specific candidates we cannot order, and nothing
    # above them to settle it. Two values with an established precedence is an
    # OVERRIDE; two we cannot order is a CONFLICT. That distinction is the
    # refinement CFG-001 accepted and rejected the alternative of.
    if undecidable:
        contenders = tuple(
            c
            for c in (*applicable, *undecidable)
            if c.precedence_rank <= max(
                (u.precedence_rank for u in undecidable), default=0
            )
        )
        outranking = tuple(
            c for c in applicable if c.precedence_rank > max(u.precedence_rank for u in undecidable)
        )
        if not outranking:
            values = {c.value for c in contenders}
            if len(values) > 1:
                return inference(
                    state=EpistemicState.CONFLICTING,
                    resolution=Resolution(
                        status=ResolutionStatus.UNRESOLVED,
                        reason=(
                            "candidates cannot be ordered: profile-specific "
                            "configuration present with no known active profile"
                        ),
                    ),
                    losing=tuple(sorted(contenders, key=_rank, reverse=True)),
                )
        else:
            # --- state E. Something genuinely outranks the undecidable pair,
            # so the profile uncertainty is irrelevant for this key. R-MONOTONE
            # in the good direction: more evidence removed uncertainty.
            top = outranking[0] if len(outranking) == 1 else sorted(outranking, key=_rank, reverse=True)[0]
            losing = tuple(
                sorted(
                    (c for c in (*applicable, *undecidable) if c is not top),
                    key=_rank,
                    reverse=True,
                )
            )
            return inference(
                state=EpistemicState.INFERRED,
                resolution=Resolution(status=ResolutionStatus.OVERRIDDEN),
                winning=top,
                losing=losing,
            )

    if top is None:
        return inference(
            state=EpistemicState.UNKNOWN,
            resolution=Resolution(
                status=ResolutionStatus.UNRESOLVED,
                reason=(
                    "only profile-specific values found and no active profile "
                    "is known"
                ),
            ),
        )

    losing = tuple(c for c in ranked[1:])

    # --- state B: one applicable candidate, nothing above it. RESOLVED.
    # --- state C / H: something higher-ranked beat a lower one. OVERRIDDEN.
    status = ResolutionStatus.OVERRIDDEN if losing else ResolutionStatus.RESOLVED
    return inference(
        state=EpistemicState.INFERRED,
        resolution=Resolution(status=status),
        winning=top,
        losing=losing,
    )

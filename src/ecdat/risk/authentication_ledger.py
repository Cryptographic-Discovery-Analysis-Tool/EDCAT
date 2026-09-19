"""Authentication exposure ledger (Pramana_Ledger_Spec.md §5.6).

The second clock, and the reason there are two ledgers rather than one
weighted list. A signature does not leak when Z arrives -- it becomes
forgeable. Nothing already signed is "lost"; what matters is whether the
artefact still has to be trustworthy after Z.

That splits cleanly in two, and the split is the whole content of this module:

* `A == 0` -- a session signature (a TLS server certificate authenticating a
  handshake). Nothing needs to stay trustworthy past the session, so the only
  requirement is that the key is off the wire before Z. The deadline is
  `Z - Y`, the rollout window, because rotation is not instantaneous.
* `required_until = signed_at + A > Z` -- a long-lived signed artefact. It
  must be re-signed with a PQ signature, or timestamped by a trusted
  authority, before Z.

The red-team fix preserved here: signatures are NOT `Z - rollout` across the
board. Collapsing both cases into one deadline loses the re-sign obligation
entirely, which is the expensive one.
"""
from __future__ import annotations

from ecdat.model.epistemic import EpistemicState
from ecdat.model.usage_context import AUTHENTICATION_FUNCTIONS, CryptoFunction
from ecdat.risk.confidentiality_ledger import LedgerNotApplicable, _evidence_refs
from ecdat.risk.record import (
    CalculationRecord,
    ExposureBand,
    LedgerInputs,
)

RULE_ID = "LEDGER-AUTH-001"


def _record(
    inputs: LedgerInputs,
    record_id: str,
    *,
    band: ExposureBand,
    reason: str = "",
    deadline=None,
    conditional_band: ExposureBand | None = None,
) -> CalculationRecord:
    return CalculationRecord(
        record_id=record_id,
        as_of=inputs.as_of,
        scenario_id=inputs.scenario.id,
        capture_assumption=inputs.policy.capture_assumption,
        policy_snapshot=inputs.policy,
        usage_context_id=inputs.usage_context.usage_context_id,
        function=inputs.usage_context.function.value,
        evidence_refs=_evidence_refs(inputs),
        band=band,
        deadline=deadline,
        conditional_band=conditional_band,
        reason=reason,
        A=inputs.binding.authenticity_lifetime_A if inputs.binding is not None else None,
        rule_version=RULE_ID,
        inputs_sha256=inputs.sha256(),
        inputs=inputs,
    )


def evaluate(inputs: LedgerInputs, *, record_id: str = "") -> CalculationRecord:
    """§5.6. One signature context in, one CalculationRecord out.

    No capture assumption appears anywhere: a signature is not harvested, so
    the row carries no "assumes capture" sentence. That asymmetry is real and
    is the point of keeping the two ledgers apart.
    """
    context = inputs.usage_context
    function = context.function.value
    record_id = record_id or f"auth:{context.usage_context_id}:{inputs.scenario.id}"

    if function is not None and function not in AUTHENTICATION_FUNCTIONS:
        raise LedgerNotApplicable(
            f"{function.value} is not an authentication function; §5.6 applies "
            "to signatures. Confidentiality functions go to §5.5."
        )

    if context.function.state == EpistemicState.UNKNOWN:
        return _record(
            inputs,
            record_id,
            band=ExposureBand.UNBOUNDED,
            reason=(
                "crypto function is UNKNOWN for this context, so no clock "
                "applies; no conditional band is derivable either"
            ),
        )

    z_date = inputs.scenario.z_date

    if inputs.binding is None or inputs.binding.authenticity_lifetime_A is None:
        return _record(
            inputs,
            record_id,
            band=ExposureBand.UNBOUNDED,
            reason=(
                "no authenticity lifetime A is bound to this target, so "
                "required_until = signed_at + A cannot be computed"
            ),
            conditional_band=ExposureBand.ROTATE_BEFORE_Z,
        )

    inferred = context.function.state == EpistemicState.INFERRED
    A = inputs.binding.authenticity_lifetime_A

    if A.is_zero:
        band = ExposureBand.ROTATE_BEFORE_Z
        deadline = inputs.policy.rollout_Y_default.before(z_date)
        reason = (
            f"session signature (A = 0): nothing must outlive the session, so "
            f"the key must be off the wire by Z - Y = {deadline.isoformat()}"
        )
    else:
        if inputs.signed_at is None:
            return _record(
                inputs,
                record_id,
                band=ExposureBand.UNBOUNDED,
                reason=(
                    f"A = {A} but signed_at is unknown, so required_until "
                    "cannot be computed"
                ),
                conditional_band=ExposureBand.RESIGN_BEFORE_Z,
            )
        required_until = inputs.binding.required_until(inputs.signed_at)
        if required_until > z_date:
            band = ExposureBand.RESIGN_BEFORE_Z
            deadline = z_date
            reason = (
                f"artefact must stay trustworthy until "
                f"{required_until.isoformat()}, past Z ({z_date.isoformat()}): "
                "re-sign with a PQ signature, or trusted-timestamp it, before Z"
            )
        else:
            band = ExposureBand.SAFE_UNTIL_Z
            deadline = None
            reason = (
                f"artefact's authenticity is only required until "
                f"{required_until.isoformat()}, at or before Z "
                f"({z_date.isoformat()})"
            )

    if inferred and not inputs.policy.accept_inferred_inputs:
        return _record(
            inputs,
            record_id,
            band=ExposureBand.UNBOUNDED,
            reason="policy does not accept INFERRED inputs; inferred here: function",
            deadline=deadline,
            conditional_band=band,
        )

    return _record(inputs, record_id, band=band, reason=reason, deadline=deadline)

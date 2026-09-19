"""UsageContext and CryptoFunction (Pramana_Ledger_Spec.md §5.1).

The red-team finding this module exists to fix: *function was on the asset,
not on the usage context*. One RSA key can be the authentication key of a TLS
endpoint (signature, fails on the Z-clock by forgery) and, on a different
surface, the key a premaster secret is encrypted to (key transport, fails on
the harvest clock). Those two facts do not share a deadline, so they cannot
share a row. One asset -> N UsageContexts; the ledgers consume contexts, never
assets.

Spec vocabulary vs the closed enum. The spec says Observed / Inferred /
Declared. `model.epistemic.EpistemicState` is a CLOSED enum (CLAUDE.md) and is
not extended here; the spec's words are read onto it:

    Observed -> KNOWN         (seen on the traffic path / in the artefact)
    Inferred -> INFERRED      (capability, configuration, keyUsage)
    Declared -> DECLARED      (an operator said so)
    absent   -> UNKNOWN       (never a default function -- §5.1 "No default")
"""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from ecdat.model.epistemic import EpistemicState
from ecdat.model.field_value import FieldValue


class CryptoFunction(str, Enum):
    """§5.1. Closed set. UNKNOWN is a real member, not a null."""

    SIGNATURE_AUTH = "SIGNATURE_AUTH"
    KEY_ESTABLISHMENT = "KEY_ESTABLISHMENT"
    ENCRYPTION = "ENCRYPTION"
    KEY_TRANSPORT = "KEY_TRANSPORT"
    HYBRID_KEX = "HYBRID_KEX"
    UNKNOWN = "UNKNOWN"


#: Functions whose failure mode is "recorded now, decrypted at Z" -- the only
#: functions the confidentiality ledger applies to (§5.5: "KEX, key transport,
#: PKE"). ENCRYPTION is symmetric bulk encryption: Grover, not Shor, so it
#: goes to a policy flag and never to the ledger. HYBRID_KEX is in scope
#: because a hybrid context still has to be *proved* hybrid from the start.
CONFIDENTIALITY_FUNCTIONS: frozenset[CryptoFunction] = frozenset(
    {
        CryptoFunction.KEY_ESTABLISHMENT,
        CryptoFunction.KEY_TRANSPORT,
        CryptoFunction.HYBRID_KEX,
    }
)

#: §5.6 -- the other clock.
AUTHENTICATION_FUNCTIONS: frozenset[CryptoFunction] = frozenset(
    {CryptoFunction.SIGNATURE_AUTH}
)


class UsageContext(BaseModel):
    """One (asset, surface, protocol position) at which one crypto function is
    performed. The ledger's unit of account.

    `function` is a FieldValue, so the spec's `function` and `status` fields
    are one object carrying its own evidence_refs and rule_id -- the house
    per-field pattern (Lock §2 principle 8) rather than a parallel status
    field that could drift out of step with the value it describes.

    `algorithm` is deliberately separate and independently stated: §5.1's
    "algorithm may be Unknown while function is Observed". A source call site
    whose transformation string comes from a properties file gives exactly
    that -- KEY_TRANSPORT observed, algorithm UNKNOWN -- and collapsing the
    two would invent one or destroy the other.
    """

    model_config = ConfigDict(frozen=True)

    usage_context_id: str
    asset_id: str
    surface_id: str
    protocol_context: str
    function: FieldValue[CryptoFunction]
    algorithm: FieldValue[str] | None = None

    @field_validator("usage_context_id", "asset_id", "surface_id", "protocol_context")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be blank")
        return value

    @model_validator(mode="after")
    def _validate_function(self) -> "UsageContext":
        fn = self.function
        if fn.state == EpistemicState.UNKNOWN:
            if fn.value not in (None, CryptoFunction.UNKNOWN):
                raise ValueError(
                    "function.state=UNKNOWN must not carry a concrete function "
                    "(§5.1: anything else -> UNKNOWN, no default)"
                )
            return self
        if fn.value is None:
            raise ValueError(
                f"function.state={fn.state.value} requires a value; only "
                "UNKNOWN may be empty"
            )
        if fn.value == CryptoFunction.UNKNOWN and fn.state != EpistemicState.UNKNOWN:
            raise ValueError(
                "CryptoFunction.UNKNOWN may only be held at state UNKNOWN -- "
                "claiming to have observed that the function is unknown is "
                "false certainty"
            )
        if fn.rule_id is None:
            raise ValueError(
                "a classified function requires the rule_id that classified it "
                "(§5.1; CLAUDE.md R-DERIVE)"
            )
        if fn.state == EpistemicState.KNOWN and not fn.evidence_refs:
            raise ValueError(
                "function.state=KNOWN (spec: Observed) requires at least one "
                "evidence_ref -- nothing is observed without an observation"
            )
        return self

    @property
    def is_confidentiality(self) -> bool:
        return self.function.value in CONFIDENTIALITY_FUNCTIONS

    @property
    def is_authentication(self) -> bool:
        return self.function.value in AUTHENTICATION_FUNCTIONS

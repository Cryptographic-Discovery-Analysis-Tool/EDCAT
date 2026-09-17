"""ProbeTargetIdentity vs ObservationContext (harness §15.2 T7, FROZEN):

"Identity != observation context. Probe-target identity = what ECDAT
*asked for*: {requested host, port, SNI sent, probe_vantage}. Observation
context = what it *got*: {resolved IP, observed_at, ...}. Resolved IP is
context, not identity (DNS round-robin, anycast, LB pools); observed_at is
never identity."
"""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, field_validator


class ProbeTargetIdentity(BaseModel):
    """What ECDAT asked for. Used for scope-field matching by correlation
    rules (T7: "Every correlation rule declares which scope fields must
    match.")."""

    model_config = ConfigDict(frozen=True)

    requested_host: str
    port: int
    sni_sent: str | None = None
    probe_vantage: str

    @field_validator("requested_host", "probe_vantage")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be blank")
        return value

    @field_validator("port")
    @classmethod
    def _valid_port(cls, value: int) -> int:
        if not (0 < value <= 65535):
            raise ValueError("port must be in 1..65535")
        return value


class ObservationContext(BaseModel):
    """What ECDAT got. Never identity -- resolved_ip and observed_at must
    never be used as correlation/scope-matching keys (T7)."""

    model_config = ConfigDict(frozen=True)

    resolved_ip: str | None = None
    observed_at: datetime

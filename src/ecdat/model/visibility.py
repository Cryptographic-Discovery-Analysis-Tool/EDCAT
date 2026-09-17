"""VisibilityEntry per dimension (Lock principle 6: "Report what could not be
seen. This is done through the visibility matrix (Directive 3), not a scalar
coverage %.").

Directive 3 itself is not available in this repo (docs/open-issues.md
OI-001), so the dimension list and support_level enum below are sourced only
from what the Lock and harness actually state, not from Directive 3's own
(unseen) detailed definition:

- Dimensions: Lock §5 row "4 Coverage" -- "Superseded by the visibility
  matrix: artifact, source, dependency, configuration, deployment, runtime,
  network, HSM/KMS, and failed/timeout targets."
- support_level: Lock §4 PRV-001 "Language adapters declare a support level
  in {full, partial, detect-only, unsupported}, which feeds the visibility
  matrix."; Lock §5 row "2 Adapters" -- "every adapter declares a
  language/surface support level."
"""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict


class VisibilityDimension(str, Enum):
    ARTIFACT = "artifact"
    SOURCE = "source"
    DEPENDENCY = "dependency"
    CONFIGURATION = "configuration"
    DEPLOYMENT = "deployment"
    RUNTIME = "runtime"
    NETWORK = "network"
    HSM_KMS = "hsm_kms"
    FAILED_TIMEOUT = "failed_timeout"


class SupportLevel(str, Enum):
    FULL = "full"
    PARTIAL = "partial"
    DETECT_ONLY = "detect-only"
    UNSUPPORTED = "unsupported"


class VisibilityEntry(BaseModel):
    model_config = ConfigDict(frozen=True)

    dimension: VisibilityDimension
    support_level: SupportLevel
    detail: str | None = None

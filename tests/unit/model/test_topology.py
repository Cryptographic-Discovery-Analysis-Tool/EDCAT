from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from ecdat.model.topology import ObservationContext, ProbeTargetIdentity


def test_probe_target_identity_valid():
    identity = ProbeTargetIdentity(
        requested_host="edge-lb.example",
        port=443,
        sni_sent="customer-portal.example",
        probe_vantage="internal-scanner-1",
    )
    assert identity.port == 443


@pytest.mark.parametrize("bad_port", [0, -1, 65536, 100000])
def test_probe_target_identity_rejects_bad_port(bad_port):
    with pytest.raises(ValidationError):
        ProbeTargetIdentity(
            requested_host="edge-lb.example",
            port=bad_port,
            probe_vantage="internal-scanner-1",
        )


def test_observation_context_has_no_identity_fields():
    ctx = ObservationContext(resolved_ip="10.0.0.5", observed_at=datetime.now(timezone.utc))
    assert not hasattr(ctx, "requested_host")
    assert not hasattr(ctx, "probe_vantage")

"""
Re-recording of tier_a_edge_lb.raw.json (2026-09-26) against the harness's
regenerated (now-deterministic) PKI, since the previous recording's
pay-edge cert bytes went stale when the PKI was regenerated.

Substitution recorded, same as the original 2026-09-17 capture and for the
same reason (README.md in this fixture directory, OI-007): no haproxy binary
on this machine, so `openssl s_server` stands in as the TLS endpoint,
presenting the exact pay-edge.pem file HAProxy's own config loads.

This constructs sslyze's own JSON output object (`SslyzeOutputAsJson`) the
same way sslyze's own CLI (`sslyze/__main__.py`) does it -- confirmed by
reading that file's `SslyzeOutputAsJson(...)` call before writing this
script -- which is what produces the "invalid_server_strings" /
"server_scan_results" / "date_scans_started" / ... top-level shape the
original tier_a_edge_lb.raw.json has (a *library* use of sslyze, not the
CLI, per this task's original "sslyze (library)" instruction -- same as
topo_x1_sni_probe.py alongside this file).

Run (after starting the local s_server -- see README.md in this directory
for the exact command):
    python tier_a_edge_lb_scan.py > tier_a_edge_lb.raw.json
"""
import sys
from datetime import datetime, timezone

from sslyze import (
    Scanner,
    ScanCommand,
    ServerNetworkLocation,
    ServerScanRequest,
    ServerScanResultAsJson,
)
from sslyze.json.json_output import SslyzeOutputAsJson

date_scans_started = datetime.now(timezone.utc)

server_location = ServerNetworkLocation(
    hostname="pay-edge",  # SNI value -- matches the cert's SAN (DNS:pay-edge)
    ip_address="127.0.0.1",
    port=8443,
)

scanner = Scanner()
scanner.queue_scans(
    [
        ServerScanRequest(
            server_location=server_location,
            # Full scan command set -- matches the original 2026-09-17
            # capture's scan_result key list (certificate_info,
            # *_cipher_suites, elliptic_curves, etc.), which this parser's
            # tests (ecdat/tests/unit/adapters/test_tls.py) read fields from
            # beyond just certificate_info (accepted cipher suites, curves).
            scan_commands=set(ScanCommand),
        )
    ]
)

all_server_scan_results = list(scanner.get_results())

output = SslyzeOutputAsJson(
    server_scan_results=[
        ServerScanResultAsJson.model_validate(result) for result in all_server_scan_results
    ],
    invalid_server_strings=[],
    date_scans_started=date_scans_started,
    date_scans_completed=datetime.now(timezone.utc),
)

sys.stdout.write(output.model_dump_json(indent=2))
sys.stdout.write("\n")

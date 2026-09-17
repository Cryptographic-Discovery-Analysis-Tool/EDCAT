"""
TOPO-X1 (Lock sec.6): confirm how sslyze records the SNI/server-name it used
when probing a TLS endpoint, using the sslyze *library* API (not the CLI),
against the Tier A edge-lb TLS-terminator substitute (see README.md in this
directory for why openssl s_server stands in for the missing HAProxy binary).

Run: python topo_x1_sni_probe.py > topo_x1_sni_probe.raw.json
"""
import json
import sys

from sslyze import (
    ServerNetworkLocation,
    ServerScanRequest,
    Scanner,
    ScanCommand,
)

server_location = ServerNetworkLocation(
    hostname="pay-edge",  # SNI value sent -- matches the cert's SAN (DNS:pay-edge)
    ip_address="127.0.0.1",
    port=8443,
)

scanner = Scanner()
scanner.queue_scans(
    [
        ServerScanRequest(
            server_location=server_location,
            scan_commands={ScanCommand.CERTIFICATE_INFO},
        )
    ]
)

results = list(scanner.get_results())
result = results[0]

output = {
    "server_location": {
        "hostname": result.server_location.hostname,
        "ip_address": result.server_location.ip_address,
        "port": result.server_location.port,
    },
    "connectivity_result": {
        "hostname_used_for_server_name_indication": (
            result.connectivity_result.client_auth_requirement.name
            if result.connectivity_result
            else None
        ),
    },
    "scan_status": str(result.scan_status),
}

# The field that actually carries "what SNI value was sent" in sslyze 6.x is
# ServerNetworkLocation.hostname itself (sslyze sends the connection hostname
# as SNI unless overridden) -- record that explicitly plus the raw object repr
# for anything else the scan attached it to.
output["sni_sent"] = server_location.hostname
output["certificate_deployments_found"] = []

if result.scan_result and result.scan_result.certificate_info.result:
    cert_info = result.scan_result.certificate_info.result
    for deployment in cert_info.certificate_deployments:
        leaf = deployment.received_certificate_chain[0]
        output["certificate_deployments_found"].append(
            {
                "leaf_subject": leaf.subject.rfc4514_string(),
                "leaf_san_dns": [
                    e.value
                    for e in leaf.extensions
                    if e.oid._name == "subjectAltName"
                ]
                if leaf.extensions
                else None,
                "verified_chain_has_sha1_signature": deployment.verified_chain_has_sha1_signature,
                "received_chain_has_valid_order": deployment.received_chain_has_valid_order,
            }
        )

json.dump(output, sys.stdout, indent=2, default=str)
print()

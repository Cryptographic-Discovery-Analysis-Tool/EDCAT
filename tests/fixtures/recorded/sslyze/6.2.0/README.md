# sslyze 6.2.0 (library) — recorded fixtures (2026-09-17)

**Exact command to install (pinned):**
```bash
pip install --no-warn-script-location 'sslyze==6.2.0'
```
Run on native Windows Python (`C:\Python314`), no WSL needed — sslyze installs
fine there, unlike semgrep.

**Exact version:** `pip show sslyze` → `Version: 6.2.0`. Recorded dependency
conflict (does not block sslyze itself): `pyopenssl 25.3.0 requires
cryptography<47,>=45.0.7, but you have cryptography 44.0.3` — pip's resolver
downgraded `cryptography` to satisfy sslyze's own pin; both were already
present on this machine from an earlier task (OI-002's PRV-T1/T2/T3 work did
not use these). Not investigated further; recorded honestly per the
anti-hallucination rule against silently assuming environment purity.

**Date run:** 2026-09-17

**Target:** Tier A edge-lb TLS endpoint (harness §5.3 / §13). **Substitution
recorded:** the harness has no `haproxy` binary available on this machine
(`docs/open-issues.md` OI-007), so `openssl s_server -accept 8443 -cert
targets/payments/edge-lb/certs/pay-edge.pem -key
targets/payments/edge-lb/certs/pay-edge.pem -www` was used as a stand-in TLS
listener, presenting the exact same `pay-edge.pem` file
(`generate-pki.sh`-produced cert+key+chain bundle) that HAProxy's own config
(`haproxy.cfg`: `bind *:8443 ssl crt /etc/haproxy/certs/pay-edge.pem`) is
written to load. This proves the certificate/SNI-recording behaviour under
test but does **not** prove HAProxy's own TLS stack behaves identically
(cipher negotiation quirks, ALPN, etc. are HAProxy-specific and untested here)
— same class of honest substitution as OI-007's Maven-instead-of-Docker
workaround.

**Code:** `topo_x1_sni_probe.py` — uses the `sslyze` **library** API (not the
CLI), per this task's "sslyze (library)" instruction:
`sslyze.Scanner`, `ServerNetworkLocation`, `ServerScanRequest`,
`ScanCommand.CERTIFICATE_INFO`.

**Exact command:**
```bash
python topo_x1_sni_probe.py > topo_x1_sni_probe.raw.json 2> topo_x1_sni_probe.stderr.log
```

**Files:**
- `topo_x1_sni_probe.py` — the script (source, not output; kept alongside the
  recording per CLAUDE.md's "no parser without a recorded fixture" rule — this
  IS the fixture-producing code, analogous to `experiments/PRV-T*` layout).
- `topo_x1_sni_probe.raw.json` — raw JSON result.
- `topo_x1_sni_probe.stderr.log` — raw stderr (one `CryptographyDeprecationWarning`
  from sslyze's own trust-store loading code, unrelated to the SNI question).

See `docs/experiments.md` TOPO-X1 entry for the finding.

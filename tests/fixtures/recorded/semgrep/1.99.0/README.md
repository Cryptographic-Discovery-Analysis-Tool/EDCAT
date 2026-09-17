# semgrep 1.99.0 — recorded fixtures (2026-09-17)

**Exact command to install (pinned):**
```bash
pip3 install --user --break-system-packages 'semgrep==1.99.0'
```
Run inside WSL Ubuntu (default distro, already present on this machine) because
`pip install semgrep` fails on native Windows Python with
`Exception: Semgrep does not support Windows yet` (semgrep issue #1330). This
gap is recorded in `docs/open-issues.md`.

**Exact version:** `semgrep --version` → `1.99.0`

**Date run:** 2026-09-17

**Target:** Tier A (harness `docs/ECDAT_Synthetic_Enterprise_Test_Harness.md` §3/§13)
- `ecdat-harness/targets/payments/payment-gateway/src` (Java source, incl. TRAP-01)
- `ecdat-harness/targets/controls/no-crypto-service` (TRAP-07 negative control)

**Exact commands:**
```bash
semgrep --config=auto --json --output pg.json  targets/payments/payment-gateway/src
semgrep --config=auto --json --output ncs.json targets/controls/no-crypto-service
```
`--config=auto` pulls Semgrep Registry community rules over the network (logged
by semgrep itself as "METRICS: Using configs from the Registry ... reports
pseudonymous rule metrics to semgrep.dev"); this is not a fully offline/pinned
rule set — only the semgrep *engine* version is pinned here, not the registry
rule content, which can change between runs. Recorded as a known limitation,
not silently treated as reproducible byte-for-byte.

**Files:**
- `e1_supplemental_payment-gateway.raw.json` — raw `--json` output against the
  payment-gateway source tree.
- `e1_supplemental_no-crypto-service.raw.json` — raw `--json` output against
  the negative-control service.

**Note on naming:** these are NOT the Lock §6 gate experiments E1–E4 (which
name Trivy/YARA/sslyze/OpenSSL, not semgrep — semgrep is not in that table).
They are recorded under an `e1_supplemental_*` prefix because this task asked
for a semgrep run against Tier A targets in addition to the canonical gate
tools; see `docs/experiments.md` and `docs/open-issues.md` for the full
reconciliation of what this task's tool list covers vs. what Lock §6 defines.

See `docs/experiments.md` for the finding-by-finding analysis.

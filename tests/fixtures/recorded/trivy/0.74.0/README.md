# trivy 0.74.0 — recorded fixtures (2026-09-17)

**Exact command to install (pinned):**
```bash
curl -sL -o trivy.tar.gz https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_Linux-64bit.tar.gz
sha256sum trivy.tar.gz   # 2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a
tar xzf trivy.tar.gz trivy
```
Run inside WSL Ubuntu — no native-Windows trivy binary was fetched (Linux
binary chosen because the harness's own eventual CI/adapter target is Linux
containers, not Windows; this machine's WSL provides that environment without
needing Docker itself). `v0.74.0` was the `releases/latest` tag on
2026-09-17 per the GitHub API (`v0.58.1`, initially guessed, does not exist —
recorded so the version isn't mistaken for a considered choice).

**Exact version:** `trivy --version` → `Version: 0.74.0`

**Date run:** 2026-09-17

**Target:** Tier A (payment-gateway, no-crypto-service). Trivy's vulnerability
DB was downloaded live from `mirror.gcr.io/aquasec/trivy-db:2` at scan time
(not pinned to a DB snapshot — recorded as a limitation: DB content, and
therefore which CVEs are flagged, can change between runs even with the same
trivy binary version).

**Exact commands and what they found:**

1. `trivy fs --scanners vuln,secret,misconfig targets/payments/payment-gateway`
   — **FAILED**: `FATAL Error remote Maven repository returned 429 Too Many
   Requests ... The repository blocks all subsequent requests from this IP
   until the block clears.` Trivy's `fs` mode resolves a Maven `pom.xml`'s
   *effective* dependency tree live against Maven Central rather than reading
   only what's already present locally. This is adapter-design-relevant: a
   trivy-based adapter run inside the harness's declared no-egress internal
   network (H6, `docker-compose.yml`) would hit this exact failure, not a
   degraded-but-working scan. Not retried after the 429 (recorded as-is,
   `Retry-After: 1800`).

2. `trivy fs --scanners vuln,secret targets/payments/payment-gateway/target`
   (directory containing the built fat jar) and
   `trivy fs --scanners vuln <jar-file-path-directly>` — both returned
   `Number of language-specific files num=0`: **trivy's `fs` command does not
   scan a standalone `.jar` file for embedded dependencies**, whether pointed
   at the jar directly or at its containing directory.

3. `trivy rootfs --scanners vuln --list-all-pkgs .` (cwd = a directory
   containing only the copied jar) — **succeeded**: detected the jar as
   `Type: jar`, `Number of language-specific files num=1`, and enumerated all
   22 embedded packages (`e1_supplemental_payment-gateway-fatjar.raw.json`),
   including `org.bouncycastle:bcprov-jdk18on 1.86` bundled inside the
   Spring Boot fat jar — 0 known vulnerabilities for any of them at scan time.
   **`fs` vs `rootfs` mode differ in jar/binary detection** — recorded because
   this materially affects which trivy subcommand an ECDAT adapter must call.

4. `trivy fs --scanners vuln,secret,misconfig targets/controls/no-crypto-service`
   — 0 results (`e1_supplemental_no-crypto-service.raw.json`). Consistent with
   TRAP-07: `requirements.txt` there is a single comment line with no
   dependencies (verified by `cat`, see `docs/experiments.md`), so there was
   nothing for trivy to find either way — this is a **negative** result of
   the intended kind (trap works), not evidence trivy can find nothing.

**Files:**
- `e1_supplemental_payment-gateway-fatjar.raw.json`
- `e1_supplemental_no-crypto-service.raw.json`

**Naming note — this does NOT satisfy Lock §6's E1.** E1 is defined as
"Trivy on a **stripped Go binary**." No Go toolchain exists on this machine
(`go` not found), and the only Go source in the harness
(`ecdat-harness/targets/research/datalake-sync`) is Tier B/Research-domain,
not Tier A (harness §3/§13 confirm Tier A = payment-gateway + edge-lb + PKI +
one trap + no-crypto control only). Running trivy against the Tier A jar
instead is useful supplemental adapter-design evidence, but it is a different
experiment from E1 and is filed under `e1_supplemental_*`, not `E1`, for
exactly that reason. The real E1 gap is recorded in `docs/open-issues.md`.

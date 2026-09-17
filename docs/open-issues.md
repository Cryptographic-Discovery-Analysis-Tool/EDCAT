# Open Issues

## OI-001 — Two of three canonical architecture docs are empty (2026-09-17)

**Status:** BLOCKING for any task that needs their content. NOT blocking for repo-skeleton/CI/tooling work.

CLAUDE.md's canonical-sources precedence order lists:
1. `docs/architecture/ECDAT_Architecture_Lock.md` — present, real content (16,618 bytes).
2. `docs/architecture/ECDAT_Architecture_Stress-Test_Directives.md` — **empty** (0 bytes). Only
   exists as a placeholder created during initial repo scaffolding; the actual directives text
   (referenced throughout the Lock as "Directive 3", "Directive 6"–"Directive 10", "Directive 12")
   has never been supplied to this repo.
3. `docs/architecture/ECDAT_Final_Architecture.md` — **empty** (0 bytes). Same situation — the
   Lock's §5 "Supersession map for `ECDAT_Final_Architecture.md`" amends a document this repo
   does not actually have a copy of.

**Why this matters:** per the anti-hallucination rules, content for these docs must never be
typed from memory or inferred from the Lock's references to them. Any task that requires reading
a specific Directive N or the pre-amendment Final Architecture text must STOP here first.

**Not currently blocking:** the 2026-09-17 task (repo skeleton, hash-vs-ADR CI check, harness-identifier
grep check, CycloneDX 1.6 schema download) does not require the content of either missing doc — it
only needs the three files to exist at the right paths, which they do. Proceeding with that work;
this entry stays open until the real source text for both docs is supplied.

**Resolution:** user must provide the actual source files for `ECDAT_Architecture_Stress-Test_Directives.md`
and `ECDAT_Final_Architecture.md`, or confirm the Lock is the sole surviving canonical doc and the
other two should be removed from the precedence list in CLAUDE.md.

## OI-002 — No harness-pinned JDK/BC/Node/OpenSSL build exists yet (2026-09-17)

**Status:** NOT blocking for the PRV-T1/T2/T3 evidence-gate experiments (2026-09-17 task), because
Lock §6.1 explicitly says these preliminary observations "do not satisfy the gate" for exactly this
reason and asks for them anyway. Blocking for ever calling PRV-001 LOCKED (harness §16.3 freeze gate
requires "the pinned JDK build", and harness §16.2 says "the harness pins one JDK build").

Lock §6.1: "the harness has not yet chosen its pinned JDK build (no payment-gateway image exists)."
No `ecdat-harness/targets/payments/payment-gateway` image, Dockerfile pin, or `harness/build/pki-lock.generated.json`
exists in the ecdat-harness repo as of this entry — confirmed by inspecting the repo tree.

**What this means for docs/experiments.md EXP-002/003/004 (PRV-T1/T2/T3):** those experiments ran
against whatever JDK/Node/OpenSSL/BC build happened to be installed on the machine that ran them
(recorded exactly, with full version strings, in each entry) — not against a harness-sanctioned pin.
Per Lock §6.1's own classification, this makes them **preliminary observations, not gate results**,
even though the commands and revised-test list match harness §16.1 "Revised tests" 1–3 exactly.

**Resolution:** once the harness builds the payment-gateway image and pins a JDK build (harness
build order, Lock §9 step 1), re-run PRV-T1/T2/T3 against that exact pinned build and record the
result as a gate result (not preliminary) in docs/experiments.md, citing the image digest.

## OI-003 — `CryptoAsset.scope_anchor` has no canonical definition (2026-09-17)

**Status:** NOT fully blocking — implemented as a minimal, explicitly-labeled ASSUMPTION field
rather than stopping the whole model-layer task, per CLAUDE.md's instruction to record and continue
where the gap doesn't require inventing load-bearing behaviour.

The 2026-09-17 model-layer task asks for "CryptoAsset (with scope_anchor)". The literal term
`scope_anchor` does not appear anywhere in `docs/architecture/ECDAT_Architecture_Lock.md` or
`ecdat-harness/docs/ECDAT_Synthetic_Enterprise_Test_Harness.md` (checked by exact grep, case
insensitive). It most plausibly belongs to Directive 3 (visibility/scope) or the Final
Architecture's Part 1 ("Targets") — both empty per [OI-001](#oi-001--two-of-three-canonical-architecture-docs-are-empty-2026-09-17).

The one adjacent canonical concept is harness §15.2 T5: a scan request declares an inventory scope
(`cmdb_scope: [payments, research]`); evidence inside that scope without an owner is
`UNATTRIBUTED`, evidence outside it is `OUT_OF_DECLARED_SCOPE`. `CryptoAsset.scope_anchor` is
implemented as `str | None` — an opaque declared-scope domain identifier (e.g. `"payments"`) an
asset can be checked against — grounded in that concept but **not verified** as the intended field.
No UNATTRIBUTED/OUT_OF_DECLARED_SCOPE logic is implemented against it (that's correlation-layer
work, out of scope here); the model layer only carries the field.

**Resolution:** confirm or correct `scope_anchor`'s intended shape once Directive 3 /
Final Architecture Part 1 is supplied.

## OI-004 — Evidence `base_confidence` has no populated source table (2026-09-17)

**Status:** NOT blocking — `Evidence.base_confidence` is modelled as a plain `float` in `[0, 1]`,
range-validated only. No source-tool → confidence mapping is hardcoded anywhere in
`src/ecdat/model/`.

Lock §5 row "3 Findings & confidence": "The base confidence table applies to evidence items."
This is the only text that exists about it — the actual table (values per source tool) would live
in `docs/architecture/ECDAT_Final_Architecture.md` Part 3, which is empty (OI-001), or as curated
rows in `data/` (currently empty except `.gitkeep`, per the project's own convention that "every
row [in data/] has a citation field"). Per CLAUDE.md's anti-hallucination rule, no such mapping may
be typed from memory, so none was added. Callers (adapters, not yet built) must supply
`base_confidence` themselves until the table exists in `data/`.

**Resolution:** populate `data/` with the cited base-confidence table once Final Architecture
Part 3 (or an equivalent decision) is supplied; wire adapters to look values up from there, never
from a hardcoded dict in `src/`.

## OI-005 — No canonical total order among epistemic states for R-DERIVE (2026-09-17)

**Status:** NOT blocking — implemented as an explicit, documented engineering decision
([ADR-001](decisions/ADR-001-epistemic-derivation-strength-order.md)), not a silent assumption.

Lock §3's R-DERIVE says a derived field "is never more certain than its weakest required input,"
but neither the Lock nor the harness gives a total order across all seven closed states
(KNOWN, UNKNOWN, NOT_OBSERVED, NOT_APPLICABLE, INFERRED, DECLARED, CONFLICTING) — only isolated
pairwise facts (e.g. CFG-001: a derived value is "INFERRED, never KNOWN"). `derive()` needs a total
order to be computable and testable at all, so one was chosen and recorded in ADR-001, with the
weakest-of computation restricted to exactly the inputs a given rule actually depends on (harness
§14.3 state D: padding is CONFLICTING but is not a required input of the tier-derivation rule, so
tier stays INFERRED — this is existing canonical behaviour the chosen order must reproduce, and
the property tests in `tests/unit/test_field_value.py` check that it does).

**Resolution:** if Directive doc content later gives an explicit ordering, reconcile ADR-001
against it and update `derivation_strength()` accordingly.

## OI-006 — `shares-public-key` identity rule has no literal rule_id (2026-09-17)

**Status:** NOT blocking — simply left out of `src/ecdat/rules/registry.py` rather than invented.

Harness §15.2 T6 gives `IDENTITY-CERT-DER-001` as the literal rule_id for the `same-object`
identity rule (SHA-256 over canonical certificate DER), but never gives an equivalent literal
rule_id for the `shares-public-key` identity rule (SHA-256 over SubjectPublicKeyInfo DER), even
though both are defined in the same subsection. Since Relationship requires `rule_id` for every
content-identity edge (Lock §4 TOPO-001; harness §15.2 T1), no `shares-public-key` Relationship
can currently be constructed without an uncited rule_id — which the model correctly rejects.

**Resolution:** get a literal rule_id for the shares-public-key rule from the same source that
produced `IDENTITY-CERT-DER-001`, then register it in `src/ecdat/rules/registry.py`.

## OI-007 — No Docker on the harness build machine; Maven and haproxy also missing (2026-09-17)

**Status:** NOT blocking for the Tier A harness-scaffolding task (2026-09-17) — worked around
where possible, recorded honestly where not.

Building `ecdat-harness` Tier A (P3 task) needs Docker (for `harness/compose/docker-compose.yml`,
the payment-gateway/edge-lb Dockerfiles) and, for the payment-gateway Java fixture, a JVM build
tool. This machine has neither `docker` nor `mvn` on PATH, and no `haproxy` binary either.

**What was actually done about it:**
- **Maven:** downloaded Apache Maven 3.9.16 directly from `dlcdn.apache.org` into the session's
  scratchpad (not part of either repo) and used it to build and run the real payment-gateway jar.
  This is how `harness/eval/experiments.md`'s CFG-R1 results are real, not fabricated — but it
  means the fixture has only been proven to build with a manually-fetched Maven, not with the
  `maven:3.9.16-amazoncorretto-25-alpine` Docker image referenced in its own `Dockerfile` (that
  image tag was verified to exist via the Docker Hub API, but never actually pulled or built).
- **Docker / docker-compose:** `harness/compose/docker-compose.yml`, and both Dockerfiles, were
  written to spec and validated only as far as `PyYAML` parsing the compose file without error.
  Neither has been built or run. `H6`'s "internal network, no egress" and the whole
  containerised Tier A chain (image → keystore → edge-lb TLS) are therefore **unverified** beyond
  static review.
- **haproxy.cfg:** transcribed from harness §5.3 verbatim plus the generated `pay-edge.pem` path;
  never run through `haproxy -c` or an actual HAProxy process, since no binary is available here.

**Resolution:** on a machine with Docker available, run `docker compose -f harness/compose/docker-compose.yml build && up`
for the payment-gateway/edge-lb pair, confirm the internal network has no egress (H6), and confirm
HAProxy actually terminates TLS with the `pay-edge` cert as `haproxy.cfg` intends. Until then, treat
the containerized path as design-reviewed but not executed.

## OI-008 — Lock §6's E1/E3/E4/TOPO-X2 have no qualifying Tier A test material (2026-09-17)

**Status:** NOT fully blocking — the 2026-09-17 task ("run pinned semgrep, sslyze, trivy, openssl
against Tier A targets; record E1–E4 and TOPO-X1–X3") was executed for the parts that genuinely
overlap Tier A (TOPO-X1, TOPO-X3, and supplemental trivy/semgrep/openssl runs against real Tier A
artifacts — see `docs/experiments.md`). The parts that don't overlap are recorded here rather than
faked with substitute material relabelled as "Tier A."

Lock §6's own E1–E4/TOPO-X1–X3 experiment definitions each name specific test material:

| ID | Needs | Exists in Tier A? |
|---|---|---|
| E1 | a stripped Go binary | **No.** Tier A = payment-gateway + edge-lb + PKI + one trap + no-crypto control (harness §3/§13, confirmed against ground-truth: every `PAY-00X`/`INF-00X` asset with `tier: A` is `application: payment-gateway` or `application: edge-lb`/`pki`; none is Go). The harness's only Go target, `targets/research/datalake-sync`, is domain `research`, not Tier A. No Go toolchain exists on this machine either (`go` not on PATH) — even a non-Tier-A stripped Go binary couldn't be built here. |
| E2 | YARA | N/A to this task — YARA isn't one of the four tools this task named (semgrep, sslyze, trivy, openssl). Not attempted, not a Tier A gap per se. |
| E3 | a TLS endpoint that negotiates a **hybrid PQ group** | **No.** The only hybrid-group-capable target in the harness is `targets/infrastructure/pqc-edge` (`nginx.conf`) — domain `infrastructure`, Tier B (harness §3: "PQC edge" is explicitly listed under Tier B, not Tier A). Tier A's `edge-lb` (`haproxy.cfg`) offers only classical ciphers (`ECDHE-ECDSA-AES128-GCM-SHA256`, `ECDHE-RSA-AES256-GCM-SHA384`). |
| E4 | a **weak certificate** (Lock's own framing: "seclevel on weak certificates") | **No.** Tier A's PKI (harness §6) is deliberately strong throughout: RSA-4096 root, ECDSA P-384 intermediate, ECDSA P-256 / RSA-2048 leaves. The harness's one deliberately-weak-crypto payments target, `settlement-batch` (DES-EDE3-CBC, RSA-1024 — harness §4 directory listing), is not tagged `tier: A` in any ground-truth asset and is absent from harness §13's explicit Tier A build list. |
| TOPO-X2 | BuildKit attestation retrieval | **No Docker on this machine** — already tracked as [OI-007](#oi-007--no-docker-on-the-harness-build-machine-maven-and-haproxy-also-missing-2026-09-17); BuildKit attestations require an actual `docker buildx build` run, which needs Docker regardless of tier scope. |

**What was done instead, and where it's recorded (`docs/experiments.md`):**
- E1: ran trivy against Tier A's actual payment-gateway fat jar (found trivy's `fs` mode can't see
  inside a standalone jar at all, `rootfs` mode can — real adapter-design evidence) and against
  `no-crypto-service`. Filed as `e1_supplemental_*`, explicitly not claimed as E1.
- E4: ran openssl seclevel mechanics against Tier A's real (strong) certs — showed `@SECLEVEL=4`
  rejects the P-256 ciphersuite locally before any handshake. Real evidence, but not "seclevel
  catching a weak cert," because there is no weak cert in Tier A.
- E3, E2, TOPO-X2: not attempted at all; no substitute material was fabricated for these.

**Why this wasn't fabricated instead:** CLAUDE.md's anti-hallucination rules and "false certainty
is the worst possible bug" — inventing a weak cert or a Go binary and filing it as "Tier A's E1/E4
result" would misrepresent what Tier A actually contains, and would corrupt any later comparison
against harness ground truth (which is scoped strictly by `tier: A` tags).

**Resolution:** E1 needs either (a) a Go toolchain on a build machine plus explicit sign-off to
test against `datalake-sync` (Tier B, out of this task's stated Tier A scope) or a purpose-built
Go binary, whichever the project lead prefers, or (b) the harness formally adding a Go binary to
Tier A (a Lock/harness-doc change, not something this task should do unilaterally, per CLAUDE.md
"don't widen scope"). E3 needs the harness to actually deploy `pqc-edge` (Tier B) and re-scope, or
an explicit decision that Tier A's classical edge-lb is an acceptable E3 substitute. E4 needs
`settlement-batch`'s weak certs, if it plants any (currently the file `src/settle.c` exists but was
not inspected for this task, which stayed in scope). TOPO-X2 needs Docker (OI-007's resolution).

## OI-009 — semgrep does not install on native Windows Python (2026-09-17)

**Status:** NOT blocking — worked around, recorded honestly.

`pip install semgrep==1.99.0` on this machine's native Windows Python
(`C:\Python314`) fails during the build step with `Exception: Semgrep does not
support Windows yet, please try again with WSL` (semgrep's own `setup.py`,
referencing semgrep issue #1330). This is a semgrep-project limitation, not
specific to this pin.

**What was done:** installed and ran semgrep 1.99.0 inside this machine's
existing WSL Ubuntu distribution instead (`wsl` was already configured on this
machine — `wsl --status` shows `Default Distribution: Ubuntu, Default Version:
2` — nothing new was installed at the OS level to work around this). The
WSL filesystem accesses the Windows repo checkout via `/mnt/c/...`.

**Resolution:** if a future adapter needs semgrep as a subprocess dependency
on a Windows dev machine, it must either shell out to WSL explicitly or the
project must standardize development on Linux/macOS/WSL for anything that
touches semgrep. Not an architecture decision — a tooling/environment note.

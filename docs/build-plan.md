# ECDAT build plan — phases P0–P9

Date: 2026-09-17. Derived from: Lock §9 (next steps, build order), the FINAL deck's 9-step
pipeline (slide 3), and `Downloads/ECDAT_SIH_deck_review_and_next_steps.md` §4. Phase numbers map
onto the deck's numbered pipeline steps so a judge can point at a slide and ask "is that built?"
and get a yes/no, not a story.

## Where the code actually is today (verified 2026-09-17, not assumed)

| Layer | State |
|---|---|
| `model/` — epistemic, field_value+derive, evidence, finding, asset, relationship, configuration, topology, visibility | **built**, unit-tested |
| `rules/registry.py` | **built** — 4 cited rule_ids |
| `adapters/*`, `store/`, `correlation/`, `risk/`, `recommend/`, `export/`, `context/`, `security/` | **empty stubs** |
| `cli.py`, `adapters/base.py` | **0 bytes** |
| `data/`, `rules/semgrep/`, `rules/yara/` | **empty** (`.gitkeep` only) |
| harness `score.py` | **built**, structural — self-test only, never fed real output |
| harness `ground-truth/visibility.expected.yaml` | **empty file** — blocks visibility scoring |
| recorded fixtures | semgrep 1.99.0, trivy 0.74.0, sslyze 6.2.0, openssl 3.5.4 |

So: the honest one-line status is **model layer + evidence gate done; nothing observes anything
yet.** Every phase below ends in a number or a test, never in a document.

## Findings that change the plan (discovered while scoping, 2026-09-17)

1. **Semgrep registry rules are the wrong tool for inventory.** The recorded Tier A run
   (`tests/fixtures/recorded/semgrep/1.99.0/`) returned exactly one finding —
   `use-of-md5` on `LegacyCardHash.java` (TRAP-01). `WebhookSigner.java`'s literal
   `Mac.getInstance("HmacSHA256")` (PAY-002) and `TokenVault.java`'s
   `Cipher.getInstance("AES/GCM/NoPadding")` (PAY-003) produced **nothing**, because registry
   rules exist to flag *insecure* crypto, not to inventory *all* crypto. ECDAT needs its own
   rules in `rules/semgrep/`. Consequence: this is also the answer to the Semgrep-licence
   objection — our own rules carry no registry licence, and run on Opengrep unchanged.
2. **`Evidence.base_confidence` has no citable source** (OI-004). Final Architecture Part 3 is
   empty. P0 must decide this honestly rather than inventing a number, or every adapter
   inherits a fabricated field.
3. **`visibility.expected.yaml` is empty**, so visibility recall cannot be scored even once
   adapters exist. Harness-side work, small, belongs in P6.
4. **Semgrep's `paths.scanned` is the only honest basis for a coverage claim.** Probe run
   (2026-09-17, our own rules, pinned Semgrep 1.99.0) against the Tier A Java tree returned
   `paths.scanned` = the 6 Java files and found all four source assets with the right semantics:
   `KeyWrapService` → non-literal rule capturing `$ARG = props.getTransformation()` (so algorithm
   is UNKNOWN from source alone — PAY-001), `TokenVault` → literal `AES/GCM/NoPadding` (PAY-003),
   `WebhookSigner` → literal `HmacSHA256` (PAY-002), `LegacyCardHash` → literal `MD5` (TRAP-01).
   Four findings where the registry ruleset found one.
   **But** the same run against the zero-crypto control returned `results: []` **and
   `paths.scanned: []`** — Java rules, Python target, so Semgrep looked at nothing. Zero findings
   there means "did not look", not "clean". Consequences, both load-bearing:
   - the adapter must parse `paths.scanned` / `paths.skipped`, not just `results`, and derive the
     visibility entry from them — otherwise TRAP-07 is failed exactly as harness §7.3 predicts
     ("silence != scanned");
   - passing TRAP-07 *honestly* (zero assets **and** a coverage entry proving the target was
     scanned) requires Python rules as well as Java, or an explicit
     `support_level: unsupported` entry for that language. Decide in P0, don't paper over it.
5. **Semgrep prefixes `check_id` with the config path** when run with `--config <path>`
   (observed: `mnt.c.Users...probe-cipher-literal`). The adapter must match rule identity on the
   final segment, not on the whole string, or rule identity breaks the moment the config moves.

---

## P0 — Unblock (no observation yet, but everything is blocked on it)

**Goal:** the three empty things every adapter needs, decided honestly.

- `data/base_confidence.yaml` — resolve OI-004. Either a cited table, or an explicit
  "no table exists; adapters declare their own value and record why" contract. **Must not**
  invent per-tool numbers from memory; the deck's "confidence per evidence source" claim must
  end up backed by whatever this decides.
- `rules/semgrep/ecdat-java-crypto.yaml` — our own inventory rules (see finding 1).
  Rules must detect *presence of a crypto call site*, including secure ones, and must not
  encode the harness's paths/identifiers (CI guard `check_no_harness_identifiers.py` enforces).
- `adapters/base.py` — the adapter contract: `supported_surface`, `support_level`
  (full/partial/detect-only/unsupported, Lock §4), `run()` → `(findings, visibility_entry)`.
  Support level feeds the visibility matrix, so it is part of the contract, not an afterthought.

**Done when:** `pytest` green, no TODO-VERIFY, OI-004 closed or explicitly re-scoped in
`docs/open-issues.md`.

## P1 — Source adapter (deck steps 1 SOURCE · 2 FINDINGS · 3 EPISTEMIC STATE)

**Goal:** Semgrep JSON → `Finding` + `Evidence`, with per-field epistemic state that matches
ground truth's `expected_observation` for every Tier A source asset.

Tests first, encoding harness ground truth (CLAUDE.md: tests encode canonical behaviour, never
the implementation):

| Case | Ground truth says | Test asserts |
|---|---|---|
| PAY-002 `WebhookSigner` | "algorithm KNOWN (literal `Mac.getInstance(\"HmacSHA256\")`)" | algorithm KNOWN; **purpose UNKNOWN** — "MAC ⇒ integrity is INFERENCE, not observation" |
| PAY-003 `TokenVault` | "algorithm KNOWN (literal + 256-bit key)" | algorithm KNOWN, AES-256-GCM |
| PAY-001 `KeyWrapService` | "must_not: algorithm state KNOWN from source alone" | call site KNOWN, **algorithm UNKNOWN**, resolution UNRESOLVED(reason) |
| TRAP-01 `LegacyCardHash` | "finding allowed … reachable UNKNOWN or false … must NOT appear as 'in use'" | finding emitted; `reachable` UNKNOWN (OQ-5: no reachability analysis) |
| TRAP-07 `no-crypto-service` | "zero crypto assets AND a coverage entry" | zero findings **and** a visibility entry proving it was scanned |

**Done when:** those five pass against a freshly recorded Semgrep run (new fixture, our rules).

## P2 — Store + score wiring — **first real numbers** (deck step 2)

- `store/` repository interface + in-memory implementation (Postgres behind the same interface
  is Lock §5 row 9 "open for implementation" — not needed to get a number).
- `cli.py`: `ecdat scan <path> --out run.json` emitting score.py's input shape.
- Feed `harness/eval/score.py` a real run: `false_certainty_rate` and `per_surface_recall`
  on the `source` surface.

**Done when:** two real numbers exist, whatever they are, recorded in `docs/experiments.md`.
This is the phase that answers "you have zero numbers."

## P3 — Config adapter / CFG-001 (deck step 6 + the PAY-001 headline)

`model/configuration.py` is already built. Add the resolver: `@ConfigurationProperties` binding →
`application.yml` → profile yml → k8s manifest env/args → `./config/` external yml, per Spring
precedence. States A–H of harness §14.3; **the answer key is already runtime-validated by CFG-R1**
(7 real JVM launches), so the tests assert against measured truth, not documentation.

Hard requirements: resolved value is **INFERRED, never KNOWN**; state F (CLI arg present) must
degrade to UNRESOLVED, not report B's or C's value; state D is CONFLICTING on padding while
family/tier stay INFERRED (R-DERIVE).

## P4 — Certs + TLS adapters (deck steps 1 · 5)

- Certs: PKCS12/PEM/DER → PAY-004. Canonicalise to DER before hashing (TOPO-X3 proved a raw
  PEM hash is wrong). Location + fingerprint only, never key bytes.
- TLS: sslyze library → PAY-005 (P-256 cert), PAY-006 (groups), PAY-007 (two suites, two tiers).
  Persist the *requested* SNI alongside the result — TOPO-X1 proved sslyze's result object
  doesn't carry it.

## P5 — Dependency adapter (Trivy) → PAY-008

`rootfs` mode, not `fs` (proven by the recorded run). Emits **capability only**: no algorithm
usage asset, `purpose: UNKNOWN`. Bouncy Castle present in the jar but no source imports it —
this is the "package presence = capability, never usage" rule with a real fixture behind it.

## P6 — Correlation, evidence graph, visibility matrix (deck steps 4 · 5 · 9)

- Merge within a surface only; cross-surface identity only via `IDENTITY-CERT-DER-001`.
- **Hard gate:** the two forbidden edges in `relationships.yaml` must never be emitted
  (score.py treats either as a correlation failure regardless of everything else).
- Fill harness `visibility.expected.yaml`, then score visibility recall.

## P7 — Declared context + Mosca risk engine (deck steps 6 · 7)

Context from CMDB/CSV → always DECLARED. Quantum tier from family via a registered rule
(R-DERIVE: tier inherits the weakest required input). Mosca X+Y>Z under three Z scenarios with
strict `>`, plus the boundary case (`X+Y == Z` is not late; +1y flips it).

## P8 — Recommendations + CBOM export (deck steps 8 · 9)

Purpose-keyed option sets; `purpose: UNKNOWN` → "insufficient evidence", never a guess.
CycloneDX 1.6 export validated against the downloaded canonical schema (`schemas/`), with the
undetermined bucket populated. Secret-leak scan must pass on the emitted CBOM.

## P9 — Measure and put it on the slide

Re-run score.py across every wired surface; replace slide 4's "No recall figure yet" with the
actual numbers. A bad number with a fixture beats a good number without one.

---

## Ordering rationale

P0→P2 is the shortest path to the single most valuable missing thing: **a real measurement**.
P3 is next because PAY-001 is the deck's headline case and its answer key is already validated.
P4–P5 widen surfaces cheaply (fixtures recorded). P6 is where the "correlation, not merging"
claim finally gets tested by the forbidden-edge gate. P7–P8 complete the deck's pipeline.

Out of scope for all phases (Lock §4, unchanged): per-language semantic analysers, runtime
instrumentation, mainframe/COBOL, Windows registry, FIPS certification judgements, HSM PKCS#11
reader (OQ-2 default — revisit only after P9), Ghidra/deep RE.

---

## Progress (updated 2026-09-17)

| Phase | State | Evidence |
|---|---|---|
| P0 — unblock | **done** | `data/base_confidence.yaml` (OI-004 closed as re-scoped, ADR-002), `rules/semgrep/crypto-inventory-java.yaml`, `adapters/base.py` (ADR-003, DEV-001). 94 tests. |
| P1 — source adapter | **done** | `adapters/source/semgrep.py`; 26 ground-truth tests; fixtures recorded under `tests/fixtures/recorded/semgrep/1.99.0/ecdat-rules/`. 120 tests. |
| P2 — store + score wiring | **done (in-memory)** | `cli.py` emits a run document; `harness/eval/score_run.py` scores it. First numbers in `docs/experiments.md`. A persistent store is not yet built — not needed for a number, and Lock §5 row 9 leaves the table layout open. |
| P3 — config adapter (CFG-001) | next | `model/configuration.py` already exists; CFG-R1 already validated the answer key with 7 real JVM launches. |
| P4–P8 | not started | — |

**Measured so far** (source surface, Tier A): false-certainty **0/8**, source
recall **4/4**, under-claiming **0/2**, all-KNOWN control **8/8**. Recall is per
surface and Tier A only; surfaces with no adapter score nothing, which is the
honest representation of their state.

**What P3 should carry over from P1.** The source adapter deliberately leaves
PAY-001's algorithm UNKNOWN with an UNRESOLVED resolution and keeps the argument
expression (`props.getTransformation()`), and separately reports the
configuration-binding declaration and its prefix (`pay.keywrap`). Those two
findings are the input the configuration adapter joins: call site → binding →
`application.yml` → profile yml → deployment override. The join is the work; both
ends already exist and are tested.

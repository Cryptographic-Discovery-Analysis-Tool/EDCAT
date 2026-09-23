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
| P3 — config adapter (CFG-001) | **done** | `adapters/config/{resolver,spring,adapter}.py`; 26 tests (17 resolver-level + 9 adapter-level) covering states A–H; resolved value is never KNOWN. |
| P4 — certs + TLS | **done** | see "Ledger phases 1–8" table below — recorded under that numbering. |
| P5 — packages (Trivy) | **done** | `adapters/packages/{parser,adapter}.py`; built against the real recorded `trivy rootfs --list-all-pkgs` fixtures (`tests/fixtures/recorded/trivy/0.74.0/`); emits presence only, no purpose/function/usage field. |
| P4b — images (cbomkit-theia) | **done** | `adapters/images/{parser,adapter}.py`; 5 tests. Wraps `ghcr.io/ibm/cbomkit-theia:latest` (digest `sha256:e156d5ee...`) and feeds its CycloneDX 1.6 output through the existing `export/cyclonedx.py::import_cbom` (phase 6); every field `DECLARED`, never `KNOWN` (third-party assertion, not our observation). Built and tested against the real `edge-lb` capture in `tests/fixtures/recorded/theia/`; the real `payment-gateway` directory-traversal failure (symlink cycle in the bundled JRE) is tested as `AdapterOutcome.FAILED`, distinct from a clean empty scan. |
| P6 — correlation | **partial, done for its defined scope** | `correlation/{merge,gate,engine}.py`; 29 tests (plus 7 CLI-level tests in `tests/unit/test_cli_correlate.py`, included in the 29). **Within-surface merge**: canonical key `(parameters, scope_anchor)` — see DEV-007 for why `algorithm_family` is not in the strict key — now dispatches per-surface via `_KEY_SIGNATURES` (only `certs-x509` and `tls-endpoint` get Part 5's aggressive algorithm-based merge; every other surface defaults to one asset per Finding, closing a real over-merge bug this session's own live testing philosophy would have caught eventually anyway: before the fix, every Finding from one surface with no `public_key_size`/`public_key_curve` field — i.e. every non-cert surface — silently collapsed into a single asset). **Cross-surface identity** (`engine.py::correlate()`): joins `AdapterRunResult`s from any number of adapters into one `CorrelationReport` — every merged asset plus `same-object` relationships wherever a `der_sha256` hash genuinely matches across surfaces, using the one registered identity rule (`IDENTITY-CERT-DER-001`); every relationship is checked through `gate.py` before being returned, raising rather than silently returning a report with a forbidden edge in it. SPKI-only matches (same key, different certificate) are surfaced as an explicit `shares_public_key_unclaimed` list rather than promoted to a Relationship or silently dropped — no rule_id is registered for that identity claim (registry.py's own comment explains why), so none is invented. Proven against the real Tier A PKI (3 scans → 6 assets, 3 same-object relationships, correctly finding one shared-bytes pair among three). `ecdat correlate --plan <plan.json>` is the CLI front end, reusing `scan`'s own `BUILDERS`. **`tls-endpoint` extended into cross-surface correlation (2026-09-20)**: `tls/parser.py::parse_sslyze` now feeds sslyze's own leaf-certificate PEM (`received_certificate_chain[0].as_pem`, present in the fixture all along) through `certs/parser.py::load_pem_or_der` — the identical canonicalise-then-hex-SHA-256 pipeline `certs-x509` uses — rather than sslyze's own base64 `fingerprint_sha256` (wrong encoding for a string-equality match, and its hashing methodology isn't documented). The Finding field is named `der_sha256`/`spki_sha256`, identically to `certs-x509`, so `engine.py`'s existing hash-matching code picked it up with **zero engine changes**. Proven against real material, not a synthetic pair: the live-recorded sslyze fixture's leaf certificate hashes byte-for-byte identical to the real on-disk `pay-edge/cert.pem` in the Tier A PKI — `tests/unit/correlation/test_engine.py::test_the_wire_certificate_and_the_on_disk_certificate_are_the_same_object` runs both real adapters and asserts `correlate()` links them. **`images-cbomkit-theia` extended into cross-surface correlation too (2026-09-20)**: unlike TLS, this tool's own CBOM carries no certificate bytes or hash at all in any form (confirmed against the real, full 5082-component capture — `certmatch.py`'s own module docstring). So the adapter's new optional `file_reader` independently re-reads the exact file cbomkit-theia's `evidence.occurrences[].location` names (live: `docker run --rm --entrypoint cat <image> <path>`, `adapters/images/certmatch.py` + `build_cat_argv`/`live_file_reader`), parses every certificate the file actually holds, and matches each back to the component describing it. The match key is (subject CN, issuer CN, not-valid-before, not-valid-after) — measured live that cbomkit-theia's own `subjectName`/`issuerName` are the bare Common Name, not the full DN `certs-x509` stores, so a naive full-subject match would silently never fire; an ambiguous or absent match is left unlabelled rather than guessed. Run live end-to-end against the real Tier A `edge-lb` image (not just the 1-certificate unit-test fixture): **818 of 5082 findings came back with an independently-verified `KNOWN` `der_sha256`/`spki_sha256`**, matched out of the real 121-certificate Alpine CA bundle at `/etc/ssl/certs/ca-certificates.crt`. `tests/unit/correlation/test_engine.py::test_a_certificate_found_in_an_image_and_the_same_certificate_on_disk_are_linked` proves the same real certificate is linked across `certs-x509` and `images-cbomkit-theia`, completing the three-way correlation (certs↔TLS↔images) with real data on every edge. **Declared/artifact_asserted edges** (the topology-driven kind, e.g. "TLS endpoint served by this image") remain out of scope — nothing in this codebase ingests the context needed to assert them. Filling harness `ground-truth/visibility.expected.yaml` is separate harness-side work, still not started. |
| P11 — HSM + KMS | **done** | `adapters/hsm/{parser,adapter}.py`; 12 tests. Reads PKCS#11 object/mechanism metadata via `pkcs11-tool` against a real, freshly-initialised SoftHSM2 2.6.1 token (RSA-2048 + EC P-256 generated on-token) — see `tests/fixtures/recorded/pkcs11-tool/opensc-0.25.0/`. Every private key confirmed `never_extractable`; an unauthenticated (no-PIN) run is modelled as a distinct, explicitly-labelled reduced-visibility case, not a silent private-key absence. **KMS half added 2026-09-20** (DEV-011): `adapters/kms/{parser,adapter}.py`; 18 tests. No real AWS account/credentials exist in this environment (checked directly, recorded in DEV-011) so this was built and recorded against LocalStack 3.0.2 instead — a real running implementation of the AWS API, hit with the real, unmodified `aws` CLI, not a real cloud account; that distinction is stated everywhere it matters (fixture README, module docstring, here). Live-proven end to end: `ecdat scan --adapter kms-aws --live --kms-endpoint-url http://localhost:4566` against the running LocalStack container produced 2 real findings from 2 real keys, including a real, independently-computed `spki_sha256` for the asymmetric key (AWS's own `GetPublicKey` already returns DER-encoded SubjectPublicKeyInfo — the exact bytes `certs-x509` hashes for its own `spki_sha256`, so this plugs into `correlation/engine.py`'s existing `shares_public_key_unclaimed` mechanism with zero engine changes). No `der_sha256` field exists on this surface — a raw KMS key is not a certificate. |
| P12 — binaries | **done** | `adapters/binary/{parser,adapter}.py`; 27 tests. Own YARA rules (`rules/yara/crypto-constants.yar`, AES S-box + SHA-256 H0, both public FIPS constants) run against two real binaries copied out of the live Tier A `edge-lb` container: `haproxy` (no embedded match — only dynamically links crypto, confirmed via `readelf -d NEEDED`) and `libcrypto.so.3` (real positive AES match, 4 offsets, via `readelf SONAME`). The adapter keeps "embedded constant" and "linked library" as two separate fields, never merged into one presence claim; RSA/ECDSA's structural undetectability by this technique is stated in the visibility detail on every run, not only when relevant. See `tests/fixtures/recorded/yara/4.5.0/` and `tests/fixtures/recorded/readelf/`. |
| CLI wiring (all 8 adapters) | **done** | `cli.py` rewritten: a per-adapter `BUILDERS` registry (`ADAPTERS` stays the plain id→class map). `certs-x509`/`config-chain-spring`/`source-semgrep` read `--input` as a path directly; `packages-trivy`/`images-cbomkit-theia`/`hsm-pkcs11`/`binary-yara-readelf` take either a recorded-file replay or `--live` (each already had a `live_*_runner()` factory from its own build); `tls-endpoint` replays only — a CLI-driven live probe needs the coordinated two-tool vantage `tools/prober/` already owns, kept as a separate concern on purpose, not an oversight. 18 new tests in `tests/unit/test_cli.py`, every one driven through `main()` against real fixtures already in the repo, not synthesised. 413 tests total. |
| Live verification (2026-09-20) | **4 of 4 live-capable wrapped adapters proven** | Installed the package into a clean WSL venv (`pip install -e .`) and ran `ecdat scan --live` for real: `binary-yara-readelf` against the real `libcrypto.so.3` (real AES match), `hsm-pkcs11` against the real SoftHSM2 token (correct unauthenticated reduced-visibility result), `images-cbomkit-theia` against the real `edge-lb` image (5082 components, matching the earlier direct-tool run exactly), `packages-trivy` against the real extracted fat jar. **Caught and fixed a real bug in the process**: `packages-trivy`'s live argv was missing `--format json` — trivy's default output is a human-readable table even with stdout piped, so the adapter's JSON parse failed against a genuinely live run despite passing every test built against the already-JSON recorded fixture. Fixed in `build_trivy_argv`, regression-tested, re-run live to confirm. Also found and fixed a missing `cryptography` entry in `pyproject.toml`'s `dependencies` (present on the dev machine some other way, absent in a clean install). `tls-endpoint`'s live path is unchanged (`tools/prober/`, not this CLI); `certs-x509`/`config-chain-spring`/`source-semgrep` read real files directly and always have been "live" in that sense. |

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

---

## Ledger phases 1–8 (added 2026-09-19)

`docs/architecture/Pramana_Ledger_Spec.md` §7.2 introduces a second phase
numbering for the exposure ledger, running 1–8 alongside the P0–P12 sensor
phases above. CLAUDE.md says this file is the only phase numbering, so the
ledger phases are recorded here rather than left to float in another document.

The master planning document behind both numberings — ratings, the full
frozen §5 spec, the deterministic §6 test set, and the "this week" ordering —
is vendored at `docs/PRAMANA_FINAL_2_Implementation_Plan_and_Rating.md`. This
table is the live status; that document is a dated snapshot (18 Sep 2026).

| Phase | Deliverable | State (2026-09-19) |
|---|---|---|
| P4 Certs + TLS | `adapters/certs/`, `adapters/tls/`, `tools/prober/` | implemented, unit-green against fixtures recorded from the live Tier A endpoint; two probes per DEV-004 |
| 1 Evidence model | `model/usage_context.py`, `model/temporal.py` | implemented, unit-green |
| 2 Function resolution | `function/classifier.py` + 9 rule_ids | implemented, unit-green |
| 3 Scenario engine | `risk/scenarios.py`, `context/binding.py`, `data/scenarios.yaml`, `data/data_lifetime.yaml`, `data/crypto_families.yaml` | implemented, unit-green |
| 4 Exposure ledger | `risk/confidentiality_ledger.py`, `risk/authentication_ledger.py`, `risk/record.py` | implemented, all of §6 green |
| 5 Closure engine | `closure/engine.py`, `data/closure_catalog.yaml` | implemented, unit-green |
| 6 CBOM export | `export/cyclonedx.py`, `export/signing.py` | implemented, unit-green; signed export built P20 (OI-013 resolved 2026-09-21) |
| 7 Dashboard | `src/ecdat/api/` (FastAPI) + `ui/dashboard/` (React/Vite) | implemented, unit-green over fixtures; `ui/app.py` Flask prototype superseded but not deleted |
| — Recommendation | `recommend/engine.py`, `data/pqc_options.yaml` | implemented, unit-green (Final Architecture Part 8; not a numbered ledger phase) |
| 8 Harness scoring | `ground-truth/exposure.expected.yaml`, `score_run.py` extension | not started |

None of 1–5 is CLOSED: per CLAUDE.md a phase closes only when `ecdat scan`
runs live on the Tier A target directory and `score_run.py` is re-run. They
have no adapter feeding them yet. Ordering rationale and the environment
constraint behind it: `docs/deviations.md` DEV-002.

---

## P13–P16 — closing the loop (added 2026-09-20)

Source of the proposal: an outside review of the SIH deck against the repository,
relayed 2026-09-20. Every item below was checked against the code before being
written down; where the review was wrong about what exists, that is recorded here
rather than quietly corrected.

**What the review got right.** The repository is materially ahead of the deck. The
deck's measured block still says "120 unit tests" and "6 of 11 tool experiments";
the tree collects **467 tests** (verified by `pytest --collect-only`, 2026-09-20),
carries **nine adapters**, five of them live-proven from `ecdat scan --live`, three
CI guards, and cross-surface correlation proven at 818-certificate scale. The deck
undersells the build by roughly a factor of four.

**What the review got wrong, and it matters.** It proposed "implement verification
after migration" as new work. Most of it is already built and tested:
`model/temporal.py::MigrationEvidence`, `risk/confidentiality_ledger.py::_Timeline`
(`first_stop`, `reopened`, `currently_stopped`, `exposure_intervals`), the UNSAVABLE
band itself, and `adapters/tls/adapter.py`'s migration-evidence builder, which
already turns a real probe into §5.7 migration evidence and already refuses to do so
when the negotiation was not observed. The tool can already say "this window closed"
and the harder "this window re-opened."

What is actually missing is not the verification logic. It is that
**`src/ecdat/store/` is a 0-byte package** — nothing remembers the previous run, so
no two runs can be compared. That single gap is also the whole of the review's
separate "drift" proposal. They are one phase, not two, and the expensive half of
both is already done.

### P13 — Run store and run-to-run diff — **done (2026-09-21), scoped**

**Falls under:** P2 (*store + score wiring*, recorded above as "done (in-memory)" —
this is the persistent half it deferred), ledger phase 4 (*exposure ledger*, built),
and §5.7's migration timeline (built).

Built: `store/repository.py` (`Run`, `RunStore` protocol, `JsonlRunStore`),
`store/diff.py` (`diff_runs`), and three CLI commands —
`ecdat ledger-run --subjects <file> --scenario <id> --target-id <id> --store-dir <dir>`
(evaluates a ledger and saves the result as a `Run`, the same `evaluate_run` the
API calls), `ecdat runs --store-dir <dir>` (list), and
`ecdat diff --store-dir <dir> --from <run> --to <run>`.

**Scoping decision, stated rather than silently narrowed:** the deck promises
PostgreSQL (JSONB). `RunStore` is the interface Lock §5 row 9 leaves open ("the
table layout open; a run is an append-only document either way"), and what ships
today behind it is `JsonlRunStore` — one JSON document per run, one file per run,
under a directory. It satisfies "append-only document" literally, needs no service
to stand up, and works offline and in CI. A `PostgresRunStore` implementing the
same `RunStore` protocol is the natural next adapter; nothing above the interface
changes when it lands. The deck's platform row should say persistence and
run-to-run diff are built, and that the backing store today is file-based pending
a Postgres adapter — not claim Postgres itself is running.

Diff classes: `NEW` · `CHANGED` · `REMOVED` · `MIGRATED` · `REGRESSED` · `UNCHANGED`,
matched by `usage_context_id`. `MIGRATED` and `REGRESSED` introduce **no new
judgement** — `diff.py::_currently_stopped` builds `confidentiality_ledger.py`'s own
`_Timeline` from each record's stored migrations and compares `currently_stopped`
across the two runs; a row becomes `MIGRATED` only on a KNOWN migration observation
with `classical_still_accepted` false, exactly the rule §5.7 already enforces
within one run, now compared across two. Authentication rows never classify as
MIGRATED/REGRESSED (the module docstring's own distinction: nothing signed is
"lost"). Verified end to end against `tests/fixtures/ledger/subjects.json`: `ecdat
ledger-run` under `Z_aggressive` then under `Z_central`, `ecdat diff` between them,
correctly finds the one row that moves BLEEDING → SAVABLE — the same row the
dashboard shows as "flips at Central" (P19).

Tests: `tests/unit/store/test_repository.py`, `tests/unit/store/test_diff.py`,
`tests/unit/test_cli_ledger_run.py` (drives `main()` with real argv, including the
false-migration-claim negative case). 496 tests pass (was 472);
`tools/ci/check_data_citations.py` still passes.

**Not done:** `PostgresRunStore`; there is no live Tier A target to take two real
network scans of yet, so "done when" is verified against `ledger-run` over the
fixture, not a live scan diff.

### P14 — Agility evidence (narrowed from the review's proposal) — **done (2026-09-21)**

**Falls under:** P1 (source adapter, done), P3 (config adapter, done), P4 (TLS, done).
All three already observed what this phase names; `agility/evidence.py` is what names it.

The review proposed six fields. Three are adopted, one stays deferred, **two are
refused**.

| Field | Verdict | Where the evidence already is |
|---|---|---|
| `algorithm_selection` — `HARDCODED` / `CONFIGURATION_DRIVEN` / `UNKNOWN` | **built** | Reads `source-semgrep`'s own literal/non-literal split: `TokenVault`'s literal `AES/GCM/NoPadding` (PAY-003, HARDCODED) against `KeyWrapService`'s `props.getTransformation()` (PAY-001, CONFIGURATION_DRIVEN). Direct relabelling of an existing observation — same state, same evidence_refs, no `derive()`. |
| `hybrid_capable` | **built**, KNOWN only when observed | Reads the TLS adapter's own `negotiated_group`. Verified against the real fixture: `False`/absent without the openssl probe (`UNKNOWN`, not promoted from a configured cipher list), `True`/`KNOWN` with it. |
| `provider_pluggable` | **built**, INFERRED ceiling, never KNOWN | Reads `provider_argument` (source text, KNOWN) and caps the *pluggability claim* to INFERRED — a call site that can take a provider argument does not prove a second provider actually runs. See DEV-012/OI-018: no rule_id is registered for this cap (nothing in the canonical docs names it), so it is built without `derive()` rather than citing an invented rule. |
| `certificate_rotation` | **defer to P13** | Not a field. It needs the same certificate seen at two times, which is exactly what the run store produces. Putting it on a Finding would imply a single scan can see it. |
| `migration_complexity` | **refuse** | It is a score. Slide 2 claims "no weights, no score, no model — lexicographic order only," and §5.10 ranks by window, not by effort. Adding this field would falsify the headline claim in exchange for a number nobody can defend. |
| `hardcoded` as a bare boolean | **refuse** | Collapses `HARDCODED` and "we could not tell" into one value. Three states or none. |

Wired into `correlation/graph.py::GraphNode.agility` (every node in the P15 evidence
graph carries its own agility evidence) and surfaced in both `ecdat correlate
--format graph` and the dashboard's "Evidence graph" tab. Verified live against the
demo fixture: all three fields honestly read `UNKNOWN` there, because that fixture
runs only `certs-x509` — no source or TLS evidence exists for it to read, and
nothing is fabricated to fill the gap.

**Done when:** every agility field carries its own epistemic state like every other
field in the model — true by construction, `AgilityEvidence`'s three fields are each
a `FieldValue` — and `check_data_citations.py` still passes.

Tests: `tests/unit/agility/test_evidence.py` (12, against real `source-semgrep` and
`tls-endpoint` fixture runs, not hand-built field dicts) plus the P15 graph tests
extended to cover `agility`. 514 tests pass (was 502);
`tools/ci/check_data_citations.py` still passes. Methodology recorded in DEV-012
and OI-018.

### P15 — Evidence graph view — **done (2026-09-21)**

**Falls under:** P6 (correlation — recorded above as "partial, done for its defined
scope"). The data already existed; `correlation/graph.py` is the rendering.

Built as `correlation/graph.py::build_graph(report)`, presentation-only over a
`CorrelationReport`: every `same-object` `Relationship` becomes a `CLAIMED` edge
carrying its `type`, `evidence_basis`, `rule_id` and `epistemic_state`; every
`shares_public_key_unclaimed` pair becomes an `UNCLAIMED` edge with `rule_id=None`
(OI-006 — no registered rule_id exists for that claim, and `EdgeStrength` is a
closed two-value enum so a renderer cannot invent a third, stronger one). The two
refused links from the review's seven-layer chain (library → usage, service →
protected data) are `CHAIN_GAPS`, a fixed, cited list a caller must actively choose
not to show — never blank space.

Deliverables, both shipped: `ecdat correlate --format graph` (CLI, tested end to
end against a real duplicated-certificate plan) and a dashboard "Evidence graph"
tab (`ui/dashboard/src/Graph.jsx`) backed by `GET /api/graph`, verified live: a
solid arrow for the one claimed same-object edge, a visibly weaker dashed arrow for
the two unclaimed shares-key edges, and both named gaps rendered with their `why`.

**Hard requirements, verified:**

- every edge renders its type *and* its epistemic basis — `test_every_edge_states_its_type_and_epistemic_basis`
  checks this structurally, not just for the fixture's own edges;
- `shares_public_key_unclaimed` renders as a visibly weaker edge than `same-object`
  and never collapses into it — `EdgeStrength.UNCLAIMED != EdgeStrength.CLAIMED` is
  asserted directly, and the dashboard renders the two with different line styles;
- edges that do not exist are drawn as named gaps, not as blank space —
  `CHAIN_GAPS` always renders, even for an empty report.

**Explicitly not built, and not drawn:** the review's seven-layer chain — crypto API
→ config → algorithm → library → certificate → service → protected data. Two of
those edges are real (config → algorithm, from P3; certificate → service, from P4)
and are drawn from the report itself when they exist. **Library → usage is not**:
the package and binary readers refuse to claim usage on purpose, and that refusal
is tested. **Service → protected data is not**: the data class is DECLARED by a
person, and there is still nowhere to declare it (P6's open item). Both are named
in `CHAIN_GAPS` with their `why`, never rendered as a line.

The API's demo fixture (`tests/fixtures/correlation/demo_plan.json` +
pre-generated certs) runs the real `certs-x509` adapter and the real correlation
engine — not hand-built assets — the same way `ecdat correlate --plan` would.
Confidence and its justification live in that plan file as data, never as a
literal in `src/`, per `tests/unit/data/test_base_confidence.py`'s own guard
(caught and fixed during this build: an earlier draft hardcoded
`base_confidence=0.9` directly in `api/app.py` and failed that guard).

Tests: `tests/unit/correlation/test_graph.py` (5, against real adapter runs) and
`tests/unit/api/test_app.py::test_graph_endpoint_is_labelled_as_a_fixture_and_carries_both_edge_strengths`.
502 tests pass (was 496); `tools/ci/check_data_citations.py` still passes.

### P16–P19 — deck promises that are real requirements and are not built yet

Revised 2026-09-20 after a second pass. The first pass framed these as claims to
delete from the deck. That was wrong, and the correction matters: **the deck is the
specification.** It states what Pramana is meant to be, and the build follows it.
Deleting an unbuilt promise from the slide does not make the deck honest — it
silently drops a genuine requirement and makes the *product* smaller.

The honest move is the one this project already applies to its own findings: keep
the claim, **say which state it is in**, and put the unbuilt half on the plan.
Slide 5 already does exactly this with its "declared as targets — not yet measured"
block. The platform row should work the same way.

One of the five below is genuinely a deletion. Four are phases.

| Deck promise | Where | Verified state, 2026-09-20 | Verdict |
|---|---|---|---|
| "PostgreSQL (JSONB evidence + snapshots)" | S3 platform | **Built 2026-09-21 — P13**, scoped: `store/` is a real, tested repository (`Run`, `RunStore`, `diff_runs`) behind a `JsonlRunStore` default; snapshots and run-to-run diff work end to end (`ecdat ledger-run` / `runs` / `diff`). Postgres itself is not running — no `postgres`/`psycopg`/`sqlalchemy` in `src/` or `pyproject.toml`. | **Say what's true:** persistence and diff are built and demoable; the backing store is file-based pending a `PostgresRunStore` adapter behind the same interface. Do not claim Postgres is running. |
| "RBAC + audit log" | S3 platform **and** S4's challenge row | zero hits for `rbac`, `audit_log`, `audit log` in `src/` or `tests/` | **Keep — P17.** This is not decoration: it is the stated answer to the challenge *"the inventory is itself a sensitive asset."* Deleting it would weaken an answer the deck needs to give. Mark *planned*. |
| "no egress (test-enforced)" | S3 **and** S4 | **No `harness/` directory exists in this repo at all** — no compose file, no `internal: true`, nothing configured. Corrected 2026-09-21; the earlier note that this was "already configured" was wrong. | **Keep — P18.** The requirement is right; neither half exists yet — network isolation is unconfigured and untested. |
| "the dates at which the ranking flips are printed" | S4, answering *"the arrival date Z is genuinely contested"* | **Built 2026-09-21 — P19.** `risk/sensitivity.py`, wired into the API and the dashboard's "Under other Z" column. | **Keep, now true.** |
| "Trivy / **Syft**" | S3 sensors | no reference to Syft anywhere in `src/`, `tests/` or `tools/` | **The one real deletion.** Trivy already provides the package inventory this needs, and `packages-trivy` is built and live-proven. Syft would add a second tool for the same fact. Cut the word. |

Separately, a wording fix rather than a phase: slide 2 (iv) promises recommendations
*"with size, latency and compatibility impact."* `recommend/engine.py` and
`data/pqc_options.yaml` carry byte counts and a cited handshake-failure rate —
**size and compatibility, but no latency figure at all**, and no cited source for one
exists in `data/`. Either vendor a citable latency measurement or say what is
actually shown: *"with size, handshake-failure precedent and compatibility impact."*
Inventing a latency number to match the slide is the one thing that must not happen.

### P17 — RBAC and audit log — **done (2026-09-21)**

**Falls under:** ledger phase 7 (*dashboard*, built). The API existed and was
unauthenticated; it is not any more.

The deck answers "the inventory is itself a sensitive asset" with four controls.
Three were real before this phase — on-prem, no key material stored (enforced by
`security/secrets.py` and tested), and the network definition (P18). The fourth is
built now.

**Built:** `security/auth.py` (`Role` -- closed two-value set, `VIEWER` and
`EXPORTER`; `TokenRegistry`, secure by default -- `TokenRegistry.empty()` when
`ECDAT_API_TOKENS` is unset, refusing every request rather than opening until an
operator remembers to lock it down; tokens are looked up and logged only by their
SHA-256 fingerprint, never as raw text) and `security/audit.py` (`Verb.READ` /
`Verb.EXPORT`, `JsonlAuditLog` -- the same append-only, one-record-per-line shape
`store/repository.py::JsonlRunStore` already uses -- and an `InMemoryAuditLog` for
tests and the default app).

Wired into `api/app.py::create_app()`: every `/api/ledger`, `/api/records/*`,
`/api/closure`, `/api/coverage`, `/api/graph`, `/api/profiles`,
`/api/recommendations` route requires `VIEWER`; `/api/export` requires
`EXPORTER` -- "export is the sensitive verb here, not scanning" is not a slogan
any more, it is a 403 a `VIEWER` token actually gets. `/api/health` and
`/api/scenarios` stay open (load-balancer-probe / discovery endpoints, not
ledger data). Every authenticated call is audited, **including refused ones** --
"who tried and was refused" is part of "who read or exported what," not a fact
this log gets to drop.

**Dashboard**, not left broken by the change: `ui/dashboard/src/api.js` wraps
every `fetch()` with an `Authorization: Bearer` header;
`tools/dev/run_dashboard.py` sets one dev-only token (`EXPORTER`, so the single
token drives every panel including the export button) before importing the app,
clearly labelled as committed-in-plain-text and never fit for anything but a local
preview. `/api/export`'s download moved from a plain `<a href>` (which cannot carry
a header at all) to a `fetch` + blob-URL flow in `App.jsx`, so the download itself
goes through the same authenticated path as everything else.

**Verified live**, end to end, after finding and fixing a real caching bug in the
preview tooling (it kept launching the *old* `python -m uvicorn
ecdat.api.app:app --port 8000` command from a prior `.claude/launch.json`, silently
ignoring the edit to run `tools/dev/run_dashboard.py` -- caught by checking the
actual running process's command line, not assumed from a green browser tab):
launched directly, then confirmed in the browser -- the ledger, closure queue,
coverage and graph tabs all loaded real data, and clicking Export produced a real
`200 OK` on `/api/export` and a saved `pramana-cbom.json`.

Tests: `tests/unit/security/test_auth.py` (13), `tests/unit/security/test_audit.py`
(6), and `tests/unit/api/test_app.py` extended with 8 RBAC/audit cases (a `VIEWER`
token gets 403 on export, no token is 401, an unrecognised token is 401, health
needs none, every allowed AND every refused request is audited, no audit entry
ever contains a raw token). 543 tests pass, 1 skipped (the P18 no-egress
integration test, correctly, on this host); `tools/ci/check_data_citations.py`
still passes.

**Confirms build-plan.md's own prediction:** "it changes nothing a judge can see"
-- the dashboard looks identical; every panel still renders the same rows, bands
and deadlines. What changed is that a request without the right token now gets
refused and logged, instead of getting an answer.

### P18 — Make no-egress test-enforced — **done (2026-09-21)**

**Falls under:** the harness, not `src/`. Smallest phase on this list.

**Corrected twice, same day.** The first correction (earlier in this session) said
"there is no `harness/` directory in this repo — nothing is configured." That was
itself wrong in a narrower way: it checked only `ecdat/`, not the sibling
`../ecdat-harness/` repo CLAUDE.md names as a canonical source. The real file is
`ecdat-harness/harness/compose/docker-compose.yml`, `internal: true` genuinely was
already set on `payments-internal` there (H6), and its own header comment said
exactly why the deck's word "test-enforced" was still ahead of the code: *"Not run
in this environment (no Docker daemon available here — see
ecdat/docs/open-issues.md OI-007) ... it has not been built or started."*

**Built and run for real.** `tools/ci/check_no_egress.sh` brings the Tier A stack
up (`docker compose up -d --build`), runs one ephemeral `alpine` container on
`payments-internal` and asserts `wget` to `1.1.1.1` fails, then runs the *same*
check on the default bridge network as a control (must succeed) — so a pass proves
`internal: true` is doing the work, not that the host has no internet at all.
`tests/integration/test_no_egress.py` wraps it for pytest discovery, skipping when
Docker is not on `PATH` or the sibling checkout is absent, exactly like
`tests/unit/correlation/test_engine.py`'s own `pytestmark_harness` skip for the
same sibling repo.

**Actually executed, not just written**, via the WSL2 Linux build box
(`docs/build-box.md`, Docker 29.1.3): the compose stack built and started from a
clean state, the control container reached `1.1.1.1` over the default bridge
network (56614 bytes, real HTTP response), and the same request from
`payments-internal` failed with `Network unreachable` — Docker's own no-route
behaviour for an `internal: true` network, not a script-level assertion faked
around it. The exact `subprocess.run(["bash", "tools/ci/check_no_egress.sh"], ...)`
call `test_no_egress.py` makes was run directly in WSL2: `returncode == 0`, `"PASS"
in stdout`. Containers were torn down afterward (`trap cleanup EXIT`); confirmed
no orphaned containers or networks remained. On this Windows host, `docker` is not
on `PATH` (only reachable via `wsl -d Ubuntu -- docker ...`), so `pytest -q` here
correctly skips the test rather than falsely passing or failing — the real
Linux/CI environment where `docker` is on `PATH` directly is where it runs, exactly
as `docs/build-box.md` already documents for every other live-tool check in this
project.

**Not attempted:** a negative control (temporarily setting `internal: false` on the
real compose file to prove the script would catch a regression) — the harness
repo's own compose file is shared, security-relevant configuration, and editing it
even temporarily was refused by this session's own safety classifier as a security
weakening action. The already-obtained contrast (isolated network blocked,
non-isolated default network succeeded) is the negative-control evidence in its
place.

### P19 — Scenario sensitivity: print the date the ranking flips — **done (2026-09-21)**

**Falls under:** ledger phase 3 (*scenario engine*, built) and phase 5 (*closure
engine*, built). Both halves existed; `risk/sensitivity.py` joins them.

Built as `risk/sensitivity.py::sensitivity_for(record)`: re-runs the record's own
ledger (`authentication_ledger` or `confidentiality_ledger`, picked the same way
`replay()` picks it) once per cited scenario in `data/scenarios.yaml`, ordered
earliest-Z first. `scenario_sensitive` is true iff the band is not identical across
all three; `first_flip` names the earliest-Z scenario after the baseline whose band
differs, with its own real, ledger-computed deadline — no date is interpolated
between scenarios, consistent with §5.12's rejection of a probabilistic Z.

Wired into `api/app.py::_row()` as a `sensitivity` field on every ledger row (so
`/api/ledger`, `/api/records/{id}`, and the evidence card all carry it without a
second endpoint), and into `ui/dashboard/src/Ledger.jsx` as an "Under other Z"
column: a `flips at <scenario>` badge (hover shows the band under all three) or
`stable across Z`. Verified live against the fixture at `/`: the SAVABLE
legacy-settlement row reads "flips at Central" and the RESIGN_BEFORE_Z
firmware-release row reads "flips at Optimistic"; every other row reads "stable
across Z" — all real re-runs, not invented labels.

Tests: `tests/unit/risk/test_sensitivity.py` (module-level, against the frozen §6
test set) and `test_app.py::test_scenario_sensitivity_flags_rows_that_actually_move`
(end-to-end: derives which fixture rows actually move across all three scenarios
independently of the flag, then asserts the flag agrees). 472 tests pass (was 467);
`tools/ci/check_data_citations.py` still passes.

### Ordering

P16's wording decisions first — they are text, and two of them (Syft, latency) are
corrections rather than promises.
Then **P19**, because it is the cheapest genuinely new capability on this list and
both halves already exist.
Then **P13**, the only one that earns the word VERIFY, and which makes the snapshot
and PostgreSQL promises true rather than deleted.
Then **P15** (the data is already computed), **P14**, **P18** (one test), and
**P17** last — it is real work and it changes nothing a judge can see.

**Out of scope, restated:** nothing in this section introduces AI, scoring, or
weighting into the analysis path. The review's own first recommendation was to keep
entropy and PRNG-prediction research out of the SIH core; that agrees with CLAUDE.md
and with slide 3's "no AI in the security path," and needs no phase.

---

## P20 — Signed export (OI-013 resolved) — **done (2026-09-21)**

Self-directed: the deck is locked (no further deck work per instruction), and
P13–P19 are closed. This phase continues the implementation by closing the one
open issue P17's RBAC/audit-log work was itself blocking: OI-013, deferred
specifically pending "a key needs a custody story," which P17 supplied.

**Falls under:** ledger phase 6 (*CBOM export*, built). §3's "signed export
(VERIFY JSF field)" and §9 item 5.

Built as `export/signing.py`: Ed25519-only JSF signing over RFC 8785 JCS-
canonicalised bytes (`rfc8785`, newly pinned — a security-critical
canonicalisation algorithm is not reimplemented here, same reasoning already
applied to `jsonschema`/`cryptography`). `schemas/jsf-0.82.schema.json` is the
real schema, fetched once from CycloneDX's own `specification` repo
(Apache-2.0) and vendored exactly the way `cyclonedx-1.6.schema.json` itself
was — the permissive stub `export/cyclonedx.py::_validator()` used before this
phase is gone; every `signature` this module produces is schema-checked for
real, not merely schema-shaped.

**A real schema bug was caught doing this, not assumed.** The first signed
document failed validation against the real JSF schema: `signature.algorithm`
is a `oneOf` between a fixed enum and a `format: "uri"` branch for proprietary
algorithms, and `jsonschema`'s `Draft7Validator` does not check `format`
without an attached `FormatChecker` (and `uri` specifically needs the
`rfc3987` package). Without one, `"Ed25519"` is *also* a syntactically valid
URI reference, matches both `oneOf` branches, and fails "exactly one must
match." Fixed with the `jsonschema[format]` extra and
`format_checker=Draft7Validator.FORMAT_CHECKER`.

**Key custody, minimum honest version:** a PEM file at `ECDAT_SIGNING_KEY_PATH`
(`ecdat keygen` generates one), never logged, held in memory only for the
duration of one signature. Rotation is manual. A verifier trusts only the bare
embedded Ed25519 public key — no certificate chain, no external PKI; that
key's fingerprint reaching a verifier is a distribution problem this module
does not solve and says so in its own docstring, rather than implying more
trust than the mechanism provides. Automated rotation and a certificate chain
are real hardening work, explicitly deferred, not silently dropped.

**Wired into:** `ecdat keygen` / `ecdat verify-export` (CLI), and `GET
/api/export` (signs when a key is configured; `X-Pramana-Signed: false` and an
unsigned document otherwise — no silent default key). Verified live,
end to end: `ecdat keygen` → sign → `ecdat verify-export` reports `signature
valid`; a tampered copy of the same export correctly reports `INVALID:
signature does not verify`, exit 1.

Tests: `tests/unit/export/test_signing.py` (16 — round-trip, tamper detection
on the document and on the signature value independently, wrong-key
rejection, non-Ed25519 rejection, real schema validation, no raw key ever
appears in a signed document) plus two in `test_app.py`. 560 tests pass (was
543); `tools/ci/check_data_citations.py` still passes.

**Not attempted:** automated key rotation with overlap, a `certificatePath`
certificate chain, and any JSF algorithm other than Ed25519 (RS*/PS*/ES*/HS*)
— all real hardening work, out of this close, matching OI-013's own original
deferral note.

---

## P21–P26 — from the 2026-09-23 review (implementation gaps + external research)

Source: a repo audit plus a web sweep on 2026-09-23 (NIST, CISA/EO 14412,
India DST, RBI/SEBI, EU, Cloudflare, OpenJDK, sslyze, Let's Encrypt, competing
SIH26164 repos). Each item was checked against the code before being listed.

| Phase | What | Why now | Status |
|---|---|---|---|
| **P21** | **Scan → ledger bridge.** Wire `function/classifier.py` (built, never called) so adapter findings become `UsageContext`s; derive `TemporalEvidence` from what adapters actually observe; give data-class binding a declaration input. | No code in `src/` constructs a `LedgerSubject`. Every band the dashboard shows comes from a hand-built fixture. This is the single largest gap. | **done (2026-09-23)** — see below |
| **P22** | **Sourced Z scenarios and policies.** Cite GRI Quantum Threat Timeline 2025 (pub. 9 Mar 2026) for the Z dates; add India DST roadmap (CII by 2029, inventories by Dec 2027), NIST IR 8547 ipd (deprecate 2030 / disallow 2035), EU roadmap (high-risk by 2030) as selectable policy deadlines. | `data/scenarios.yaml` Z dates are `TEST_CONSTANT`; `crypto_families.yaml` carries a `TODO-VERIFY: cite NIST IR 8547`. | **done (2026-09-23)** — see below |
| **P23** | **Recommendation corrections.** Public-web TLS server authentication: Chrome has stated it will not accept ML-DSA in X.509 and is backing Merkle Tree Certificates (Let's Encrypt staging late 2026). Add FN-DSA (FIPS 206, draft) and HQC (selected Mar 2025) as flagged-draft options. | `pqc_options.yaml` recommends ML-DSA generically for signatures. | open |
| **P24** | **Performance.** Evaluate a run once per request set, cache per (subjects, scenario, policy, as_of); compute scenario sensitivity from the three cached runs instead of 3× re-evaluation per row; index the run store. | Dashboard triggers 3 full ledger runs + 3× per-row sensitivity per page load; `list_runs` reads every run file in full. | open |
| **P25** | **SARIF output + CI gate.** `ecdat ledger-run --sarif`, and a gate that fails a pipeline on BLEEDING / REGRESSED rows. | A competing SIH26164 repo ships both; cheap, and it is how the tool fits a developer workflow. | open |
| **P26** | **CycloneDX 1.7.** Vendor the 1.7 schema (ECMA-424 2nd ed.), move export to 1.7, keep 1.6 import. | 1.7 released Oct 2025; EO 14412 CBOM minimum elements due ~Mar 2027. | open |

**Confirmed, no change needed:** sslyze 6.3.0 / 6.3.1 release notes still show
no ML-KEM / hybrid-group support — OI-017 stands and the two-probe TLS design
(DEV-004) remains necessary. OpenSSL 3.5 and JDK 27 (JEP 527) now negotiate
X25519MLKEM768 by default with no application change, which is direct support
for the rule that only an *observed* negotiation stops the clock.

Order: P21 → P22 → P23 → P24 → P25 → P26.

### P21 — Scan → ledger bridge — **done (2026-09-23)**

`src/ecdat/assemble/bridge.py::assemble(results, declarations=...)` turns adapter
runs into `LedgerSubject`s, adding no judgement of its own: functions come from
`function/classifier.py` (§5.1, previously never called from `src/`), clock-stopping
from `adapters/tls/adapter.py::migration_evidence_from` (§5.7), and every date
from a field an adapter observed.

- **TLS** → `NegotiatedHandshake` → KNOWN key-establishment + server-auth contexts;
  `first_observed` = the probe date (the only input §5.2 lets confirm); `not_before`
  joined from `certs-x509` only on an exact DER hash (IDENTITY-CERT-DER-001).
  **A successful classical-only probe becomes its own row** (`|classical-client`):
  on the recorded Tier A endpoint the hybrid path is SAFE while a classical-only
  client still negotiates X25519 — BLEEDING under Z_aggressive, SAVABLE under
  Z_central, both PARTIAL. Without this row the surface would read as SAFE because
  the *best* client is safe.
- **Certificates** → keyUsage → INFERRED capability contexts, `not_before` as
  possibility only. A certificate already seen in a handshake is not emitted twice.
- **Source** → `SourceCallSite` (the adapter now records `api_class` from the rule's
  `$1` capture, present in the recorded 1.99.0 fixture). No start date is invented
  for a call site. Symmetric `Cipher`, `Mac`, `MessageDigest` stay UNKNOWN, exactly
  as §5.1 says ("Anything else → UNKNOWN. No default.").
- **Data class** — the one input no scanner observes — comes from a `Declarations`
  YAML (`surface` or `asset`, `data_class` naming a cited `data_lifetime.yaml` row,
  and a required `declared_by`). Undeclared → no binding → UNBOUNDED + closure task.
- Nothing is dropped silently: every finding that does not become a subject is
  listed in `Assembly.unassembled` with its reason (package presence: "capability,
  never usage — by design").

Wired into `ecdat assemble --plan <plan> [--declarations <yaml>] --out subjects.json`
(same plan format as `correlate`; output is the exact fixture shape `ledger-run` and
the dashboard read), and into the API via `ECDAT_SUBJECTS_PATH`, with `/api/health`
reporting `fixture: false` so the dashboard's "Fixture data" banner is shown only
when it is true. Verified end to end through the real CLI: 2 recorded scans → 7
subjects → `ledger-run` under two scenarios → `diff` shows the classical-client row
BLEEDING → SAVABLE; and in the browser: banner reads "Scan data", rows are the
assembled ones.

Also fixed on the way: `ecdat diff` now exits 2 with a message on a malformed run
id instead of a traceback; `test_source_text_is_never_carried_into_a_finding` now
checks the actual matched lines Semgrep echoed rather than the proxy word
`MessageDigest` (a stricter check — the class name is a metavariable capture, not
source text).

Tests: `tests/unit/assemble/test_bridge.py` (17, all over real adapter runs).
577 tests pass; all three CI guards pass.

**Not yet:** the config-chain join (PAY-001's `KeyWrapService` should become an
INFERRED KEY_TRANSPORT with a conditional band per §6, once the `config-chain-spring`
resolution is fed to the bridge); multi-run `first_observed` (earliest observation
across the P13 run store rather than this run's date); image/HSM/KMS/binary
classifier paths.

### P22 — Sourced Z scenarios and policy deadlines — **done (2026-09-23)**

Three primary sources vendored as excerpt notes under `docs/sources/` (metadata,
SHA-256 of the fetched PDF, the exact text used — extracted with pypdf, not
recalled): NIST IR 8547 ipd (Nov 2024, Tables 2 and 4), India DST *Roadmap to
Quantum Resiliency* (May 2026, milestones pp. 105–107), GRI *Quantum Threat
Timeline Report 2025* (9 Mar 2026, publication page).

- **Z scenarios.** Z_central (2036) and Z_optimistic (2041) now cite GRI 2025's own
  10- and 15-year figures, "quite possible (28-49%)" and "likely (51-70%)" —
  resolving §9 item 2 for those two. Z_aggressive stays a test constant: the
  page gives no 5-year figure for this edition, and the "5-14%" secondary sources
  quote belongs to the 2024 survey, so it is not borrowed. Dates stay operator
  assumptions (§5.12: no probabilistic Z); the source is their basis.
- **DH resolved.** `crypto_families.yaml`'s DH row was `usable: false` pending
  exactly "cite NIST IR 8547 once it is vendored". Table 4 lists finite-field DH as
  quantum-vulnerable; the row is now usable. Two tests (ledger, closure) had used
  DH as their example of an *uncited* family — they now use SM2, which still has no
  row; the behaviour they test is unchanged.
- **Policy deadlines** (`data/policy_deadlines.yaml`, `risk/policy.py`): India
  DST CII (high-priority 2028-12-31, full 2029-12-31), India DST Enterprises (2030,
  2033), NIST IR 8547 ipd "Disallowed after 2035". Laid **over** a row as
  `open / met / undetermined / not_applicable` — never read by the ledger, so no
  band moves because a regulator published a date. `met` requires the row's own
  observed stop `M` on or before the deadline and no REOPENED qualifier.
  Programme-level milestones (India "Building the foundations": inventory, CBOM
  requests) are scoped `programme` and never charged to a single key.
  **Recorded, not applied:** NIST's "Deprecated after 2030" (112-bit only; no row
  carries a key strength) and the EU roadmap (primary PDF not vendored yet).
- **Surfaced** as `policy_deadlines` on every API row and a "Policy deadline"
  column in the dashboard (nearest open milestone; hover lists all). Verified live
  on the P21 scan data: the classical X25519 path reads "2028-12-31 · India CII ·
  High-priority systems migrated"; the hybrid path "not applicable"; rows with an
  unknown algorithm "undetermined".

**Found on the way, worth knowing:** India's roadmap moves CBOMs into procurement
— "start requesting CBOMs" from FY2026–27, "mandate submission of CBOM from the
vendors" from FY2027–28 (p. 106). That is the document this tool exports.

Tests: `tests/unit/risk/test_policy.py` (10). 587 tests pass; all three CI guards pass.

#### P22 addendum (same day) — the two "recorded, not applied" items, now applied

- **NIST 112-bit deprecation.** IR 8547 defers "security level" to SP 800-57, so two
  more NIST sources were vendored: SP 800-57 Pt 1 Rev 5 Table 2 (RSA k=2048 → 112,
  k=3072 → 128; FFC likewise) and SP 800-186 Table 1 (P-256, Curve25519,
  Edwards25519 → 128; P-384 → 192; P-224 → 112). New `data/security_strength.yaml`.
  The "Deprecated after 2030" milestone now carries `applies_at_strength: 112`: it
  is `not_applicable` to a 128-bit X25519/P-256 row, `open` for a 112-bit one, and
  `undetermined` for RSA/DH — their strength depends on a key size no row carries
  yet, so it is not guessed. SP 800-186 is used for the curves on purpose: SP
  800-57's field-size column alone would put Curve25519 (255-bit field) at 112.
- **EU roadmap.** The PDF (v1.1, 11.06.2025) is now fetched and vendored. Its
  per-use-case rule — quantum-vulnerable public key "shall not be used stand-alone
  after the end of 2030" for high-risk, 2035 for medium-risk — is carried as two
  policies, `EU_HIGH_RISK` and `EU_MEDIUM_RISK`. The roadmap derives risk level from
  a score the organisation computes (p. 10); this tool computes no score (§5.12), so
  the level is the operator's to state, as with India CII vs Enterprise.
  "Stand-alone" matches the existing `met` rule: an observed migration with
  classical refused.
- `crypto_families.yaml` gains P-224, P-384, P-521, X448, Ed25519 as Shor-broken,
  each cited to the IR 8547 table row that lists it. Found because a P-224 test
  correctly came back `undetermined` — the family had no row.

591 tests pass; all three CI guards pass.

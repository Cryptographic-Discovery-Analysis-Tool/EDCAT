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
| 6 CBOM export | `export/cyclonedx.py` | implemented, unit-green; signed export deferred (OI-013) |
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

### P14 — Agility evidence (narrowed from the review's proposal)

**Falls under:** P1 (source adapter, done), P3 (config adapter, done), P4 (TLS, done).
All three already observe what this phase names; none of them names it.

The review proposed six fields. Three are adopted, one is deferred, **two are
refused**.

| Field | Verdict | Where the evidence already is |
|---|---|---|
| `algorithm_selection` — `HARDCODED` / `CONFIGURATION_DRIVEN` / `UNKNOWN` | adopt | The source rules already split literal from non-literal: `TokenVault`'s literal `AES/GCM/NoPadding` (PAY-003) against `KeyWrapService`'s `props.getTransformation()` resolved through the config chain (PAY-001). This is that distinction, named. |
| `hybrid_capable` | adopt, KNOWN only when observed | The TLS adapter's `negotiated_group`. A configured cipher list is INFERRED at best, never KNOWN. |
| `provider_pluggable` | adopt, INFERRED ceiling | JCA provider indirection is readable from source; an actual provider registration is not, so UNKNOWN is the default and INFERRED is the maximum. |
| `certificate_rotation` | **defer to P13** | Not a field. It needs the same certificate seen at two times, which is exactly what the run store produces. Putting it on a Finding would imply a single scan can see it. |
| `migration_complexity` | **refuse** | It is a score. Slide 2 claims "no weights, no score, no model — lexicographic order only," and §5.10 ranks by window, not by effort. Adding this field would falsify the headline claim in exchange for a number nobody can defend. |
| `hardcoded` as a bare boolean | **refuse** | Collapses `HARDCODED` and "we could not tell" into one value. Three states or none. |

**Done when:** every agility field carries its own epistemic state like every other
field in the model, and `check_data_citations.py` still passes.

### P15 — Evidence graph view

**Falls under:** P6 (correlation — recorded above as "partial, done for its defined
scope"). The data already exists; only the rendering does not.

`CorrelationReport` already carries the assets, the `same-object` relationships
gated through `IDENTITY-CERT-DER-001`, and the `shares_public_key_unclaimed` pairs
that deliberately are *not* relationships. That is a graph in everything but
presentation.

Deliverables: a graph tab in the dashboard, and `ecdat correlate --format graph`.

**Hard requirements, because this is the easiest place in the whole project to
draw a lie:**

- every edge renders its type *and* its epistemic basis;
- `shares_public_key_unclaimed` renders as a visibly weaker edge than `same-object`,
  and never collapses into it — there is no registered rule_id for that claim
  (OI-006), and the renderer must not invent one by drawing the same line;
- edges that do not exist are drawn as named gaps, not as blank space.

**Explicitly not built, and not to be drawn:** the review sketched a seven-layer
chain — crypto API → config → algorithm → library → certificate → service →
protected data. Two of those edges are real (config → algorithm, from P3;
certificate → service, from P4). **Library → usage is not**: the package and binary
readers refuse to claim usage on purpose, and that refusal is tested. **Service →
protected data is not**: the data class is DECLARED by a person, and there is still
nowhere to declare it (P6's open item). Rendering the clean chain would be precisely
the false-certainty failure this tool exists to prevent, on the one screen a judge
is most likely to photograph.

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

### P17 — RBAC and audit log

**Falls under:** ledger phase 7 (*dashboard*, built). The API exists and is
unauthenticated.

The deck answers "the inventory is itself a sensitive asset" with four controls.
Three are real — on-prem, no key material stored (enforced by
`security/secrets.py` and tested), and the network definition. The fourth is not
started. Minimum honest scope: an authenticated API, roles that distinguish reading
the ledger from changing a scenario or exporting, and an append-only log of who
read or exported what. Export is the sensitive verb here, not scanning.

### P18 — Make no-egress test-enforced

**Falls under:** the harness, not `src/`. Smallest phase on this list.

**Corrected 2026-09-21:** there is no `harness/` directory in this repo — not
the compose file, not `internal: true`, nothing. The earlier note in this plan
claiming `internal: true` was "already set" was wrong; it cited a file that
does not exist here. Both halves are unbuilt: write the compose network
definition with `internal: true` on the isolated network, then add the test
that asserts a container on it cannot reach the outside world. Until both
land, the deck should say neither "enforced by the network definition" nor
"test-enforced" — say nothing about egress isolation at all.

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

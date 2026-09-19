# Pramāṇa — FINAL document 2: implementation plan, differentiator, ratings

Date: 18 Sep 2026. This supersedes `ECDAT_NTRO_Implementation_Plan.md`,
`ECDAT_NTRO_Architecture_Decisions.md`, `ECDAT_NTRO_Final_Review.md` and
`Pramana_Exposure_Ledger_RedTeam_Spec_Plan.md`. Everything still true from those files is here;
anything not here is dropped. Tags: FACT (checked in the repos or a primary source), CANON (the
locked architecture docs), JUDGEMENT, ESTIMATE, VERIFY.

Repo state referenced: `EDCAT` main `8ebbe05`, `ecdat-harness` main `13128cc`.

---

## 0. Ratings (the numbers you asked for)

| Item | Rating | What it would take to move it |
|---|---|---|
| **Differentiator — the Exposure Ledger** | **9 / 10** | Temporal, function-aware, two-clock, interval-start, replayable, closure-driven, deterministic, no score, no model. Every one of those words is a red-team fix, not an adjective. It is 9 not 10 because it is unimplemented and because "assumes capture" is a scenario assumption a hostile judge can push on (the answer is on the slide and in §5). |
| Deck (`Pramana_SIH2026_5slides.pptx`) | **8.5 / 10** | See document 1. Flips to 9+ when slide 5's function-accuracy and exposure-correctness pills become MEASURED (Phases 2, 4, 8). |
| This plan | **9 / 10** | Formula-level, testable, phased, with acceptance per phase. Three VERIFY items open (§9). |
| Code today vs this plan | **1.5 / 10** | Evidence model, adapter contract, source adapter, scorer exist and are measured (FACT: 120 tests, 4/4, 0/8). Nothing from the ledger spec exists. |
| Public readiness today | **3 / 10** | Repo name, licence, README, secret scanning, NTRO wording — one day of work (§10). |

---

## 1. What the differentiator is, in one paragraph

NTRO's actual problem is not "where is our cryptography" but "which of our secrets are already
beyond saving, which are still bleeding, and which can we still protect." Harvest-now-decrypt-later
means every byte sent over a Shor-vulnerable *confidentiality* channel is recoverable at Z if it was
recorded; migration stops the bleed and recovers nothing. So the correct migration order is by
**still-savable time window**, per **actual crypto function**, under a **stated scenario** — not by
algorithm and key size. Signatures fail on a different clock (forgery after Z, re-sign if the
artefact must stay trustworthy past Z), so there are two ledgers. Every input carries an evidence
status; Unknown makes the row UNBOUNDED and generates the minimum next piece of evidence that would
bound it. Every result replays from its record. There is no score and no model.

Pipeline: **OBSERVE → STATUS → BIND → CLOCK → LEDGER → CLOSE → ACT.**

---

## 2. Where the code is today, against the brief (FACT)

| Brief | Exists | Status |
|---|---|---|
| (i) catalogue algorithms, keys, certs, protocols, libraries, hardware, cloud | One adapter (Semgrep source, Java rules). `certs/ tls/ config/ packages/ binary/` are empty `__init__.py`. HSM/KMS: nothing; harness mock files are 0 bytes. | ~15 % |
| (ii) quantum risk, systems prone, risks to sensitive data | `risk/` empty | 0 % |
| (iii) classify by type/lifetime/criticality; Mosca | `context/` empty; lifetime table uncited | 0 % |
| (iv) PQC/hybrid recommendations | `recommend/` empty | 0 % |
| Scan source, binaries, libraries, images | 1 of 4 | — |
| Standardised report (CBOM) | `export/` empty; 1.6 schema downloaded | 0 % |
| Interactive GUI | Flask replay form | prototype |

What is real and load-bearing: per-field evidence status (7 closed states + resolution status),
adapter contract that distinguishes "did not look" from "clean", own Semgrep inventory rules
(4/4 planted assets vs registry 1/4), harness scorer with a live-metric self-check
(all-KNOWN control scores 8/8), recorded fixtures for semgrep 1.99.0 / trivy 0.74.0 /
sslyze 6.2.0 / openssl 3.5.4. Synthetic Reference Enterprise Tier A is built and launched
(payment-gateway, PKI, 10 ground-truth assets); Tier B/C is a tree of 0-byte files.

Over-investment to stop: governance artefacts (4 ADRs, 9 OIs, 2 CI guards) ahead of adapters;
experiments recorded before the adapters that consume them; a confidence registry with zero
usable rows; four deck edits in a day with no new surface; a demo UI before the CBOM export.

---

## 3. Decided stack (frozen)

| Layer | Decision | Basis |
|---|---|---|
| Source | Semgrep CE (LGPL-2.1) + own rule packs: Java (built), Python, Go, JS/TS, C/OpenSSL EVP; runs on Opengrep | CE is single-function/single-file (FACT, README) — the reason per-field status exists |
| Config chain | own resolver (CFG-001; answer key runtime-validated by 7 JVM launches) | CANON harness §14 |
| Certificates | OpenSSL 3 + python-cryptography; DER SHA-256 / SPKI identity, canonicalised | TOPO-X3 FACT |
| TLS | sslyze 6.2.0, **separate process, optional adapter**; requested SNI + vantage persisted; transcript/cert import always available | AGPL-3.0 satisfied by process boundary + full source delivery; ZGrab2 rejected (no enumeration / PQ support stated) |
| Packages / images | `cbomkit-theia` (Apache-2.0, CycloneDX 1.6) for images/dirs/certs/keys/secrets; **one** of Trivy `rootfs` / Syft for components, chosen by a recorded fixture on the fat jar | Trivy `fs` sees nothing in a jar (FACT); Syft nested-jar behaviour not stated |
| Binaries | YARA constants + `readelf`/`strings`; family only; RSA "not detectable by constants" reported | Ghidra roadmap only |
| Hardware / cloud | PKCS#11 metadata (SoftHSM2 in the reference enterprise); KMS export importer + AWS reader behind an interface; no key material ever | — |
| Model | evidence status per field; Part 3 confidence table cited as "engineering estimate, Part 3; no published benchmark" | OI-004 resolved by supplied Part 3 |
| Resolution + graph | within-surface merge on Part 5 key (`scope_anchor` per surface); cross-surface only by cert/SPKI hash; every edge Observed/Inferred/Declared | CANON Part 5 |
| Function / temporal / ledgers / closure | §5 below | red-team frozen |
| Recommendation | purpose-keyed option sets (FIPS 203/204/205, hybrid X25519MLKEM768), policy profiles (NIST L3 default, CNSA 2.0 L5); `purpose UNKNOWN` → "insufficient evidence" | CANON Part 8 |
| Export | CycloneDX 1.6 validated against `schemas/`; undetermined bucket; exposure as `pramana:exposure:*` properties; CBOM **import** from other tools as an evidence source; signed export (VERIFY JSF field) | — |
| Store / jobs | PostgreSQL JSONB + Postgres job table; raw captures on a volume; snapshots for deltas | no NATS/Redis/object storage |
| API / UI | FastAPI + React (Vite static bundle) | no Next.js SSR in an air-gap |
| Delivery | Compose, no-egress network (test-enforced), RBAC, audit log, encrypted export, signed offline update bundle, tool-pin manifest `tools.lock` | — |
| AI | none in 1.0 | security property |
| Licence | Apache-2.0 (both repos) | matches every sensor; sovereign story |
| Rejected | ZGrab2, Ghidra (1.0), OSV/CVE intelligence, NATS/Redis, object storage, Next.js, LLM explanations, additive risk score, float-only confidence, cross-surface identity resolution, traffic-volume estimation, probabilistic Z | each with a reason in the earlier Decisions/red-team files, all retained here as rejected |

---

## 4. Why this and not the free tool (the only competitive claims we make)

Documented against READMEs read 18 Sep 2026 (FACT): CBOMkit / sonar-cryptography / cbomkit-theia
(Apache-2.0) inventory source (needs SonarQube) or images (theia); they emit CycloneDX 1.6. They do
not model exposure over time, do not separate confidentiality from authentication clocks, do not
carry evidence status per field, do not report what they could not see, and do not generate the
next evidence to collect. Pramāṇa **runs them** (theia as a sensor; any CycloneDX 1.6 CBOM as an
import) and adds the ledger on top. Honest counter: for a plain Java/Python/Go source CBOM, CBOMkit
is free and adequate — say so. Commercial platforms: do not characterise their features without
verifying each; our properties are on-prem, air-gapped, source-delivered, replayable, and we
publish our own error rates.

---

## 5. Frozen specification (post red-team)

Red-team result: 20 attacks, 8 High. Three were formula-level and would have produced wrong
rankings on stage (`already_lost = years(start→today)` over-counts; function was on the asset,
not the usage context; signatures reduced to `Z − rollout`). All fixed below.

### 5.1 Crypto-function classifier — `src/ecdat/function/classifier.py`
`CryptoFunction ∈ {SIGNATURE_AUTH, KEY_ESTABLISHMENT, ENCRYPTION, KEY_TRANSPORT, HYBRID_KEX, UNKNOWN}`
lives on a **UsageContext** `(asset_id, surface_id, protocol_context, function, status, evidence_refs, rule_id)` — never on the asset. One asset → N rows.
- Negotiated TLS suite observed: `ECDHE_*` → KEY_ESTABLISHMENT (Observed) + cert → SIGNATURE_AUTH (Observed); `TLS_RSA_*` negotiated → KEY_TRANSPORT (Observed); negotiated `X25519MLKEM768` → HYBRID_KEX (Observed).
- Offered-but-not-negotiated suites, keyUsage/EKU → **Inferred** capability contexts.
- Source call-site class (own rules): `Cipher` in wrap mode / `RSA/...` → KEY_TRANSPORT; `Signature` → SIGNATURE_AUTH; `KeyAgreement` → KEY_ESTABLISHMENT; algorithm may be Unknown while function is Observed (separate fields).
- Package presence → no context. Anything else → UNKNOWN. No default.

### 5.2 Temporal evidence — `src/ecdat/model/temporal.py`
`TemporalEvidence {surface_id, first_observed, not_before, declared_go_live, possible_since, confirmed_since, observation_ts, status_per_field}`;
`MigrationEvidence {surface_id, vantage, observed_at, negotiated_group, classical_still_accepted, status}`.
`possible_since = min(not_before, declared_go_live, first_snapshot_containing)`; `confirmed_since = earliest Observed traffic-path observation` (Declared go-live only if policy allows). `notBefore` alone never confirms.

### 5.3 Data-class binding — `src/ecdat/context/binding.py`
`DataClassBinding {target_id, classification, secrecy_lifetime_X_days, authenticity_lifetime_A_days|None, status=Declared, source_ref, cited_table_row}`; rows in `data/data_lifetime.yaml` are usable only with a citation.

### 5.4 Scenario engine — `src/ecdat/risk/scenarios.py`
`Scenario {id, Z_date, basis_citation, label}` in `data/scenarios.yaml` (three, cited; VERIFY GRI percentiles). `Policy {accept_inferred_inputs=false, accept_declared_go_live=true, capture_assumption ∈ {SINCE_CONFIRMED, SINCE_POSSIBLE, SINCE_DATE(d)}, rollout_Y_default}`. Pure date arithmetic; no hidden constants.

### 5.5 Confidentiality ledger — `src/ecdat/risk/confidentiality_ledger.py`
Applies only to Shor-broken confidentiality functions (KEX, key transport, PKE). Grover cases go to policy flags, not the ledger.
```
start    = confirmed_since | possible_since | d   (per capture_assumption)
M        = earliest MigrationEvidence with status=Observed and classical_still_accepted=false, else ∞
deadline = Z − X
unsavable_window = [max(start, deadline), min(as_of, M)]  if lo < hi else ∅
bleeding = as_of > deadline and (M == ∞ or M > as_of)
band: Unknown input → UNBOUNDED
      Inferred input and !accept_inferred → UNBOUNDED (+ conditional band attached)
      not Shor-broken, or HYBRID_KEX from start → SAFE
      bleeding → BLEEDING (+ window)
      window ≠ ∅ and stopped → UNSAVABLE (STOPPED at M)
      window = ∅ and as_of ≤ deadline → SAVABLE (deadline)
qualifiers: PARTIAL (hybrid observed, classical still accepted, per vantage); REOPENED (later classical observation)
```
Every row outputs the windows, `deadline`, all input ids + statuses, and the literal "assumes capture since {start} ({capture_assumption})". No volume anywhere; all quantities are time windows.

### 5.6 Authentication ledger — `src/ecdat/risk/authentication_ledger.py`
`required_until = signed_at + A`. `A == 0` (session) → ROTATE_BEFORE_Z, deadline `Z − Y`. `required_until > Z` → RESIGN_BEFORE_Z (PQ signature or trusted timestamp before Z). Else SAFE_UNTIL_Z. Unknown/Inferred as 5.5.

### 5.7 Hybrid clock
Stops a surface only on an **observed** negotiation with classical disabled, per vantage; a later classical observation re-opens from that date; config-only evidence is Inferred and never stops the clock.

### 5.8 Evidence Closure Engine — `src/ecdat/closure/engine.py`
For every UNBOUNDED row: list the Unknown/Inferred required inputs; look up the minimum evidence per input in `data/closure_catalog.yaml`; compute decision impact by re-running the ledger over the admissible values of the missing input and reporting the reachable bands; rank tasks lexicographically (worst reachable band, rows affected, longest reachable window). Each task: what to collect, why it bounds the row, rows touched, reachable outcomes.

### 5.9 Replayable record — `src/ecdat/risk/record.py`
`CalculationRecord {record_id, as_of, scenario_id, capture_assumption, policy_snapshot, usage_context_id, function, evidence_refs[{id,status,ts}], X, A, start_possible, start_confirmed, M_evidence_ids, rule_version, calc_version, band, qualifiers, windows, deadline, conditional_band, sha256(inputs)}`; property test `replay(record).band == record.band`.

### 5.10 Ranking
Lexicographic on categorical fields: band order (BLEEDING > UNSAVABLE-stopped > SAVABLE > SAFE), then criticality category, then longest window. No weights, no products.

### 5.11 Export — `src/ecdat/export/cyclonedx.py`
CycloneDX 1.6 component `properties`: `pramana:exposure:band|qualifiers|scenario|as_of|unsavable_window|deadline|capture_assumption|record_id|function|function_status`, plus `confidenceLevel`, `detectionContext`, the undetermined bucket. Schema-validated; secret-leak scan on output. Described as "CycloneDX-compatible properties", never as a standard field.

### 5.12 Rejected in the spec (do not add)
Traffic-volume estimation; probabilistic Z; weighted priority score; auto-remediation; LLM explanations; timestamp-authority verification of old signatures (roadmap).

---

## 6. Deterministic test set (frozen expected outcomes)

`as_of = 2026-09-18`; Z_aggr 2031-01-01, Z_central 2036-01-01, Z_optim 2041-01-01 (test constants).

| Case | Expected |
|---|---|
| RSA cert, TLS auth only (ECDHE negotiated) | no confidentiality row for the key; auth: ROTATE_BEFORE_Z |
| RSA static key transport, X=7y, since 2021-01-01 | central: SAVABLE, deadline 2029-01-01; aggressive: BLEEDING, unsavable [2024-01-01, as_of] |
| X25519 ECDHE, X=25y, since 2021-01-01 | all Z: BLEEDING, unsavable [2021-01-01, as_of] |
| P-256 ECDHE, X=1y | central: SAVABLE (deadline 2035) |
| X25519MLKEM768 negotiated, classical off, M=2026-06-01, X=25y, since 2021 | UNSAVABLE (STOPPED 2026-06-01), window [2021-01-01, 2026-06-01] |
| Hybrid configured, not observed | M=∞ → BLEEDING; closure task "probe negotiated group from vantage" |
| Expired certificate on live endpoint | ledger unaffected; lifecycle EXPIRED flagged separately |
| notBefore 2019, first_observed 2024, no go-live | possible 2019 / confirmed 2024; both windows reported per capture mode |
| Missing go-live, only notBefore | UNBOUNDED; task "declare go-live or take first observation" |
| Inferred configuration (PAY-001) | UNBOUNDED + conditional BLEEDING; task "resolve config chain / runtime capture" |
| Unknown KEX | UNBOUNDED, no conditional |
| X=25y vs X=1y on the same channel | BLEEDING vs SAVABLE in all Z |
| Long-lived signed artefact, signed 2026-01-01, A=15y | RESIGN_BEFORE_Z (required until 2041 > Z_central) |
| RSA cert: `TLS_RSA_*` offered (Inf) + ECDHE negotiated (Obs) | two contexts: KEY_TRANSPORT UNBOUNDED(conditional); SIGNATURE_AUTH auth row |
| Multiple Z | bands differ exactly at deadline crossings; flip dates listed |
| M=2030 vs M=2038, Z=2036, X=10y, since 2020 | deadline 2026; M=2030 → UNSAVABLE [2026, 2030] STOPPED; M=2038 → BLEEDING, M>Z recorded |
| Hybrid observed 2026-06-01 (classical off), classical observed 2026-08-01 | REOPENED, BLEEDING from 2026-08-01 |
| Replay | `replay(record).band == record.band`, hash-stable |

---

## 7. Phases

**Prerequisite (no way round it):** a Linux build box with Docker, Go, Maven, haproxy, SoftHSM2
(FACT: OI-007/008/009 — Semgrep does not install on Windows; images and the Go binary cannot be
built here). ESTIMATE half a day.

### 7.1 Sensor phases (existing `docs/build-plan.md` numbering; re-order filed as DEV-002)

| Phase | Deliverable | Must hit | Acceptance | ESTIMATE |
|---|---|---|---|---|
| P0b | Part 3 confidence rows → `usable: true`, adapters → `CITED_TABLE`, ADR-002 test updated | — | no `ADAPTER_DECLARED` in a shipped adapter | 0.5 d |
| P4 | Certs (PKCS12/PEM/DER, DER-canonical hash, location+fingerprint only) + TLS (sslyze, SNI/vantage persisted, **negotiated suite and group recorded** — the ledger's input) | PAY-004..007, INF-001, INF-017 | score rows `certs`, `tls`; secret-leak test passes | 3–4 d |
| P5 | Trivy `rootfs` (or Syft, by fixture); capability only | PAY-008 | score row `packages`; no usage asset emitted | 1–2 d |
| P4b | `cbomkit-theia` wrapper + CycloneDX 1.6 CBOM importer (any tool's CBOM becomes evidence) | PAY-004 in image, INF-017, CUS-002 | score row `image`; never merges with source except by DER/SPKI | 2–3 d |
| P3 | Config-chain resolver (states A–H; INFERRED never KNOWN; F → UNRESOLVED; D → CONFLICTING) | PAY-001 | 8 state fixtures pass | 3–4 d |
| P6 | Within-surface merge; cross-surface only by hash; forbidden-edge gate; coverage report; fill `visibility.expected.yaml` | relationships.yaml | forbidden edges never emitted; visibility recall scored | 4–5 d |
| P11 | PKCS#11 metadata (SoftHSM2) + KMS export importer + AWS reader | PAY-011, INF-018..020 | rows `hsm`, `kms`; NOT_OBSERVED when absent | 3–4 d |
| P12 | YARA constants + readelf; family only | RES-003/004, CUS-004, PAY-009/010 | row `binary`; nothing invented for RSA | 3–4 d |
| Harness B/C | HR, Customer, datalake-sync (stripped), KMS mock content, SoftHSM2 token, COBOL file; ground-truth YAML per asset | Tier B/C ids | 0-byte files gone; "48" becomes true | 5–8 d |

### 7.2 Ledger phases (the differentiator)

| Phase | Modules | Data structures | Algorithms | Tests | Acceptance | Demo evidence | ESTIMATE |
|---|---|---|---|---|---|---|---|
| **1 Evidence model** | `model/temporal.py`, `model/usage_context.py`, migrations `usage_contexts`, `temporal_evidence`, `migration_evidence` | §5.1–5.2 | interval derivation; R-DERIVE status propagation | confirmed ≥ possible; notBefore alone never confirms | every Tier A cert/TLS asset carries temporal rows | PAY-005 row shows both dates | 2–3 d |
| **2 Function resolution** | `function/classifier.py`, `rules/registry.py` | CryptoFunction, rule ids | §5.1 tables; Observed vs Inferred by evidence kind | 6 function cases + multi-function | PAY-001..007 contexts match harness §7.2 purpose with correct status | one asset, two rows | 2–3 d |
| **3 Scenario engine** | `risk/scenarios.py`, `data/scenarios.yaml`, `data/data_lifetime.yaml` | Scenario, Policy, binding | pure date arithmetic; cited constants | deadline/window tests; SINCE_* modes | CI grep: no uncited constant in `data/` | scenario switch flips bands live | 1–2 d |
| **4 Exposure ledger** | `risk/confidentiality_ledger.py`, `risk/authentication_ledger.py`, `risk/record.py` | CalculationRecord | §5.5–5.6, §5.10 | all of §6; replay property | every row replays; false certainty 0 on ledger inputs | RES-001 vs INF-001 (slide 4) | 3–4 d |
| **5 Closure engine** | `closure/engine.py`, `data/closure_catalog.yaml` | ClosureTask | reachable-band enumeration; lexicographic rank | each UNBOUNDED case → exactly one minimum task; impact sets correct | precision measured: executing a task on the harness bounds its row | PAY-001 task → P3 → row bounds | 2–3 d |
| **6 CBOM export** | `export/cyclonedx.py` | properties map | serialise, validate, secret-leak scan; import path | schema validation; undetermined bucket; no key bytes | valid 1.6 file with `pramana:exposure:*` | open the JSON on stage | 2–3 d |
| **7 Dashboard** | `ui/` FastAPI + React/Vite: Ledger, Evidence card, Closure queue, Coverage, Export | API over records | presentation only | view tests over fixtures | two-minute script passes on the reference enterprise | the 9-line judge script | 5–7 d |
| **8 Test harness + adversarial** | `ground-truth/exposure.expected.yaml`; `score_run.py` extension: ledger accuracy, closure precision, function accuracy | expected bands per asset per scenario | join by surface | §6 as harness assets; adversarial: fake M, config-only hybrid, notBefore trap | metrics printed → slide 5 pills flip | metrics slide | 2–3 d |

Order: P0b → P4 → P5 → 1 → 2 → 3 → 4 → 8 (minimum) → P3 → 5 → 6 → P4b → P6 → 7 → P11 → P12 → 8 (full) → hardening (Compose, no-egress test, RBAC, audit, signed bundle, `tools.lock`, threat-model doc, "what it cannot see" doc). ESTIMATE total 55–75 engineer-days after the build box.

---

## 8. Definition of finished (1.0)

1. `docker compose up` on the build box: API, worker, DB, console; no egress (test-enforced).
2. A scan of the Synthetic Reference Enterprise (source, images, cert dirs, one TLS endpoint, one SoftHSM2 token, one KMS export) completes under per-target timeouts.
3. The ledger view shows every Shor-broken confidentiality context with a band, windows, evidence statuses and "assumes capture"; every UNBOUNDED row has a closure task; every row replays.
4. Export validates against the 1.6 schema with the undetermined bucket and `pramana:exposure:*`; passes the secret-leak scan; import of a third-party CBOM round-trips as evidence.
5. `score_run.py` prints: per-surface recall, false certainty, under-claiming, function accuracy, exposure correctness (18/18), closure precision, replayability — and slide 5 shows exactly those numbers.
6. Install/operator docs followed once by someone who did not write them.
7. Every capability sentence in the deck points at 1–6.

---

## 9. VERIFY before printing or shipping

1. sslyze 6.2.0 reports `X25519MLKEM768` as a negotiated/offered group (recorded probe used `CERTIFICATE_INFO` only — FACT).
2. GRI Quantum Threat Timeline 2024 percentiles behind the three Z dates.
3. `cyclonedx-python-lib` support for 1.6 `cryptoProperties` (else: schema-validated JSON writer, already sufficient).
4. Syft nested-jar cataloguing on the Tier A fat jar (fixture decides Trivy vs Syft).
5. CycloneDX JSF `signature` field for signed export.
6. DST Task Force Feb 2026 milestone status (report, not law).

---

## 10. Public-hygiene day (before the first post)

Rename repo `EDCAT` → `pramana`; add Apache-2.0 LICENSE to both repos; replace the one-line
README (thesis, measured table, how to run, what it cannot see, licence); add gitleaks to CI;
pin Python 3.12; strip team name and hackathon template from anything public; never write
"client" or "prepared for NTRO" — "built against problem statement SIH26164". Post it as a
build-in-public with the measured table as the hook; launch when §8 passes.

---

## 11. This week, in order, nothing else

1. Linux build box.
2. Build Tier A images; close OI-007.
3. P0b (half a day).
4. P4 certs + TLS — record negotiated suite and group; this is the ledger's first real input.
5. Phase 1 + Phase 2 on top of P4's observations.
6. Phase 4 with the §6 test set; re-run `score_run.py`; flip the first TARGET pill.

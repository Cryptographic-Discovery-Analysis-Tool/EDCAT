# ECDAT — Final Architecture (Part-by-Part)

**Problem statement:** SIH 26164 — Enterprise Cryptographic Discovery & Analysis Tool (CBOM + quantum risk + PQC migration).

**How to read this document.** Every part has the same five headings: what it does, what goes in and out, how it is built, **caveats** (the things that are actually true about it, including the unflattering ones), and **the question a judge will ask**. The caveats are not disclaimers — they are design constraints carried forward from the research and stress-test sessions. Anything marked ⚠️ is a correction to an earlier version of this architecture and must not be reverted.

---

## Part 0 — Scope and non-negotiable principles

These constrain every part below.

1. **Reuse scanners, don't rebuild them.** ECDAT is a correlation, risk and migration layer. The detection tools are commodity.
2. **Evidence-first.** Every asset, risk score and recommendation traces back to a raw scanner observation that can be shown on screen.
3. **Finding ≠ Asset.** A finding is one observation by one tool. An asset is a cryptographic entity. Many findings may describe one asset — but proving that is hard (see Part 5).
4. **CBOM is an output, not the internal model.** The internal model is richer than CycloneDX and must stay that way.
5. **Deterministic security logic.** Detection, risk scoring and PQC mapping are rule-based. No model decides whether something is risky.
6. **AI is auxiliary.** LLMs may summarise a finding in plain English for a user. They are never authoritative for detection, risk or algorithm mapping.
7. ⚠️ **Report what you could not see.** A crypto inventory that silently omits undetectable crypto creates false assurance, which is worse than no tool. Coverage reporting is a first-class output, not a footnote. This is the single strongest differentiator in the design.
8. **MVP-first.** No Kafka, no Kubernetes, no Neo4j, no deep reverse engineering, no continuous monitoring until the core workflow is proven end to end.

---

## Part 1 — Targets (what gets scanned)

### What it does
Defines the six surfaces where cryptography can be observed, and the scope boundary for a scan job.

### In / Out
- **In:** a scan request naming targets — repository path/URL, container image reference, binary path, certificate file or directory, host:port list.
- **Out:** a validated, authorised target list bound to a scan ID.

### How it is built
| Surface | Why it exists |
|---|---|
| Source repositories | Shows *intent* — how the application asks for cryptography |
| Libraries / dependencies | Shows *capability* — what crypto code is present |
| Container images | Packaging reality; also where certs and keys get baked in |
| Certificates & key material files | Highest-precision evidence available |
| TLS / network endpoints | Shows *actual deployed* cryptography, which often differs from source |
| Binaries | Compiled components where source is unavailable |

### Caveats
- ⚠️ **Network targets need explicit authorisation.** Active TLS probing of hosts you do not own is abuse. The scan request must carry an allow-list and a consent flag. Judges on a security panel will ask about this.
- Targets are scanned inside resource-limited sandboxes: untrusted binaries and images are parsed by `readelf`/`objdump`/`openssl`/YARA, all of which have crash and exploit history on hostile input.
- Per-target timeouts and file-size caps are mandatory, not optional. A single large monorepo or a 4 GB image will otherwise stall the demo.

### Judge's question
*"What stops someone pointing this at infrastructure they don't own?"* → Scope allow-list, explicit consent flag per scan, passive-by-default for everything except the network adapter.

---

## Part 2 — Discovery adapters (the sensors)

### What it does
Runs the external scanners and nothing else. Each adapter knows one tool.

### In / Out
- **In:** one target + scan configuration.
- **Out:** raw tool output, stored verbatim (JSONB), plus an execution record (exit code, duration, what was skipped).

### How it is built
Common interface: `supports(target)` → `scan(target)` → `normalize(raw)`.

| Adapter | Tool | What it actually yields |
|---|---|---|
| Source | Semgrep | Crypto API call sites with file:line |
| Packages | Trivy | Package inventory + versions (SBOM) |
| Image | Trivy | Layer-aware package list; cert/key files |
| Certificates | OpenSSL + keystore parsers | Key algorithm, key size, signature algorithm, validity, **keyUsage** |
| Network | **sslyze** (primary), testssl.sh (fallback) | TLS versions, cipher suites, key exchange groups, cert chain, signature algorithms |
| Binary | `file`, `readelf`, `objdump`, `strings` + **YARA crypto-constant rules** | Linked libs, dynamic symbols, crypto constants |
| Cloud keys | AWS KMS / Azure Key Vault / GCP KMS **metadata read** | Key spec, algorithm, rotation state — no key material |

### Caveats — read this section twice
- ⚠️ **Semgrep is intra-procedural and unsound by design.** No pointer or alias analysis; cross-file taint is a paid feature. Anything where the algorithm comes from config, environment, reflection, a database, or a wrapper in another file **will be missed**. Semgrep answers "a crypto API is called here," not "this application uses RSA-2048."
- ⚠️ **Trivy reports packages, not algorithms.** "This image contains OpenSSL 3.0.2" is a statement about *capability*, not *usage*. There is no dataflow into application code. Trivy's own CBOM support (crypto file discovery) is an open design discussion, not a shipped feature. Never present a Trivy package as a used algorithm.
- ⚠️ **`strings`/`readelf` collapse on modern binaries.** Go and Rust binaries are statically linked and frequently stripped — no symbols, few useful strings. **YARA crypto-constant rules are the fix and are not optional**: they match AES S-boxes, SHA init constants, the ChaCha20 `expand 32-byte k` constant, and curve parameters, and they still work on stripped static binaries. Known limit: constant matching fails on obfuscated implementations and on algorithms without distinctive constants — notably **RSA**.
- **sslyze over testssl.sh as primary.** Cleaner JSON, faster, Python-native, easier to drive from FastAPI. testssl.sh gives more depth and vulnerability checks but runs ~60–120 s per host (~30–40 s with `--fast`), can hang enumerating legacy SSL, and has known JSON quirks under mass scanning. Keep it as the depth fallback.
- **Cloud KMS is metadata-only.** Listing key specs via API covers the "cloud services / hardware modules" clause of the problem statement cheaply. PKCS#11 slot enumeration and TPM presence detection (`/dev/tpm0`) are the same trick for hardware. Implementing even one converts "deferred" into "covered at MVP level."
- ⚠️ **Adapter count is the real scope risk, not the database schema.** Each adapter is invoke + parse + normalise + confidence-assign + test. If time is short, cut adapters — not layers. Minimum viable set: **source, certificates/TLS, image/packages, binary+YARA.**

### Judge's question
*"Semgrep finds a call to `Cipher.getInstance(algo)` where `algo` is read from a properties file. What does your tool report?"* → A finding with `algorithm: unknown`, low confidence, and an entry in the coverage report flagging a dynamically-configured crypto call site. That honesty is the correct answer, and it is the answer most competing teams cannot give.

---

## Part 3 — Normalisation into Findings + Evidence

### What it does
Converts every tool's output into one canonical record shape so nothing downstream needs to understand five formats.

### In / Out
- **In:** raw tool output.
- **Out:** `Finding` records, each pointing at preserved `Evidence`.

### How it is built
A Finding carries: source tool, target, location (file:line / image layer / host:port / binary offset), algorithm, parameters (key size, mode, padding, curve), **purpose**, confidence, and a pointer to the raw evidence snippet.

### Caveats
- ⚠️ **Confidence must be assigned by source, not uniformly.** The earlier beginner-facing draft labelled a Semgrep hit "HIGH". That is backwards and is exactly where a technical judge will attack. Base confidence by evidence type:

| Evidence source | Base confidence | Why |
|---|---|---|
| Parsed certificate / keystore | ~0.95 | The algorithm is literally encoded in the artefact |
| TLS observation on the wire | ~0.90 | Directly observed in a live handshake |
| YARA crypto constant in binary | ~0.70 | Strong signal, but file-level and no usage context |
| Semgrep literal match | ~0.60 | Pattern matched; may be dead code, test code, or overridden |
| Binary symbol / string | ~0.40 | Presence, not use |
| Trivy package present | ~0.30 | Capability only |

  Raise confidence when independent sources agree on the same asset. Adopt CycloneDX's native `confidenceLevel` (0.0–1.0) and `detectionContext` fields directly rather than inventing a scheme.

- ⚠️ **Cryptographic purpose is mostly undiscoverable and this is structural.** The PQC recommendation engine is purpose-aware (Part 8), but only two surfaces carry purpose explicitly: **X.509 `keyUsage`/`extendedKeyUsage`**, and **TLS cipher suite structure** (which separates key exchange from authentication by construction). Semgrep sees RSA and cannot tell key transport from signing; Trivy sees a package and tells you nothing. Therefore: certificates and TLS are the **primary evidence anchors**, and every source/package finding is written with `purpose: unknown` — explicitly, never defaulted.
- Realistic error rates: static crypto detection has meaningful false negatives (dynamic/config/transitive crypto) and non-trivial false positives (dead code, test vectors, vendored dependencies). There is no published FP/FN benchmark for PQC *inventory* detection specifically — the nearest evidence is crypto-*misuse* benchmarking. Measure your own numbers on your demo corpus (Part 12) rather than claiming an industry figure.

### Judge's question
*"Why is one finding 0.9 and another 0.3?"* → Because one observed a live handshake and the other observed that a library is installed. Show both evidence snippets side by side.

---

## Part 4 — Coverage & blind-spot reporting ⚠️ NEW, and the differentiator

### What it does
Records, for every scan, what was examined, what was skipped, and why — then exposes it as a first-class output alongside the inventory.

### In / Out
- **In:** adapter execution records, skip reasons, timeouts.
- **Out:** a coverage report per scan, and an explicit **"undetermined"** bucket in both the dashboard and the CBOM export.

### How it is built
Per target, emit: files/artefacts seen, files/artefacts skipped with reason (stripped binary, unsupported language, timeout, size cap, encrypted archive, dynamically-configured call site), and a coverage percentage with the denominator stated.

### Caveats
- This exists because **a CBOM that omits undetected crypto produces false assurance.** A customer reading "12 crypto assets found" and concluding they are clean is a worse outcome than having no tool.
- Do not report a single glossy "94% coverage" number without saying what the denominator is. Percentage without denominator is theatre.
- Neither IBM CBOMkit nor cryptobom-forge appear to surface this prominently. If you build exactly one thing that no competitor has, build this.

### Judge's question
*"You scanned this image and reported 12 crypto assets. How do you know there aren't 40?"* → The coverage report. Named skipped artefacts, named reasons. **This is the question that decides the round** and it is the one you can answer better than anyone else in the room.

---

## Part 5 — Asset resolution (deliberately constrained)

### What it does
Merges duplicate observations into cryptographic assets — **within a surface only** — and expresses everything else as relationships.

### In / Out
- **In:** Findings.
- **Out:** `CryptoAsset` records + `Relationship` edges.

### How it is built
Canonical asset key = `(algorithm_family, parameters, purpose, scope_anchor)` where **scope_anchor is per-surface**: repo path, image + layer digest, host:port, or binary path.

- **Within a surface:** merge aggressively. All "RSA-2048 signing in repo X" collapses to one asset.
- **Across surfaces:** do **not** merge. Emit explicit relationship edges instead — `TLS endpoint → served by → container image → contains → OpenSSL package`.

### Caveats
- ⚠️ **This is the hidden hard problem and the earlier beginner doc got it wrong.** It showed four findings (Semgrep RSA, binary RSA, cert RSA, TLS RSA) collapsing into one asset. Nothing mechanically links them. There is no shared identifier across source, package, binary and wire; the four sources describe different granularities. Over-merge and you invent relationships that don't exist; under-merge and the inventory fragments. The resolution is to **stop trying to prove identity** and model relationships instead.
- Cross-surface relationship edges are **context-driven and human-asserted**, and the UI must label them as such. Judges reward honest provenance over fake automation.
- Cost of this decision: the blast-radius view looks shallower. Mitigate by wiring **at least one complete chain** end to end for the demo (Part 11).

### Judge's question
*"How do you know the RSA in the source is the same RSA on the wire?"* → We don't, and we don't claim it. We assert a relationship through the deployment context the user supplied, and we show which link is discovered versus declared.

---

## Part 6 — Context ingestion

### What it does
Attaches business meaning: application, owner, environment, criticality, data sensitivity, data lifetime.

### In / Out
- **In:** a per-application form + CSV import, plus defaults derived from data classification.
- **Out:** context records bound to applications and, through them, to assets.

### How it is built
Data lifetime (X in Mosca) is **derived from a data-class lookup table**, not typed freehand:

| Data class | Typical required secrecy lifetime | Basis |
|---|---|---|
| Payment / card data | ~7 years | Retention norms |
| Health records | 20+ years | Retention norms |
| KYC / financial identity | ~8 years | Indian financial retention norms |
| National security | 25+ years | Conservative default |
| Session / ephemeral | < 1 year | — |

⚠️ Cite the actual source document for each row before finals; do not ship numbers from memory.

### Caveats
- ⚠️ **None of this is discoverable by scanning, and that's fine** — IBM and SandboxAQ ingest it from CMDB/ServiceNow or manual tagging too. The credibility move is not to fake automation; it is to **visibly mark which inputs are discovered and which are declared** everywhere they appear.
- Ship a realistic pre-filled sample dataset so the demo is not a live spreadsheet-typing exercise. Non-technical judges lose the thread instantly if the input step looks like manual Excel fiddling.

### Judge's question
*"Where does 'criticality: high' come from?"* → The user, explicitly, and the UI says so. Data lifetime is derived from data classification via a cited lookup table.

---

## Part 7 — Quantum risk engine

### What it does
Turns algorithm + context into a defensible, explainable priority.

### In / Out
- **In:** asset (algorithm, parameters, purpose), context (criticality, sensitivity, lifetime), exposure, migration complexity estimate.
- **Out:** risk band, Mosca verdict, ranked migration queue.

### How it is built

**Step 1 — quantum vulnerability tier.** ⚠️ This must come first and must be explicit:

| Tier | Algorithms | Action |
|---|---|---|
| **Broken by Shor** | RSA, ECDSA, ECDH, DH, DSA | Replace — no parameter increase helps |
| **Weakened by Grover** | AES-128, SHA-1, smaller hashes | Increase size — Grover is quadratic, not exponential |
| **Not quantum-affected** | AES-256, SHA-384/512 | No action |

**Step 2 — Mosca's inequality.** ⚠️ Stated correctly:

> **X + Y > Z** — where **X** = how long the data must stay secret, **Y** = how long migration takes, **Z** = time until a cryptographically-relevant quantum computer (CRQC). **If X + Y > Z, you are already late.**

An earlier draft wrote this as "data lifetime + migration time > planning horizon." That is wrong and loses the entire point. The third term is the arrival of the threat, not a project calendar.

**Step 3 — modifiers.** Exposure (internet-facing vs internal), business criticality, environment (prod vs test).

**Reference values for Z, with honest framing:**
- Global Risk Institute / evolutionQ *Quantum Threat Timeline Report 2024* (Dec 2024, 32 experts): **19–34% chance of a CRQC within 10 years**; 5–14% within 5 years.
- Gidney & Ekerå 2019: RSA-2048 in 8 hours with ~20 million noisy qubits. Gidney (Google Quantum AI), arXiv:2505.15917, May 2025: **under 1 million noisy qubits, under a week** — same hardware assumptions, a ~20× drop with nothing new built.
- Honest headline: **the estimates are moving faster than the hardware.** Today's machines are far below CRQC. Do not assert a Q-Day date.

### Caveats
- ⚠️ **Mosca reduces to arithmetic over user input, and a sharp judge will notice.** X comes from context, Y is estimated, Z is a published survey figure. The only term ECDAT *discovers* is the algorithm. Two cheap defences, both mandatory:
  1. **Derive X from data classification** (Part 6) so lifetime is justified, not invented.
  2. **Run a sensitivity analysis** — show how the migration ranking shifts when X or Z moves ±5 years. This is roughly forty lines of logic and it single-handedly answers "isn't your score arbitrary?"
- Risk scoring is deterministic and rule-based. If a score cannot be explained by pointing at its inputs on screen, the rule is too clever.

### Judge's question
*"Which inputs to your Mosca score did the tool discover, and which did the user type?"* → Algorithm and exposure discovered; lifetime derived from classification; criticality declared. And here is what happens to the ranking when the CRQC estimate moves five years.

---

## Part 8 — PQC / hybrid recommendation

### What it does
Maps a risky asset to an appropriate replacement, driven by **purpose**, not by algorithm name.

### In / Out
- **In:** asset + purpose + protocol/library context + compatibility constraints.
- **Out:** recommended algorithm + parameter set, hybrid guidance, and a cost estimate.

### How it is built

| Purpose | Recommendation |
|---|---|
| Key establishment / encapsulation | **ML-KEM** (FIPS 203) — ML-KEM-768 is the general-purpose default |
| General digital signature | **ML-DSA** (FIPS 204) |
| Long-lived, low-frequency signing (firmware, roots) | **SLH-DSA** (FIPS 205), or LMS/XMSS where stateful is acceptable |
| TLS key exchange, transition period | **Hybrid** — X25519MLKEM768 |

**Standards status (verify against NIST before finals):** FIPS 203 / 204 / 205 finalised **13 Aug 2024**. **FIPS 206 (FN-DSA, Falcon-based) is still draft.** **HQC selected March 2025** as a code-based backup KEM; standard in development.

**Why hybrid for key exchange but not signatures:** recorded traffic can be decrypted later, so confidentiality needs protection *today* — hence hybrid KEM. A signature is verified in real time; there is nothing to harvest, so the only risk is future forgery, and hybrid signatures double an already large size cost.

**Cost model (this is problem-statement clause iv, which the original architecture barely addressed).** A simple lookup table keyed on algorithm + parameter set, no modelling required:

| Item | Value |
|---|---|
| ML-KEM-768 encapsulation key / ciphertext | 1,184 B / 1,088 B |
| ML-DSA-65 public key / signature | 1,952 B / 3,309 B |
| ML-DSA-87 public key / signature | 2,592 B / 4,627 B |
| ECDSA P-256 key / signature (baseline) | ~64 B / ~64–72 B |
| SLH-DSA signature | ~7.8 KB – 49 KB |
| X25519MLKEM768 client key share vs X25519 | **1,216 B vs 32 B** |
| All-ML-DSA-44 TLS handshake overhead | **~15 KB added** |

Per-asset cost dimensions: handshake bytes added, CPU class, certificate chain bloat, real-time-safe flag.

⚠️ **Migration breakage risk belongs here, not in the scanner's risk register.** ECDAT is an observer — it never deploys PQC to anything. But when it *recommends* a hybrid migration, the recommendation should carry the known breakage precedent: a ~1.2 KB ClientHello crosses the single-TCP-segment / MTU boundary, and Cloudflare measured **~0.34% of scanned origins failing the TLS handshake** when sent a post-quantum key share first, because of ossified middleboxes and servers assuming a one-packet ClientHello. Quantifying that turns a caveat into a feature no competitor offers.

### Caveats
- ⚠️ **Never emit a confident recommendation from a `purpose: unknown` finding.** Output "insufficient evidence to recommend — purpose undetermined" and route it to the coverage report.
- Parameter-set selection is policy-dependent: the internet defaults to NIST Level 3 (ML-KEM-768, ML-DSA-65); **NSA CNSA 2.0 mandates Level 5 only** (ML-KEM-1024, ML-DSA-87) and LMS/XMSS for firmware signing. Make the policy a configurable profile, not a hardcoded constant.
- Byte-exact signature sizes vary slightly by library encoding. Cite the FIPS 204 canonical values (3,309 and 4,627).

### Judge's question
*"Why not just map RSA to ML-KEM?"* → Because RSA does three different jobs. Which one this instance is doing determines the answer, and when we can't determine it, we say so instead of guessing.

---

## Part 9 — Persistence

### What it does
Stores the model. PostgreSQL is the system of record.

### How it is built
⚠️ **Collapse the 14-table schema to six for the MVP:**

```
scans            -- job, targets, timing, coverage summary
findings         -- normalised observations, evidence inline, raw in JSONB
crypto_assets    -- resolved per-surface assets
relationships    -- typed edges, with discovered/declared flag
context          -- applications, owners, criticality, data class
risk_assessments -- scores, Mosca verdict, recommendations
```

Raw scanner output lives in JSONB. Expand toward the full normalised model only if time remains.

### Caveats
- The schema is *not* your scope risk — it collapses in an hour. Adapter count is (Part 2). Do not spend a week normalising tables while a scanner sits unwritten.
- **Never store discovered secret material.** You will find private keys and hardcoded secrets. Store the finding and its location; redact the material in the database, the UI and the CBOM export.

---

## Part 10 — Dashboard

### What it does
Turns the model into four answers a security team can act on.

### How it is built
1. **What crypto do we have?** — inventory, ⚠️ **grouped by quantum vulnerability tier**, never as a flat count. Showing "RSA 42 / AES 76" side by side teaches the viewer that AES is a quantum problem. It mostly isn't.
2. **What's risky?** — risk bands with the Mosca verdict and the sensitivity slider.
3. **What depends on it?** — blast radius, with discovered edges visually distinct from declared ones.
4. **What do we migrate first?** — ranked queue with cost estimate and breakage risk per item.
5. ⚠️ **What couldn't we see?** — the coverage report, as a peer of the other four, not buried in a settings page.

### Caveats
- Confidence and provenance must be visible on every asset, not hidden behind a click.
- Redact key material in the UI.

---

## Part 11 — CBOM export

### What it does
Serialises the internal model into the standard interchange format.

### How it is built
- **Target CycloneDX 1.6** (cryptoProperties introduced there; ratified as ECMA-424, June 2024) for maximum tool compatibility. 1.7 (Oct 2025) adds `algorithmFamily` and elliptic-curve modelling — optional upgrade.
- Component `type`: `cryptographic-asset`.
- `assetType` ∈ `algorithm` | `certificate` | `protocol` | `related-crypto-material`.
- `primitive` ∈ `ae`, `block-cipher`, `combiner`, `drbg`, `hash`, `kdf`, `kem`, `key-agree`, `mac`, `pke`, `signature`, `stream-cipher`, `xof`, `other`, `unknown`. ⚠️ Exact spellings — `block-cipher` not "blockcipher", `signature` not "sign".
- `cryptoFunctions` ∈ `decapsulate`, `decrypt`, `digest`, `encapsulate`, `encrypt`, `generate`, `keyderive`, `keygen`, `sign`, `tag`, `verify`, `other`, `unknown`.
- `nistQuantumSecurityLevel`: integer 0–6 (0 = meets none; 1 ≈ AES-128; 3 ≈ AES-192; 5 ≈ AES-256). `classicalSecurityLevel` is a separate bits field.
- Use native `confidenceLevel` (0.0–1.0) and `detectionContext` (filePath, lineNumbers) rather than a custom scheme.

### Caveats
- ⚠️ **Verify every enum against the official cyclonedx.org JSON schema before finals.** These were confirmed via schema mirrors and IBM's CBOM repositories, not read directly off the canonical spec. An enum typo in a live demo is an avoidable, humiliating failure.
- The CBOM must include the **undetermined bucket**. Exporting only what was found is exactly the false-assurance failure Part 4 exists to prevent.

---

## Part 12 — Validation (ground truth)

### What it does
Produces real accuracy numbers for your own tool on your own demo corpus.

### How it is built
1. Pick a **real, recognisable** demo corpus: a known open-source Java application, a public Docker Hub image, a live TLS endpoint you control. ⚠️ Scanning your own toy repo gets discounted instantly — non-trivial findings on code you didn't write is the line between "prototype" and "tool."
2. Manually enumerate every place cryptography appears in that corpus.
3. Diff against what the scanners reported. Record misses, false positives, and empty results with reasons.
4. Feed the result into the coverage report and into your stage answer.
5. **Dogfood:** run ECDAT on ECDAT and its dependency tree. Costs nothing, memorable, pre-empts "does this work on real code?"

### Caveats
- This is the only source of defensible accuracy claims you will have. There is no published FP/FN benchmark for PQC inventory detection to borrow.
- This task requires no programming and is ideal for a team member learning the domain — it forces them to understand how the tools genuinely behave rather than how the docs claim they behave.

---

## Part 13 — Deployment

Docker Compose. React/Next.js → FastAPI → background workers → PostgreSQL. API stateless so workers scale horizontally later without redesign.

**Deferred, explicitly:** Ghidra / deep binary RE, runtime instrumentation, full KMS/HSM/TPM integration beyond metadata reads, CMDB/SIEM integration, continuous monitoring, autonomous agents, microservices/K8s/Kafka, multi-tenant IAM/SSO.

---

## Part 14 — Build order

**Stage 1 — vertical slice (do this first, on a fixed corpus).**
Repo + image + one TLS endpoint → findings with per-source confidence → within-surface dedup → Mosca banding from pre-filled context → purpose-aware recommendation → CycloneDX 1.6 CBOM + dashboard. If only this works on stage, every explicit deliverable of the problem statement is satisfied.

**Stage 2 — raise evidence quality.**
YARA crypto constants for binaries. Certificate + JKS/PKCS#12 deep parsing as the high-confidence anchor. sslyze as primary TLS collector.

**Stage 3 — close the two problem-statement gaps.**
The latency/cost lookup table (clause iv). One cloud KMS metadata reader (clause i: "cloud services, hardware modules").

**Stage 4 — differentiate.**
Coverage reporting. Sensitivity analysis on Mosca. Indian regulatory mapping. The "how we differ from IBM CBOMkit" slide.

**Abort signals:**
- Any single scanner exceeding ~2–3 min on demo data → cap scope, don't optimise.
- Tempted to merge assets across surfaces → stop, keep relationships.
- Full schema not wired by mid-build → ship the six-table version.
- Adapter count slipping → cut adapters, never layers.

---

## Part 15 — The three questions that decide the round

1. **"Which inputs to your Mosca score did the tool discover, and which did the user type?"**
   → Algorithm and exposure discovered. Lifetime derived from data classification via a cited table. Criticality declared, and the UI says so. Here's the sensitivity analysis.

2. **"You reported 12 crypto assets in this image. How do you know there aren't 40?"**
   → The coverage report. Named skipped artefacts, named reasons, an explicit undetermined bucket in the CBOM.

3. **"IBM open-sourced CBOMkit and donated it to the Linux Foundation. Why are you building this?"**
   → We don't rebuild their detector — we reuse detectors. What no open tool provides is multi-surface evidence with honest confidence, coverage reporting, deterministic Mosca prioritisation with business context, a migration cost and breakage model, and Indian regulatory alignment, all running fully offline.

If these three cannot be answered in under thirty seconds each, the architecture does not matter.

---

## Appendix — Facts requiring verification before finals

| Claim | Status |
|---|---|
| CycloneDX enum spellings | Confirmed via schema mirrors — **verify against cyclonedx.org canonical schema** |
| FIPS 203/204/205 finalised 13 Aug 2024 | Verified |
| FIPS 206 (FN-DSA) still draft; HQC selected Mar 2025 | Verified as of research date — **recheck** |
| NIST IR 8547: RSA/ECC deprecated after 2030, disallowed after 2035 | **Initial public draft**, not final — say so when citing |
| ML-DSA signature byte sizes | Vary by encoding; cite FIPS 204 canonical 3,309 / 4,627 |
| Cloudflare ~0.34% origin handshake failure | Verified from Cloudflare engineering data |
| GRI 2024: 19–34% CRQC within 10 years | Verified (Dec 2024 report, 32 experts) |
| India DST task-force milestones (CII 2029, enterprise 2033, mandatory CBOM FY2027–28) | From a Feb 2026 task-force report — **not binding law; verify current status** |
| SIH PS 26164 owning organisation | From secondary aggregators — **verify on sih.gov.in** |
| Data-retention lifetimes in the context lookup table | **Cite the actual regulation for each row before shipping** |

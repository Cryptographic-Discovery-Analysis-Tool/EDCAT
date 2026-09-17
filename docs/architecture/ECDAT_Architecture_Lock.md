# ECDAT — Architecture Lock Record

**Lock date:** 2026-09-16
**Canonical sources, in precedence order:**
1. This lock record.
2. `ECDAT Architecture Stress-Test Directives.md`.
3. `ECDAT_Final_Architecture.md`, as amended by the supersession map in Section 5.
4. `ECDAT_Synthetic_Enterprise_Test_Harness.md` (Sections 14–16 hold the full decision text and rationale).

Where these conflict, the higher-ranked source wins. Nothing in working notes, chat history or model output is canonical unless it is recorded here.

---

## 1. Lock status

| Status | Meaning |
|---|---|
| **LOCKED** | Decided, recorded, and accepted as the current design. Load-bearing factual claims were checked against documentary sources (specs, vendor docs). **Not necessarily empirically validated.** Implementation may depend on it. |
| **LOCKED-PENDING-EVIDENCE** | Design decided, but named empirical evidence is required before promotion to LOCKED. Dependent adapters wait. |
| **OPEN-WITH-DEFAULT** | Not decided. Implementation uses the stated conservative default until a decision is recorded. |

| Item | Status |
|---|---|
| Core thesis & principles (Section 2) | LOCKED |
| Foundational rules R-UNSEEN / R-DERIVE / R-MONOTONE | LOCKED |
| CFG-001 static configuration resolution (incl. A1–A5, W1–W2) | LOCKED |
| TOPO-001 topology / evidence correlation (incl. T1–T7) | LOCKED |
| PRV-001 execution layer / provider | **LOCKED-PENDING-EVIDENCE** (gate: Section 6) |
| Open questions OQ-1…OQ-5 | OPEN-WITH-DEFAULT (Section 7) |

**Honesty note:** "the architecture is locked" means the design is fixed. It does not mean the design is validated. Nothing below has been exercised against a running scanner yet.

---

## 2. Core thesis and principles (LOCKED)

**Thesis (Directive 11).** ECDAT is an evidence-correlation and cryptographic-migration decision-support layer built on heterogeneous discovery sensors. It is not "a scanner that scans more files."

**Principles:**
1. **Reuse scanners, don't rebuild them.**
2. **Evidence-first.**
3. **Finding ≠ asset.**
4. **CBOM is an output, not the internal model.**
5. **Security logic is deterministic.** AI is auxiliary and never authoritative.
6. **Report what could not be seen.** This is done through the visibility matrix (Directive 3), not a scalar coverage %.
7. **Epistemic states are closed.** The set is exactly: KNOWN, UNKNOWN, NOT_OBSERVED, NOT_APPLICABLE, INFERRED, DECLARED, CONFLICTING (Directive 2).
   - No new states are added without a recorded decision.
   - *DERIVED, UNRESOLVED, POSSIBLY and SHADOW are explicitly not states.*
8. **Epistemic state is assigned per field, not per asset.**
9. **Observation surfaces, not programming languages, structure the model.** Language-specific logic lives only inside adapters.
10. **Every important result answers four questions** (Directive 13):
    - What do we believe?
    - What supports it?
    - How confident are we?
    - What remains unknown?

---

## 3. Foundational rules (LOCKED)

- **R-UNSEEN.** A merely possible source that ECDAT could not see does not invalidate an inference. An identified, relevant source that is present but unsupported does invalidate it.
- **R-DERIVE.** A derived field or relationship is never more certain than its weakest required input. Derivation is recorded as `derived_from` + `rule_id`, never as a new state.
- **R-MONOTONE.** Stronger evidence may reduce uncertainty. It must never create certainty the evidence does not support.

---

## 4. Decision register (summary)

Full text, rationale, evidence and rejected options are in the harness document, Sections 14–16.

### CFG-001 — Evidence-bounded static configuration resolution (LOCKED)

**Scope of resolution.** The chain ECDAT follows is:
- a crypto API call,
- then a known Spring property binding,
- then a literal value in same-repo `application.yml`/`.yaml`,
- then literal, exec-form deployment overrides in plain Kubernetes manifests: `env`, `JAVA_TOOL_OPTIONS`, `SPRING_APPLICATION_JSON`, and `args`.

**Rules for results:**
- A successful resolution is **INFERRED, never KNOWN**. "Effective" does not mean "observed"; the runtime is NOT_OBSERVED.
- `resolution_status` ∈ {RESOLVED, OVERRIDDEN, UNRESOLVED} is kept separate from `epistemic_state`. Every UNRESOLVED result carries a reason.
- The output must expose:
  - candidates and their sources,
  - which sources were inspected and which were not,
  - the precedence rule applied,
  - which candidate was selected, if any.
- Two values whose precedence is established are an override, not a conflict. CONFLICTING is reserved for applicable candidates whose precedence or applicability cannot be established.

**Specific handling:**
- An unrendered Helm chart, `valueFrom`, or a shell-form or variable-expanded command yields UNRESOLVED.
- A deployment override attaches to an application only when there is image-provenance evidence (A5).

**Out of scope:**
- secret managers and config servers,
- cross-repo config,
- profile resolution when the active profile is unknown,
- `spring.config.import`/`location`,
- JNDI, reflection and custom property sources,
- full Spring semantics.

### TOPO-001 — Evidence-bounded topology correlation (LOCKED)

**What it does.** ECDAT does not discover enterprise topology. It correlates declared topology, observations, artifact assertions, content identity and explicit inference rules.

**Relationship contract:**

| Field | Values / notes |
|---|---|
| `type` | relationship type |
| `source_entity`, `target_entity` | the two ends |
| `evidence_basis` | {observed, content_identity, artifact_asserted, config_declared, human_declared, inferred} |
| `assurance` | only for artifact_asserted: {unsigned_annotation, unsigned_attestation, signature_verified} |
| `epistemic_state` | from the closed set in Section 2 |
| `rule_id` | required for inferred edges, content-identity edges and conflicts |
| `evidence_refs[]` | confidence lives on each evidence item; the edge has no free-standing confidence |
| `observed_at` | observation time |

**Scope (T7).**
- Probe-target identity is `{requested host, port, SNI sent, probe_vantage}`.
- Resolved IP and `observed_at` are observation context, not identity.
- Declared scope fields carry their own evidence basis and state.
- Each rule declares which scope fields must match. If a required field is UNKNOWN, no edge is emitted and the case is reported as unresolved correlation.

**Identity.**
- `same-object` requires equal SHA-256 hashes of the canonical DER certificate.
- `shares-public-key` requires equal SHA-256 hashes of the canonical DER SPKI.
- Neither implies serves, deployed-on, owned-by, terminates or built-from.
- Identity is never computed from private-key material.

**Conflict rules (enumerated for MVP; no generic engine):**
- **TLS-FRONT-001:** declared `terminates-tls-for`, same SNI, and both certificates observed.
- **IMG-SRC-001:** the declared source repository differs from the image-asserted source. Both are reported as conflicting claims.
- **TLS-POLICY-001:** a declared TLS policy, with its own provenance, differs from observed endpoint behaviour.

**Attribution labels.**
- Evidence inside the declared scope but without an owner is `UNATTRIBUTED`.
- Evidence outside the declared scope is `OUT_OF_DECLARED_SCOPE`.
- Ownership staleness is never inferred.

### PRV-001 — Execution layer / provider (LOCKED-PENDING-EVIDENCE)

**Call-site and provider evidence.**
- Each call site carries `dispatch_mode` ∈ {explicit_provider, default_provider_chain, platform_service, bundled_library, language_native, unknown}.
- Explicitness is evaluated **per field**. A transformation string does not imply its parameters are fixed; for example, the OAEP MGF1 digest is provider-dependent.
- Provider configuration uses the CFG-001 contract. Initial resolution covers only:
  - **JCA:** the image JDK's `java.security`, `-Djava.security.properties` via CFG-001 sources, source-level `insertProviderAt`, and SunPKCS11 config.
  - **OpenSSL 3:** provider activation and `OPENSSL_CONF`.
- A source-level `insertProviderAt` yields a CONFLICTING candidate set, except in the two narrow exceptions recorded in harness §16.1.
- An OpenSSL call site links to provider config only after evidence establishes both **library-instance identity** and **the binding from that instance to its config**.
- The edge is named `governed-by-provider-config`, with state, applicability and `rule_id`. "Executed via" is never asserted.

**Where provider evidence may influence decisions (hard constraint).** Provider evidence enters risk or recommendation logic only for:
1. **Key location**, e.g. keys held in PKCS#11/HSM.
2. **Migration-option availability** for this asset's operation, purpose and parameter set.
   - HSM capability is normally UNKNOWN from static evidence.
3. **Tier-relevant generation defaults.**
   - The runtime JDK version is evidence here: JDK 19 raised default key sizes (JDK-8267319).

Everything else is recorded and not correlated.

**Out of scope:**
- per-language semantic analysers,
- runtime instrumentation,
- mainframe access,
- Windows registry scanning,
- FIPS certification judgements.
- CNG, crypto-policies, Go FIPS mode and ICSF are recorded as evidence only.

**Language adapters** declare a support level ∈ {full, partial, detect-only, unsupported}, which feeds the visibility matrix.

---

## 5. Supersession map for `ECDAT_Final_Architecture.md`

| Part | Status after lock |
|---|---|
| 0 Principles | Kept. Principle 7 ("coverage %") is **superseded** by the visibility matrix (Directive 3). |
| 1 Targets | **Amended.** Targets also include: configuration sets, plain Kubernetes manifests, declared topology inputs (CMDB export with declared scope, GRC attestations), build/provenance artifacts. The network allow-list, consent flag and probe vantage are recorded per probe. |
| 2 Adapters | Kept. **Amended:** every adapter declares a language/surface support level. A configuration adapter is added (CFG-001). |
| 3 Findings & confidence | Kept. The base confidence table applies to **evidence items**. Relationships carry no independent confidence (T1). |
| 4 Coverage | **Superseded** by the visibility matrix: artifact, source, dependency, configuration, deployment, runtime, network, HSM/KMS, and failed/timeout targets. |
| 5 Asset resolution | Kept, **refined** by T6. The only permitted cross-surface identity is `same-object` / `shares-public-key` via canonical hashes. |
| 6 Context | Kept. Context fields carry evidence_basis = human_declared. Lifetime table citations are still required. |
| 7 Risk | **Amended.** Mosca becomes scenario-based with sensitivity (Directive 8). Tier derivation follows R-DERIVE. |
| 8 Recommendations | **Amended.** Recommendations are candidate option sets (Directive 6). A purpose of UNKNOWN yields "insufficient evidence". The "cost model" is renamed **migration impact model** (Directive 7). Provider capability matters only per PRV-001. |
| 9 Persistence | **Open for implementation.** The six-table MVP must accommodate, without schema redesign: scan snapshots and deltas (Directive 9), per-field epistemic state, configuration candidates, the relationship contract, and entity scope. Table layout is an implementation decision, not an architecture decision. |
| 10 Dashboard | Kept. "What couldn't we see?" is served by the visibility matrix. The UI shows evidence_basis / epistemic_state on every transition (Directive 12). |
| 11 CBOM | Kept. The undetermined bucket is required. Enum verification is still outstanding. |
| 12 Validation | Kept and **extended** by the harness: planted truth vs expected observation, the false-certainty metric, blind holdout, and the anti-overfitting mutation test. |
| 13 Deployment | Kept. ECDAT-as-sensitive-platform controls (Directive 10) apply. |
| 14 Build order | Kept, preceded by the evidence gate in Section 6. |

---

## 6. Evidence gate (required before PRV-001 is LOCKED and before the dependent adapters are built)

Each result is recorded in `harness/eval/experiments.md` with the exact tool, JDK, OpenSSL and Node versions/build IDs.

| ID | Experiment | Blocks |
|---|---|---|
| PRV-T1 | SunJCE vs Bouncy Castle with the same OAEP transformation string: do the MGF1 digests differ, and does cross-decryption fail? | PRV-001, PAY-001 answer key |
| PRV-T2 | Unsized `KeyGenerator("AES")` / `KeyPairGenerator("RSA"\|"EC")` on the pinned JDK build | PRV-001, planted tiers |
| PRV-T3 | Node's bundled OpenSSL vs a system `openssl_conf` that activates a provider | PRV-001 OpenSSL binding |
| CFG-R1 | Run payment-gateway states B, C, D (with profile), F, H; read the actual bound value at runtime | CFG-001 answer key |
| E1–E4 | Trivy on a stripped Go binary; YARA hits; sslyze hybrid-group reporting; OpenSSL seclevel on weak certificates | adapter design |
| TOPO-X1–X3 | sslyze SNI recording; BuildKit attestation retrieval by image store; DER hash equality across PEM, DER and PKCS12 | TOPO-001 adapters |

### 6.1 Preliminary observations (NOT gate results)

These do not satisfy the gate: the harness has not yet chosen its pinned JDK build (no payment-gateway image exists), and neither run used Bouncy Castle.

| Obs | Environment | Result | Counts toward |
|---|---|---|---|
| P-1 (user-reported) | OpenJDK 21.0.11 | unsized AES 256, RSA 3072, EC 384 | PRV-T2 (preliminary only) |
| P-2 | OpenJDK 21.0.10+7-Ubuntu-124.04, `crypto.policy=unlimited` | AES 256 (SunJCE), RSA 3072 (SunRsaSign), EC 384 (SunEC) | PRV-T2 (preliminary only) — corroborates P-1 on a different build |
| P-3 | same as P-2 | `RSA/ECB/OAEPWithSHA-256AndMGF1Padding` on SunJCE reports md=SHA-256, **MGF1=SHA-1**; decrypting with explicit MGF1-SHA-1 succeeds, with MGF1-SHA-256 fails (`BadPaddingException`) | PRV-T1, SunJCE half only; Bouncy Castle half still required |

Gate recording must include the provider name returned by `getProvider()` — the default is a provider property, not a JDK property.

**Failure rule:** if an experiment contradicts a locked decision, the decision is reopened through change control (Section 8). The answer key is corrected before any code is changed to "pass".

---

## 7. Open questions with defaults (OPEN-WITH-DEFAULT)

These were never decided. They do not block the lock, because each has a conservative default.

| ID | Question | Default until decided |
|---|---|---|
| OQ-1 | SSH/IPsec: build config parsers, or visibility-only? | Visibility-only: `unsupported_protocol` entries. No assets are emitted from `sshd_config` or `swanctl.conf`. |
| OQ-2 | Build a PKCS#11 metadata reader? | No. HSM visibility = NOT_OBSERVED. `uses-hsm-key` edges are not emitted. |
| OQ-3 | Mosca X for signature assets: data lifetime or trust horizon? | Record both values. Compute with data lifetime. Flag signature assets as "X semantics under review" in the UI. |
| OQ-4 | Library-semantics inference (e.g. Fernet → AES-128-CBC + HMAC-SHA256): allowed? | Allowed as INFERRED only when a curated entry exists with a cited primary source and a `rule_id`. No entry means algorithm UNKNOWN. |
| OQ-5 | Dead-code / test-scope detection | No reachability analysis. `reachable` = UNKNOWN. Path-based test-scope tags (`src/test`, `*_test.go`, etc.) are applied as INFERRED with a `rule_id`. |

Also still open outside architecture:
- CycloneDX 1.6 enum verification against the canonical schema.
- Citations for the data-retention lookup table.
- FIPS 206 / HQC status recheck before finals.

---

## 8. Change control

A locked item may be reopened only by one of:
1. an experiment result that contradicts it;
2. a contradiction found between locked items;
3. an implementation failure that shows the design cannot be built as specified;
4. an explicit decision by the project lead, citing new evidence.

"A more sophisticated design exists" and "an exotic enterprise scenario we imagined" are not grounds for reopening.

Every reopening must be recorded as: issue → evidence → options → decision → rejected options → impact. The superseded text is kept, struck through, not deleted.

---

## 9. Next steps (in order)

1. Run the Section 6 evidence gate. Record the results.
2. Promote PRV-001 to LOCKED, or reopen it per Section 8.
3. Decompose into implementation modules against Tier A of the harness only.
4. Build one vertical slice: payment-gateway → image → keystore → edge-lb TLS → declared context → Mosca scenarios → candidate options → CBOM with visibility matrix.
5. Score that slice with the false-certainty metric before adding anything.

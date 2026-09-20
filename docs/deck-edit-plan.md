# SIH deck edit plan — `ECDAT_Pramana_SIH2026_Idea.pptx`

Date: 2026-09-20. Written against the deck as it exists today and against the
repository at `ace70d7`, both read directly. Every number below was verified,
not recalled.

The governing rule for this edit: **the deck is currently both under-selling and
over-claiming at the same time.** It undersells what was built by a factor of
about four, and it asserts three platform features that do not exist. Fixing the
second is more urgent than fixing the first.

---

## 1. What the repository actually contains (verified 2026-09-20)

| Claim | Verified how | Result |
|---|---|---|
| Test count | `pytest --collect-only -q` | **467 collected** |
| Adapters | `ls src/ecdat/adapters/` | **9** — source, config, certs, tls, packages, images, hsm, kms, binary |
| CI guards | `ls tools/ci/` | **3** — architecture hashes, data citations, no-harness-identifiers |
| Dashboard | ran `uvicorn ecdat.api.app:app`, opened it | **works** — ledger, evidence card, closure queue, move-to, coverage, CycloneDX export |
| Correlation | `correlation/engine.py` + build-plan record | certs ↔ TLS ↔ images, **818 certificates** independently verified in one real image |
| Recommendation engine | `recommend/engine.py`, `data/pqc_options.yaml` | built |
| Persistence | `wc -c src/ecdat/store/__init__.py` | **0 bytes — nothing is stored** |
| PostgreSQL | grep `postgres|psycopg|sqlalchemy` in `src/` + `pyproject.toml` | **no hits — not used at all** |
| RBAC / audit log | grep `rbac|audit_log|audit log` in `src/` + `tests/` | **no hits — not started** |
| "no egress (test-enforced)" | `harness/compose/docker-compose.yml` | `internal: true` is **configured**; **no test asserts it** |

---

## 2. Verdict on each proposed addition

### Adopt — run store and run-to-run diff

The review proposed "verification after migration" and "drift" as two separate
features. They are one, and the hard half is already built: `MigrationEvidence`,
the `_Timeline` class with `first_stop` / `reopened` / `currently_stopped`, the
UNSAVABLE band, and a TLS adapter that already turns a real probe into migration
evidence and refuses to when the negotiation was not observed.

What is missing is only that nothing remembers the previous run. Build the store;
`MIGRATED` and `REGRESSED` fall out of logic that already exists and is already
tested. See `docs/build-plan.md` **P13**.

### Adopt, narrowed — agility evidence

Three fields, not six. `algorithm_selection` (hardcoded / configuration-driven /
unknown) is already observable — it is the literal-versus-non-literal split the
source rules already make. `hybrid_capable` is already observed by the TLS probe.
`provider_pluggable` caps at INFERRED.

**Refuse `migration_complexity`.** It is a score, and slide 2's headline
innovation claim is *"no weights, no score, no model — lexicographic order only."*
Adding it would falsify the deck's own differentiator. **Refuse `hardcoded` as a
bare boolean** — it collapses "hardcoded" and "we could not tell" into one value.
Defer `certificate_rotation`; it needs two observations over time, which is the run
store, not a field. See **P14**.

### Adopt, corrected — evidence graph

The data exists (`CorrelationReport`: assets, `same-object` edges,
`shares_public_key_unclaimed`). Only the drawing is missing.

**But the review's seven-layer chain must not be drawn.** Crypto API → config →
algorithm → library → certificate → service → protected data: only two of those
edges are real. Library → usage is *deliberately* refused by the package and
binary readers, and that refusal is tested. Service → protected data is DECLARED
by a person and there is still nowhere to declare it. Drawing the clean chain
would be the exact false-certainty failure this tool exists to prevent, on the one
screen a judge is most likely to photograph. Draw the real edges, label each with
its epistemic basis, and draw the missing ones as named gaps. See **P15**.

### Agree — leave entropy research out

Black holes, vacuum fluctuations, AI-predicted PRNGs: correctly excluded. Slide 3
already claims *"no AI in the security path — a deliberate security property."*
Nothing to do.

### Missed by the review — three unbacked platform claims

Slide 3's Platform row asserts PostgreSQL with JSONB snapshots, RBAC with an audit
log, and test-enforced no-egress. Verified above: the first two do not exist at
all and the third is configured rather than tested. **This is the most serious
problem in the deck** and the review did not catch it. See **P16**.

### Missed by the review — a trap in the numbers update

Slide 5 currently separates *measured* from *"declared as targets — not yet
measured,"* and the second list includes **exposure correctness (18 / 18 frozen
cases)**. The 18 worked examples do pass as unit tests — but the **scoring harness
has never printed a number for them** (ledger phase 8, "not started").

When the test count is updated to 467 "including all 18 worked examples," it will
be very easy to let exposure correctness slide into the measured column. **It must
not.** A passing unit test is not a scored measurement, and slide 5 says so in its
own words: *"A target becomes a measurement only when the scoring harness prints
it — never before."* Keep that line, keep that row where it is.

---

## 3. Per-slide edit plan

Density budget: **every addition is paid for by a deletion on the same slide.**
The deck is already dense; the fix is not more boxes.

### Slide 1 — Title

**Untouched.**

### Slide 2 — Idea / bands / PS mapping

| | |
|---|---|
| **Untouched** | Harvest-now-decrypt-later framing · the four bands and the SAFE footnote · the (i)–(v) problem-statement mapping · the five innovation lines |
| **Change** | (v) "cloud KMS export" does not appear here, but if the sensor list is repeated, see slide 3's wording fix |
| **Add** | One thin spine above the bands: **DISCOVER → PROVE → PRIORITISE → RECOMMEND → VERIFY** — *conditional on P13 landing.* If the run store is not built by deck day, the spine ends at RECOMMEND. Do not print VERIFY for something that cannot be demonstrated |
| **Do not add** | The reviewer's separate "Crypto-Agility" box. Slide 2 is at capacity and agility is an evidence property, not a pillar. One line on slide 3 instead |

### Slide 3 — Technical approach (the real work happens here, and it must get *lighter*)

| | |
|---|---|
| **Untouched** | **Both clock diagrams.** The confidentiality window formula and the three-way authentication split are the best technical content in the deck and a judge can follow them unaided. Do not touch them. Also keep the closing "no AI in the security path" line |
| **Change — pipeline** | `OBSERVE → STATUS → BIND → CLOCK → LEDGER → CLOSE → ACT` becomes `OBSERVE → STATUS → CORRELATE → BIND → CLOCK → LEDGER → CLOSE → ACT → VERIFY`. **Insert two steps, rename none.** The reviewer's STATUS→EVIDENCE and ACT→MIGRATE renames are churn: STATUS is the more precise word (it is the epistemic *state* per field), and MIGRATE is something the customer does, not something Pramana does |
| **Change — wording** | "cloud KMS export" → **"cloud KMS metadata (the API cannot return key material)"**. "Export" is the wrong word and it is a trigger word for a crypto-literate judge |
| **Delete** | **"PostgreSQL (JSONB evidence + snapshots)"** — not used anywhere. **"RBAC + audit log"** — not started. **"(test-enforced)"** after no-egress → "enforced by the network definition" |
| **Add** | One line under the deterministic-core row: *"agility evidence — hardcoded vs configuration-driven vs hybrid-capable, observed, never scored."* Paid for by the three deletions above, so the slide comes out shorter |

### Slide 4 — Feasibility

| | |
|---|---|
| **Untouched** | The four-row ledger table with the exposure bars. It is the clearest thing in the deck, the ordering explanation ("why the order looks wrong — and isn't") is the deck's single best paragraph, and the "Dates are test constants" caveat stays |
| **Untouched** | The five "challenges → how we handle them" rows. All five are still exactly what the code does |
| **Delete** | The entire stale "ALREADY MEASURED (17–18 Sep 2026)" block: *"120 unit tests green · 6 of 11 tool experiments run, 5 logged"* and *"Next scored targets: OpenSSL and public source repositories"* |
| **Add** | Three proof tiles in its place: **9 ADAPTERS · 467 TESTS · 3 CI GUARDS**, with one line under them: *"source · config · certificates · TLS · packages · container images · HSM (PKCS#11) · cloud KMS · binaries — five proven from a live tool run"* |
| **Add** | Keep the still-true detection numbers: *"our own rules found 4/4 planted source assets; the public registry found 1/4 · false certainty 0/8 · under-claiming 0/2 · control 8/8"* |
| **Add** | **Screenshot 1** (see §4). Room comes from compressing "Analysis of feasibility" from four paragraphs to four short lines |

### Slide 5 — Impact

| | |
|---|---|
| **Untouched** | The audience row · the four impact lines · the DST PQC Task Force citation · **the entire "declared as targets — not yet measured" block and its closing sentence** · the three "benefits of the solution" lines · the closing FROM/TO line |
| **Change** | In the measured block: **120 → 467** unit tests. Nothing else in that block moves — see the trap in §2 |
| **Add** | A fourth measured tile: **818** — *certificates inside one real container image, each independently re-verified against the image itself rather than taken on the scanner's word* |
| **Add** | **Screenshot 2** (see §4) |
| **Optional add** | A small "what changed since last scan" strip — `NEW · CHANGED · MIGRATED · REGRESSED · UNKNOWN` — **with no numbers on it** until P13 produces real ones. An illustrative strip with invented counts on this deck would be worse than no strip |

### Slide 6 — References

| | |
|---|---|
| **Untouched** | All six references · the status-discipline block · the closing positioning line. This slide is well made and current |
| **Change** | The tooling row lists Semgrep · Trivy · sslyze. Add **cbomkit-theia · pkcs11-tool (SoftHSM2) · YARA + readelf · aws CLI**, since all four are now wrapped sensors with recorded fixtures |
| **Do not add** | The reviewer's six-word spine. It duplicates slide 2 |

---

## 4. Screenshots — exactly two

Both were captured live from the running dashboard on 2026-09-20 and verified to
contain what is described. Recapture at 1440×1000.

### Screenshot 1 — the evidence card *(slide 4)*

Open the dashboard, click any BLEEDING row, screenshot the right-hand drawer.

It contains, top to bottom in one frame: the verdict · the stated assumption
(*"assumes capture since 2021-01-01 (SINCE_CONFIRMED)"*) · ledger · function ·
algorithm · exposed window · deadline · secrecy lifetime · when we could have vs
when we proved · the data class with its **cited row** (`data_lifetime.yaml#TEST.X_25Y`)
· the evidence used · **MOVE TO** (ML-KEM · X25519MLKEM768) · the policy in force ·
and **SHOW YOUR WORKING** — rule id, calculation version, input fingerprint, and
*"Re-run now → same answer (BLEEDING), same inputs."*

That one panel is the entire product thesis. It is the strongest single image in
the project. Caption it: **"Every verdict opens into the evidence behind it — and
re-computes from its own stored inputs."**

### Screenshot 2 — the ledger list *(slide 5)*

The main ledger table with the band counts along the top and the left-hand
controls (**when is Z?** · **assume recording since** · **evaluate as of**) visible.

**Keep the fixture banner in the frame.** It reads: *"Fixture data. No sensor has
run. These rows are constructed evidence used to exercise every band while the
live connection prober is still being built — nothing here was observed on a real
network."*

That banner is an asset, not an embarrassment. It is the deck's thesis rendered
inside the product, and cropping it out to make the screenshot look like a live
enterprise scan would undo the credibility the rest of the deck spends five slides
building. Caption it: **"Prototype console on fixture data — the banner is the
product's own honesty rule, not a disclaimer."**

### Runner-up, if a third slot ever opens

The **Coverage** tab — *"What each sensor looked at"*, the surfaces reaching the
ledger, and **"Reported but not banded"** (symmetric encryption is a key-size
question, not a deadline). This is the "we tell you what we could not see"
differentiator made visible. At two screenshots it does not make the cut.

### Do not screenshot

VS Code · the terminal · the folder tree · pytest output · GitHub commits · code.
`467 passed` is a number for a tile, not a picture.

---

## 5. Order of work

1. **Slide 3 deletions** (P16). Text only. Removes three false claims. Do this first
   regardless of everything else.
2. **Slide 4 and 5 number refresh.** Text only. Recovers the four-times undersell.
   Watch the exposure-correctness trap in §2.
3. **The two screenshots.** Nothing to build; the dashboard already runs.
4. **P13 — run store and diff.** The only item that earns the word VERIFY on
   slides 2 and 3, and it retires the PostgreSQL claim by making a true statement
   possible rather than by deleting a false one.
5. **P15 — graph view**, then **P14 — agility fields**, if time remains.

Steps 1–3 need no new code and move the deck further than steps 4–5 do.

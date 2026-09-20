# SIH idea deck — final audit and what was built

Date: 2026-09-20 (third and final pass). The deck is
`ECDAT_Pramana_SIH2026_Idea_v3.pptx`, built by editing the previous deck in
place — same file, same theme, same chrome — with `docs/deck/build_deck.py`.

**The framing, settled.** This is the *idea* submission. It states what Pramāṇa
is and how it works. It does **not** report build status: no test counts, no
"already measured" block, no built-versus-planned split. Two earlier passes of
this document argued about how to present implementation status on the slides;
that question is closed — none of it belongs here. The engineering status lives
in `docs/build-plan.md`, where it is checked against the code.

What survives from the earlier audit is the part that still matters: the
**capability audit**, which found five deck promises with nothing behind them
yet. Four became phases (P13–P19 in `docs/build-plan.md`); one was a genuine
deletion.

---

## 1. Template compliance (SIH 2026 official format)

| Requirement | State |
|---|---|
| Maximum six slides, including the title | **6** |
| Only the provided template, idea-detail pointers unchanged | Every pointer now appears verbatim as a section heading — see §2 |
| Title slide fields (PS ID, title, theme, category, team ID, team name) | present; **Team ID is still blank — fill it before upload** |
| "Avoid paragraphs; use points / diagrams / infographics / pictures" | no paragraph blocks remain; two diagrams, one table, three product images |
| Submit as PDF | `ECDAT_Pramana_SIH2026_Idea_v3.pdf` exported alongside the .pptx |

## 2. Official pointers, verbatim, as section headings

| Slide | Pointer, as the template words it |
|---|---|
| 2 | **Proposed Solution (Describe your Idea / Solution / Prototype)** · **Detailed explanation of the proposed solution** · **How it addresses the problem** · **Innovation and uniqueness of the solution** |
| 3 | **Methodology and process for implementation** · **Technologies to be used** |
| 4 | **Analysis of the feasibility of the idea** · **Potential challenges and risks** · **Strategies for overcoming these challenges** |
| 5 | **Potential impact on the target audience** · **Benefits of the solution (social, economic, …)** |
| 6 | **Details / links of the reference and research work** |

The previous deck renamed several of these ("Challenges → how we handle them",
"Analysis of feasibility"). The template says not to change them, so they are
back to the official wording.

## 3. What changed, slide by slide

**Untouched throughout:** the deck's visual identity — Times New Roman display
titles, Calibri body, the navy/blue/red/green/amber palette, the team oval, the
SIH logo, the blue footer bar and page numbers. All of it is the previous deck's
own chrome, kept shape-for-shape.

| Slide | Kept | Removed | Added |
|---|---|---|---|
| **1** | everything | — | — |
| **2** | harvest-now framing · the four bands · the SAFE footnote | long trailing clauses on every list row | official pointer headings; each list row cut to one readable line |
| **3** | **both clock diagrams** (the strongest technical content in the deck) | "Syft" · a redundant "no AI" line the heading already carries | `CORRELATE` and `VERIFY` in the pipeline (now nine steps); "cloud KMS export" → **"cloud KMS metadata"**; the **replay strip** image |
| **4** | the worked-example ledger table with its exposure bars · "why the order looks wrong — and isn't" · all five challenge rows | the stale "already measured" block entirely | feasibility split into four compact tiles; challenges and strategies paired explicitly, one panel each |
| **5** | audience row · four impact lines · DST citation · three benefit lines · the FROM/TO closer | the measured and not-yet-measured blocks | the **closure-queue** image, at half the slide |
| **6** | all six references · status discipline · positioning line | — | the official pointer heading; cbomkit-theia, pkcs11-tool, YARA+readelf added to the tooling row |

## 4. The three images

Captured from the running console with Playwright at 2× device scale, cropped
with Pillow. Reproduce with `docs/deck/capture_shots.py` then
`docs/deck/crop_shots.py`; sources are in `docs/deck/screenshots/`.

| Image | Slide | Why it earns its space |
|---|---|---|
| **`strip_replay.png`** — rule id, calculation version, input fingerprint, and *"Re-run now → same answer (BLEEDING), same inputs"* | 3, beside the technology table | Four lines of monospace. It is the only visual proof of the *Replayable* claim, at almost no cost in space — the best proof-to-density ratio in the deck. |
| **`card_closure.png`** — three closure tasks, each with why it settles the rows it names, what the answer could turn out to be, the days at stake, and a spec citation | 5, half the slide | The **most unique** thing in the product and redundant with nothing else in the deck. An earlier draft put the ledger list here; that was wrong — slide 4 already renders the ledger as slide content. |
| **`card_evidence.png`** — verdict → assumption → window → deadline → data class with its cited row → evidence used | held in reserve | Strong, but slide 4 is full and the replay strip already carries the traceability point at a fraction of the size. |

**Deliberately not screenshotted:** VS Code, terminals, the folder tree, pytest
output, GitHub. A test count is a number, not a picture — and on this deck, not
even a number.

## 5. The capability audit that still stands

Five promises the deck makes that the code does not yet keep. They stay in the
deck — it is the specification — and they are now planned work.

| Promise | Verdict |
|---|---|
| PostgreSQL / JSONB snapshots; "snapshots show new exposure, closed windows and certificate change" | **P13** — run store and run-to-run diff. The verification logic already exists (`MigrationEvidence`, `_Timeline.first_stop` / `.reopened`, the UNSAVABLE band); only persistence is missing. |
| RBAC + audit log | **P17** — it is the stated answer to "the inventory is itself a sensitive asset", so it cannot simply be dropped. |
| "no egress (test-enforced)" | **P18** — already configured via `internal: true`; one test makes the word true. |
| "the dates at which the ranking flips are printed" | **P19** — not implemented, and the highest-value item on the list: it turns "we do not know when Z is" into an output. Both halves already exist. |
| "Trivy / **Syft**" | **cut.** `packages-trivy` already produces this fact; Syft would be a second tool for the same answer. |

And one wording fix, made: slide 2 (iv) promised *"size, latency and
compatibility impact"*. The engine carries byte costs and a cited
handshake-failure rate — size and compatibility, no latency figure, and no
citable source for one. The slide now says what is actually shown.

## 6. Before upload

1. Fill **Team ID** on slide 1.
2. Re-export the PDF if anything changes — the portal takes PDF only.
3. Delete nothing else: the deck is at the six-slide limit exactly.

---

## 7. Final pass (2026-09-20) — fact-checked additions

Every claim below was verified against a primary source or against this
repository's own code before it went on a slide. Items that did not survive
verification are recorded here too.

### Verified against the official problem statement

Two independent copies of the SIH26164 text agree verbatim. The PS says:

- *"Classify all the artefacts by type, **lifetime and business criticality**."*
- *"Recommend suitable alternatives (PQC/ Hybrid algorithms) for applications
  based on **risk profile, latency, cost**, etc."*

**This reversed an earlier decision in this document.** §2 of the previous pass
told you to drop "latency" from slide 2 because `data/pqc_options.yaml` carries
no latency figure. That was correct for an implementation claim and **wrong for
an idea deck** — latency and cost are explicit PS requirements, so the deck must
promise them. Slide 2 (iv) now reads *"size, latency, cost, compatibility"*.
Cost was missing entirely before and is now present.

### Verified against this repository's code

`risk/record.py::rank_key` — the ranking is already
`(band_rank, criticality, -longest_window)`, documented as §5.10 *"lexicographic
on categorical fields — band, then criticality category, then longest window."*

So the outside review's claim that business criticality "is not actually part of
the decision" is **wrong about the design** — it is spec'd and implemented. The
real gap was that the deck never showed it. Slide 2 now prints the actual chain,
**band → business criticality → longest window**, not an invented five-level
order.

`risk/run.py::GroverFlag` — symmetric encryption is *"reported, not banded … a
key-size question under Grover, not a harvest-now deadline."* The SAFE footnote
on slide 2 now says exactly that. The review proposed renaming the band to
SHOR-RESILIENT; **rejected** — SAFE also covers data that stops mattering before
Z, which has nothing to do with Shor, and renaming would break deck↔code
consistency against `ExposureBand.SAFE`.

### Verified against NIST

- **NIST CSWP 39upd1**, *Considerations for Achieving Crypto Agility: Strategies
  and Practices* — **final**, 19 Dec 2025, updated 29 Jun 2026. Definition
  confirmed verbatim: *"the capabilities needed to replace and adapt
  cryptographic algorithms in protocols, applications, software, hardware,
  firmware, and infrastructures while preserving security and ongoing
  operations."* Now cited on slide 6.
- **NIST SP 1800-38** — **preliminary draft**, not final. Vol B *Quantum
  Readiness: Cryptographic Discovery*; Vol C *Quantum Readiness: Testing Draft
  Standards for Interoperability and Performance*. The deck previously cited it
  without its draft status; slide 6 and the status-discipline block now say so.

### The "no AI" reframe

Slide 3's *"no AI in the security path"* became:

> **AI may suggest. Only evidence may decide.** No model sits in the detection,
> correlation, banding or recommendation path — those are rule-driven and
> replayable. A model's claim may still enter, but only as any third party's
> does: DECLARED, to be confirmed by observation before it moves a deadline.

Checked against `CLAUDE.md`, whose hard rule is *"No LLM calls in any detection,
correlation, risk, or recommendation path."* The first draft of this line said
only "AI may suggest", which implied a model in the detection path and would
have contradicted the contract. The shipped wording names the four forbidden
paths explicitly, so deck and contract agree and **no DEV entry is needed**.

The reframe is not a softening. Determinism is what makes replay possible, and
replay is the deck's strongest claim; an LLM in the banding path would destroy
it by construction. The new line says the same thing while answering the
question a 2026 judge actually has.

### Also added

- Slide 2: the spine **DISCOVER → PROVE → PRIORITISE → RECOMMEND → VERIFY**.
- Slide 3: `business-context binding (owner · criticality · data class)` in the
  deterministic core.
- Slide 5: a four-stage programme strip — **DISCOVERED → EXPOSED → PLANNED
  (owners · blockers) → VERIFIED** — deliberately **without counts**, since no
  measured numbers exist to put on it.

### Considered and rejected

| Proposal | Why not |
|---|---|
| A five-level rank (exposure → deadline → criticality → sensitivity → blast radius) | Not what §5.10 or `rank_key` does. The deck prints the real three-level chain. |
| Rename SAFE → SHOR-RESILIENT | Misdescribes the band and breaks deck↔code consistency. A precise Grover footnote does the same job. |
| A migration-programme funnel with counts | No measured numbers exist. Labels only. |
| A what-if / migration-sandbox panel on slide 4 | Slide 4 is the strongest slide and is full. Adding it would re-densify what this pass spent its budget de-densifying. |
| A scenario-sensitivity matrix on a slide | Good idea, but it is P19 and unbuilt. Slide 4 already promises the flip dates in words. |

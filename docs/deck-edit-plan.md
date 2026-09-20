# SIH idea deck — final audit and what was built

Date: 2026-09-20 (third and final pass). The deck is
`ECDAT_Pramana_SIH2026_Idea_v2.pptx`, built by editing the previous deck in
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
| Submit as PDF | `ECDAT_Pramana_SIH2026_Idea_v2.pdf` exported alongside the .pptx |

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

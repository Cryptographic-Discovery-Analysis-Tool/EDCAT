# SIH deck edit plan — `ECDAT_Pramana_SIH2026_Idea.pptx`

Date: 2026-09-20, revised the same day after a second pass. Written against the
deck as it exists today and against the repository at `e14ed5d`, both read
directly. Every number below was verified, not recalled.

**The governing rule, corrected.** The first draft of this plan told you to delete
three platform claims the code does not back. That was wrong in an important way.
**The deck is the specification** — it states what Pramana is meant to be, and the
build follows it. Deleting an unbuilt promise does not make the deck honest; it
silently drops a real requirement and makes the *product* smaller.

The honest move is the one this project already applies to its own findings: keep
the claim, **say which state it is in**, and put the unbuilt half on the plan.
Slide 5 already does this perfectly with its "declared as targets — not yet
measured" block. The platform row should work the same way. So the deck needs a
**built / planned** distinction, not a delete key.

Of everything checked, exactly **one** item is a genuine deletion.

---

## 1. What the repository actually contains (verified 2026-09-20)

| Claim | Verified how | Result |
|---|---|---|
| Test count | `pytest --collect-only -q` | **467 collected** |
| Adapters | `ls src/ecdat/adapters/` | **9** — source, config, certs, tls, packages, images, hsm, kms, binary |
| CI guards | `ls tools/ci/` | **3** — architecture hashes, data citations, no-harness-identifiers |
| Dashboard | ran it, clicked every tab | **works** — ledger, evidence card, closure queue, move-to, coverage, CycloneDX export |
| Correlation | `correlation/engine.py` | certs ↔ TLS ↔ images, **818 certificates** independently verified in one real image |
| Recommendation engine | `recommend/engine.py`, `data/pqc_options.yaml` | built — byte costs and a cited breakage rate |
| Closure engine | `closure/engine.py`, live in the UI | built, and stronger than the deck lets on (see §4) |
| Persistence | `wc -c src/ecdat/store/__init__.py` | **0 bytes — nothing is stored** |
| PostgreSQL | grep in `src/` + `pyproject.toml` | **no hits** |
| RBAC / audit log | grep in `src/` + `tests/` | **no hits** |
| Syft | grep in `src/`, `tests/`, `tools/` | **no hits** |
| Latency figures | grep `latency` in `data/` | **no hits** — bytes and breakage only |
| "ranking flip dates printed" | grep `flip` in `src/` | **no hits** — not implemented |
| "no egress (test-enforced)" | harness compose file | `internal: true` **configured**; **no test asserts it** |

---

## 2. Re-audit: what must NOT be cut

Five deck promises are ahead of the code. Four of them are genuine requirements
that should be built, not removed. Full detail in `docs/build-plan.md` **P16–P19**.

| Promise | Verdict | Why |
|---|---|---|
| **PostgreSQL / JSONB snapshots** | **keep, mark planned → P13** | Slide 5's *"snapshots show new exposure, closed windows and certificate change"* is the same requirement stated twice. It is the drift feature. Cutting it from slide 3 would leave slide 5 promising something with no mechanism behind it. |
| **RBAC + audit log** | **keep, mark planned → P17** | It appears twice, and the second place is load-bearing: it is the stated answer to slide 4's challenge *"the inventory is itself a sensitive asset."* Deleting it weakens an answer the deck has to give. |
| **no egress (test-enforced)** | **keep → P18** | The requirement is right and already configured (`internal: true`). Only the word *test-enforced* is ahead of the code, and that gap closes with one test. Until it does, say "enforced by the network definition." |
| **"the dates at which the ranking flips are printed"** | **keep → P19, and build it first** | This is a real innovation claim and it is not implemented. It is also the cheapest new capability on the whole list — see §3. |
| **Syft** ("Trivy / Syft") | **the one real deletion** | `packages-trivy` is built and live-proven and already produces this fact. Syft would be a second tool for the same answer. Cut the word. |

Plus one wording fix, not a phase: slide 2 (iv) promises *"size, latency and
compatibility impact."* The engine carries byte counts and a cited handshake-failure
rate — **size and compatibility, but no latency figure, and no citable source for
one in `data/`**. Either vendor a measurement or say what is actually shown:
*"size, handshake-failure precedent and compatibility impact."* Inventing a latency
number to match the slide is the one thing that must not happen.

---

## 3. The highest-ROI thing available, and it is not a screenshot

**P19 — print the date the ranking flips.**

Slide 4 already claims it, so it is not a new idea; it is an unkept promise. Both
halves exist: `data/scenarios.yaml` carries all three Z dates and
`Scenario.load_all()` reads them; `closure/engine.py` already re-evaluates a record
under alternative inputs to work out what a missing fact *could* turn out to be.
Pointing that same counterfactual machinery at the scenario axis gives you
*"BLEEDING under Z=2031 and Z=2036, SAVABLE under Z=2041."*

Why it is worth doing before anything else: it converts the deck's weakest-sounding
admission — **we do not know when Z is** — into its strongest move. Every competing
tool either picks a date and hides it, or refuses to rank at all. A tool that prints
*the date at which the answer changes, and which row changes first* has turned a
contested assumption into an output. Nothing else on the list buys that much for as
little code, and it needs **zero new slide space** — it strengthens a line slide 4
already has.

---

## 4. Verdict on the reviewer's four proposals

**Run store + drift — adopt, and note the deck already promised it.** The reviewer
proposed "verify after migration" and "drift" as two new features. They are one, the
hard half is already built and tested (`MigrationEvidence`, `_Timeline.first_stop` /
`.reopened`, the UNSAVABLE band, and a TLS adapter that already turns a real probe
into migration evidence and refuses to when the negotiation was not observed), and
slide 5 already promises the result. Only persistence is missing. → **P13**

**Crypto-agility — adopt three fields, refuse two.** `algorithm_selection` and
`hybrid_capable` are already observed and merely unnamed. **Refuse
`migration_complexity`** — it is a score, and slide 2's headline differentiator is
*"no weights, no score, no model."* **Refuse `hardcoded` as a bare boolean** — it
collapses "hardcoded" and "we could not tell." Defer `certificate_rotation`; it
needs two observations over time, which is the run store. → **P14**

**Evidence graph — adopt, but not the graph they drew.** Of the proposed seven-layer
chain, only two edges are real. Library → usage is *deliberately* refused by the
package and binary readers and that refusal is tested; service → protected data is
human-declared with nowhere yet to declare it. Draw the real edges with their
epistemic basis, and the missing ones as named gaps. → **P15**

**Entropy research — agreed, leave it out.** Slide 3 already claims *"no AI in the
security path."*

**A trap in the numbers refresh.** Raising 120 → 467 makes it easy to let *"exposure
correctness (18 / 18 frozen cases)"* slide out of slide 5's not-yet-measured column.
It must not. The 18 examples pass as unit tests, but the **scoring harness has never
printed a number for them** (ledger phase 8, not started), and slide 5's own rule
says *"a target becomes a measurement only when the scoring harness prints it."*

---

## 5. Per-slide edit plan

Density budget: **every addition is paid for by a deletion on the same slide.**

### Slide 1 — Title
**Untouched.**

### Slide 2 — Idea / bands / PS mapping

| | |
|---|---|
| **Untouched** | Harvest-now-decrypt-later framing · the four bands and the SAFE footnote · the (i)–(v) mapping · the five innovation lines |
| **Change** | (iv) "size, latency and compatibility impact" → **"size, handshake-failure precedent and compatibility impact"** (see §2) |
| **Add** | The **replay strip** — a thin three-line crop, not a screenshot (see §6). It sits beside the "Replayable" innovation line, which currently has no visual anywhere in the deck |
| **Add, conditional** | The spine **DISCOVER → PROVE → PRIORITISE → RECOMMEND → VERIFY**, *only if P13 lands*. Otherwise it ends at RECOMMEND. Do not print VERIFY for something that cannot be demonstrated |
| **Do not add** | A separate "crypto-agility" box. Slide 2 is at capacity; agility is an evidence property, not a pillar. One line on slide 3 instead |

### Slide 3 — Technical approach

| | |
|---|---|
| **Untouched** | **Both clock diagrams** — the best technical content in the deck, and a judge can follow them unaided. Also the closing "no AI in the security path" line |
| **Change — pipeline** | `OBSERVE → STATUS → BIND → CLOCK → LEDGER → CLOSE → ACT` becomes `OBSERVE → STATUS → CORRELATE → BIND → CLOCK → LEDGER → CLOSE → ACT → VERIFY`. **Insert two, rename none** — STATUS is the more precise word (it is the epistemic *state* per field), and MIGRATE is something the customer does, not something Pramana does |
| **Change — wording** | "cloud KMS export" → **"cloud KMS metadata (the API cannot return key material)"**. *Export* is the wrong word and a trigger word for a crypto-literate judge |
| **Delete** | **"Syft"** only. Trivy already produces this fact |
| **Change, not delete** | Split the Platform row into **built** and **planned**. Built: FastAPI · React/Vite · CycloneDX 1.6 · Docker Compose, no egress (enforced by the network definition) · key material never stored. Planned: **evidence store with run snapshots · RBAC + audit log · test-enforced no-egress.** Three words — "planned:" — keep three real requirements in the deck instead of deleting them |
| **Add** | One line under the deterministic-core row: *"agility evidence — hardcoded vs configuration-driven vs hybrid-capable, observed, never scored"* |

### Slide 4 — Feasibility

| | |
|---|---|
| **Untouched** | The four-row ledger table with the exposure bars · the "why the order looks wrong — and isn't" paragraph (the deck's single best) · "Dates are test constants" · all five challenge rows |
| **Delete** | The stale measured block: *"120 unit tests green · 6 of 11 tool experiments run, 5 logged"* and *"Next scored targets: OpenSSL and public source repositories"* |
| **Add** | Three tiles in its place: **9 ADAPTERS · 467 TESTS · 3 CI GUARDS**, with one line under: *"source · config · certificates · TLS · packages · container images · HSM (PKCS#11) · cloud KMS · binaries — five proven from a live tool run"* |
| **Keep** | The still-true detection numbers: *4/4 planted source assets vs the registry's 1/4 · false certainty 0/8 · under-claiming 0/2 · control 8/8* |
| **Add** | **Screenshot 1** — the evidence card (§6). Room comes from compressing "Analysis of feasibility" from four paragraphs to four lines |

### Slide 5 — Impact

| | |
|---|---|
| **Untouched** | Audience row · four impact lines · DST PQC Task Force citation · **the whole "declared as targets — not yet measured" block and its closing sentence** · the three benefits lines · the FROM/TO closer |
| **Change** | Measured block: **120 → 467** tests. Nothing else moves — see the trap in §4 |
| **Add** | A fourth measured tile: **818** — *certificates inside one real container image, each independently re-verified against the image rather than taken on the scanner's word* |
| **Add** | **Screenshot 2** — the closure queue (§6) |
| **Do not add** | A "what changed since last scan" strip with invented counts. Once P13 produces real ones, it earns its place |

### Slide 6 — References

| | |
|---|---|
| **Untouched** | All six references · the status-discipline block · the closing positioning line |
| **Change** | Tooling row currently lists Semgrep · Trivy · sslyze. Add **cbomkit-theia · pkcs11-tool (SoftHSM2) · YARA + readelf · aws CLI** — all four are wrapped sensors with recorded fixtures |
| **Do not add** | The reviewer's six-word spine. It duplicates slide 2 |

---

## 6. Images — two screenshots and one thin strip

All captured live from the running dashboard on 2026-09-20 and checked to contain
what is described. Recapture at 1440×1000.

### Screenshot 1 — the evidence card *(slide 4)*

Click any BLEEDING row; screenshot the right-hand drawer. In one frame: verdict ·
the stated assumption (*"assumes capture since 2021-01-01 (SINCE_CONFIRMED)"*) ·
ledger · function · algorithm · exposed window · deadline · secrecy lifetime · when
we *could have* vs when we *proved* · the data class with its **cited row**
(`data_lifetime.yaml#TEST.X_25Y`) · evidence used · **MOVE TO** · policy in force ·
and **SHOW YOUR WORKING**.

Caption: **"Every verdict opens into the evidence behind it — and re-computes from
its own stored inputs."**

### Screenshot 2 — the closure queue *(slide 5)* — **changed from the first draft**

The first draft proposed the ledger list here. **Demote it**: slide 4 already
renders the ledger as slide content, so a ledger screenshot proves something the
deck has already shown.

The closure queue is redundant with nothing, and it is the most *unique* thing in
the product — no competing tool does it. It proves slide 2's "closure engine"
innovation line, and it is richer live than the deck currently suggests. Each task
shows: the plain-language action · **why it settles those rows** · which rows ·
**"what you might find"** — the actual possible outcomes, re-computed rather than
guessed · **"longest window at stake"** in days (2758 · 1648 · 260) · and a spec
citation per task. The header reads *"each task is the smallest thing that would
settle the rows it names. Ranked by the worst thing it could reveal, then by how
many rows it would settle."*

The fixture banner is in this frame too, so this one screenshot carries both the
differentiator and the honesty. **Keep the banner.** It reads *"Fixture data. No
sensor has run… nothing here was observed on a real network."* That banner is the
deck's thesis rendered inside the product; cropping it to look like a live
enterprise scan would undo the credibility the other five slides spend their time
building.

Caption: **"Every unknown becomes the single smallest task that would settle it —
ranked by the worst thing it could reveal."**

### The strip — "show your working" *(slide 2, beside the Replayable line)*

Not a screenshot. A three-line crop of the bottom of the evidence card: the rule id
(`LEDGER-CONF-001`), the calculation version, the input fingerprint, and
**"Re-run now → same answer (BLEEDING), same inputs."**

It is four lines of monospace, costs almost no space, and it is the only visual
proof of an innovation line that currently has none. Highest ratio of proof to
density in the entire deck.

### Runner-up, if a slot ever opens

The **Coverage** tab — *"what each sensor looked at"*, surfaces reaching the ledger,
and **"reported but not banded"** (symmetric encryption is a key-size question, not
a deadline). The "we tell you what we could not see" differentiator, made visible.

### Do not screenshot

VS Code · terminal · folder tree · pytest output · GitHub commits · code.
`467 passed` is a tile, not a picture.

---

## 7. Order of work

1. **Slide 3 wording** — cut Syft, fix "cloud KMS export", split Platform into
   built/planned. Text only, and it removes the over-claim *without* dropping a
   requirement.
2. **Slide 2 (iv) latency wording**, and **slides 4–5 number refresh.** Text only;
   recovers the four-times undersell. Watch the trap in §4.
3. **The two screenshots and the strip.** Nothing to build.
4. **P19 — scenario flip dates.** Cheapest real capability, keeps a promise slide 4
   already makes, needs no new slide space.
5. **P13 — run store and diff.** Earns VERIFY on slides 2–3, and makes the snapshot
   and PostgreSQL promises true rather than deleted.
6. **P15** (data already computed) → **P14** → **P18** (one test) → **P17** last:
   real work, but nothing a judge can see.

Steps 1–3 need no new code and move the deck further than 4–6 do. Step 4 is the
best code-for-impact trade on the list.

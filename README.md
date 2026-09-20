# Pramāṇa

**Which of our secrets are already lost, which are still leaking, and which can we still protect?**

Pramāṇa answers that question about an organisation's encryption, and shows its
working for every answer.

> Built against Smart India Hackathon problem statement **SIH26164**.
> Repository still carries its old working name `ecdat` — see the checklist at
> the bottom.

---

## The problem, in plain words

Most encryption used today relies on a maths problem that ordinary computers
cannot solve in any useful amount of time. A quantum computer, once one is big
enough, will solve it quickly. Nobody knows exactly when that happens. Call
that future date **Z**.

Here is the part people miss.

An attacker does not have to wait for Z to start. They can record encrypted
traffic **today**, store it, and decrypt it the day Z arrives. This is usually
called *harvest now, decrypt later*. It has an uncomfortable consequence:

> **If your data was recorded, upgrading your encryption tomorrow does not save
> it. It was already taken.**

Upgrading stops the *future* leak. It recovers nothing from the past.

So the real question is not "which of our encryption is old?" It is:

- Data we sent **and** that still needs to be secret after Z → **already beyond saving**
- Data we are sending **right now** that will still matter after Z → **still leaking, stop it**
- Data that stops mattering before Z → **fine, leave it alone**

Which bucket something lands in depends on **how long that particular data has
to stay secret**. A password reset link that matters for ten minutes and a
medical record that matters for twenty-five years can travel down the exact
same connection, protected by the exact same encryption, and be in completely
different trouble.

That is the thing existing tools do not tell you.

---

## What other tools do, and where they stop

There are good, free tools that find encryption in your code and your
containers and list it (CBOMkit, sonar-cryptography, cbomkit-theia). They
produce a solid inventory. **If a plain inventory is what you need, use them —
they are free and they are good at it.**

What they do not do:

- track exposure **over time** — an inventory is a photo, not a timeline
- tell **secrecy** apart from **identity** — two different problems, two different deadlines
- say **how sure** they are about each individual detail
- report **what they could not see** — silence reads the same as "all clear"
- tell you **what to go and find out next**

Pramāṇa runs those tools as inputs, and adds the missing layer on top.

---

## What Pramāṇa adds

### 1. Two different clocks, because there are two different problems

**Secrecy.** Someone reads your data. Recording it today is enough — Z just
unlocks it later. The deadline already passed, or it is passing right now.

**Identity.** Someone forges your signature. You cannot forge a signature by
recording one; you have to wait for Z. So nothing is lost yet — but anything
that must still be trusted *after* Z needs re-signing before then.

Mixing these into one "risk score" hides the difference. Pramāṇa keeps two
separate ledgers.

### 2. The same key can be doing two jobs

One certificate often proves who a server is **and** helps set up the
encryption. Those two jobs fail in different ways on different dates. So
Pramāṇa attaches the job to the *usage*, not to the key. One key can produce
several rows, each with its own deadline.

### 3. "We saw it" and "we assume it" are never the same thing

Every single detail carries how we know it:

| We say | We mean |
|---|---|
| **Observed** | We actually saw this happen |
| **Inferred** | A config file suggests it. We did not watch it happen |
| **Declared** | A person told us |
| **Unknown** | We do not know, and we are saying so |

A configuration file claiming "we upgraded" does **not** stop the clock. Only
watching a real connection does. This matters more than it sounds: plenty of
systems are configured for something they never actually use.

If a required detail is Unknown, the row comes out **UNBOUNDED** — "we cannot
honestly answer yet" — instead of a confident guess.

### 4. Every "unknown" comes with a job to do

An UNBOUNDED row is not a dead end. It tells you:

- exactly which missing fact is blocking it
- the **smallest** thing you could do to get it ("probe this one endpoint")
- why that would settle it
- and what the answer could turn out to be — worked out by re-running the
  calculation with each possible value, not guessed

### 5. Every answer shows its working

Each row stores every input it used and a fingerprint of them. Re-run it later
and you get the same answer, or the record was tampered with. There is **no
score, no weighting, no machine learning, no AI**. Just dates and stated
assumptions. If you disagree with an answer, you can point at the exact input
you disagree with.

### 6. You choose the assumptions; the tool does not hide them

Two things are honestly unknowable, so you pick them and every row says which
you picked:

- **When is Z?** Three options ship: 2031, 2036, 2041. Flip between them and
  watch the answers move.
- **Since when do we assume someone was recording?** Since we can *prove*
  traffic flowed? Since it was first *possible*? Since a date you name?

Every row prints its assumption in words, for example
*"assumes capture since 2021-01-01 (SINCE_CONFIRMED)"*. A tool that hides this
is lying by omission.

---

## What one answer actually looks like

A real row from the test suite, in plain English:

> **This connection has been leaking since 1 January 2021.**
>
> We watched it on 1 January 2021 using X25519 key exchange, which a quantum
> computer breaks. The data it carries must stay secret for 25 years. Assuming
> Z is 2036, anything sent after 2011 was already past saving — and this
> connection started after that. We have never seen it upgraded.
>
> - **Verdict:** BLEEDING
> - **Exposed window:** 1 Jan 2021 → today
> - **Assumes capture since:** 2021-01-01 (because you chose SINCE_CONFIRMED)
> - **Based on:** one observed connection, one declared data class
>
> Change Z to 2041 and it still bleeds. Shorten the secrecy requirement to one
> year and it becomes SAVABLE, with a deadline of 2035.

Same connection, same encryption. **Different data, different answer.** That is
the whole point.

---

## The verdicts

**For secrecy:**

| Verdict | Meaning |
|---|---|
| **BLEEDING** | Leaking right now. Stop it |
| **UNSAVABLE** | Was leaking, has since been fixed. What went out is gone |
| **SAVABLE** | Not past the deadline yet. You have until *this date* |
| **SAFE** | Already quantum-resistant, or the data stops mattering in time |
| **UNBOUNDED** | We cannot answer yet. Here is what to go and find out |

**For identity:**

| Verdict | Meaning |
|---|---|
| **ROTATE_BEFORE_Z** | Just replace the key before Z. Nothing to re-sign |
| **RESIGN_BEFORE_Z** | This must still be trusted after Z. Re-sign it first |
| **SAFE_UNTIL_Z** | Stops mattering before Z |

---

## What it will never do

Being clear about this is part of the design, not a disclaimer:

- **It will not guess how much data leaked.** We can say *when* a connection was
  exposed. We cannot know how many bytes went over it, so we do not pretend to.
- **It will not give you a risk score out of 100.** Any such number needs
  weights, and nobody can defend the weights. You get categories and dates.
- **It will not predict when Z is.** You pick. It shows you all three.
- **It will not use AI anywhere in the analysis.** A tool for classified
  networks should be inspectable line by line.
- **It will not silently fill in a blank.** Missing means missing.
- **It will not treat a config file as proof.** Only observations count.

---

## Running it today

Needs Python 3.12 or newer.

```bash
pip install -e ".[dev]"
```

```bash
python -m pytest -q
```

That runs 351 tests, including all 18 worked examples from the frozen
specification. The calculation engine is real and fully tested. **The part that
goes and looks at your actual systems is not finished yet** — see the checklist.

---

## Status

### Done

- [x] **Evidence tracking** — every detail carries how we know it (seen / inferred / told / unknown)
- [x] **Two timelines per connection** — when it *could* have started vs when we can *prove* it did
- [x] **Job detection** — works out what a key is actually being used for, and refuses to guess
- [x] **The Z-date chooser** — three timelines, switchable, every answer says which it used
- [x] **Data lifetime table** — how long each kind of data must stay secret
- [x] **The secrecy ledger** — BLEEDING / UNSAVABLE / SAVABLE / SAFE / UNBOUNDED
- [x] **The identity ledger** — rotate before Z vs re-sign before Z
- [x] **Upgrade detection** — only a watched connection counts; a later fallback re-opens the wound
- [x] **Show your working** — every answer replays from its own stored inputs
- [x] **Ordering** — worst first, by category, never by a made-up score
- [x] **The to-do list generator** — every unknown becomes a specific, smallest-possible task
- [x] **All 18 worked examples from the spec pass**
- [x] **Source code scanner** — finds encryption in Java (our own rules, not borrowed ones)
- [x] **Standard report export** — writes a CycloneDX 1.6 file, checked against the official schema, with a "could not determine" list so silence is never read as "all clear"
- [x] **Import other tools' reports** — reads any CycloneDX 1.6 file as evidence, recorded as *someone told us*, never as *we saw it*
- [x] **Leak guard on export** — refuses to write a file that looks like it contains key material
- [x] **Upgrade recommendations** — what to move to, chosen by what the key is *doing*, with the size cost and the known breakage rate attached
- [x] **Dashboard** — web interface showing the ledger, the evidence behind each verdict, the to-do queue and coverage, with the Z date and the recording assumption as controls you can move
- [x] **Automated checks** — no uncited number anywhere in the data files
- [x] **Linux build box** — Docker, Go, Maven, haproxy, SoftHSM2, YARA and all three scanners at their pinned versions, from one re-runnable script
- [x] **A running test enterprise** — the reference containers build and run, and the load balancer answers a real TLS handshake
- [x] **Certificate reader** — reads certificates from PEM, DER and PKCS#12 files. Holds private keys in memory and provably emits none
- [x] **Live connection prober** — actually connects and records what was negotiated, from a stated vantage, and separately checks whether the old encryption still works
- [x] **Config file resolver** — works out which setting actually wins across `application.yml`, profile files, Kubernetes manifests and same-repo ConfigMaps, per Spring's real precedence order. Never reports a resolved value as fully certain — an answer is always *our best reading*, not a watched fact — and if a command-line flag or system property could be overriding it, it says so instead of guessing
- [x] **Package/dependency scanner** — runs Trivy against a container filesystem and lists what's bundled inside. Deliberately says nothing about whether any of it is actually *used* — a library sitting unused in a jar is a very different fact from one the code calls into, and this tool refuses to blur that line
- [x] **Within-surface asset merging** — the same key found twice in one place (say, two certificate files naming the same key) becomes one entry, not two; a genuine disagreement between them becomes a flagged conflict, never a silent guess
- [x] **Forbidden-correlation gate** — a check that blocks the tool from ever claiming two different keys are "the same object" without the one specific kind of proof that actually supports that claim
- [x] **Apache-2.0 licence file**

### Not done yet

- [ ] **Java keystore formats** — JKS and BCFKS are not read yet; they are reported as skipped, never as absent
- [ ] **Container image scanner** — a certificate/secret-in-image reader (`cbomkit-theia`) has been test-driven against a real container and works; it is not wired into the tool as an adapter yet
- [ ] **Hardware security module and cloud key reader** — real PKCS#11 metadata has been captured from a SoftHSM2 token (key labels, sizes, mechanisms — never key bytes); the reader itself is not built yet
- [ ] **Compiled binary scanning** — YARA rules for AES/SHA-256 and a `readelf` dependency check have been proven against a real binary from the test enterprise; the adapter that runs them is not built yet
- [ ] **Cross-surface relationships** — connecting "this key in the source code" to "this key on the wire" as a labelled, human-asserted link rather than an assumed identity
- [ ] **Signed export** — the report is not signed yet, so it proves nothing about who wrote it
- [ ] **Accuracy scoring** — measure and publish our own error rates on a test environment
- [ ] **Packaging** — one-command install, offline, no internet access required
- [ ] **Rename repository** `ecdat` → `pramana`

**Honest summary:** the thinking is built and tested, and as of 20 Sep 2026
four of the seven sensors are real and wired in: certificates, a live TLS
probe, the config-file resolver, and the package/dependency scanner. Three
more — container images, hardware/cloud keys, and compiled binaries — have
been proven against real material from the test enterprise (a real scan, a
real token, a real binary) but the adapter code that would make them run as
part of a normal scan is not written yet. Nothing here has been run against a
production network.

---

## Why "Pramāṇa"

Sanskrit, from Indian philosophy: *the means by which one arrives at valid
knowledge* — and the study of what separates knowing something from merely
believing it. That is the entire design brief. Every answer here has to say how
it knows.

---

## Licence

Apache-2.0. See [`LICENSE`](LICENSE).

## For developers

- `docs/architecture/Pramana_Ledger_Spec.md` — the frozen specification
- `CLAUDE.md` — the rules this codebase is built under
- `docs/deviations.md` — every place the code departs from the spec, and why
- `docs/open-issues.md` — every question still open
- `docs/build-plan.md` — phases and what state each is in

---

## How to use it

Three things you can do today. Every command is copy-pasteable.

### 1. Run the tests

Proves the calculation engine works, including all 18 worked examples from the
specification. Needs nothing but Python 3.12+.

```bash
pip install -e ".[dev,api]"
```

```bash
python -m pytest -q
```

### 2. Open the dashboard

```bash
cd ui/dashboard && npm install && npm run build && cd ../..
```

```bash
python -m uvicorn ecdat.api.app:app --port 8000
```

Then open <http://127.0.0.1:8000>.

It opens on **fixture data** — constructed evidence used to exercise every
verdict. The page says so at the top. Things worth trying:

- Change **"When is Z?"** and watch verdicts move between BLEEDING and SAVABLE.
- Switch **"Assume recording since"** to `SINCE_POSSIBLE` — a row that said
  "we cannot answer yet" becomes answerable.
- Click any row for the evidence behind it, including a live re-run proving
  the answer is reproducible.
- **Move to** shows what to migrate each key to, with byte costs.
- **Export CycloneDX 1.6** downloads a report other tools can read.

### 3. Read real certificates

Points the certificate reader at a folder and prints what it finds. It never
prints key material — that is enforced, not promised.

```bash
python -c "
from ecdat.adapters.base import ScanTarget
from ecdat.adapters.certs.adapter import CertificateAdapter
from ecdat.model.evidence import ConfidenceBasis

basis = ConfidenceBasis(source='ADAPTER_DECLARED', justification='Read directly from an artefact; no cited confidence table exists yet.')
result = CertificateAdapter(base_confidence=0.95, confidence_basis=basis).run(
    ScanTarget(target_id='certs', locator='PUT_A_FOLDER_PATH_HERE'))

print(f'{len(result.findings)} certificate(s), {len(result.coverage.skipped)} file(s) skipped')
for f in result.findings:
    print(' ', f.fields['subject'].value, '|', f.fields['public_key_algorithm'].value, '|', f.fields['der_sha256'].value[:16])
"
```

Add `keystore_password=b'...'` to read a `.p12` keystore.

---

## Running the test enterprise (Linux, optional)

This part needs Docker and a Linux machine or WSL. It builds a small fake
company — an app, a load balancer, a certificate authority — so the prober has
something real to talk to.

**Set up the machine once** (installs Docker, Go, Maven, haproxy, SoftHSM2 and
the three scanners at their pinned versions):

```bash
sudo bash tools/provision/build-box.sh
```

**Start it:**

```bash
cd ../ecdat-harness/harness/compose && docker compose up -d
```

**Probe it.** The endpoint sits on a no-egress network on purpose, so you
connect from a container on that same network — which is also the only vantage
a real deployment would have:

```bash
IP=$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$v.IPAddress}}{{end}}' ecdat-harness-tier-a-edge-lb-1)
docker run --rm --network ecdat-harness-tier-a_payments-internal alpine/openssl s_client -connect "$IP:8443" -brief </dev/null
```

You should see `Negotiated TLS1.3 group: X25519MLKEM768`.

**One gotcha:** run the start and the probe in the *same* terminal session. If
a WSL session ends, the distro can shut down and take the containers with it.

Full details, including what the first real handshake revealed:
[docs/build-box.md](docs/build-box.md).

---

## Why "Pramāṇa"

Sanskrit, from Indian philosophy: *the means by which one arrives at valid
knowledge* — and the study of what separates knowing something from merely
believing it. That is the entire design brief. Every answer here has to say how
it knows.

---

## Licence

Apache-2.0. See [`LICENSE`](LICENSE).

## For developers

- `docs/architecture/Pramana_Ledger_Spec.md` — the frozen specification
- `CLAUDE.md` — the rules this codebase is built under
- `docs/deviations.md` — every place the code departs from the spec, and why
- `docs/open-issues.md` — every question still open
- `docs/build-plan.md` — phases and what state each is in

---

## Running the dashboard

```bash
pip install -e ".[dev,api]"
```

```bash
cd ui/dashboard && npm install && npm run build
```

```bash
python -m uvicorn ecdat.api.app:app --port 8000
```

Then open <http://127.0.0.1:8000>. It opens on fixture data — constructed
evidence used to exercise every verdict while the live connection prober is
still being built. The page says so at the top; nothing in it was observed on
a real network.

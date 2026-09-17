# Open Issues

## OI-001 — Two of three canonical architecture docs are empty (2026-09-17)

**Status:** BLOCKING for any task that needs their content. NOT blocking for repo-skeleton/CI/tooling work.

CLAUDE.md's canonical-sources precedence order lists:
1. `docs/architecture/ECDAT_Architecture_Lock.md` — present, real content (16,618 bytes).
2. `docs/architecture/ECDAT_Architecture_Stress-Test_Directives.md` — **empty** (0 bytes). Only
   exists as a placeholder created during initial repo scaffolding; the actual directives text
   (referenced throughout the Lock as "Directive 3", "Directive 6"–"Directive 10", "Directive 12")
   has never been supplied to this repo.
3. `docs/architecture/ECDAT_Final_Architecture.md` — **empty** (0 bytes). Same situation — the
   Lock's §5 "Supersession map for `ECDAT_Final_Architecture.md`" amends a document this repo
   does not actually have a copy of.

**Why this matters:** per the anti-hallucination rules, content for these docs must never be
typed from memory or inferred from the Lock's references to them. Any task that requires reading
a specific Directive N or the pre-amendment Final Architecture text must STOP here first.

**Not currently blocking:** the 2026-09-17 task (repo skeleton, hash-vs-ADR CI check, harness-identifier
grep check, CycloneDX 1.6 schema download) does not require the content of either missing doc — it
only needs the three files to exist at the right paths, which they do. Proceeding with that work;
this entry stays open until the real source text for both docs is supplied.

**Resolution:** user must provide the actual source files for `ECDAT_Architecture_Stress-Test_Directives.md`
and `ECDAT_Final_Architecture.md`, or confirm the Lock is the sole surviving canonical doc and the
other two should be removed from the precedence list in CLAUDE.md.

## OI-002 — No harness-pinned JDK/BC/Node/OpenSSL build exists yet (2026-09-17)

**Status:** NOT blocking for the PRV-T1/T2/T3 evidence-gate experiments (2026-09-17 task), because
Lock §6.1 explicitly says these preliminary observations "do not satisfy the gate" for exactly this
reason and asks for them anyway. Blocking for ever calling PRV-001 LOCKED (harness §16.3 freeze gate
requires "the pinned JDK build", and harness §16.2 says "the harness pins one JDK build").

Lock §6.1: "the harness has not yet chosen its pinned JDK build (no payment-gateway image exists)."
No `ecdat-harness/targets/payments/payment-gateway` image, Dockerfile pin, or `harness/build/pki-lock.generated.json`
exists in the ecdat-harness repo as of this entry — confirmed by inspecting the repo tree.

**What this means for docs/experiments.md EXP-002/003/004 (PRV-T1/T2/T3):** those experiments ran
against whatever JDK/Node/OpenSSL/BC build happened to be installed on the machine that ran them
(recorded exactly, with full version strings, in each entry) — not against a harness-sanctioned pin.
Per Lock §6.1's own classification, this makes them **preliminary observations, not gate results**,
even though the commands and revised-test list match harness §16.1 "Revised tests" 1–3 exactly.

**Resolution:** once the harness builds the payment-gateway image and pins a JDK build (harness
build order, Lock §9 step 1), re-run PRV-T1/T2/T3 against that exact pinned build and record the
result as a gate result (not preliminary) in docs/experiments.md, citing the image digest.

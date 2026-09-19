# Deviations

Places where the implementation departs from a plan or a canonical document, and
why. Recorded per CLAUDE.md: a departure is filed, never silently substituted.

## DEV-001 — P0's adapter-contract shape differs from `docs/build-plan.md` (2026-09-17)

**Issue.** `docs/build-plan.md` P0 specifies the adapter contract as
`supported_surface`, `support_level`, and `run()` → `(findings, visibility_entry)`.
The implemented contract in `src/ecdat/adapters/base.py` uses `dimensions`
(plural) and returns a single `AdapterRunResult`.

**Evidence.** Two facts drove the change, both discovered after the plan was
written:

1. A tuple return makes the TRAP-07 failure easy to write by accident:
   `return ([], [])` type-checks and reads as "nothing found", yet loses the
   distinction between *scanned and clean* and *never looked*. harness §7.3 is
   explicit that reporting zero assets without a coverage entry is a failure.
2. Recorded observation: a Semgrep run with Java rules over a Python target
   returns `results: []` **and** `paths.scanned: []`. Representing that honestly
   needs a `Coverage {scanned, skipped}` field, which a two-tuple has no place
   for. One adapter also legitimately covers more than one dimension, so the
   singular `visibility_entry` was wrong regardless.

**Options.** (a) Keep the tuple and bolt coverage on later — rejected, the
invariant would be unenforceable at the point it matters. (b) Return one
validated result object — chosen. (c) Return an iterable of results — rejected:
a generator that yields nothing is indistinguishable from a target never
scanned, which is the exact failure being guarded against.

**Impact.** `run()` is one target in, exactly one result out, so an orchestrator
can assert `len(results) == len(targets)` and diff the visibility matrix against
the target list mechanically. `supported_surface` → `dimensions` because the
values are `VisibilityDimension` members and an adapter may declare several.
No canonical document is contradicted; only the plan's own draft wording is.
`docs/build-plan.md` P0 should be read as superseded by this entry.

## DEV-002 — ledger phases 1–4 built before sensor phases P4/P5 (2026-09-19)

**Issue.** `docs/architecture/Pramana_Ledger_Spec.md` §7 fixes the order
`P0b -> P4 -> P5 -> 1 -> 2 -> 3 -> 4 -> 8`, and §11 puts a Linux build box
first. Phases 1–4 (evidence model, function resolution, scenario engine,
exposure ledger) were built first instead, on Windows, with no sensor work.

**Evidence.** §7's prerequisite is real: semgrep does not install on native
Windows (OI-009), and the Tier A images and Go binary cannot be built here. P4
(certs + TLS) needs sslyze and a live endpoint; P5 needs Trivy. None of that is
available on this machine today.

Phases 1–4, by contrast, have no external dependency at all. §5.4 requires
"pure date arithmetic; no hidden constants", and the ledger modules read no
clock, no network and no file at evaluation time (every input arrives in
`LedgerInputs`). The whole of §6's frozen test set is expressible against
constructed evidence objects. So the ordering constraint between P4 and
phase 1 is a *data* dependency -- phase 1 wants real observations to consume --
not a *build* dependency.

**Options.** (a) Wait for the build box and do nothing -- rejected, it stalls
the differentiator behind an environment problem. (b) Stub the sensors and
build phases 1–4 on fake adapters -- rejected: a stub adapter that emits
plausible evidence is exactly the "false certainty" failure, and it would need
deleting later. (c) Build phases 1–4 against explicitly-constructed evidence
objects and §6's frozen expectations, with no adapter involved -- chosen. The
ledger's input types are the contract P4 will fill; writing them first means
P4 has a typed target instead of a prose one.

**Impact.** `score_run.py` cannot yet score these phases on live output, so per
CLAUDE.md's workflow rule they are NOT closed -- they are implemented and
unit-green. Phase 1 and 2 close when P4's adapter produces
`NegotiatedHandshake` / `TemporalEvidence` from a real handshake. The §6 test
set does not depend on that and stays green either way.

## DEV-003 — lifetimes are stored in their policy's unit, not in days (2026-09-19)

**Issue.** `Pramana_Ledger_Spec.md` §5.3 names the fields
`secrecy_lifetime_X_days` and `authenticity_lifetime_A_days`.
`src/ecdat/context/binding.py` stores a `Lifetime` holding *either* years or
days, and `data/data_lifetime.yaml` rows are written in years.

**Evidence.** §6's own expected dates are calendar-year arithmetic and a fixed
day count cannot reproduce them across different leap-year spans. Row 2 of §6
is "RSA static key transport, X=7y ... aggressive: BLEEDING, unsavable
[2024-01-01, as_of]", i.e. `Z_aggr(2031-01-01) - 7y = 2024-01-01`. Seven
calendar years before 2031-01-01 spans two leap days (2024, 2028) and is 2557
days; seven before `Z_central(2036-01-01)` spans one (2032) and is 2556. Any
single day count is therefore wrong for one of the two scenarios:

    2036-01-01 - 2556d = 2029-01-01   (matches §6 "deadline 2029-01-01")
    2031-01-01 - 2556d = 2024-01-02   (§6 says 2024-01-01 -- off by one day)

Verified by running both subtractions before the model was written.

**Options.** (a) Keep days and accept the one-day error -- rejected; a deadline
that is wrong by a day is wrong, and the frozen test set is the acceptance
criterion. (b) Keep days and special-case leap years at subtraction time --
rejected: that is calendar-year arithmetic with the unit thrown away, which is
the bug. (c) Store the unit the policy was written in and subtract in that unit
-- chosen. A policy that says "seven years" means seven calendar years; storing
it as a day count silently re-dates every deadline crossing a different number
of leap days.

**Impact.** Field names change from `..._days` to `secrecy_lifetime_X` /
`authenticity_lifetime_A`, both `Lifetime`. `Lifetime` requires exactly one of
`years` / `days`, so a policy genuinely written in days still round-trips
exactly. The §5.4 requirement "pure date arithmetic; no hidden constants" is
strengthened, not weakened: there is no 365.2425 anywhere. Export (§5.11) must
serialise the unit alongside the number.

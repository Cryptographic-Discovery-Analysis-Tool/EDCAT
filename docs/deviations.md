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

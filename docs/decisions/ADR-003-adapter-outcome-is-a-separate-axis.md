# ADR-003 — Adapter outcome is a third axis, separate from epistemic state

**Date:** 2026-09-17
**Status:** Accepted

## Issue

The visibility matrix must distinguish "scanned, found nothing" from "failed"
and from "timed out" (Lock §5 row 4 lists "failed/timeout targets" as a
dimension). None of the existing enums can express that:

- `EpistemicState` is closed and must not be extended (hard rule). It describes
  what we know about a *field*, not how a *run* ended.
- `ResolutionStatus` is about a configuration value's resolution, not a run.
- `SupportLevel` is *capability* — what an adapter can do in principle — not
  *what happened* on one target.

Conflating any of these with run outcome is a false-certainty risk: a
`support_level: full` adapter that timed out has full capability and zero
observation, and the matrix must show both.

## Decision

Add `AdapterOutcome ∈ {completed, failed, timed_out}` in `adapters/base.py`, and
`Coverage {scanned, skipped}` recording what the tool itself said it looked at.

`AdapterOutcome` is **not** an epistemic state and **not** a resolution status;
the closed enum is untouched. The Lock names "failed/timeout targets" but gives
no literal enum, so the three tokens are an engineering choice recorded here —
the same pattern as ADR-001.

`not_attempted` was considered and dropped: it is unreachable from `run()` (a
target that is never passed to an adapter produces no result at all), and an
unreachable state that validation cannot constrain is a trap, not a feature.

## Why `Coverage` is separate from `findings`

Recorded observation (2026-09-17): Semgrep run with Java rules over a Python
target returns `results: []` **and** `paths.scanned: []`. Zero findings there
means *did not look*, not *clean*. Without `Coverage`, those two cases have the
same shape, and harness §7.3 TRAP-07 fails a tool that cannot tell them apart —
"reporting 'zero assets' alone is a failure".

`AdapterRunResult` therefore rejects findings when `coverage.scanned` is empty:
a finding must come from something the tool actually looked at.

## Consequences

- A timed-out probe reports both a `failed_timeout` row and a row for each
  dimension it was supposed to cover, so it cannot silently vanish.
- `failure_reason` records the exception **type only**, never its text:
  exception messages routinely echo the input that caused them, and that string
  reaches the store, the CLI and snapshots, where secret bytes are forbidden.
- A contract violation in our own code is re-raised rather than converted into
  a `failed` outcome — laundering a bug into "this target failed" would be a
  false claim about the target.

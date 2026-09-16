# ECDAT — Operating Contract for Claude Code

## What this is
Evidence-correlation and PQC migration decision-support layer over existing crypto scanners.
Not a scanner. Trust > completeness. False certainty is the worst possible bug.

## Canonical sources (precedence order) — READ-ONLY, never edit
1. docs/architecture/ECDAT_Architecture_Lock.md
2. docs/architecture/ECDAT_Architecture_Stress-Test_Directives.md
3. docs/architecture/ECDAT_Final_Architecture.md (as amended by Lock §5)
4. ../ecdat-harness/ docs §14–16 (decision text)
Read only the sections relevant to the current task. Cite section numbers in plans.

## Hard rules
- Epistemic states are a CLOSED enum: KNOWN, UNKNOWN, NOT_OBSERVED, NOT_APPLICABLE,
  INFERRED, DECLARED, CONFLICTING. Never add states. No DERIVED/UNRESOLVED/POSSIBLY/SHADOW.
- resolution_status {RESOLVED, OVERRIDDEN, UNRESOLVED(+reason)} is a separate field.
- State is per FIELD, not per asset.
- R-DERIVE: derived value state = weakest required input; record derived_from + rule_id.
- R-MONOTONE: more evidence never creates unsupported certainty.
- R-UNSEEN: a merely possible unseen source doesn't invalidate an inference; a present-but-unsupported one does.
- Never merge across surfaces. Only cross-surface identity: same-object (SHA-256 of cert DER),
  shares-public-key (SHA-256 of SPKI DER).
- Relationships have NO free-standing confidence; confidence lives on evidence_refs.
- Package presence = capability, never usage. purpose defaults to UNKNOWN, never guessed.
- No private key / secret bytes in DB, logs, CLI output, CBOM, test snapshots. Store location + fingerprint only.
- Network probing only for targets in scan allow-list with consent flag. Record probe_vantage.
- No LLM calls in any detection, correlation, risk, or recommendation path.
- No harness identifiers (meridian, harness paths, hostnames) anywhere in src/ or rules/.

## Anti-hallucination rules
- Never write a parser for tool output that isn't in tests/fixtures/recorded/. If missing: STOP,
  write the exact command needed to docs/open-issues.md.
- Never type a spec enum, key size, byte count, or standard date from memory. It must come from
  schemas/ or data/ with a citation field, or be marked TODO-VERIFY and fail a test.
- Label claims in plans/ADRs: FACT / VERIFIED / UNVERIFIED / INFERENCE / ASSUMPTION / DECISION.
- If a locked decision seems wrong or a simpler design exists: do NOT implement it.
  Append to docs/deviations.md (issue, evidence, options, impact) and stop.
- Don't widen scope. Items listed "out of scope" in the Lock are out of scope.

## Workflow
- Start every task in plan mode. Plan must list: Lock sections used, files touched,
  tests written first, out-of-scope items.
- Tests encode expected behaviour from canonical docs/harness ground truth, NOT from your implementation.
- Done = tests pass + no TODO-VERIFY in touched code paths + short ADR if a choice was made.

## Stack
Python 3.12, pydantic v2, pytest + hypothesis, PostgreSQL (JSONB) behind a repository
interface, Typer CLI. FastAPI/UI deferred until vertical slice passes scoring.

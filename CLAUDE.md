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

## Anti-hallucination rules (amended)
- PARSERS are written only against tests/fixtures/recorded/. RUNTIME INPUT is never
  rejected for being unrecorded: parse it, and if tool_version differs from every
  recorded version, attach a VisibilityEntry warning "parser validated against <v>;
  observed <v'>" to the run. Raise only in --strict mode (used by scoring).
- Every adapter MUST be able to invoke its tool (subprocess) on a real target path,
  with pinned flags, per-target timeout, and network egress disabled. Replay of a
  recorded file (--input) is for tests and scoring only.
- Canonical docs must be non-empty. CI fails on any 0-byte file in docs/architecture/.
  Never cite a Directive or Part whose file is empty; stop and file an open issue.
- Confidence values come from data/base_confidence.yaml rows with a citation. No CLI
  or UI input for confidence. Rows sourced from Final Architecture Part 3 are cited as
  "engineering estimate, Part 3; no published benchmark" — usable, labelled.

## Workflow (amended)
- CI runs pytest. A phase is not done until CI is green.
- The only phase numbering is docs/build-plan.md.
- A phase is done only when `ecdat scan` runs LIVE on the Tier A target directory and
  score_run.py is re-run. Fixture-only passes do not close a phase.
- Any departure from build-plan.md or CLAUDE.md gets a DEV-NNN entry the same session.

## Security defaults for subprocesses
- semgrep: --metrics=off, SEMGREP_SEND_METRICS=off, --config rules/semgrep only,
  --timeout per file, --max-target-bytes.
- trivy: --skip-db-update with configured offline DB path; --timeout.
- All tool invocations: no network (test enforces), wall-clock limit, output size cap.

## Stack
Python 3.12, pydantic v2, pytest + hypothesis, PostgreSQL (JSONB) behind a repository
interface, Typer CLI. FastAPI/UI deferred until vertical slice passes scoring.

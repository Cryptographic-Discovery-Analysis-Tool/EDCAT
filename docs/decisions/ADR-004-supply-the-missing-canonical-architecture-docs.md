# ADR-004 — Supply the missing canonical architecture docs, closing OI-001

**Date:** 2026-09-18
**Status:** Accepted
**Closes:** [OI-001](../open-issues.md#oi-001--two-of-three-canonical-architecture-docs-are-empty-2026-09-17)

## Issue

Two of the three files CLAUDE.md's canonical-sources list points at were
0-byte placeholders in this repo:

- `docs/architecture/ECDAT_Architecture_Stress-Test_Directives.md`
- `docs/architecture/ECDAT_Final_Architecture.md`

The Lock cites both by name ("Directive 3", "Directive 6"-"Directive 10",
"Directive 12"; Final Architecture Part 3, Part 5) for content this repo did
not actually hold. OI-001 recorded this as blocking for any task needing that
content, and OI-003, OI-004, and OI-005 each recorded a specific question that
could not be answered without them.

## Evidence

The user supplied the real source files (2026-09-18). Both are non-empty and
readable UTF-8 text:

- `ECDAT_Architecture_Stress-Test_Directives.md` — 196 lines, 13 numbered
  directives (the doc's own headings are `### 1.` … `### 13.`, not the literal
  string "Directive N"; the Lock's "Directive N" citations are presumed to
  refer to these ordinal headings, but that mapping is not itself asserted by
  either document and is not reconciled here — doing so is a Lock-level
  question, out of scope for this ADR per CLAUDE.md "don't widen scope").
- `ECDAT_Final_Architecture.md` — 430 lines, 15 numbered Parts plus an
  appendix, matching the Part numbers the Lock and OI-003/OI-004 already
  refer to (Part 1 "Targets", Part 3 "Normalisation into Findings +
  Evidence", Part 5 "Asset resolution", etc.).

## Options

1. **Leave the files empty and continue treating every citation to them as
   blocked.** Rejected: this is the status quo OI-001 already described as
   untenable for any task touching their content, and the content now exists.
2. **Summarize or re-derive their content from the Lock's citations instead of
   copying the source.** Rejected: CLAUDE.md's anti-hallucination rule forbids
   typing spec content from memory or inference; the actual text must be the
   text on disk.
3. **Copy the supplied files in verbatim, regenerate `HASHES.lock`, and record
   this ADR in the same change per CLAUDE.md's own hash-vs-ADR CI gate.**
   Chosen.

## Decision

- `docs/architecture/ECDAT_Architecture_Stress-Test_Directives.md` and
  `docs/architecture/ECDAT_Final_Architecture.md` are replaced with the
  supplied source text, copied verbatim (no edits, no reformatting).
- `docs/architecture/HASHES.lock` is regenerated for all three files under
  `docs/architecture/*.md`, using the same normalization
  `tools/ci/check_architecture_hashes.py` applies (CRLF/CR collapsed to LF
  before hashing, so a line-ending change alone can never look like a content
  change). `ECDAT_Architecture_Lock.md`'s hash is unchanged, confirming the
  regeneration used the same algorithm the CI check expects.
- OI-001 is closed by this ADR, per `check_architecture_hashes.py`'s own rule
  that any `docs/architecture/*.md` change must ship with a new
  `docs/decisions/ADR-*.md` in the same diff.
- OI-003 and OI-004 are re-read against this new text and updated in place
  (see `docs/open-issues.md`); OI-005 is re-read and confirmed to remain open,
  since neither document supplies a total order over the epistemic states.
- No code changes accompany this ADR. Only docs/architecture and
  docs/open-issues are touched.

## Consequences

- Every "Directive N" / "Part N" citation already written into the Lock, into
  ADRs, and into open-issues entries can now be checked against real text
  instead of taken on faith.
- OI-003's `scope_anchor` question is materially answered by Part 5's asset-key
  definition; OI-004's remaining gap is materially answered by Part 3's
  per-source confidence table. Neither answer required a code change to adopt
  yet — see the updated OI entries for what a follow-up implementation task
  would need to do.
- OI-005 stays open: Directive 2 restates the closed epistemic-state enum but
  gives no ordering across it, and Final Architecture never addresses
  R-DERIVE's ordering question either. ADR-001's chosen order is not
  contradicted, but it is also still not confirmed by a canonical source.

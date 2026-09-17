# ADR-002 — An uncited confidence value must carry its own justification

**Date:** 2026-09-17
**Status:** Accepted
**Supersedes:** the "populate `data/` with the cited table" resolution in OI-004

## Issue

`Evidence.base_confidence` needs a value before any adapter can emit evidence.
Lock §5 row 3 says "The base confidence table applies to evidence items", and
that table would live in `ECDAT_Final_Architecture.md` Part 3 — an empty file in
this repo (OI-001). CLAUDE.md forbids typing such a number from memory. So
either adapters cannot emit evidence at all, or some non-cited number must be
allowed to exist.

## Evidence

FACT (grep, 2026-09-17): the ordering `certificate 0.95 … package 0.30`, which
appeared on an early slide draft, occurs **nowhere** in this repository, nowhere
in the harness docs, and in none of the four recorded fixture READMEs. It has no
citable basis and must not ship.

FACT: the only numeric confidence in any canonical source is the harness's own
directory commentary, "symbols → capability/likely-use, confidence ~0.40 per
Part 3". It is explicitly approximate and forwards to the empty Part 3.

## Options

1. **Invent a table.** Rejected: five plausible floats wearing a `citation:`
   key is exactly the fabrication CLAUDE.md exists to prevent.
2. **Refuse all confidence until Part 3 arrives.** Rejected: no `Evidence` could
   ever be constructed, so no `Finding` could carry `evidence_refs`, and the
   whole source surface would emit nothing. That blocks the build on a document
   nobody can produce on demand.
3. **Allow an adapter-declared value that must justify itself, and record the
   absence as data.** Chosen.

## Decision

- `data/base_confidence.yaml` is a **citation registry, not a table of numbers**.
  A row is usable only when `usable: true`, which requires a citation to a
  non-empty in-repo source stating the literal value. Today `usable_row_count`
  is 0, and `lookup()` raises `NoCitedConfidenceError` for every key rather than
  returning a default.
- `Evidence.confidence_basis` is **required**. `CITED_TABLE` must name its row
  and citation; `ADAPTER_DECLARED` must give a written justification and may not
  claim a citation. An unexplained confidence cannot be constructed.
- The registry also records what was searched for and *not* found, so the same
  ground is not re-searched later.

## Consequences

- Adapters are unblocked without anything being invented.
- Uncited values are individually visible and countable, so "confidence per
  evidence source" means *declared per source, each with its reason on the
  record* — which is true — rather than *derived from a table*, which is not.
- When Part 3 (or an equivalent decision) arrives, rows flip to `usable: true`
  and adapters switch to `CITED_TABLE` without touching the model.
- A test asserts the uncited slide ordering cannot be reintroduced, and another
  asserts no `base_confidence = <number>` literal appears anywhere in `src/`.

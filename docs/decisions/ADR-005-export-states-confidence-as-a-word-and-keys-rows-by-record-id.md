# ADR-005 — Export states confidence as a word, and keys rows by record_id

**Date:** 2026-09-19
**Status:** Accepted (both options confirmed by the project lead, 2026-09-19)
**Relates to:** ADR-002, OI-004, OI-012, Pramana_Ledger_Spec.md §5.11

Two choices in `src/ecdat/export/cyclonedx.py` that a reader would otherwise
have to reverse-engineer from the code. Both were put to the project lead as
open questions rather than decided in passing, because both are visible in
every file the tool ever emits.

## Decision 1 — the numeric confidence slot stays empty

CycloneDX 1.6 provides `component.evidence.identity.confidence`, a float in
[0, 1]. We emit nothing there.

**Why.** The source for such a number is `data/base_confidence.yaml`, whose
`usable_row_count` is 0: the table it would come from is Final Architecture
Part 3, an empty file (OI-001, OI-004). ADR-002 already established that an
uncited confidence may exist only with a written justification attached. A
float in a standard field carries no justification with it — it arrives at the
consumer stripped of every caveat, and reads as measured.

**Instead:** `pramana:evidence:confidenceLevel` carries the epistemic state as
a word — `KNOWN`, `INFERRED`, `DECLARED`, `UNKNOWN`. It sits under our own
namespace precisely so no consumer mistakes it for a standard measurement.

**Cost, accepted:** a consumer that reads only the standard numeric field sees
nothing from us. That is the correct outcome: we would rather be silent than
be believed about a number we made up.

**Reopens if:** a citable confidence table lands in the repo (build-plan P0b).
At that point the numeric field becomes emittable, and this ADR should be
superseded rather than quietly ignored.

## Decision 2 — one file carries every scenario; `bom-ref` is the record_id

One usage context produces one ledger row *per* Z scenario. All of them go in
one export, and each component's `bom-ref` is the record_id
(`conf:<usage_context_id>:<scenario_id>`), not the usage context id.

**Why.** `bom-ref` must be unique within a document or no reference inside it
resolves. Keyed on usage context, the three answers for one connection would
collide.

**Why one file rather than one per scenario.** The single most useful thing an
operator or a reviewer can do with this output is put the same connection's
three futures side by side — `BLEEDING` under an aggressive Z, `SAVABLE` under
a central one — and see that the answer is a function of a stated assumption
rather than a property of the key. Splitting by scenario makes that a
three-file diff.

**Cost, accepted:** the file has roughly three components per real connection,
which is unusual for a CBOM and will surprise a reader expecting an inventory.
`pramana:exposure:scenario` is on every component, and
`pramana:export:spec` at BOM level says what the file is, so the structure is
discoverable rather than merely odd.

**Options rejected:** one file per Z date (loses side-by-side comparison);
a single chosen Z per export (loses it entirely, and makes the assumption
invisible again — the failure this whole design exists to prevent).

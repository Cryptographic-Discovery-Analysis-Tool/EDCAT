# ADR-001: Total order over EpistemicState for R-DERIVE's "weakest input wins"

**Status:** ACCEPTED (implementation decision, not an architecture change — see Lock §5 row 9's
precedent: "table layout is an implementation decision, not an architecture decision.")

## Context

Lock §3, R-DERIVE: "A derived field or relationship is never more certain than its weakest
required input." The closed epistemic-state enum (Lock §2 principle 7) has seven members: KNOWN,
UNKNOWN, NOT_OBSERVED, NOT_APPLICABLE, INFERRED, DECLARED, CONFLICTING. Implementing `derive()`
requires computing "weakest" over a set of input states, which requires a total order. Neither the
Lock nor the harness document (sections 14–16) gives one — see
[docs/open-issues.md OI-005](../open-issues.md#oi-005--no-canonical-total-order-among-epistemic-states-for-r-derive-2026-09-17).

The only directly verified pairwise facts:
- CFG-001 (Lock §4, harness §14): a successfully resolved config value is "INFERRED, never KNOWN"
  — i.e. derivation caps below KNOWN even when its inputs are themselves KNOWN.
- Harness §14.3 state D: family/primitive/purpose/quantum tier stay INFERRED while padding is
  CONFLICTING, because padding is not a required input of the tier-derivation rule. This is not
  evidence for an ordering between INFERRED and CONFLICTING in general — it shows `derive()` must
  only consider a rule's *actual* required inputs, never all fields on an asset.

## Decision

`derive()` takes `inputs: Sequence[FieldValue]` as exactly the fields a given rule depends on
(caller's responsibility — never inferred automatically), and its output state is the weakest of
those inputs by this order, weakest first:

1. `UNKNOWN` — no determination possible.
2. `NOT_APPLICABLE` — the field doesn't apply to this case.
3. `NOT_OBSERVED` — observation wasn't attempted or available.
4. `CONFLICTING` — applicable candidates exist but can't be resolved (strictly more information
   than the states above: we know *specific competing claims* exist).
5. `INFERRED` — settled by an explicit rule from evidence.
6. `DECLARED` — human-provided; ranked above INFERRED (authoritative declaration outranks a
   machine inference) and below KNOWN (not independently tool-verified). This DECLARED-vs-INFERRED
   ranking is not directly stated anywhere and is the least-supported part of this order.
7. `KNOWN` — direct, verified observation. Strongest.

**Additional rule, directly grounded (not an assumption):** if the computed weakest state is
KNOWN, `derive()` downgrades the result to INFERRED. A derived value is never KNOWN regardless of
its inputs (CFG-001, verbatim above) — derivation itself caps certainty, independent of the input
ordering.

No rule is implemented for what happens when the weakest input is DECLARED — the output is left as
DECLARED as-is, since nothing in the canonical text supports capping it further (unlike the
KNOWN case, which is explicit). This may be wrong; flagged in OI-005.

## Consequences

- `derive()` is deterministic and testable (see `tests/unit/test_field_value.py` hypothesis
  properties for R-DERIVE and R-MONOTONE).
- If the missing Directive doc later specifies a different order, this ADR and
  `derivation_strength()` in `src/ecdat/model/epistemic.py` must be revisited together.
- Rankings 1–4 (UNKNOWN/NOT_APPLICABLE/NOT_OBSERVED/CONFLICTING) and the DECLARED/INFERRED
  ordering are the parts most likely to need correction; the KNOWN-downgrade rule is the one part
  of this ADR backed by a direct quote.

## Rejected options

- **No total order; raise on ambiguous input sets.** Rejected: `derive()` would then be unusable
  for the one case that's actually specified (harness §14.3 state D), since a real rule call would
  need to declare in advance which of two unranked states "wins."
- **Partial order with explicit incomparability errors.** More honest about the uncertainty, but
  disproportionate for MVP — Lock §5 row 9 explicitly favours implementation-level decisions over
  building more machinery than the current evidence justifies.

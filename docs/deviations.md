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

## DEV-004 — the TLS adapter runs two probes, not one (2026-09-19)

**Issue.** `Pramana_Ledger_Spec.md` §3 names sslyze as the TLS sensor, and
§7.1 P4 requires "negotiated suite and group recorded — the ledger's input".
`src/ecdat/adapters/tls/` runs sslyze **and** an `openssl s_client` probe.

**Evidence.** sslyze 6.2.0 cannot report a hybrid post-quantum group. Its TLS
stack is nassl 5.4.0, whose key-type enum is exactly `DH, EC, X25519, X448,
RSA, DSA, RSA_PSS` — no ML-KEM member exists, so nothing can be reported.
Measured against the live Tier A endpoint: OpenSSL 3.5.8 negotiated
`X25519MLKEM768` with it; sslyze scanning the same endpoint listed only
classical curves. Full working in OI-017.

So §3's tool choice and §7.1's requirement are in conflict, and the
requirement is the load-bearing one: without the negotiated group there is no
§5.7 evidence, no clock ever stops, and a completed migration is invisible.

**Options.** (a) Drop the group requirement and band every surface from
offered suites — rejected: it makes BLEEDING permanent and unfalsifiable.
(b) Wait for nassl to add ML-KEM — rejected: it makes the ledger's central
claim depend on someone else's roadmap. (c) Patch or fork nassl — rejected:
maintaining a TLS stack is not this project's business. (d) Add a second,
minimal probe that reads the negotiated group from a modern OpenSSL — chosen.

**Impact.** `TlsProbeBundle` carries three captures: sslyze JSON, a
full-offer `s_client` handshake, and a classical-only `s_client` handshake.
The third is what makes a migration falsifiable — an endpoint that negotiates
hybrid *and* still completes when offered only classical has stopped nothing,
and that is the Tier A endpoint's actual state today.

sslyze keeps the job it is good at (certificate chain, accepted suites, curve
enumeration) and keeps its separate-process boundary, so the AGPL-3.0
reasoning in §3 is untouched. The visibility entry names the ceiling in words
on every run, so a reader is never left thinking the curve list was exhaustive.

`tools/prober/Dockerfile` pins the prober's own TLS stack for the same reason
OI-014 gives: a scanner whose results depend on the host distribution's
OpenSSL is not reproducible.

## DEV-007 — within-surface merge key drops `algorithm_family` from strict equality (2026-09-20)

**Issue.** `docs/architecture/ECDAT_Final_Architecture.md` Part 5 states the canonical asset key
as `(algorithm_family, parameters, purpose, scope_anchor)`, which reads as: two Findings must
match on `algorithm_family` exactly before they are even candidates to merge. `src/ecdat/
correlation/merge.py` (P6, within-surface merge) is separately required to handle two Findings
that *disagree* on `public_key_algorithm` for the same `scope_anchor` by producing one merged
`CryptoAsset` with a CONFLICTING field on that key — not two separate, individually-certain
single-Finding assets that are never compared to each other.

**Evidence.** These two requirements are in direct tension. If `algorithm_family` gates grouping
by strict equality, two Findings that disagree on it can never land in the same group by
construction — `_merge_field` never runs on `public_key_algorithm` for them, so the required
CONFLICTING outcome is structurally unreachable. The disagreement would instead surface as "two
unrelated assets", which is a *worse* epistemic claim than "one asset, disputed field": it hides
that both observations were made at the same location, and CLAUDE.md's R-MONOTONE rule ("more
evidence never creates unsupported certainty") cuts both ways — silently splitting one location's
conflicting observations into two individually-confident assets manufactures unsupported
*distinctness* exactly as much as picking a winner would manufacture unsupported *certainty*.

**Options.** (a) Keep `algorithm_family` in the strict key and accept that a disagreement on it
never produces a CONFLICTING field, only two separate assets — rejected: it is the less honest
representation of what was actually observed, for the reason above, and it is incompatible with
the explicit within-surface-merge behaviour this phase is required to implement. (b) Drop
`scope_anchor` from the key too, and merge on `parameters` alone, even across surfaces — rejected
outright: it directly violates the hard "never merge across surfaces" rule (Lock; CLAUDE.md;
Part 5), which this module's own tests guard (`tests/unit/correlation/test_merge.py::
test_different_surfaces_with_matching_algorithm_and_parameters_never_merge`). (c) Key on
`(parameters, scope_anchor)` only, and let `algorithm_family` — like every other field
(`subject`, `key_usage`, etc.) — flow through the ordinary per-field agree/CONFLICT merge path —
chosen. `parameters` (key size and/or curve) remains a strong same-object signal on its own in
every surface this task covers: an RSA key and an EC key do not coincidentally share a
`(size, curve)` shape, so genuinely different key material at one location still lands in
different assets in practice. `algorithm_family` becomes data the merge can be honestly wrong
about, which is the more conservative claim.

**Impact.** `src/ecdat/correlation/merge.py`'s grouping key (`MergeKey`) is `(parameters,
scope_anchor)`, not the full Part 5 four-tuple — `purpose` was already excluded per this task's
own scope (a raw adapter Finding does not populate it; see the module docstring). `CryptoAsset.
algorithm_family` (the plain convenience field added alongside this module, `src/ecdat/model/
asset.py`) is populated from the merged `public_key_algorithm` field only when that field is
*not* itself CONFLICTING; under disagreement it is `None` and the authoritative record is
`asset.fields["public_key_algorithm"].state == CONFLICTING`. `CryptoAsset.purpose` is populated
the same convenience-readback way, from whatever `fields["purpose"]` ends up being after an
ordinary (non-key) merge, if a Finding happens to populate it. Cross-surface merging remains
structurally impossible regardless of any of this, because `scope_anchor` stays in the key
unconditionally.

## DEV-011 — P11's KMS half built and recorded against LocalStack, not a real AWS account (2026-09-20)

**Issue.** `docs/build-plan.md` and `docs/PRAMANA_FINAL_2_Implementation_Plan_and_Rating.md` §3
both call for a real AWS KMS reader (`adapters/kms/`). CLAUDE.md's anti-hallucination rule
("PARSERS are written only against tests/fixtures/recorded/") requires that fixture to be a real,
observed API response, not documentation transcribed from memory — and no AWS account or
credentials exist anywhere in this environment.

**Evidence.** Checked directly before deciding anything: `aws` is not installed, `~/.aws/` does
not exist, no `AWS_*` environment variable is set, on either the Windows host or the Linux build
box (WSL). This was not assumed; it was checked and the negative result recorded here rather than
silently working around it.

**Options.** (a) Write the adapter against AWS's published API documentation only, without a
recorded fixture — rejected outright: this is exactly the "documentation instead of a fixture"
shortcut CLAUDE.md's anti-hallucination rules exist to forbid, and it is indistinguishable from
guessing the moment AWS's own JSON shape differs from the docs in some undocumented way (as it
already does for at least one field here — see below). (b) Skip the KMS half of P11 entirely,
as it had been until this session — a defensible, already-filed position, but the user explicitly
asked for a real credential test rather than continuing to skip it. (c) Provision LocalStack (a
real, running open-source implementation of the AWS API surface) in the Linux build box, and hit
it with the real, unmodified `aws` CLI — chosen, with the user's explicit sign-off after being
asked directly (three options were put to them: provide real credentials, use LocalStack, or
leave it skipped).

**Impact.** Every fixture under `tests/fixtures/recorded/aws-kms/localstack-3.0.2/` is a real
HTTP response from a real running service, not invented — but it is not a genuine AWS account,
and that distinction is stated in that directory's own README, in
`adapters/kms/adapter.py`'s module docstring, and in `docs/build-plan.md`'s progress table, every
place the fact matters. `adapters/kms/adapter.py`'s live code path (`build_*_argv`,
`live_kms_runner`) is the real, unmodified `aws kms` CLI invocation shape; LocalStack is reached
only via the `--endpoint-url` option a real account run simply omits, so nothing about the
adapter's own code is LocalStack-specific. One genuine, measured finding came out of using a real
implementation rather than documentation: LocalStack's `latest` image tag now refuses to start at
all without a paid auth token (`License activation failed`, exit 55) — recorded in the fixture
README as a fact about the image at time of recording, and `:3.0` used instead as the last tag
confirmed to run the free/community KMS emulation.

## DEV-012 — P14's agility fields built without new rule_ids (2026-09-21)

**Issue.** `docs/build-plan.md` P14 adopts three agility fields (`algorithm_selection`,
`hybrid_capable`, `provider_pluggable`) narrowed from an outside review's proposal. None of the
three appears anywhere in the canonical architecture docs (`grep -rn "algorithm_selection\|
hybrid_capable\|provider_pluggable" docs/architecture/` returns nothing) — they are new,
build-plan-level work, not spec-named concepts. CLAUDE.md's anti-hallucination rule forbids
adding a `rule_id` to `src/ecdat/rules/registry.py` "from memory": every entry there must cite a
literal Lock or harness §14–16 section, and none names these three fields, so no citable
`rule_id` exists for them.

**Resolution.** `src/ecdat/agility/evidence.py` builds all three without `model.field_value
.derive()` and without setting `derived_from` on the resulting `FieldValue`, so `FieldValue`'s
own validator (`derived_from` set requires `rule_id`) is never in a position to need one:

- `algorithm_selection` and `hybrid_capable` are **relabellings**, not new inferences: each reads
  one existing source-adapter field (`algorithm_literal_at_call_site` / `algorithm_argument` from
  `source-semgrep`; `negotiated_group` from `tls-endpoint`) and names its already-observed state
  under a new enum value, copying that field's `state` and `evidence_refs` verbatim. No new
  epistemic content is introduced, so no rule governs the mapping — the same principle
  `model/temporal.py`'s `_earliest()` already applies to `possible_since` (a `min()` selection is
  not a derivation).
- `provider_pluggable` **is** a genuine epistemic downgrade: `source-semgrep`'s
  `provider_argument` is `KNOWN` (the source text literally names a provider argument at that
  call site), but the claim "this key's provider is pluggable" is weaker than what was observed
  — a call site that *can* take a provider argument is not proof that a second, actual provider is
  registered and reachable at runtime (the field's own module comment: "whether that is the
  provider that executes is a different question this surface cannot answer"). The result is
  capped to `INFERRED` directly (never `KNOWN`, matching build-plan.md P14's own text: "INFERRED
  ceiling"), with `evidence_refs` still copied from the source field so the claim remains
  traceable, but `derived_from` is left empty rather than cited against an invented `rule_id`.

**Impact.** All three agility fields are fully traceable to their source evidence
(`evidence_refs` never dropped) and replay identically (pure functions of `CryptoAsset.fields`,
no clock, no randomness), but they are not currently checkable by `model.field_value.derive()`'s
own R-DERIVE enforcement path the way a registered-rule_id derivation is. If build-plan.md P14's
work is later folded into a canonical architecture doc with a named rule for
`provider_pluggable`'s downgrade, register that rule_id in `rules/registry.py` and route
`provider_pluggable` through `derive()` at that point — filed as OI-018 alongside this entry.

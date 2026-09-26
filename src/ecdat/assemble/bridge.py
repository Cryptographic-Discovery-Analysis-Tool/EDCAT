"""Scan -> ledger bridge (build-plan.md P21).

Until this module existed, nothing in `src/` constructed a `LedgerSubject`:
adapters produced Findings, the ledger consumed hand-built fixture subjects,
and the two halves never met. This is the glue, and it adds no judgement of
its own -- every crypto function comes from `function/classifier.py` (§5.1),
every clock-stopping decision from `adapters/tls/adapter.py::
migration_evidence_from` (§5.7), and every date from a field an adapter
actually observed.

What it does, per adapter:

* `tls-endpoint` -> a `NegotiatedHandshake` -> `classify_handshake` -> the
  key-establishment context (KNOWN) and the server-certificate
  authentication context (KNOWN). `first_observed` is the probe's own
  observation date (KNOWN, on the traffic path -- the only input §5.2 lets
  confirm). `not_before` is joined from a `certs-x509` finding only when the
  DER hash matches exactly (the one registered identity rule,
  IDENTITY-CERT-DER-001). Migration evidence is attached to the
  key-establishment context only.
* `certs-x509` -> `CertificateKeyUsage` -> `classify_key_usage` -> INFERRED
  capability contexts, with `not_before` bounding possibility only. A
  certificate already observed in a handshake is not emitted a second time as
  a capability row; that is recorded, not silent.
* `source-semgrep` -> `SourceCallSite` -> `classify_call_site`. A literal
  algorithm is passed through; a non-literal one is not (PAY-001: the
  function is observed, the algorithm is not). No traffic-path date exists
  for a call site, so none is invented: the row's start stays unknown and
  the closure engine asks for it.
* every other adapter -> nothing yet, and each is listed in `unassembled`
  with the reason. Package presence yields no context by design (§5.1).

Data class is the one input no scanner can observe. `Declarations` is where
a person states it, per surface or per asset, and who said so; it reaches
the ledger as a DECLARED binding through `LedgerSubject.binding_key`.
Nothing declared -> no binding -> UNBOUNDED with a closure task, never a
default lifetime.
"""
from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Iterable

import yaml
from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from ecdat.adapters.base import AdapterRunResult
from ecdat.adapters.tls.adapter import migration_evidence_from
from ecdat.function.classifier import (
    CertificateKeyUsage,
    NegotiatedHandshake,
    SourceCallSite,
    classify_call_site,
    classify_handshake,
    classify_key_usage,
)
from ecdat.model.epistemic import EpistemicState
from ecdat.model.field_value import FieldValue
from ecdat.model.finding import Finding
from ecdat.model.temporal import MigrationEvidence, TemporalEvidence
from ecdat.model.usage_context import UsageContext
from ecdat.risk.run import LedgerSubject


# --- declarations: the input a person supplies ------------------------------


class BindingDeclaration(BaseModel):
    """"This surface / asset carries data of class X" -- stated by someone.

    `data_class` names a row in data/data_lifetime.yaml, so the lifetime
    that reaches the ledger is always a cited one. `declared_by` is
    required: a declaration with no author is indistinguishable from a
    guess."""

    model_config = ConfigDict(frozen=True)

    surface: str | None = None
    asset: str | None = None
    data_class: str
    declared_by: str

    @field_validator("data_class", "declared_by")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be blank")
        return value

    @model_validator(mode="after")
    def _targets_something(self) -> "BindingDeclaration":
        if not self.surface and not self.asset:
            raise ValueError("a declaration must name a surface or an asset")
        return self


class Declarations(BaseModel):
    model_config = ConfigDict(frozen=True)

    bindings: tuple[BindingDeclaration, ...] = ()

    @classmethod
    def load(cls, path: Path | str) -> "Declarations":
        document = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        return cls.model_validate(document)

    def binding_for(self, *, surface_id: str, asset_id: str) -> BindingDeclaration | None:
        """An asset-level declaration beats a surface-level one: it is the
        more specific statement."""
        for declaration in self.bindings:
            if declaration.asset and declaration.asset == asset_id:
                return declaration
        for declaration in self.bindings:
            if declaration.surface and declaration.surface == surface_id:
                return declaration
        return None


# --- output -----------------------------------------------------------------


class Unassembled(BaseModel):
    """A finding (or a whole adapter run) that did not become a ledger
    subject, and why. Nothing disappears between the scan and the ledger
    without being named here."""

    model_config = ConfigDict(frozen=True)

    adapter_id: str
    finding_id: str | None
    reason: str


class Assembly(BaseModel):
    model_config = ConfigDict(frozen=True)

    subjects: tuple[LedgerSubject, ...]
    unassembled: tuple[Unassembled, ...]

    def to_subjects_document(self) -> dict:
        """The same shape as tests/fixtures/ledger/subjects.json, so an
        assembled file drops straight into `ecdat ledger-run --subjects` and
        the dashboard."""
        return {"subjects": [s.model_dump(mode="json") for s in self.subjects]}


# --- helpers ----------------------------------------------------------------


def _known(finding: Finding, name: str):
    fv = finding.fields.get(name)
    if fv is None or fv.state != EpistemicState.KNOWN or fv.value in (None, "", ()):
        return None
    return fv.value


def _refs(finding: Finding, name: str) -> tuple[str, ...]:
    fv = finding.fields.get(name)
    return fv.evidence_refs if fv is not None and fv.evidence_refs else finding.evidence_refs


def _cert_asset_id(der_sha256: str) -> str:
    return f"cert:{der_sha256[:16]}"


def _observed_on(result: AdapterRunResult) -> date:
    return result.context.observed_at.date()


class _CertIndex:
    """`der_sha256 -> (not_before, evidence_refs)` from every certs-x509
    finding in the run set -- the only join this module makes across
    surfaces, and only on an exact DER hash."""

    def __init__(self, results: Iterable[AdapterRunResult]):
        self._by_der: dict[str, tuple[date, tuple[str, ...]]] = {}
        for result in results:
            if result.adapter_id != "certs-x509":
                continue
            for finding in result.findings:
                der = _known(finding, "der_sha256")
                not_before = _known(finding, "not_before")
                if der and not_before:
                    self._by_der[der] = (
                        date.fromisoformat(not_before),
                        _refs(finding, "not_before"),
                    )

    def not_before(self, der: str | None) -> FieldValue[date] | None:
        if not der or der not in self._by_der:
            return None
        day, refs = self._by_der[der]
        return FieldValue[date](value=day, state=EpistemicState.KNOWN, evidence_refs=refs)


def _subject(
    context: UsageContext,
    temporal: TemporalEvidence,
    declarations: Declarations,
    migrations: tuple[MigrationEvidence, ...] = (),
) -> LedgerSubject:
    declaration = declarations.binding_for(surface_id=context.surface_id, asset_id=context.asset_id)
    return LedgerSubject(
        usage_context=context,
        temporal=temporal,
        binding_key=declaration.data_class if declaration else None,
        binding_source_ref=(
            f"declared by {declaration.declared_by}" if declaration else "operator declaration"
        ),
        migrations=migrations,
    )


# --- per-adapter assembly ---------------------------------------------------


def _from_tls(
    result: AdapterRunResult,
    certs: _CertIndex,
    declarations: Declarations,
    seen_certs: set[str],
    unassembled: list[Unassembled],
) -> list[LedgerSubject]:
    if not result.findings:
        unassembled.append(
            Unassembled(adapter_id=result.adapter_id, finding_id=None, reason="probe produced no finding")
        )
        return []
    finding = result.findings[0]
    suite = _known(finding, "negotiated_cipher_suite")
    if suite is None:
        unassembled.append(
            Unassembled(
                adapter_id=result.adapter_id,
                finding_id=finding.finding_id,
                reason="negotiated handshake not observed; no KNOWN context to classify",
            )
        )
        return []

    observed_on = _observed_on(result)
    der = _known(finding, "der_sha256")
    evidence_id = (finding.evidence_refs or ("",))[0]
    observation = NegotiatedHandshake(
        surface_id=finding.surface,
        vantage=_known(finding, "probe_vantage") or "unknown",
        observed_at=observed_on,
        cipher_suite=suite,
        negotiated_group=_known(finding, "negotiated_group"),
        kex_asset_id=f"tls-kex:{finding.surface}",
        cert_asset_id=_cert_asset_id(der) if der else None,
        evidence_id=evidence_id,
    )
    if der:
        seen_certs.add(der)

    temporal = TemporalEvidence(
        surface_id=finding.surface,
        observation_ts=observed_on,
        first_observed=FieldValue[date](
            value=observed_on,
            state=EpistemicState.KNOWN,
            evidence_refs=_refs(finding, "negotiated_cipher_suite"),
        ),
        not_before=certs.not_before(der),
    )
    migration = migration_evidence_from(result, observed_on=observed_on)

    migrations = (migration,) if migration is not None else ()
    subjects = []
    for context in classify_handshake(observation):
        is_kex = context.usage_context_id.endswith("|kex")
        subjects.append(
            _subject(context, temporal, declarations, migrations=migrations if is_kex else ())
        )

    # The classical-only probe is a second, independent observation on the
    # same surface: a client that offers no hybrid group. When it KNOWN-ly
    # succeeded, classical key establishment is still being negotiated here
    # -- that path is harvestable today regardless of what a hybrid-capable
    # client gets, and it is exactly the "hybrid negotiated, classical still
    # accepted" case §5.5 qualifies as PARTIAL. Dropping it would report the
    # surface as SAFE because the *best* client is safe.
    classical_group = _known(finding, "classical_group")
    if _known(finding, "classical_still_accepted") is True and classical_group:
        classical_observation = observation.model_copy(
            update={"negotiated_group": classical_group, "cert_asset_id": None}
        )
        for context in classify_handshake(classical_observation):
            if not context.usage_context_id.endswith("|kex"):
                continue
            context = context.model_copy(
                update={
                    "usage_context_id": context.usage_context_id + "|classical-client",
                    "protocol_context": f"classical-only client: {classical_group}",
                }
            )
            classical_temporal = temporal.model_copy(
                update={
                    "first_observed": FieldValue[date](
                        value=observed_on,
                        state=EpistemicState.KNOWN,
                        evidence_refs=_refs(finding, "classical_still_accepted"),
                    )
                }
            )
            subjects.append(
                _subject(context, classical_temporal, declarations, migrations=migrations)
            )

    # DEV-013: the individual group-probe path (adapters/tls/adapter.py)
    # answers "does this endpoint ACCEPT this hybrid group", one probe per
    # group -- broader than the single negotiated_group above, which only
    # ever reports what the endpoint PREFERS when everything is offered.
    # Each accepted hybrid group OTHER than the preferred one is a genuinely
    # separate observation (a handshake that offered only that group and
    # completed) and gets its own subject, so the recommendation engine and
    # the exposure ledger see every group this endpoint will actually do
    # hybrid key exchange with -- not only the one it happens to prefer.
    accepted_field = finding.fields.get("hybrid_kex_accepted_groups")
    if accepted_field is not None and accepted_field.state == EpistemicState.KNOWN:
        classical_field = finding.fields.get("classical_still_accepted")
        if classical_field is not None and classical_field.state == EpistemicState.KNOWN:
            group_classical_accepted = bool(classical_field.value)
            group_status = EpistemicState.KNOWN
        else:
            # Same conservative default `migration_evidence_from` uses: an
            # untested classical path is assumed still open, so the clock
            # keeps running until someone actually checks it.
            group_classical_accepted = True
            group_status = EpistemicState.INFERRED
        for group in accepted_field.value:
            if group == observation.negotiated_group:
                continue  # already the subject the main pass above emitted
            group_refs = _refs(finding, f"group_accepted_{group}")
            group_observation = observation.model_copy(
                update={
                    "negotiated_group": group,
                    "cert_asset_id": None,
                    "evidence_id": (group_refs or (evidence_id,))[0],
                }
            )
            group_migration = MigrationEvidence(
                surface_id=finding.surface,
                vantage=observation.vantage,
                observed_at=observed_on,
                negotiated_group=group,
                classical_still_accepted=group_classical_accepted,
                status=group_status,
                evidence_refs=group_refs or (evidence_id,),
            )
            for context in classify_handshake(group_observation):
                if not context.usage_context_id.endswith("|kex"):
                    continue
                context = context.model_copy(
                    update={
                        "usage_context_id": context.usage_context_id + f"|group-probe-{group}",
                        "protocol_context": f"individual-group probe: {group} (accepted)",
                    }
                )
                group_temporal = temporal.model_copy(
                    update={
                        "first_observed": FieldValue[date](
                            value=observed_on,
                            state=EpistemicState.KNOWN,
                            evidence_refs=group_refs or (evidence_id,),
                        )
                    }
                )
                subjects.append(
                    _subject(
                        context, group_temporal, declarations, migrations=(group_migration,)
                    )
                )
    return subjects


def _from_certs(
    result: AdapterRunResult,
    declarations: Declarations,
    seen_certs: set[str],
    unassembled: list[Unassembled],
) -> list[LedgerSubject]:
    subjects = []
    observed_on = _observed_on(result)
    for finding in result.findings:
        der = _known(finding, "der_sha256")
        if der and der in seen_certs:
            unassembled.append(
                Unassembled(
                    adapter_id=result.adapter_id,
                    finding_id=finding.finding_id,
                    reason=(
                        "same certificate (DER match) already observed in a TLS handshake; "
                        "the observed context supersedes a keyUsage capability row"
                    ),
                )
            )
            continue
        bits = _known(finding, "key_usage")
        if not bits:
            unassembled.append(
                Unassembled(
                    adapter_id=result.adapter_id,
                    finding_id=finding.finding_id,
                    reason="certificate states no keyUsage; no capability context to classify",
                )
            )
            continue
        observation = CertificateKeyUsage(
            surface_id=finding.surface,
            asset_id=_cert_asset_id(der) if der else finding.finding_id,
            evidence_id=(finding.evidence_refs or ("",))[0],
            key_usage=tuple(bits),
        )
        not_before = _known(finding, "not_before")
        temporal = TemporalEvidence(
            surface_id=finding.surface,
            observation_ts=observed_on,
            not_before=(
                FieldValue[date](
                    value=date.fromisoformat(not_before),
                    state=EpistemicState.KNOWN,
                    evidence_refs=_refs(finding, "not_before"),
                )
                if not_before
                else None
            ),
        )
        for context in classify_key_usage(observation):
            subjects.append(_subject(context, temporal, declarations))
    return subjects


def _from_source(
    result: AdapterRunResult,
    declarations: Declarations,
    unassembled: list[Unassembled],
) -> list[LedgerSubject]:
    subjects = []
    observed_on = _observed_on(result)
    for finding in result.findings:
        api_class = _known(finding, "api_class")
        path = _known(finding, "path")
        line = _known(finding, "line")
        if not api_class or not path or line is None:
            unassembled.append(
                Unassembled(
                    adapter_id=result.adapter_id,
                    finding_id=finding.finding_id,
                    reason="not a crypto call site (e.g. a configuration-binding declaration)",
                )
            )
            continue
        surface_id = f"source:{path}"
        observation = SourceCallSite(
            surface_id=surface_id,
            asset_id=f"src:{path}:{line}",
            api_class=api_class,
            location=f"{path}:{line}",
            evidence_id=(finding.evidence_refs or ("",))[0],
            # Only a literal written at the call site is an observed
            # algorithm; a propagated or non-literal one is not (PAY-001).
            transformation=(
                _known(finding, "algorithm")
                if _known(finding, "algorithm_literal_at_call_site") is True
                else None
            ),
        )
        # A call site has no traffic path: nothing here confirms when it
        # started carrying data, and nothing is invented to fill that in.
        temporal = TemporalEvidence(surface_id=surface_id, observation_ts=observed_on)
        for context in classify_call_site(observation):
            subjects.append(_subject(context, temporal, declarations))
    return subjects


# --- entry point ------------------------------------------------------------


def assemble(
    results: Iterable[AdapterRunResult], *, declarations: Declarations | None = None
) -> Assembly:
    results = list(results)
    declarations = declarations or Declarations()
    certs = _CertIndex(results)
    seen_certs: set[str] = set()
    unassembled: list[Unassembled] = []
    subjects: list[LedgerSubject] = []

    # TLS first, so certificates it observed are known before the
    # certificate reader's capability rows are considered.
    ordered = sorted(results, key=lambda r: 0 if r.adapter_id == "tls-endpoint" else 1)
    for result in ordered:
        if result.adapter_id == "tls-endpoint":
            subjects += _from_tls(result, certs, declarations, seen_certs, unassembled)
        elif result.adapter_id == "certs-x509":
            subjects += _from_certs(result, declarations, seen_certs, unassembled)
        elif result.adapter_id == "source-semgrep":
            subjects += _from_source(result, declarations, unassembled)
        else:
            reason = (
                "package presence is capability, never usage -- no context by design (§5.1)"
                if result.adapter_id == "packages-trivy"
                else f"no classifier path for {result.adapter_id} yet"
            )
            unassembled.append(
                Unassembled(adapter_id=result.adapter_id, finding_id=None, reason=reason)
            )

    return Assembly(subjects=tuple(subjects), unassembled=tuple(unassembled))

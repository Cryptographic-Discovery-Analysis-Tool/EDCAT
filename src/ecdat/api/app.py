"""FastAPI read API over ledger rows (Pramana_Ledger_Spec.md §7.2 phase 7).

Presentation and orchestration only. Every number this API returns comes out
of `risk/`; nothing here decides a band, weights anything, or holds a
threshold. If a value appears on screen that this module computed, that is a
bug -- the dashboard's job is to show the ledger, not to be a second one.

Two deliberate awkwardnesses, both there to keep assumptions visible:

* `scenario` is a required query parameter. There is no "the answer"; there is
  an answer per Z date, and the caller has to say which one it is asking about.
* `rollout_y_days` is required too, with no default. data/scenarios.yaml
  records that §5.4 names the knob and states no number, so a default here
  would put an uncited constant behind every ROTATE_BEFORE_Z deadline in the
  UI. The dashboard shows it as a control the operator owns.
"""
from __future__ import annotations

import json
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Callable

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from ecdat.closure.engine import closure_queue, tasks_for
from ecdat.context.binding import Lifetime
from ecdat.export.cyclonedx import build_bom
from ecdat.model.epistemic import EpistemicState
from ecdat.recommend.engine import (
    NoCitedOptionError,
    Profile,
    hybrid_rationale,
    recommend,
)
from ecdat.risk.record import CalculationRecord, ExposureBand, rank_key, replay
from ecdat.risk.run import GroverFlag, LedgerSubject, RunResult, evaluate_run
from ecdat.risk.scenarios import (
    CaptureAssumption,
    CaptureMode,
    NoCitedScenarioError,
    Policy,
    Scenario,
)

SubjectsProvider = Callable[[], list[LedgerSubject]]

#: The fixture the dashboard opens with when nothing else is configured.
#: Clearly labelled in the UI as a fixture: it is constructed evidence, not a
#: scan of anything, and no adapter has run.
DEFAULT_SUBJECTS = (
    Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "ledger" / "subjects.json"
)


def load_subjects(path: Path) -> list[LedgerSubject]:
    document = json.loads(path.read_text(encoding="utf-8"))
    return [LedgerSubject.model_validate(row) for row in document["subjects"]]


def _policy(
    capture: CaptureMode, since: date | None, accept_inferred: bool, rollout_y_days: int
) -> Policy:
    try:
        return Policy(
            capture_assumption=CaptureAssumption(mode=capture, since=since),
            rollout_Y_default=Lifetime(days=rollout_y_days),
            accept_inferred_inputs=accept_inferred,
        )
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error


def _scenario(scenario_id: str) -> Scenario:
    try:
        return Scenario.load(scenario_id)
    except NoCitedScenarioError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error


def _row(record: CalculationRecord) -> dict[str, Any]:
    """One ledger row, flattened for display. No input is summarised away that
    a reader would need in order to disagree with the band."""
    context = record.inputs.usage_context
    return {
        "record_id": record.record_id,
        "usage_context_id": record.usage_context_id,
        "asset_id": context.asset_id,
        "surface_id": context.surface_id,
        "protocol_context": context.protocol_context,
        "function": record.function.value if record.function else "UNKNOWN",
        "function_status": context.function.state.value,
        "algorithm": context.algorithm.value if context.algorithm else None,
        "algorithm_status": (
            context.algorithm.state.value if context.algorithm else EpistemicState.UNKNOWN.value
        ),
        "band": record.band.value,
        "qualifiers": [q.value for q in record.qualifiers],
        "windows": [{"start": w.start.isoformat(), "end": w.end.isoformat(), "days": w.days} for w in record.windows],
        "deadline": record.deadline.isoformat() if record.deadline else None,
        "conditional_band": record.conditional_band.value if record.conditional_band else None,
        "reason": record.reason,
        "capture_sentence": record.capture_sentence,
        "scenario_id": record.scenario_id,
        "ledger": "authentication" if record.rule_version.startswith("LEDGER-AUTH") else "confidentiality",
        "X": str(record.X) if record.X else None,
        "A": str(record.A) if record.A else None,
        "M": record.M.isoformat() if record.M else None,
        "start_possible": record.start_possible.isoformat() if record.start_possible else None,
        "start_confirmed": record.start_confirmed.isoformat() if record.start_confirmed else None,
    }


def _evidence_card(record: CalculationRecord) -> dict[str, Any]:
    """§7.2's "Evidence card": everything the band rests on, plus proof that
    re-running the calculation still produces it."""
    replayed = replay(record)
    return {
        **_row(record),
        "evidence_refs": [
            {"id": ref.id, "status": ref.status, "ts": ref.ts.isoformat() if ref.ts else None}
            for ref in record.evidence_refs
        ],
        "temporal_status": {
            name: state.value for name, state in record.inputs.temporal.status_per_field.items()
        },
        "migrations": [
            {
                "vantage": m.vantage,
                "observed_at": m.observed_at.isoformat(),
                "negotiated_group": m.negotiated_group,
                "classical_still_accepted": m.classical_still_accepted,
                "status": m.status.value,
                "stops_the_clock": m.stops_the_clock,
            }
            for m in record.inputs.migrations
        ],
        "binding": (
            {
                "classification": record.inputs.binding.classification,
                "cited_table_row": record.inputs.binding.cited_table_row,
                "source_ref": record.inputs.binding.source_ref,
                "status": record.inputs.binding.status.value,
            }
            if record.inputs.binding
            else None
        ),
        "policy": {
            "capture_assumption": str(record.capture_assumption),
            "accept_inferred_inputs": record.policy_snapshot.accept_inferred_inputs,
            "accept_declared_go_live": record.policy_snapshot.accept_declared_go_live,
            "rollout_Y": str(record.policy_snapshot.rollout_Y_default),
        },
        "provenance": {
            "rule_version": record.rule_version,
            "calc_version": record.calc_version,
            "inputs_sha256": record.inputs_sha256,
        },
        "replay": {
            "band": replayed.band.value,
            "matches": replayed.band == record.band,
            "hash_stable": replayed.inputs_sha256 == record.inputs_sha256,
        },
        "closure_tasks": [task.model_dump(mode="json") for task in tasks_for(record)],
        "recommendation": recommend(record.inputs.usage_context).model_dump(mode="json"),
    }


def _coverage(result: RunResult) -> dict[str, Any]:
    """§7.2's "Coverage" panel.

    What this can honestly report today is the evidence status of what reached
    the ledger. The adapter visibility matrix -- what each sensor looked at and
    what it skipped -- is P6 work and no adapter feeds this yet, so the panel
    says so rather than showing an empty table that reads as full coverage.
    """
    by_status: dict[str, int] = {}
    surfaces: dict[str, set[str]] = {}
    for record in result.records:
        state = record.inputs.usage_context.function.state.value
        by_status[state] = by_status.get(state, 0) + 1
        surfaces.setdefault(record.inputs.usage_context.surface_id, set()).add(state)

    bands: dict[str, int] = {}
    for record in result.records:
        bands[record.band.value] = bands.get(record.band.value, 0) + 1

    return {
        "rows": len(result.records),
        "by_function_status": by_status,
        "by_band": bands,
        "surfaces": {surface: sorted(states) for surface, states in sorted(surfaces.items())},
        "grover_flags": [flag.model_dump(mode="json") for flag in result.grover_flags],
        "skipped": list(result.skipped),
        "adapter_visibility": {
            "available": False,
            "note": (
                "No adapter has run. Per-sensor coverage -- what was scanned, "
                "what was skipped, what is unsupported -- arrives with P6 and "
                "is not shown as empty here, because an empty coverage table "
                "reads as full coverage."
            ),
        },
    }


def create_app(
    subjects_provider: SubjectsProvider | None = None,
    *,
    static_dir: Path | None = None,
) -> FastAPI:
    app = FastAPI(
        title="Pramana",
        description="Read API over the exposure ledger. Presentation only.",
        version="0.1.0",
    )
    provider: SubjectsProvider = subjects_provider or (lambda: load_subjects(DEFAULT_SUBJECTS))

    def run(
        scenario_id: str,
        capture: CaptureMode,
        since: date | None,
        accept_inferred: bool,
        rollout_y_days: int,
        as_of: date | None,
    ) -> RunResult:
        return evaluate_run(
            provider(),
            scenario=_scenario(scenario_id),
            policy=_policy(capture, since, accept_inferred, rollout_y_days),
            as_of=as_of or date.today(),
        )

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "subjects": len(provider())}

    @app.get("/api/scenarios")
    def scenarios() -> dict[str, Any]:
        return {
            "scenarios": [
                {
                    "id": s.id,
                    "label": s.label,
                    "z_date": s.z_date.isoformat(),
                    "basis_citation": s.basis_citation,
                }
                for s in Scenario.load_all()
            ],
            "capture_modes": [mode.value for mode in CaptureMode],
            "rollout_y_note": (
                "No cited default for Y exists (data/scenarios.yaml). "
                "Whatever you set here is your assumption, and it is recorded "
                "on every row it affects."
            ),
        }

    @app.get("/api/ledger")
    def ledger_rows(
        scenario: str = Query(...),
        capture: CaptureMode = Query(CaptureMode.SINCE_CONFIRMED),
        since: date | None = Query(None),
        accept_inferred: bool = Query(False),
        rollout_y_days: int = Query(..., ge=0),
        as_of: date | None = Query(None),
    ) -> dict[str, Any]:
        result = run(scenario, capture, since, accept_inferred, rollout_y_days, as_of)
        ordered = sorted(result.records, key=lambda r: rank_key(r))
        return {
            "scenario_id": result.scenario_id,
            "as_of": result.as_of.isoformat(),
            "rows": [_row(record) for record in ordered],
            "counts": {
                band.value: sum(1 for r in result.records if r.band == band)
                for band in ExposureBand
                if any(r.band == band for r in result.records)
            },
        }

    @app.get("/api/records/{record_id:path}")
    def record_detail(
        record_id: str,
        scenario: str = Query(...),
        capture: CaptureMode = Query(CaptureMode.SINCE_CONFIRMED),
        since: date | None = Query(None),
        accept_inferred: bool = Query(False),
        rollout_y_days: int = Query(..., ge=0),
        as_of: date | None = Query(None),
    ) -> dict[str, Any]:
        result = run(scenario, capture, since, accept_inferred, rollout_y_days, as_of)
        for record in result.records:
            if record.record_id == record_id:
                return _evidence_card(record)
        raise HTTPException(status_code=404, detail=f"no record {record_id!r} in this run")

    @app.get("/api/closure")
    def closure(
        scenario: str = Query(...),
        capture: CaptureMode = Query(CaptureMode.SINCE_CONFIRMED),
        since: date | None = Query(None),
        accept_inferred: bool = Query(False),
        rollout_y_days: int = Query(..., ge=0),
        as_of: date | None = Query(None),
    ) -> dict[str, Any]:
        result = run(scenario, capture, since, accept_inferred, rollout_y_days, as_of)
        return {
            "scenario_id": result.scenario_id,
            "tasks": [task.model_dump(mode="json") for task in closure_queue(result.records)],
        }

    @app.get("/api/coverage")
    def coverage(
        scenario: str = Query(...),
        capture: CaptureMode = Query(CaptureMode.SINCE_CONFIRMED),
        since: date | None = Query(None),
        accept_inferred: bool = Query(False),
        rollout_y_days: int = Query(..., ge=0),
        as_of: date | None = Query(None),
    ) -> dict[str, Any]:
        return _coverage(run(scenario, capture, since, accept_inferred, rollout_y_days, as_of))

    @app.get("/api/profiles")
    def profiles() -> dict[str, Any]:
        return {
            "profiles": [
                {
                    "key": p.key,
                    "label": p.label,
                    "parameter_sets": p.parameter_sets,
                    "firmware_signing": p.firmware_signing,
                    "citation": p.citation,
                }
                for p in Profile.load_all()
            ],
            "default": Profile.default().key,
        }

    @app.get("/api/recommendations")
    def recommendations(profile: str | None = Query(None)) -> dict[str, Any]:
        """Part 8. Keyed on purpose, so it needs no scenario and no Z date --
        what to move to does not depend on when Z is, only on what the key is
        doing."""
        try:
            chosen = Profile.load(profile) if profile else Profile.default()
        except NoCitedOptionError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        results = [recommend(subject, profile=chosen) for subject in provider()]
        return {
            "profile": {
                "key": chosen.key,
                "label": chosen.label,
                "citation": chosen.citation,
            },
            "hybrid_rationale": hybrid_rationale(),
            "recommendations": [r.model_dump(mode="json") for r in results],
            "undetermined": [
                r.usage_context_id for r in results if r.insufficient_evidence
            ],
        }

    @app.get("/api/export")
    def export(
        capture: CaptureMode = Query(CaptureMode.SINCE_CONFIRMED),
        since: date | None = Query(None),
        accept_inferred: bool = Query(False),
        rollout_y_days: int = Query(..., ge=0),
        as_of: date | None = Query(None),
    ) -> JSONResponse:
        """Every scenario in one document (ADR-005 decision 2)."""
        records: list[CalculationRecord] = []
        for scenario in Scenario.load_all():
            records.extend(
                run(scenario.id, capture, since, accept_inferred, rollout_y_days, as_of).records
            )
        document = build_bom(records, timestamp=datetime.now(timezone.utc))
        return JSONResponse(
            content=document,
            headers={"Content-Disposition": 'attachment; filename="pramana-cbom.json"'},
        )

    bundle = static_dir or (Path(__file__).resolve().parents[3] / "ui" / "dashboard" / "dist")
    if bundle.is_dir():
        app.mount("/assets", StaticFiles(directory=bundle / "assets"), name="assets")

        @app.get("/")
        def index() -> FileResponse:
            return FileResponse(bundle / "index.html")

    return app


app = create_app()

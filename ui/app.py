"""Minimal demo UI for ECDAT.

Wraps the existing `ecdat scan` path and, if a sibling `ecdat-harness`
checkout is present, the harness scorer -- both already tested and used from
the command line. This file adds no detection, correlation, risk, or
recommendation logic of its own (CLAUDE.md: "No LLM calls in any detection,
correlation, risk, or recommendation path" -- there is no model here either;
it is presentation only, over run documents `ecdat scan` already produces).

Run:
    python ui/app.py
Then open http://127.0.0.1:5000/
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from flask import Flask, render_template, request

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from ecdat.adapters.base import ScanTarget  # noqa: E402
from ecdat.cli import ADAPTERS, _run_document  # noqa: E402
from ecdat.model.evidence import ConfidenceBasis  # noqa: E402

# Harness lives in a sibling checkout, not inside this repo (CLAUDE.md: no
# harness identifiers inside src/ or rules/ -- this is neither). Scoring is
# best-effort: the UI works without it, just without the ground-truth panel.
HARNESS_ROOT = REPO_ROOT.parent / "ecdat-harness"
_score_run = None
if (HARNESS_ROOT / "harness" / "eval" / "score_run.py").exists():
    sys.path.insert(0, str(HARNESS_ROOT / "harness" / "eval"))
    from score_run import score_run as _score_run  # type: ignore  # noqa: E402

FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "recorded" / "semgrep" / "1.99.0" / "ecdat-rules"

app = Flask(__name__)


def _available_inputs() -> list[dict[str, str]]:
    """Recorded semgrep outputs this adapter can replay (CLAUDE.md: never parse
    live tool output that isn't first recorded to tests/fixtures/recorded/)."""
    if not FIXTURES_DIR.exists():
        return []
    return [
        {"path": str(p), "name": p.name}
        for p in sorted(FIXTURES_DIR.glob("*.raw.json"))
    ]


DEFAULT_JUSTIFICATION = (
    "no cited confidence table exists for semgrep yet (OI-004); 0.5 chosen as "
    "a neutral placeholder pending Final Architecture Part 3"
)

STATE_ORDER = {
    "KNOWN": 0,
    "INFERRED": 1,
    "DECLARED": 2,
    "CONFLICTING": 3,
    "UNKNOWN": 4,
    "NOT_OBSERVED": 5,
    "NOT_APPLICABLE": 6,
}


@app.route("/", methods=["GET"])
def index():
    return render_template(
        "index.html",
        inputs=_available_inputs(),
        adapters=sorted(ADAPTERS),
        default_justification=DEFAULT_JUSTIFICATION,
        harness_available=_score_run is not None,
        harness_root=str(HARNESS_ROOT),
        result=None,
    )


@app.route("/scan", methods=["POST"])
def scan():
    adapter_id = request.form["adapter"]
    input_path = request.form["input_path"]
    target_id = request.form["target_id"].strip() or "demo-target"
    confidence = float(request.form["confidence"])
    justification = request.form["justification"].strip() or DEFAULT_JUSTIFICATION
    do_score = request.form.get("score") == "on"

    adapter_class = ADAPTERS[adapter_id]
    basis = ConfidenceBasis(source="ADAPTER_DECLARED", justification=justification)
    adapter = adapter_class(base_confidence=confidence, confidence_basis=basis)
    run_result = adapter.run(ScanTarget(target_id=target_id, locator=input_path))
    document = _run_document(run_result)

    for finding in document["findings"]:
        finding["fields"].sort(key=lambda f: STATE_ORDER.get(f["epistemic_state"], 9))

    score: dict[str, Any] | None = None
    score_error: str | None = None
    if do_score:
        if _score_run is None:
            score_error = f"no ecdat-harness checkout found at {HARNESS_ROOT}"
        else:
            try:
                score = _score_run(document)
            except Exception as exc:  # surfaced to the reader, not swallowed
                score_error = f"{type(exc).__name__}: {exc}"

    return render_template(
        "index.html",
        inputs=_available_inputs(),
        adapters=sorted(ADAPTERS),
        default_justification=DEFAULT_JUSTIFICATION,
        harness_available=_score_run is not None,
        harness_root=str(HARNESS_ROOT),
        result={
            "document": document,
            "document_json": json.dumps(document, indent=2),
            "score": score,
            "score_error": score_error,
            "form": {
                "adapter": adapter_id,
                "input_path": input_path,
                "target_id": target_id,
                "confidence": confidence,
                "justification": justification,
                "score": do_score,
            },
        },
    )


if __name__ == "__main__":
    app.run(debug=True)

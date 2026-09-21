"""build-plan.md P18: make "no egress" test-enforced.

Drives `tools/ci/check_no_egress.sh`, which brings up the real Tier A
compose stack (../ecdat-harness/harness/compose/docker-compose.yml) and
asserts a container on `payments-internal` cannot reach the public
internet, with a control run on the default bridge network to rule out
"the host itself has no internet" as a false positive.

Skips when Docker is not on PATH or the sibling ecdat-harness checkout is
not present, exactly like tests/unit/correlation/test_engine.py's own
`pytestmark_harness` skip for the same sibling checkout -- this is
infrastructure verification, not something every environment running
`pytest -q` is expected to have. Verified to actually run and pass (not
just skip) via the WSL2 Linux build box (docs/build-box.md), 2026-09-21;
recorded in docs/build-plan.md P18 rather than claimed here.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "tools" / "ci" / "check_no_egress.sh"
HARNESS_COMPOSE = REPO_ROOT.parent / "ecdat-harness" / "harness" / "compose" / "docker-compose.yml"

pytestmark = pytest.mark.skipif(
    shutil.which("docker") is None or not HARNESS_COMPOSE.exists(),
    reason="docker not on PATH, or sibling ecdat-harness checkout not present",
)


def test_a_container_on_payments_internal_cannot_reach_the_public_internet():
    result = subprocess.run(
        ["bash", str(SCRIPT)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert result.returncode == 0, (
        f"check_no_egress.sh exited {result.returncode}\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert "PASS" in result.stdout

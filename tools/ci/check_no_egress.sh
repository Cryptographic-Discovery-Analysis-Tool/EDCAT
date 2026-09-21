#!/usr/bin/env bash
# build-plan.md P18: make "no egress" test-enforced, not just configured.
#
# H6 (../ecdat-harness/harness/compose/docker-compose.yml): "All live
# endpoints run on an internal Docker network with no egress." `internal:
# true` on `payments-internal` has been set in that file since it was
# written, but until this script existed nothing asserted it was true --
# the deck's word "test-enforced" was ahead of the code (build-plan.md P18,
# corrected 2026-09-21).
#
# This script brings the real Tier A compose stack up, runs one ephemeral
# container ON `payments-internal` and asserts it cannot reach the public
# internet, then runs the SAME check on the default bridge network as a
# control -- proving the failure is `internal: true` doing its job, not a
# broken Docker daemon or no network access at all.
#
# Skips (exit 0) rather than failing when Docker is not on PATH or the
# sibling ecdat-harness checkout is not present, exactly like
# tests/unit/correlation/test_engine.py's own `pytestmark_harness` skip --
# this is infrastructure verification, not a claim that Docker is always
# available.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
COMPOSE_DIR="$REPO_ROOT/../ecdat-harness/harness/compose"
NETWORK="ecdat-harness-tier-a_payments-internal"
PROBE_TARGET="1.1.1.1"

if ! command -v docker >/dev/null 2>&1; then
  echo "check_no_egress: SKIP -- docker not on PATH"
  exit 0
fi
if [ ! -f "$COMPOSE_DIR/docker-compose.yml" ]; then
  echo "check_no_egress: SKIP -- sibling ecdat-harness checkout not present at $COMPOSE_DIR"
  exit 0
fi

cleanup() {
  (cd "$COMPOSE_DIR" && docker compose down --remove-orphans >/dev/null 2>&1) || true
}
trap cleanup EXIT

echo "check_no_egress: bringing up the Tier A stack..."
(cd "$COMPOSE_DIR" && docker compose up -d --build)

echo "check_no_egress: control -- default bridge network must reach the internet..."
if ! docker run --rm alpine:3.20 sh -c "wget -T 5 -O /dev/null http://$PROBE_TARGET" >/dev/null 2>&1; then
  echo "check_no_egress: FAIL -- the control itself could not reach $PROBE_TARGET on the default"
  echo "  bridge network. This host has no internet access right now, so a failure on"
  echo "  payments-internal would prove nothing. Not a pass, not a fail of H6 -- inconclusive."
  exit 2
fi
echo "check_no_egress: control passed -- egress works on the default network."

echo "check_no_egress: asserting no egress from $NETWORK..."
if docker run --rm --network "$NETWORK" alpine:3.20 sh -c "wget -T 5 -O /dev/null http://$PROBE_TARGET" >/dev/null 2>&1; then
  echo "check_no_egress: FAIL -- a container on $NETWORK reached $PROBE_TARGET. H6 is violated."
  exit 1
fi

echo "check_no_egress: PASS -- a container on $NETWORK cannot reach $PROBE_TARGET (H6 holds)."

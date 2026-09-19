"""Read API over the ledger (Pramana_Ledger_Spec.md §7.2 phase 7).

Phase 7 acceptance: "view tests over fixtures". These run against
tests/fixtures/ledger/subjects.json, the same constructed evidence the
dashboard opens with.
"""
import pytest
from fastapi.testclient import TestClient

from ecdat.api.app import DEFAULT_SUBJECTS, create_app, load_subjects

AS_OF = "2026-09-18"
BASE = {"rollout_y_days": 365, "as_of": AS_OF}


@pytest.fixture(scope="module")
def client():
    return TestClient(create_app())


def q(**kw):
    return {**BASE, **kw}


# --- the fixture itself -----------------------------------------------------


def test_the_shipped_fixture_loads():
    subjects = load_subjects(DEFAULT_SUBJECTS)
    assert len(subjects) >= 10
    assert all(s.usage_context.usage_context_id for s in subjects)


def test_health_reports_how_many_subjects_are_loaded(client):
    body = client.get("/api/health").json()
    assert body["status"] == "ok"
    assert body["subjects"] == len(load_subjects(DEFAULT_SUBJECTS))


# --- assumptions are required, never defaulted ------------------------------


def test_scenario_is_required(client):
    assert client.get("/api/ledger", params=BASE).status_code == 422


def test_rollout_y_has_no_default(client):
    """data/scenarios.yaml records that §5.4 names Y and states no number. A
    default here would put an uncited constant behind every auth deadline."""
    assert client.get("/api/ledger", params={"scenario": "Z_central", "as_of": AS_OF}).status_code == 422


def test_unknown_scenario_is_a_404_not_a_guess(client):
    r = client.get("/api/ledger", params=q(scenario="Z_wishful"))
    assert r.status_code == 404
    assert "Z_wishful" in r.json()["detail"]


def test_since_date_without_a_date_is_rejected(client):
    r = client.get("/api/ledger", params=q(scenario="Z_central", capture="SINCE_DATE"))
    assert r.status_code == 422


def test_scenarios_endpoint_names_its_citation_and_the_missing_default(client):
    body = client.get("/api/scenarios").json()
    ids = {s["id"] for s in body["scenarios"]}
    assert ids == {"Z_aggressive", "Z_central", "Z_optimistic"}
    assert all(s["basis_citation"] for s in body["scenarios"])
    assert "no cited default" in body["rollout_y_note"].lower()


# --- the ledger view --------------------------------------------------------


def test_ledger_returns_rows_ranked_worst_first(client):
    rows = client.get("/api/ledger", params=q(scenario="Z_central")).json()["rows"]
    assert rows[0]["band"] == "BLEEDING"
    bands = [r["band"] for r in rows]
    assert bands.index("BLEEDING") < bands.index("SAVABLE")


def test_confidentiality_rows_state_their_capture_assumption_and_auth_rows_do_not(client):
    """The asymmetry is real and deliberate: data is harvested, signatures are
    not, so only the confidentiality ledger has a capture assumption to state
    (§5.6). A row claiming one on the wrong clock would be noise."""
    rows = client.get("/api/ledger", params=q(scenario="Z_central")).json()["rows"]
    banded = [r for r in rows if r["band"] != "UNBOUNDED"]
    assert banded

    for row in banded:
        if row["ledger"] == "confidentiality":
            assert "assumes capture since" in row["capture_sentence"], row["record_id"]
        else:
            assert "no capture assumption applied" in row["capture_sentence"], row["record_id"]


def test_changing_the_scenario_moves_bands(client):
    """The demo claim, asserted: flipping Z changes answers."""
    central = client.get("/api/ledger", params=q(scenario="Z_central")).json()
    aggressive = client.get("/api/ledger", params=q(scenario="Z_aggressive")).json()
    assert aggressive["counts"]["BLEEDING"] > central["counts"]["BLEEDING"]

    by_id = {r["usage_context_id"]: r["band"] for r in central["rows"]}
    moved = {
        r["usage_context_id"]
        for r in aggressive["rows"]
        if by_id[r["usage_context_id"]] != r["band"]
    }
    assert moved, "no row changed band between Z dates"


def test_changing_the_capture_assumption_moves_a_start_date(client):
    """The archive node has a notBefore and no observation: unbounded under
    SINCE_CONFIRMED, banded under SINCE_POSSIBLE."""
    confirmed = client.get("/api/ledger", params=q(scenario="Z_central")).json()
    possible = client.get(
        "/api/ledger", params=q(scenario="Z_central", capture="SINCE_POSSIBLE")
    ).json()

    def band(rows, uid):
        return next(r["band"] for r in rows if r["usage_context_id"] == uid)

    assert band(confirmed["rows"], "archive-node:tls:kex") == "UNBOUNDED"
    assert band(possible["rows"], "archive-node:tls:kex") == "BLEEDING"


def test_accepting_inferred_input_bands_a_previously_unbounded_row(client):
    strict = client.get("/api/ledger", params=q(scenario="Z_central")).json()
    loose = client.get(
        "/api/ledger", params=q(scenario="Z_central", accept_inferred=True)
    ).json()

    def band(rows, uid):
        return next(r["band"] for r in rows if r["usage_context_id"] == uid)

    uid = "legacy-settlement:tls:offered"
    assert band(strict["rows"], uid) == "UNBOUNDED"
    assert band(loose["rows"], uid) != "UNBOUNDED"


def test_symmetric_encryption_never_appears_as_a_ledger_row(client):
    """§5.5: Grover cases go to a policy flag, not the ledger."""
    rows = client.get("/api/ledger", params=q(scenario="Z_central")).json()["rows"]
    assert all(r["function"] != "ENCRYPTION" for r in rows)


# --- the evidence card ------------------------------------------------------


def test_evidence_card_replays_the_band(client):
    rows = client.get("/api/ledger", params=q(scenario="Z_central")).json()["rows"]
    card = client.get(
        f"/api/records/{rows[0]['record_id']}", params=q(scenario="Z_central")
    ).json()
    assert card["replay"]["matches"] is True
    assert card["replay"]["hash_stable"] is True
    assert card["replay"]["band"] == rows[0]["band"]


def test_evidence_card_shows_every_input_state(client):
    card = client.get(
        "/api/records/conf:payments-api:tls:kex:Z_central",
        params=q(scenario="Z_central"),
    ).json()
    assert card["temporal_status"]["first_observed"] == "KNOWN"
    assert card["temporal_status"]["declared_go_live"] == "NOT_OBSERVED"
    assert card["binding"]["status"] == "DECLARED"
    assert card["binding"]["cited_table_row"].startswith("data_lifetime.yaml#")
    assert card["evidence_refs"]


def test_evidence_card_shows_why_a_migration_did_not_stop_the_clock(client):
    card = client.get(
        "/api/records/conf:partner-gateway:tls:kex:Z_central",
        params=q(scenario="Z_central"),
    ).json()
    (migration,) = card["migrations"]
    assert migration["status"] == "INFERRED"
    assert migration["stops_the_clock"] is False
    assert card["band"] == "BLEEDING"


def test_unbounded_card_carries_its_closure_task(client):
    card = client.get(
        "/api/records/conf:archive-node:tls:kex:Z_central",
        params=q(scenario="Z_central"),
    ).json()
    assert card["band"] == "UNBOUNDED"
    assert [t["key"] for t in card["closure_tasks"]] == ["start_confirmed"]


def test_missing_record_is_a_404(client):
    r = client.get("/api/records/conf:nope:Z_central", params=q(scenario="Z_central"))
    assert r.status_code == 404


# --- closure queue ----------------------------------------------------------


def test_closure_queue_is_ranked_and_cited(client):
    tasks = client.get("/api/closure", params=q(scenario="Z_central")).json()["tasks"]
    assert tasks
    assert all(t["citation"].startswith("docs/architecture/") for t in tasks)
    narrowing = [t for t in tasks if t["reachable_bands"]]
    assert narrowing[0]["reachable_bands"], "a ranked task should promise something"
    # A task that narrows nothing must not outrank one that reaches BLEEDING.
    keys = [t["key"] for t in tasks]
    assert keys.index("algorithm_family") < keys.index("function")


# --- coverage ---------------------------------------------------------------


def test_coverage_refuses_to_show_an_empty_adapter_matrix(client):
    """An empty coverage table reads as full coverage."""
    body = client.get("/api/coverage", params=q(scenario="Z_central")).json()
    assert body["adapter_visibility"]["available"] is False
    assert "No adapter has run" in body["adapter_visibility"]["note"]


def test_coverage_reports_the_grover_flag_rather_than_dropping_it(client):
    body = client.get("/api/coverage", params=q(scenario="Z_central")).json()
    (flag,) = body["grover_flags"]
    assert flag["algorithm"] == "AES/GCM/NoPadding"
    assert "not banded" in flag["note"]


def test_coverage_counts_how_we_know_each_row(client):
    body = client.get("/api/coverage", params=q(scenario="Z_central")).json()
    assert body["by_function_status"]["KNOWN"] > 0
    assert body["by_function_status"]["UNKNOWN"] == 1
    assert body["rows"] == len(
        client.get("/api/ledger", params=q(scenario="Z_central")).json()["rows"]
    )


# --- export -----------------------------------------------------------------


def test_export_carries_every_scenario_in_one_document(client):
    """ADR-005 decision 2."""
    document = client.get("/api/export", params=BASE).json()
    scenarios = {
        p["value"]
        for c in document["components"]
        for p in c["properties"]
        if p["name"] == "pramana:exposure:scenario"
    }
    assert scenarios == {"Z_aggressive", "Z_central", "Z_optimistic"}


def test_export_bom_refs_are_unique(client):
    document = client.get("/api/export", params=BASE).json()
    refs = [c["bom-ref"] for c in document["components"]]
    assert len(refs) == len(set(refs))


def test_export_is_offered_as_a_download(client):
    r = client.get("/api/export", params=BASE)
    assert "attachment" in r.headers["content-disposition"]
    assert r.json()["specVersion"] == "1.6"

"""Read API over the ledger (Pramana_Ledger_Spec.md §7.2 phase 7).

Phase 7 acceptance: "view tests over fixtures". These run against
tests/fixtures/ledger/subjects.json, the same constructed evidence the
dashboard opens with.
"""
import pytest
from fastapi.testclient import TestClient

from ecdat.api.app import DEFAULT_SUBJECTS, create_app, load_subjects
from ecdat.security.audit import InMemoryAuditLog
from ecdat.security.auth import Role, TokenRegistry

AS_OF = "2026-09-18"
BASE = {"rollout_y_days": 365, "as_of": AS_OF}

#: build-plan.md P17. Test-only tokens, never logged and never compared
#: against a real one -- security/auth.py stores and compares only their
#: fingerprint, so these two strings exist nowhere but this file and the
#: in-memory registry a test app is built with.
VIEWER_TOKEN = "test-viewer-token"
EXPORTER_TOKEN = "test-exporter-token"


@pytest.fixture(scope="module")
def audit_log():
    return InMemoryAuditLog()


@pytest.fixture(scope="module")
def app(audit_log):
    registry = TokenRegistry.from_raw_tokens(
        {VIEWER_TOKEN: Role.VIEWER, EXPORTER_TOKEN: Role.EXPORTER}
    )
    return create_app(token_registry=registry, audit_log=audit_log)


@pytest.fixture(scope="module")
def client(app):
    return TestClient(app, headers={"Authorization": f"Bearer {VIEWER_TOKEN}"})


@pytest.fixture(scope="module")
def export_client(app):
    return TestClient(app, headers={"Authorization": f"Bearer {EXPORTER_TOKEN}"})


@pytest.fixture
def anonymous_client(app):
    return TestClient(app)


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


def test_scenario_sensitivity_flags_rows_that_actually_move(client):
    """P19: every row carries its band under all three cited Z dates, and the
    rows this test just proved move between scenarios must be the ones marked
    scenario_sensitive -- not a separately-invented flag."""
    by_scenario = {
        scenario: {
            r["usage_context_id"]: r["band"]
            for r in client.get("/api/ledger", params=q(scenario=scenario)).json()["rows"]
        }
        for scenario in ("Z_aggressive", "Z_central", "Z_optimistic")
    }
    central = client.get("/api/ledger", params=q(scenario="Z_central")).json()["rows"]

    moved = {
        uid
        for uid in by_scenario["Z_central"]
        if len({bands[uid] for bands in by_scenario.values()}) > 1
    }
    assert moved

    for row in central:
        sensitivity = row["sensitivity"]
        assert {o["scenario_id"] for o in sensitivity["under_scenario"]} == {
            "Z_aggressive",
            "Z_central",
            "Z_optimistic",
        }
        if row["usage_context_id"] in moved:
            assert sensitivity["scenario_sensitive"] is True
            assert sensitivity["first_flip"] is not None
        else:
            assert sensitivity["scenario_sensitive"] is False
            assert sensitivity["first_flip"] is None


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


def test_export_carries_every_scenario_in_one_document(export_client):
    """ADR-005 decision 2."""
    document = export_client.get("/api/export", params=BASE).json()
    scenarios = {
        p["value"]
        for c in document["components"]
        for p in c["properties"]
        if p["name"] == "pramana:exposure:scenario"
    }
    assert scenarios == {"Z_aggressive", "Z_central", "Z_optimistic"}


def test_export_bom_refs_are_unique(export_client):
    document = export_client.get("/api/export", params=BASE).json()
    refs = [c["bom-ref"] for c in document["components"]]
    assert len(refs) == len(set(refs))


def test_export_is_offered_as_a_download(export_client):
    r = export_client.get("/api/export", params=BASE)
    assert "attachment" in r.headers["content-disposition"]
    assert r.json()["specVersion"] == "1.6"


# --- RBAC and the audit log (build-plan.md P17) ------------------------------


def test_export_with_a_viewer_token_is_403_not_a_silent_downgrade(client):
    r = client.get("/api/export", params=BASE)
    assert r.status_code == 403


def test_ledger_with_no_token_is_401(anonymous_client):
    r = anonymous_client.get("/api/ledger", params=q(scenario="Z_central"))
    assert r.status_code == 401


def test_ledger_with_an_unrecognised_token_is_401(anonymous_client):
    r = anonymous_client.get(
        "/api/ledger",
        params=q(scenario="Z_central"),
        headers={"Authorization": "Bearer not-a-real-token"},
    )
    assert r.status_code == 401


def test_health_needs_no_token(anonymous_client):
    """Not a data endpoint -- a load balancer probe should not need a role."""
    assert anonymous_client.get("/api/health").status_code == 200


def test_every_allowed_request_is_audited(client, audit_log, export_client):
    before = len(audit_log.entries())
    client.get("/api/ledger", params=q(scenario="Z_central"))
    entries = audit_log.entries()
    assert len(entries) == before + 1
    entry = entries[-1]
    assert entry.outcome == "allowed"
    assert entry.verb.value == "READ"
    assert entry.path == "/api/ledger"
    assert entry.principal_fingerprint != "(unauthenticated)"


def test_export_is_audited_as_the_export_verb(export_client, audit_log):
    before = len(audit_log.entries())
    export_client.get("/api/export", params=BASE)
    entries = audit_log.entries()
    assert len(entries) == before + 1
    assert entries[-1].verb.value == "EXPORT"
    assert entries[-1].path == "/api/export"


def test_a_refused_request_is_audited_too(anonymous_client, audit_log):
    before = len(audit_log.entries())
    anonymous_client.get("/api/ledger", params=q(scenario="Z_central"))
    entries = audit_log.entries()
    assert len(entries) == before + 1
    assert entries[-1].outcome == "MissingTokenError"
    assert entries[-1].principal_fingerprint == "(unauthenticated)"


def test_no_audit_entry_ever_contains_a_raw_token(client, audit_log):
    client.get("/api/ledger", params=q(scenario="Z_central"))
    for entry in audit_log.entries():
        dumped = entry.model_dump_json()
        assert VIEWER_TOKEN not in dumped
        assert EXPORTER_TOKEN not in dumped


# --- recommendations (Part 8) ------------------------------------------------


def test_recommendations_need_no_scenario(client):
    """What to move to depends on what the key does, not on when Z is."""
    assert client.get("/api/recommendations").status_code == 200


def test_recommendations_default_to_nist_level_3(client):
    body = client.get("/api/recommendations").json()
    assert body["profile"]["key"] == "NIST_L3"
    kex = next(
        r for r in body["recommendations"] if r["usage_context_id"] == "payments-api:tls:kex"
    )
    assert [o["parameter_set"] for o in kex["options"]] == ["ML-KEM-768", None]


def test_switching_profile_moves_every_parameter_set(client):
    body = client.get("/api/recommendations", params={"profile": "CNSA_2_0"}).json()
    kex = next(
        r for r in body["recommendations"] if r["usage_context_id"] == "payments-api:tls:kex"
    )
    assert kex["options"][0]["parameter_set"] == "ML-KEM-1024"


def test_unknown_profile_is_a_404(client):
    assert client.get("/api/recommendations", params={"profile": "NOPE"}).status_code == 404


def test_undetermined_purposes_are_listed_separately(client):
    body = client.get("/api/recommendations").json()
    assert body["undetermined"] == ["unknown-appliance:tls:kex"]


def test_the_hybrid_rationale_is_quoted_once_without_markdown(client):
    body = client.get("/api/recommendations").json()
    quote = body["hybrid_rationale"]["quote"]
    assert "nothing to harvest" in quote
    assert "*" not in quote, "source markdown must not reach the screen"


def test_the_evidence_card_carries_the_recommendation(client):
    card = client.get(
        "/api/records/conf:payments-api:tls:kex:Z_central",
        params=q(scenario="Z_central"),
    ).json()
    assert [o["algorithm"] for o in card["recommendation"]["options"]] == [
        "ML-KEM",
        "X25519MLKEM768",
    ]


def test_profiles_endpoint_cites_each_profile(client):
    body = client.get("/api/profiles").json()
    assert body["default"] == "NIST_L3"
    assert all(p["citation"].startswith("docs/architecture/") for p in body["profiles"])


def test_graph_endpoint_is_labelled_as_a_fixture_and_carries_both_edge_strengths(client):
    """P15: nodes, typed edges with both strengths present in this demo
    fixture, and the two named gaps -- never silently dropped."""
    body = client.get("/api/graph").json()
    assert body["fixture"] is True
    assert len(body["nodes"]) >= 3

    strengths = {edge["strength"] for edge in body["edges"]}
    assert "claimed" in strengths
    assert "unclaimed" in strengths

    claimed = [e for e in body["edges"] if e["strength"] == "claimed"]
    assert all(e["rule_id"] == "IDENTITY-CERT-DER-001" for e in claimed)
    assert all(e["evidence_basis"] == "content_identity" for e in claimed)

    unclaimed = [e for e in body["edges"] if e["strength"] == "unclaimed"]
    assert all(e["rule_id"] is None for e in unclaimed)
    assert all(e["type"] == "shares_public_key_unclaimed" for e in unclaimed)

    layers = {(g["from_layer"], g["to_layer"]) for g in body["gaps"]}
    assert ("library", "usage") in layers
    assert ("service", "protected data") in layers
    assert all(g["why"] for g in body["gaps"])

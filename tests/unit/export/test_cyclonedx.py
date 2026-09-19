"""CycloneDX 1.6 export and import (Pramana_Ledger_Spec.md §5.11).

Phase 6 acceptance (§7.2): "schema validation; undetermined bucket; no key
bytes" and "valid 1.6 file with `pramana:exposure:*`".
"""
import json
from datetime import date, datetime, timezone

import pytest

from ecdat.context.binding import Lifetime
from ecdat.export.cyclonedx import (
    NAMESPACE,
    SchemaValidationError,
    SecretLeakError,
    build_bom,
    exposure_properties_of,
    import_cbom,
    scan_for_secrets,
    to_json,
    validate,
    write,
)
from ecdat.model.epistemic import EpistemicState
from ecdat.model.field_value import FieldValue
from ecdat.model.temporal import TemporalEvidence
from ecdat.model.usage_context import CryptoFunction, UsageContext
from ecdat.risk import authentication_ledger, confidentiality_ledger
from ecdat.risk.record import ExposureBand, LedgerInputs
from ecdat.risk.scenarios import (
    CaptureAssumption,
    CaptureMode,
    Policy,
    Scenario,
    binding_for,
)

AS_OF = date(2026, 9, 18)
TIMESTAMP = datetime(2026, 9, 18, 12, 0, tzinfo=timezone.utc)
SERIAL = "urn:uuid:00000000-0000-4000-8000-000000000000"
OBSERVED = EpistemicState.KNOWN
Z_CENTRAL = Scenario.load("Z_central")
Z_AGGR = Scenario.load("Z_aggressive")


def policy(**kw):
    return Policy(
        capture_assumption=CaptureAssumption(mode=CaptureMode.SINCE_CONFIRMED),
        rollout_Y_default=Lifetime(years=1),
        **kw,
    )


def context(function, algorithm=None, *, state=OBSERVED, uid="UC-1"):
    return UsageContext(
        usage_context_id=uid,
        asset_id="PAY-001",
        surface_id="tls:pay:443",
        protocol_context="TLS_RSA_WITH_AES_128_CBC_SHA",
        function=FieldValue[CryptoFunction](
            value=function,
            state=state,
            evidence_refs=("E-probe",) if state == OBSERVED else (),
            rule_id="FUNC-TLS-KEX-001" if function is not None else None,
        ),
        algorithm=(
            FieldValue[str](value=algorithm, state=state, evidence_refs=("E-probe",))
            if algorithm
            else None
        ),
    )


def temporal(confirmed=None):
    return TemporalEvidence(
        surface_id="tls:pay:443",
        observation_ts=AS_OF,
        first_observed=(
            FieldValue[date](value=confirmed, state=OBSERVED, evidence_refs=("E-probe",))
            if confirmed
            else None
        ),
    )


def inputs(**kw):
    kw.setdefault("as_of", AS_OF)
    kw.setdefault("scenario", Z_CENTRAL)
    kw.setdefault("policy", policy())
    return LedgerInputs(**kw)


def x(key):
    return binding_for(target_id="PAY-001", key=key, source_ref="operator declaration")


def bleeding_row(scenario=Z_AGGR):
    return confidentiality_ledger.evaluate(
        inputs(
            scenario=scenario,
            usage_context=context(CryptoFunction.KEY_TRANSPORT, "RSA"),
            temporal=temporal(confirmed=date(2021, 1, 1)),
            binding=x("TEST.X_7Y"),
        )
    )


def unbounded_row():
    return confidentiality_ledger.evaluate(
        inputs(
            usage_context=context(None, state=EpistemicState.UNKNOWN, uid="UC-unk"),
            temporal=temporal(confirmed=date(2021, 1, 1)),
            binding=x("TEST.X_25Y"),
        )
    )


def auth_row():
    return authentication_ledger.evaluate(
        inputs(
            usage_context=context(CryptoFunction.SIGNATURE_AUTH, uid="UC-auth"),
            temporal=temporal(confirmed=date(2026, 1, 1)),
            binding=x("TEST.A_15Y"),
            signed_at=date(2026, 1, 1),
        )
    )


def bom(rows=None):
    return build_bom(
        rows if rows is not None else [bleeding_row()],
        timestamp=TIMESTAMP,
        serial_number=SERIAL,
    )


# --- schema validation ------------------------------------------------------


def test_export_validates_against_the_bundled_1_6_schema():
    validate(bom([bleeding_row(), unbounded_row(), auth_row()]))


def test_validation_actually_rejects_a_bad_document():
    """A validator that passes everything proves nothing."""
    document = bom()
    document["components"][0]["type"] = "not-a-real-component-type"
    with pytest.raises(SchemaValidationError):
        validate(document)


def test_validation_rejects_a_missing_required_field():
    document = bom()
    del document["bomFormat"]
    with pytest.raises(SchemaValidationError):
        validate(document)


def test_validation_needs_no_network():
    """The 1.6 schema references spdx and jsf by URL. Validating must not
    reach for them -- the delivery target is air-gapped."""
    import socket

    real = socket.socket

    def forbidden(*args, **kwargs):
        raise AssertionError("schema validation attempted a network connection")

    socket.socket = forbidden
    try:
        validate(bom())
    finally:
        socket.socket = real


# --- §5.11 property map -----------------------------------------------------


def test_every_required_exposure_property_is_present():
    """§5.11 names the property list literally."""
    document = bom([bleeding_row()])
    names = {p["name"] for p in document["components"][0]["properties"]}
    for field in (
        "band",
        "qualifiers",
        "scenario",
        "as_of",
        "unsavable_window",
        "deadline",
        "capture_assumption",
        "record_id",
        "function",
        "function_status",
    ):
        expected = f"{NAMESPACE}:exposure:{field}"
        if field == "qualifiers":
            continue  # only present when the row has one; covered below
        assert expected in names, field


def test_qualifiers_are_emitted_one_property_per_qualifier():
    from ecdat.model.temporal import MigrationEvidence

    record = confidentiality_ledger.evaluate(
        inputs(
            usage_context=context(CryptoFunction.KEY_ESTABLISHMENT, "X25519"),
            temporal=temporal(confirmed=date(2021, 1, 1)),
            binding=x("TEST.X_25Y"),
            migrations=(
                MigrationEvidence(
                    surface_id="tls:pay:443",
                    vantage="dmz-probe-1",
                    observed_at=date(2026, 6, 1),
                    negotiated_group="X25519MLKEM768",
                    classical_still_accepted=False,
                    status=OBSERVED,
                    evidence_refs=("E-m",),
                ),
            ),
        )
    )
    document = bom([record])
    qualifiers = [
        p["value"]
        for p in document["components"][0]["properties"]
        if p["name"] == f"{NAMESPACE}:exposure:qualifiers"
    ]
    assert qualifiers == ["STOPPED"]


def test_confidence_is_a_word_not_a_number():
    """No cited confidence row exists (OI-004), so CycloneDX's numeric
    `evidence.identity.confidence` must stay empty."""
    document = bom([bleeding_row()])
    component = document["components"][0]
    assert "evidence" not in component
    level = [
        p["value"]
        for p in component["properties"]
        if p["name"] == f"{NAMESPACE}:evidence:confidenceLevel"
    ]
    assert level == ["KNOWN"]


def test_detection_context_says_where_we_looked():
    document = bom([bleeding_row()])
    value = next(
        p["value"]
        for p in document["components"][0]["properties"]
        if p["name"] == f"{NAMESPACE}:evidence:detectionContext"
    )
    assert "tls:pay:443" in value


def test_the_capture_assumption_travels_with_the_row():
    document = bom([bleeding_row()])
    values = {p["name"]: p["value"] for p in document["components"][0]["properties"]}
    assert values[f"{NAMESPACE}:exposure:capture_assumption"] == "SINCE_CONFIRMED"
    assert "assumes capture since 2021-01-01" in values[f"{NAMESPACE}:exposure:assumes_capture"]


def test_exposure_never_claims_to_be_a_standard_field():
    """§5.11: 'Described as "CycloneDX-compatible properties", never as a
    standard field.' Structurally: every exposure fact is inside `properties`,
    in our namespace, and nowhere else."""
    document = bom([bleeding_row()])
    component = document["components"][0]
    outside_properties = json.dumps(
        {k: v for k, v in component.items() if k != "properties"}
    )
    for band in ExposureBand:
        assert band.value not in outside_properties
    assert all(p["name"].startswith(f"{NAMESPACE}:") for p in component["properties"])


# --- the undetermined bucket ------------------------------------------------


def test_undetermined_rows_are_counted_and_named_at_bom_level():
    """Silence must never read as 'clean'."""
    document = bom([bleeding_row(), unbounded_row()])
    properties = {p["name"]: p["value"] for p in document["properties"]}
    assert properties[f"{NAMESPACE}:undetermined:count"] == "1"
    assert properties[f"{NAMESPACE}:undetermined:total_rows"] == "2"
    refs = [
        p["value"]
        for p in document["properties"]
        if p["name"] == f"{NAMESPACE}:undetermined:ref"
    ]
    assert len(refs) == 1
    assert "UC-unk" in refs[0]
    assert "UNKNOWN" in refs[0], "the bucket says WHY, not just which"


def test_an_all_determined_export_still_states_the_count():
    document = bom([bleeding_row()])
    properties = {p["name"]: p["value"] for p in document["properties"]}
    assert properties[f"{NAMESPACE}:undetermined:count"] == "0"


def test_undetermined_rows_are_still_components():
    """They are real assets we could not band. Dropping them would be the
    silence this bucket exists to prevent."""
    document = bom([unbounded_row()])
    assert len(document["components"]) == 1


# --- no key bytes -----------------------------------------------------------


def test_secret_scan_catches_a_pem_private_key():
    with pytest.raises(SecretLeakError, match="private key"):
        scan_for_secrets('{"x": "-----BEGIN PRIVATE KEY-----MIIB..."}')


def test_secret_scan_catches_a_credential_assignment():
    with pytest.raises(SecretLeakError):
        scan_for_secrets('{"note": "password=hunter2"}')


def test_export_refuses_to_emit_a_document_carrying_key_material():
    """The gate is on the export path, not a separate lint someone can skip."""
    document = bom()
    document["components"][0]["description"] = (
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----"
    )
    with pytest.raises(SecretLeakError):
        to_json(document)


def test_a_clean_export_passes_the_scan():
    assert to_json(bom([bleeding_row(), unbounded_row(), auth_row()]))


def test_write_runs_both_gates(tmp_path):
    path = write(bom(), tmp_path / "cbom.json")
    assert json.loads(path.read_text(encoding="utf-8"))["specVersion"] == "1.6"


# --- reproducibility --------------------------------------------------------


def test_two_exports_of_the_same_rows_are_byte_identical():
    """`timestamp` is a parameter, not a clock read, so an export is diffable
    and a change in output means a change in evidence."""
    assert to_json(bom()) == to_json(bom())


def test_bom_refs_are_unique_across_scenarios():
    """One usage context produces one row per scenario; they cannot share a
    bom-ref or no consumer can resolve a reference."""
    document = bom([bleeding_row(Z_AGGR), bleeding_row(Z_CENTRAL)])
    refs = [c["bom-ref"] for c in document["components"]]
    assert len(refs) == len(set(refs))


# --- import -----------------------------------------------------------------


def test_import_reads_crypto_assets_as_declared_never_observed():
    """Another tool's assertion is a statement, not our observation."""
    assets = import_cbom(bom([bleeding_row()]))
    (asset,) = assets
    assert asset.state == EpistemicState.DECLARED
    assert asset.name == "RSA"
    assert asset.primitive == "pke"
    assert asset.source_tool == "pramana"


def test_import_skips_components_that_are_not_crypto_assets():
    document = bom([bleeding_row()])
    document["components"].append(
        {"type": "library", "name": "bcprov-jdk18on", "version": "1.78"}
    )
    assert len(import_cbom(document)) == 1, "a library is not a crypto asset"


def test_import_validates_before_reading():
    """'Another tool wrote it' is not a reason to trust bytes."""
    with pytest.raises(SchemaValidationError):
        import_cbom({"bomFormat": "CycloneDX"})


def test_import_rejects_a_different_spec_version():
    document = bom()
    document["specVersion"] = "1.5"
    with pytest.raises(SchemaValidationError, match="specVersion"):
        import_cbom(document)


def test_a_third_party_cbom_imports_without_our_properties():
    """cbomkit-theia and friends emit no `pramana:*`. That must import
    cleanly and simply carry no exposure facts."""
    third_party = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": TIMESTAMP.isoformat(),
            "tools": {"components": [{"type": "application", "name": "cbomkit-theia", "version": "1.0"}]},
        },
        "components": [
            {
                "type": "cryptographic-asset",
                "bom-ref": "alg:rsa-2048",
                "name": "RSA-2048",
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "oid": "1.2.840.113549.1.1.1",
                    "algorithmProperties": {"primitive": "pke"},
                },
            }
        ],
    }
    (asset,) = import_cbom(third_party)
    assert asset.source_tool == "cbomkit-theia"
    assert asset.oid == "1.2.840.113549.1.1.1"
    assert exposure_properties_of(asset) == {}


def test_our_own_export_round_trips_its_exposure_facts():
    """§8 item 4: 'import of a third-party CBOM round-trips as evidence'."""
    record = bleeding_row()
    (asset,) = import_cbom(bom([record]))
    exposure = exposure_properties_of(asset)
    assert exposure["band"] == record.band.value
    assert exposure["record_id"] == record.record_id
    assert exposure["inputs_sha256"] == record.inputs_sha256
    assert exposure["unsavable_window"] == str(record.windows[0])


def test_import_creates_no_usage_context():
    """§5.1: inventory presence yields no context. A standard file format does
    not relax that rule."""
    (asset,) = import_cbom(bom([bleeding_row()]))
    assert not hasattr(asset, "function")
    assert not hasattr(asset, "usage_context_id")

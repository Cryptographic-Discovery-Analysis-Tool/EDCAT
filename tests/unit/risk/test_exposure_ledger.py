"""The frozen deterministic test set (Pramana_Ledger_Spec.md §6).

`as_of = 2026-09-18`; Z_aggr 2031-01-01, Z_central 2036-01-01, Z_optim
2041-01-01. Every expected band and window below is quoted from §6; nothing
here is an expectation invented to match the implementation.
"""
from datetime import date

import pytest

from ecdat.model.epistemic import EpistemicState
from ecdat.model.field_value import FieldValue
from ecdat.model.temporal import MigrationEvidence, TemporalEvidence
from ecdat.model.usage_context import CryptoFunction, UsageContext
from ecdat.risk import authentication_ledger, confidentiality_ledger
from ecdat.risk.confidentiality_ledger import LedgerNotApplicable
from ecdat.risk.record import (
    ExposureBand,
    LedgerInputs,
    Qualifier,
    Window,
    band_rank,
    rank_key,
    replay,
)
from ecdat.risk.scenarios import (
    CaptureAssumption,
    CaptureMode,
    Policy,
    Scenario,
    binding_for,
)
from ecdat.context.binding import Lifetime

AS_OF = date(2026, 9, 18)
OBSERVED = EpistemicState.KNOWN

Z_AGGR = Scenario.load("Z_aggressive")
Z_CENTRAL = Scenario.load("Z_central")
Z_OPTIM = Scenario.load("Z_optimistic")
ALL_Z = (Z_AGGR, Z_CENTRAL, Z_OPTIM)


def policy(mode=CaptureMode.SINCE_CONFIRMED, since=None, **kw):
    return Policy(
        capture_assumption=CaptureAssumption(mode=mode, since=since),
        rollout_Y_default=Lifetime(years=1),
        **kw,
    )


def context(function, algorithm=None, *, state=OBSERVED, uid="UC-1", asset="PAY-001"):
    return UsageContext(
        usage_context_id=uid,
        asset_id=asset,
        surface_id="tls:pay:443",
        protocol_context="observed handshake",
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


def temporal(confirmed=None, not_before=None, declared=None):
    return TemporalEvidence(
        surface_id="tls:pay:443",
        observation_ts=AS_OF,
        first_observed=(
            FieldValue[date](value=confirmed, state=OBSERVED, evidence_refs=("E-probe",))
            if confirmed
            else None
        ),
        not_before=(
            FieldValue[date](value=not_before, state=OBSERVED, evidence_refs=("E-cert",))
            if not_before
            else None
        ),
        declared_go_live=(
            FieldValue[date](value=declared, state=EpistemicState.DECLARED)
            if declared
            else None
        ),
    )


def inputs(**kw):
    kw.setdefault("as_of", AS_OF)
    kw.setdefault("scenario", Z_CENTRAL)
    kw.setdefault("policy", policy())
    return LedgerInputs(**kw)


def stop_at(day, group="X25519MLKEM768"):
    return MigrationEvidence(
        surface_id="tls:pay:443",
        vantage="dmz-probe-1",
        observed_at=day,
        negotiated_group=group,
        classical_still_accepted=False,
        status=OBSERVED,
        evidence_refs=("E-m",),
    )


def classical_at(day):
    return MigrationEvidence(
        surface_id="tls:pay:443",
        vantage="dmz-probe-1",
        observed_at=day,
        negotiated_group="X25519",
        classical_still_accepted=True,
        status=OBSERVED,
        evidence_refs=("E-c",),
    )


def x(key):
    return binding_for(target_id="PAY-001", key=key, source_ref="operator declaration")


# --- §6 row 1 ---------------------------------------------------------------


def test_rsa_cert_tls_auth_only_has_no_confidentiality_row():
    """'RSA cert, TLS auth only (ECDHE negotiated) | no confidentiality row
    for the key; auth: ROTATE_BEFORE_Z'."""
    auth_ctx = context(CryptoFunction.SIGNATURE_AUTH, uid="UC-auth", asset="PAY-005")
    with pytest.raises(LedgerNotApplicable):
        confidentiality_ledger.evaluate(
            inputs(usage_context=auth_ctx, temporal=temporal(confirmed=date(2021, 1, 1)))
        )
    record = authentication_ledger.evaluate(
        inputs(
            usage_context=auth_ctx,
            temporal=temporal(confirmed=date(2021, 1, 1)),
            binding=x("TEST.A_SESSION"),
        )
    )
    assert record.band == ExposureBand.ROTATE_BEFORE_Z
    assert record.deadline == date(2035, 1, 1), "Z_central - Y(1y)"


# --- §6 row 2 ---------------------------------------------------------------


def _rsa_key_transport(scenario):
    return confidentiality_ledger.evaluate(
        inputs(
            scenario=scenario,
            usage_context=context(CryptoFunction.KEY_TRANSPORT, "RSA"),
            temporal=temporal(confirmed=date(2021, 1, 1)),
            binding=x("TEST.X_7Y"),
        )
    )


def test_rsa_static_key_transport_central_is_savable():
    """'central: SAVABLE, deadline 2029-01-01'."""
    record = _rsa_key_transport(Z_CENTRAL)
    assert record.band == ExposureBand.SAVABLE
    assert record.deadline == date(2029, 1, 1)
    assert record.windows == ()


def test_rsa_static_key_transport_aggressive_is_bleeding():
    """'aggressive: BLEEDING, unsavable [2024-01-01, as_of]'."""
    record = _rsa_key_transport(Z_AGGR)
    assert record.band == ExposureBand.BLEEDING
    assert record.windows == (Window(start=date(2024, 1, 1), end=AS_OF),)


# --- §6 row 3 ---------------------------------------------------------------


def test_x25519_ecdhe_x25y_bleeds_under_every_scenario():
    """'all Z: BLEEDING, unsavable [2021-01-01, as_of]'."""
    for scenario in ALL_Z:
        record = confidentiality_ledger.evaluate(
            inputs(
                scenario=scenario,
                usage_context=context(CryptoFunction.KEY_ESTABLISHMENT, "X25519"),
                temporal=temporal(confirmed=date(2021, 1, 1)),
                binding=x("TEST.X_25Y"),
            )
        )
        assert record.band == ExposureBand.BLEEDING, scenario.id
        assert record.windows == (Window(start=date(2021, 1, 1), end=AS_OF),), scenario.id


# --- §6 row 4 ---------------------------------------------------------------


def test_p256_ecdhe_x1y_central_is_savable_with_2035_deadline():
    """'central: SAVABLE (deadline 2035)'."""
    record = confidentiality_ledger.evaluate(
        inputs(
            usage_context=context(CryptoFunction.KEY_ESTABLISHMENT, "P-256"),
            temporal=temporal(confirmed=date(2021, 1, 1)),
            binding=x("TEST.X_1Y"),
        )
    )
    assert record.band == ExposureBand.SAVABLE
    assert record.deadline == date(2035, 1, 1)


# --- §6 row 5 ---------------------------------------------------------------


def test_observed_hybrid_stop_gives_unsavable_window_closed_at_M():
    """'X25519MLKEM768 negotiated, classical off, M=2026-06-01, X=25y,
    since 2021 | UNSAVABLE (STOPPED 2026-06-01), window
    [2021-01-01, 2026-06-01]'."""
    record = confidentiality_ledger.evaluate(
        inputs(
            usage_context=context(CryptoFunction.KEY_ESTABLISHMENT, "X25519"),
            temporal=temporal(confirmed=date(2021, 1, 1)),
            binding=x("TEST.X_25Y"),
            migrations=(stop_at(date(2026, 6, 1)),),
        )
    )
    assert record.band == ExposureBand.UNSAVABLE
    assert Qualifier.STOPPED in record.qualifiers
    assert record.M == date(2026, 6, 1)
    assert record.windows == (Window(start=date(2021, 1, 1), end=date(2026, 6, 1)),)


# --- §6 row 6 ---------------------------------------------------------------


def test_hybrid_configured_but_not_observed_does_not_stop_the_clock():
    """'Hybrid configured, not observed | M=inf -> BLEEDING'."""
    configured = MigrationEvidence(
        surface_id="tls:pay:443",
        vantage="config-file",
        observed_at=date(2026, 6, 1),
        negotiated_group="X25519MLKEM768",
        classical_still_accepted=False,
        status=EpistemicState.INFERRED,
    )
    record = confidentiality_ledger.evaluate(
        inputs(
            usage_context=context(CryptoFunction.KEY_ESTABLISHMENT, "X25519"),
            temporal=temporal(confirmed=date(2021, 1, 1)),
            binding=x("TEST.X_25Y"),
            migrations=(configured,),
        )
    )
    assert record.band == ExposureBand.BLEEDING
    assert record.M is None, "M stays infinite -- config is not an observation"


# --- §6 row 7 ---------------------------------------------------------------


def test_certificate_lifecycle_does_not_enter_the_ledger():
    """'Expired certificate on live endpoint | ledger unaffected; lifecycle
    EXPIRED flagged separately'.

    Structural: LedgerInputs has no notAfter field, so certificate expiry
    cannot reach a band. Asserted by construction rather than by comparing
    two runs, because there is no input to vary.
    """
    assert "not_after" not in LedgerInputs.model_fields
    assert "not_after" not in TemporalEvidence.model_fields


# --- §6 rows 8 and 9 --------------------------------------------------------


def test_notbefore_2019_observed_2024_reports_both_capture_modes():
    """'possible 2019 / confirmed 2024; both windows reported per capture
    mode'."""
    temporal_evidence = temporal(confirmed=date(2024, 7, 9), not_before=date(2019, 3, 1))
    common = dict(
        usage_context=context(CryptoFunction.KEY_ESTABLISHMENT, "X25519"),
        temporal=temporal_evidence,
        binding=x("TEST.X_25Y"),
    )
    confirmed = confidentiality_ledger.evaluate(inputs(**common))
    possible = confidentiality_ledger.evaluate(
        inputs(policy=policy(CaptureMode.SINCE_POSSIBLE), **common)
    )
    assert confirmed.windows == (Window(start=date(2024, 7, 9), end=AS_OF),)
    assert possible.windows == (Window(start=date(2019, 3, 1), end=AS_OF),)
    assert confirmed.start_possible == date(2019, 3, 1)
    assert confirmed.start_confirmed == date(2024, 7, 9)
    assert "assumes capture since 2024-07-09" in confirmed.capture_sentence


def test_only_notbefore_leaves_the_row_unbounded():
    """'Missing go-live, only notBefore | UNBOUNDED; task "declare go-live or
    take first observation"'."""
    record = confidentiality_ledger.evaluate(
        inputs(
            usage_context=context(CryptoFunction.KEY_ESTABLISHMENT, "X25519"),
            temporal=temporal(not_before=date(2019, 3, 1)),
            binding=x("TEST.X_25Y"),
        )
    )
    assert record.band == ExposureBand.UNBOUNDED
    assert "never confirm" in record.reason


# --- §6 row 10 --------------------------------------------------------------


def test_inferred_input_is_unbounded_with_a_conditional_band():
    """'Inferred configuration (PAY-001) | UNBOUNDED + conditional BLEEDING'."""
    record = confidentiality_ledger.evaluate(
        inputs(
            usage_context=context(
                CryptoFunction.KEY_TRANSPORT, "RSA", state=EpistemicState.INFERRED
            ),
            temporal=temporal(confirmed=date(2021, 1, 1)),
            binding=x("TEST.X_25Y"),
        )
    )
    assert record.band == ExposureBand.UNBOUNDED
    assert record.conditional_band == ExposureBand.BLEEDING
    assert record.windows == (), "an unbounded row asserts no window"


def test_inferred_input_is_banded_when_policy_accepts_inferred():
    record = confidentiality_ledger.evaluate(
        inputs(
            policy=policy(accept_inferred_inputs=True),
            usage_context=context(
                CryptoFunction.KEY_TRANSPORT, "RSA", state=EpistemicState.INFERRED
            ),
            temporal=temporal(confirmed=date(2021, 1, 1)),
            binding=x("TEST.X_25Y"),
        )
    )
    assert record.band == ExposureBand.BLEEDING


# --- §6 row 11 --------------------------------------------------------------


def test_unknown_kex_is_unbounded_with_no_conditional():
    """'Unknown KEX | UNBOUNDED, no conditional'."""
    record = confidentiality_ledger.evaluate(
        inputs(
            usage_context=context(None, state=EpistemicState.UNKNOWN),
            temporal=temporal(confirmed=date(2021, 1, 1)),
            binding=x("TEST.X_25Y"),
        )
    )
    assert record.band == ExposureBand.UNBOUNDED
    assert record.conditional_band is None


def test_unknown_algorithm_family_is_unbounded_with_a_conditional():
    """A function we observed over an algorithm no cited row classifies."""
    record = confidentiality_ledger.evaluate(
        inputs(
            # Any family with no usable row in data/crypto_families.yaml. DH was
            # the example until NIST IR 8547 (vendored 2026-09-23) cited it.
            usage_context=context(CryptoFunction.KEY_ESTABLISHMENT, "SM2"),
            temporal=temporal(confirmed=date(2021, 1, 1)),
            binding=x("TEST.X_25Y"),
        )
    )
    assert record.band == ExposureBand.UNBOUNDED
    assert record.conditional_band == ExposureBand.BLEEDING
    assert "Shor-broken is unknown" in record.reason


# --- §6 row 12 --------------------------------------------------------------


def test_same_channel_different_X_gives_different_bands_in_every_scenario():
    """'X=25y vs X=1y on the same channel | BLEEDING vs SAVABLE in all Z'."""
    for scenario in ALL_Z:
        common = dict(
            scenario=scenario,
            usage_context=context(CryptoFunction.KEY_ESTABLISHMENT, "X25519"),
            temporal=temporal(confirmed=date(2021, 1, 1)),
        )
        long_lived = confidentiality_ledger.evaluate(
            inputs(binding=x("TEST.X_25Y"), **common)
        )
        short_lived = confidentiality_ledger.evaluate(
            inputs(binding=x("TEST.X_1Y"), **common)
        )
        assert long_lived.band == ExposureBand.BLEEDING, scenario.id
        assert short_lived.band == ExposureBand.SAVABLE, scenario.id


# --- §6 row 13 --------------------------------------------------------------


def test_long_lived_signed_artefact_must_be_resigned_before_z():
    """'Long-lived signed artefact, signed 2026-01-01, A=15y |
    RESIGN_BEFORE_Z (required until 2041 > Z_central)'."""
    record = authentication_ledger.evaluate(
        inputs(
            usage_context=context(CryptoFunction.SIGNATURE_AUTH, uid="UC-art"),
            temporal=temporal(confirmed=date(2026, 1, 1)),
            binding=x("TEST.A_15Y"),
            signed_at=date(2026, 1, 1),
        )
    )
    assert record.band == ExposureBand.RESIGN_BEFORE_Z
    assert "2041-01-01" in record.reason


def test_same_artefact_is_safe_under_the_optimistic_scenario():
    record = authentication_ledger.evaluate(
        inputs(
            scenario=Z_OPTIM,
            usage_context=context(CryptoFunction.SIGNATURE_AUTH, uid="UC-art"),
            temporal=temporal(confirmed=date(2026, 1, 1)),
            binding=x("TEST.A_15Y"),
            signed_at=date(2026, 1, 1),
        )
    )
    assert record.band == ExposureBand.SAFE_UNTIL_Z, "required_until 2041 == Z_optim"


# --- §6 row 15 --------------------------------------------------------------


def test_bands_flip_exactly_at_the_deadline_crossing():
    """'Multiple Z | bands differ exactly at deadline crossings'."""
    bands = {}
    for scenario in ALL_Z:
        record = confidentiality_ledger.evaluate(
            inputs(
                scenario=scenario,
                usage_context=context(CryptoFunction.KEY_TRANSPORT, "RSA"),
                temporal=temporal(confirmed=date(2021, 1, 1)),
                binding=x("TEST.X_7Y"),
            )
        )
        bands[scenario.id] = (record.band, record.deadline)
    assert bands["Z_aggressive"] == (ExposureBand.BLEEDING, date(2024, 1, 1))
    assert bands["Z_central"] == (ExposureBand.SAVABLE, date(2029, 1, 1))
    assert bands["Z_optimistic"] == (ExposureBand.SAVABLE, date(2034, 1, 1))
    for band, deadline in bands.values():
        assert (band == ExposureBand.BLEEDING) == (AS_OF > deadline)


# --- §6 row 16 --------------------------------------------------------------


def _m_case(m_date, as_of):
    """'M=2030 vs M=2038, Z=2036, X=10y, since 2020 | deadline 2026'.

    §6 states the window for M=2030 as [2026, 2030], which requires an `as_of`
    after M -- a migration observed in 2030 cannot be evidence on 2026-09-18.
    The row is therefore evaluated at an as_of that makes its own M
    observable; §5.5's `min(as_of, M)` is applied unchanged. Recorded as
    OI-011.
    """
    migrations = (stop_at(m_date),) if m_date <= as_of else ()
    return confidentiality_ledger.evaluate(
        LedgerInputs(
            as_of=as_of,
            scenario=Z_CENTRAL,
            policy=policy(),
            usage_context=context(CryptoFunction.KEY_ESTABLISHMENT, "X25519"),
            temporal=temporal(confirmed=date(2020, 1, 1)),
            binding=x("TEST.X_10Y"),
            migrations=migrations,
        )
    )


def test_migration_before_now_stops_the_window_at_M():
    record = _m_case(date(2030, 1, 1), as_of=date(2030, 6, 1))
    assert record.deadline == date(2026, 1, 1)
    assert record.band == ExposureBand.UNSAVABLE
    assert Qualifier.STOPPED in record.qualifiers
    assert record.windows == (Window(start=date(2026, 1, 1), end=date(2030, 1, 1)),)


def test_migration_still_in_the_future_leaves_the_row_bleeding():
    record = _m_case(date(2038, 1, 1), as_of=date(2030, 6, 1))
    assert record.band == ExposureBand.BLEEDING
    assert record.M is None, "a migration not yet observed is not an M"


# --- §6 row 17 --------------------------------------------------------------


def test_classical_observed_after_a_stop_reopens_the_clock():
    """'Hybrid observed 2026-06-01 (classical off), classical observed
    2026-08-01 | REOPENED, BLEEDING from 2026-08-01'."""
    record = confidentiality_ledger.evaluate(
        inputs(
            usage_context=context(CryptoFunction.KEY_ESTABLISHMENT, "X25519"),
            temporal=temporal(confirmed=date(2021, 1, 1)),
            binding=x("TEST.X_25Y"),
            migrations=(stop_at(date(2026, 6, 1)), classical_at(date(2026, 8, 1))),
        )
    )
    assert record.band == ExposureBand.BLEEDING
    assert Qualifier.REOPENED in record.qualifiers
    assert record.windows[-1] == Window(start=date(2026, 8, 1), end=AS_OF)
    assert record.windows[0] == Window(start=date(2021, 1, 1), end=date(2026, 6, 1))


# --- §6 row 18: replay ------------------------------------------------------


def _every_band_record():
    yield _rsa_key_transport(Z_CENTRAL)
    yield _rsa_key_transport(Z_AGGR)
    yield _m_case(date(2030, 1, 1), as_of=date(2030, 6, 1))
    yield confidentiality_ledger.evaluate(
        inputs(
            usage_context=context(None, state=EpistemicState.UNKNOWN),
            temporal=temporal(confirmed=date(2021, 1, 1)),
            binding=x("TEST.X_25Y"),
        )
    )
    yield authentication_ledger.evaluate(
        inputs(
            usage_context=context(CryptoFunction.SIGNATURE_AUTH, uid="UC-art"),
            temporal=temporal(confirmed=date(2026, 1, 1)),
            binding=x("TEST.A_15Y"),
            signed_at=date(2026, 1, 1),
        )
    )


def test_every_record_replays_to_the_same_band():
    """'Replay | replay(record).band == record.band, hash-stable'."""
    for record in _every_band_record():
        again = replay(record)
        assert again.band == record.band, record.record_id
        assert again.inputs_sha256 == record.inputs_sha256, record.record_id
        assert again.model_dump() == record.model_dump(), record.record_id


def test_the_hash_covers_the_inputs():
    record = _rsa_key_transport(Z_CENTRAL)
    tampered = record.inputs.model_copy(update={"as_of": date(2030, 1, 1)})
    assert tampered.sha256() != record.inputs_sha256


# --- §5.5 output contract and §5.10 ranking --------------------------------


def test_every_row_states_its_capture_assumption_in_words():
    record = _rsa_key_transport(Z_AGGR)
    assert record.capture_sentence == (
        "assumes capture since 2021-01-01 (SINCE_CONFIRMED)"
    )


def test_ranking_is_lexicographic_with_bleeding_first():
    """§5.10: 'band order (BLEEDING > UNSAVABLE-stopped > SAVABLE > SAFE)'."""
    bleeding = _rsa_key_transport(Z_AGGR)
    savable = _rsa_key_transport(Z_CENTRAL)
    unsavable = _m_case(date(2030, 1, 1), as_of=date(2030, 6, 1))
    order = sorted([savable, unsavable, bleeding], key=lambda r: rank_key(r))
    assert [r.band for r in order] == [
        ExposureBand.BLEEDING,
        ExposureBand.UNSAVABLE,
        ExposureBand.SAVABLE,
    ]
    assert band_rank(ExposureBand.SAFE) > band_rank(ExposureBand.SAVABLE)


def test_no_row_reports_a_volume():
    """§5.12 rejects traffic-volume estimation. Structural: nothing on the
    record is a count of anything."""
    forbidden = {"volume", "bytes", "records", "score", "weight", "probability"}
    assert forbidden.isdisjoint(
        {name.lower() for name in type(_rsa_key_transport(Z_CENTRAL)).model_fields}
    )

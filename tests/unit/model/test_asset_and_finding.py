import pytest
from pydantic import ValidationError

from ecdat.model.asset import CryptoAsset
from ecdat.model.epistemic import EpistemicState
from ecdat.model.field_value import FieldValue
from ecdat.model.finding import Finding


def test_finding_holds_per_field_epistemic_values():
    finding = Finding(
        finding_id="F-1",
        surface="source",
        evidence_refs=("ev-1",),
        fields={"family": FieldValue(value="RSA", state=EpistemicState.INFERRED)},
    )
    assert finding.fields["family"].state == EpistemicState.INFERRED


def test_finding_rejects_blank_surface():
    with pytest.raises(ValidationError):
        Finding(finding_id="F-1", surface="   ")


def test_crypto_asset_scope_anchor_is_optional():
    asset = CryptoAsset(asset_id="PAY-001")
    assert asset.scope_anchor is None


def test_crypto_asset_holds_finding_refs_and_fields():
    asset = CryptoAsset(
        asset_id="PAY-001",
        scope_anchor="payments",
        finding_refs=("F-1",),
        fields={"family": FieldValue(value="RSA", state=EpistemicState.INFERRED)},
    )
    assert asset.scope_anchor == "payments"
    assert asset.finding_refs == ("F-1",)


def test_crypto_asset_rejects_blank_id():
    with pytest.raises(ValidationError):
        CryptoAsset(asset_id="  ")

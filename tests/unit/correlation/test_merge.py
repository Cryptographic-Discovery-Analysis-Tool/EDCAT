"""Within-surface merge (Final Architecture Part 5; docs/deviations.md
DEV-007 for why `algorithm_family` disagreement still produces one merged
asset with a CONFLICTING field rather than two separate assets)."""
from __future__ import annotations

from ecdat.correlation.merge import merge_within_surface
from ecdat.model.epistemic import EpistemicState
from ecdat.model.field_value import FieldValue
from ecdat.model.finding import Finding

SURFACE_A = "certdir:/etc/pki/service-a"
SURFACE_B = "certdir:/etc/pki/service-b"


def _known(value):
    return FieldValue(value=value, state=EpistemicState.KNOWN, evidence_refs=("ev-1",))


def _cert_finding(
    finding_id: str,
    *,
    surface: str,
    algorithm: str,
    size: int | None = 2048,
    curve: str | None = None,
    extra_fields: dict | None = None,
) -> Finding:
    """A Finding shaped like CertificateAdapter._fields() actually emits
    (src/ecdat/adapters/certs/adapter.py): only the fields this merge task
    reads (public_key_algorithm/public_key_size/public_key_curve) plus one
    unrelated field (subject) to prove ordinary fields merge too."""
    fields = {
        "public_key_algorithm": _known(algorithm),
        "public_key_size": _known(size) if size is not None else FieldValue(
            value=None, state=EpistemicState.UNKNOWN
        ),
        "public_key_curve": _known(curve) if curve is not None else FieldValue(
            value=None, state=EpistemicState.UNKNOWN
        ),
        "subject": _known(f"CN={finding_id}"),
    }
    if extra_fields:
        fields.update(extra_fields)
    return Finding(
        finding_id=finding_id,
        surface=surface,
        evidence_refs=("ev-1",),
        fields=fields,
    )


def test_matching_algorithm_and_size_same_surface_merge_into_one_asset():
    finding_a = _cert_finding("cert-a", surface=SURFACE_A, algorithm="RSA", size=2048)
    finding_b = _cert_finding("cert-b", surface=SURFACE_A, algorithm="RSA", size=2048)

    assets = merge_within_surface([finding_a, finding_b])

    assert len(assets) == 1
    asset = assets[0]
    assert set(asset.finding_refs) == {"cert-a", "cert-b"}
    assert asset.scope_anchor == SURFACE_A
    assert asset.algorithm_family == "RSA"
    assert asset.fields["public_key_algorithm"].state == EpistemicState.KNOWN
    assert asset.fields["public_key_algorithm"].value == "RSA"
    # evidence_refs from both source Findings are unioned onto the field.
    assert asset.fields["public_key_algorithm"].evidence_refs == ("ev-1",)


def test_disagreeing_algorithm_same_scope_anchor_produces_conflicting_field_not_a_winner():
    # Same parameters (key size) and the same scope_anchor -- two tools
    # disagreeing about what the key material AT THAT LOCATION actually is.
    # Merging into one asset and flagging the field CONFLICTING is the
    # R-MONOTONE-honest outcome; silently splitting into two "certain"
    # single-source assets would hide that both observations point at the
    # same place. See DEV-007.
    finding_a = _cert_finding("cert-a", surface=SURFACE_A, algorithm="RSA", size=2048)
    finding_b = _cert_finding("cert-b", surface=SURFACE_A, algorithm="DSA", size=2048)

    assets = merge_within_surface([finding_a, finding_b])

    assert len(assets) == 1
    asset = assets[0]
    assert set(asset.finding_refs) == {"cert-a", "cert-b"}
    field = asset.fields["public_key_algorithm"]
    assert field.state == EpistemicState.CONFLICTING
    assert field.value is None  # never a silently-chosen winner
    assert field.resolution is not None
    assert field.resolution.reason
    # The plain convenience field must not paper over the conflict either.
    assert asset.algorithm_family is None
    # A field the two Findings actually agreed on still merges cleanly.
    assert asset.fields["public_key_size"].state == EpistemicState.KNOWN
    assert asset.fields["public_key_size"].value == 2048


def test_different_surfaces_with_matching_algorithm_and_parameters_never_merge():
    finding_a = _cert_finding("cert-a", surface=SURFACE_A, algorithm="RSA", size=2048)
    finding_b = _cert_finding("cert-b", surface=SURFACE_B, algorithm="RSA", size=2048)

    assets = merge_within_surface([finding_a, finding_b])

    assert len(assets) == 2
    scope_anchors = {asset.scope_anchor for asset in assets}
    assert scope_anchors == {SURFACE_A, SURFACE_B}
    for asset in assets:
        assert len(asset.finding_refs) == 1


def test_three_findings_two_matching_one_distinct_parameters_split_correctly():
    # Not one of the required cases, but guards the grouping key against a
    # regression where "aggressively merge within a surface" is read as
    # "merge everything on one surface into a single asset".
    finding_a = _cert_finding("cert-a", surface=SURFACE_A, algorithm="RSA", size=2048)
    finding_b = _cert_finding("cert-b", surface=SURFACE_A, algorithm="RSA", size=2048)
    finding_c = _cert_finding("cert-c", surface=SURFACE_A, algorithm="EC", size=None, curve="secp256r1")

    assets = merge_within_surface([finding_a, finding_b, finding_c])

    assert len(assets) == 2
    by_refs = {frozenset(asset.finding_refs): asset for asset in assets}
    assert frozenset({"cert-a", "cert-b"}) in by_refs
    assert frozenset({"cert-c"}) in by_refs
    ec_asset = by_refs[frozenset({"cert-c"})]
    assert ec_asset.algorithm_family == "EC"
    assert ec_asset.parameters == "secp256r1"


def test_empty_input_produces_no_assets():
    assert merge_within_surface([]) == ()

from ecdat.model.visibility import SupportLevel, VisibilityDimension, VisibilityEntry


def test_all_lock_5_dimensions_constructible():
    # Lock §5 row "4 Coverage": artifact, source, dependency, configuration,
    # deployment, runtime, network, HSM/KMS, and failed/timeout targets.
    for dimension in VisibilityDimension:
        entry = VisibilityEntry(dimension=dimension, support_level=SupportLevel.DETECT_ONLY)
        assert entry.dimension == dimension


def test_all_support_levels_constructible():
    for level in SupportLevel:
        entry = VisibilityEntry(dimension=VisibilityDimension.SOURCE, support_level=level)
        assert entry.support_level == level

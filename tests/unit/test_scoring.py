"""Unit: confidence formula locks + severity orthogonality."""

from secretsieve.detectors import scoring


def test_plan_example_github_99():
    # base 90 + strong 15 + struct 5 = 110 -> clamped 99.
    assert scoring.compute_confidence(base=90, tier="strong", struct_bonus=5) == 99


def test_plan_example_hunter2_45():
    # generic base 30 + strong 15, no entropy/struct -> 45.
    assert scoring.compute_confidence(base=30, tier="strong") == 45


def test_never_100():
    assert scoring.compute_confidence(base=95, tier="strong", entropy_bonus_pts=15, struct_bonus=5, pair_bonus=10) == 99


def test_benign_and_penalties():
    assert scoring.compute_confidence(base=90, tier="benign", struct_bonus=5) == 75
    assert scoring.compute_confidence(base=90, tier="none", penalties=10) == 80
    assert scoring.compute_confidence(base=30, tier="none", penalties=99) == 0


def test_bands():
    assert scoring.confidence_band(99) == "very-high"
    assert scoring.confidence_band(90) == "very-high"
    assert scoring.confidence_band(89) == "high"
    assert scoring.confidence_band(75) == "high"
    assert scoring.confidence_band(74) == "medium"
    assert scoring.confidence_band(50) == "medium"
    assert scoring.confidence_band(49) == "low"
    assert scoring.confidence_band(0) == "low"


def test_severity_never_from_confidence():
    # Property: severity adjustment is a pure function of deployment context.
    for conf in (0, 45, 75, 99):
        sev, _ = scoring.adjust_severity("CRITICAL", is_test=False, is_docs=False, is_example=False, generated=False)
        assert sev == "CRITICAL", conf


def test_demotion_caps():
    sev, caps = scoring.adjust_severity("CRITICAL", is_test=True, is_docs=False, is_example=False, generated=False)
    assert sev == "HIGH" and caps
    # Private keys in docs stay CRITICAL.
    sev, _ = scoring.adjust_severity("CRITICAL", is_test=False, is_docs=True, is_example=False, generated=False, is_private_key=True)
    assert sev == "CRITICAL"
    sev, _ = scoring.adjust_severity("HIGH", is_test=False, is_docs=True, is_example=False, generated=False)
    assert sev == "MEDIUM"
    sev, _ = scoring.adjust_severity("INFO", is_test=True, is_docs=True, is_example=True, generated=True)
    assert sev == "INFO"


def test_fail_on_and_floor():
    assert scoring.meets_fail_on("LOW", "low")
    assert scoring.meets_fail_on("CRITICAL", "critical")
    assert not scoring.meets_fail_on("MEDIUM", "high")
    assert not scoring.meets_fail_on("INFO", "low")  # INFO never fails
    assert scoring.meets_floor("INFO", "info")
    assert not scoring.meets_floor("LOW", "medium")

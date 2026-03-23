"""Tests für den Scoring Service."""
import pytest
from app.services.scoring_service import (
    calculate_scores,
    calculate_overall_rating,
    apply_override_rules,
    recalculate,
    recalculate_detailed,
    SCORE_DIMENSIONS,
)


def make_finding(severity, status="open", affects="technical", comp_required=False, comp_desc=None):
    return {
        "severity": severity,
        "status": status,
        "affects_score": affects,
        "compensating_control_required": comp_required,
        "compensating_control_description": comp_desc,
    }


def test_no_findings():
    scores = calculate_scores([])
    assert scores["technical"] == 100
    assert scores["operational"] == 100
    assert scores["lifecycle"] == 100


def test_high_finding_reduces_technical():
    findings = [make_finding("high")]
    scores = calculate_scores(findings)
    assert scores["technical"] == 85  # 100 - 15


def test_critical_finding():
    findings = [make_finding("critical")]
    scores = calculate_scores(findings)
    assert scores["technical"] == 70  # 100 - 30


def test_compensated_finding_half_penalty():
    findings = [make_finding("high", status="compensated")]
    scores = calculate_scores(findings)
    assert scores["technical"] == 93  # 100 - 7 (15//2)


def test_false_positive_no_penalty():
    findings = [make_finding("critical", status="false_positive")]
    scores = calculate_scores(findings)
    # false_positive should not penalize
    assert scores["technical"] >= 90


def test_lifecycle_finding():
    findings = [make_finding("medium", affects="lifecycle")]
    scores = calculate_scores(findings)
    assert scores["lifecycle"] == 92  # 100 - 8
    assert scores["technical"] == 100  # unaffected


def test_rating_green():
    scores = {"technical": 90, "operational": 90, "compensation": 90, "lifecycle": 90, "vendor": 90}
    assert calculate_overall_rating(scores) == "green"


def test_rating_yellow():
    scores = {"technical": 60, "operational": 60, "compensation": 60, "lifecycle": 60, "vendor": 60}
    assert calculate_overall_rating(scores) == "yellow"


def test_rating_orange():
    scores = {"technical": 40, "operational": 40, "compensation": 40, "lifecycle": 40, "vendor": 40}
    assert calculate_overall_rating(scores) == "orange"


def test_rating_red():
    scores = {"technical": 10, "operational": 10, "compensation": 10, "lifecycle": 10, "vendor": 10}
    assert calculate_overall_rating(scores) == "red"


def test_override_two_critical():
    findings = [make_finding("critical"), make_finding("critical")]
    rating = apply_override_rules("green", findings)
    assert rating == "red"


def test_override_one_critical_uncompensated():
    findings = [make_finding("critical")]
    rating = apply_override_rules("green", findings)
    assert rating == "orange"


def test_override_one_critical_compensated():
    findings = [make_finding("critical", status="compensated")]
    rating = apply_override_rules("green", findings)
    assert rating == "green"  # compensated critical doesn't override


def test_recalculate():
    findings = [make_finding("high"), make_finding("medium", affects="lifecycle")]
    result = recalculate(findings)
    assert "technical" in result
    assert "overall_rating" in result
    assert result["technical"] == 85
    assert result["lifecycle"] == 92


def test_score_weights_sum_to_one():
    """The sum of all dimension weights must equal exactly 1.0."""
    total = sum(d["weight"] for d in SCORE_DIMENSIONS.values())
    assert abs(total - 1.0) < 1e-9, f"Weights sum to {total}, expected 1.0"


def test_score_never_below_zero():
    """Score must never go below 0 even with many critical findings."""
    findings = [make_finding("critical") for _ in range(10)]
    scores = calculate_scores(findings)
    for dim, val in scores.items():
        assert val >= 0, f"Score for {dim} went below 0: {val}"


def test_score_never_above_100():
    """Score must never exceed 100 even with no findings."""
    scores = calculate_scores([])
    for dim, val in scores.items():
        assert val <= 100, f"Score for {dim} exceeded 100: {val}"


def test_accepted_finding_no_penalty():
    """Findings with status 'accepted' must not penalize the score."""
    findings = [make_finding("critical", status="accepted")]
    scores = calculate_scores(findings)
    assert scores["technical"] == 100


def test_low_lifecycle_score_caps_rating_at_yellow():
    """Lifecycle score < 20 must prevent green overall rating (max yellow)."""
    # All scores high → would normally be green
    findings = [make_finding("high", affects="lifecycle") for _ in range(6)]
    scores = calculate_scores(findings)
    # lifecycle score should be 10 (100 - 6*15)
    assert scores["lifecycle"] < 20
    base_rating = calculate_overall_rating(scores)
    final_rating = apply_override_rules(base_rating, [], scores)
    # If base was green, lifecycle cap should downgrade to yellow
    if base_rating == "green":
        assert final_rating == "yellow"


def test_two_critical_findings_force_red():
    """Two critical findings must result in red regardless of other scores."""
    findings = [make_finding("critical"), make_finding("critical")]
    result = recalculate(findings)
    assert result["overall_rating"] == "red"


def test_scoring_result_contains_reasons():
    """recalculate_detailed must return a ScoringResult with reasons per dimension."""
    findings = [
        make_finding("high", affects="technical"),
        make_finding("medium", affects="lifecycle"),
    ]
    result = recalculate_detailed(findings)
    assert result.overall_rating in ("green", "yellow", "orange", "red")
    assert "technical" in result.dimensions
    assert "lifecycle" in result.dimensions
    tech = result.dimensions["technical"]
    assert tech.score == 85
    assert len(tech.reasons) == 1
    assert tech.reasons[0].impact == -15


def test_unknown_affects_score_falls_back_to_technical():
    """Findings with unknown affects_score dimension fall back to 'technical'."""
    findings = [make_finding("high", affects="nonexistent_dimension")]
    scores = calculate_scores(findings)
    # Should not raise and should deduct from technical
    assert scores["technical"] == 85

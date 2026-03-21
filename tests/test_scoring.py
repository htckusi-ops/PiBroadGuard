"""Tests für den Scoring Service."""
import pytest
from app.services.scoring_service import (
    calculate_scores,
    calculate_overall_rating,
    apply_override_rules,
    recalculate,
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

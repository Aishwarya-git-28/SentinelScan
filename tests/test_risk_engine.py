"""
tests/test_risk_engine.py
Tests for scanner/risk_engine.py
"""

from __future__ import annotations

import pytest

from scanner.security_checks import Finding
from scanner.risk_engine import calculate_risk, RiskReport, _score_to_grade, SEVERITY_ORDER


def _make_finding(severity: str, status: str = "finding") -> Finding:
    return Finding(
        finding_id="TEST-001",
        title=f"Test {severity} {status}",
        category="Test",
        severity=severity,
        status=status,
        short_description="Test finding",
        evidence="N/A",
        why_it_matters="Testing",
        remediation="Test",
        confidence="high",
    )


class TestCalculateRisk:
    def test_empty_findings_returns_100(self):
        report = calculate_risk([])
        assert report.score == 100
        assert report.grade == "A+"
        assert report.total_findings == 0

    def test_single_critical_deducts_30(self):
        findings = [_make_finding("critical")]
        report = calculate_risk(findings)
        assert report.score == 70
        assert report.grade == "B"

    def test_single_high_deducts_20(self):
        findings = [_make_finding("high")]
        report = calculate_risk(findings)
        assert report.score == 80
        assert report.grade == "A"

    def test_single_medium_deducts_10(self):
        findings = [_make_finding("medium")]
        report = calculate_risk(findings)
        assert report.score == 90
        assert report.grade == "A+"

    def test_single_low_deducts_5(self):
        findings = [_make_finding("low")]
        report = calculate_risk(findings)
        assert report.score == 95
        assert report.grade == "A+"

    def test_single_informational_deducts_1(self):
        findings = [_make_finding("informational")]
        report = calculate_risk(findings)
        assert report.score == 99
        assert report.grade == "A+"

    def test_multiple_findings_accumulate(self):
        findings = [
            _make_finding("critical"),    # -30
            _make_finding("high"),        # -20
            _make_finding("medium"),      # -10
        ]
        report = calculate_risk(findings)
        assert report.score == 40  # 100 - 60 = 40

    def test_score_never_below_zero(self):
        findings = [_make_finding("critical")] * 10  # 10 × -30 = -300
        report = calculate_risk(findings)
        assert report.score == 0

    def test_passed_findings_have_no_deduction(self):
        findings = [_make_finding("critical", "passed")]
        report = calculate_risk(findings)
        assert report.score == 100
        assert report.passed_count == 1
        assert report.total_findings == 0

    def test_inconclusive_findings_have_no_deduction(self):
        findings = [_make_finding("high", "inconclusive")]
        report = calculate_risk(findings)
        assert report.score == 100
        assert report.inconclusive_count == 1

    def test_severity_counts_accurate(self):
        findings = [
            _make_finding("critical"),
            _make_finding("critical"),
            _make_finding("high"),
            _make_finding("medium"),
            _make_finding("low", "passed"),
        ]
        report = calculate_risk(findings)
        assert report.findings_by_severity["critical"] == 2
        assert report.findings_by_severity["high"] == 1
        assert report.findings_by_severity["medium"] == 1
        assert report.passed_count == 1

    def test_deterministic_for_same_input(self):
        findings = [_make_finding("medium"), _make_finding("high")]
        r1 = calculate_risk(findings)
        r2 = calculate_risk(findings)
        assert r1.score == r2.score
        assert r1.grade == r2.grade

    def test_summary_is_non_empty_string(self):
        findings = [_make_finding("high")]
        report = calculate_risk(findings)
        assert isinstance(report.summary, str)
        assert len(report.summary) > 0


class TestScoreToGrade:
    @pytest.mark.parametrize("score,expected_grade", [
        (100, "A+"),
        (90, "A+"),
        (89, "A"),
        (80, "A"),
        (79, "B"),
        (70, "B"),
        (69, "C"),
        (55, "C"),
        (54, "D"),
        (35, "D"),
        (34, "F"),
        (0, "F"),
    ])
    def test_grade_boundaries(self, score, expected_grade):
        assert _score_to_grade(score) == expected_grade

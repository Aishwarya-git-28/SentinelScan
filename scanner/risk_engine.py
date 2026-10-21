"""
scanner/risk_engine.py
Deterministic risk scoring for SentinelScan.

Formula
-------
Start with a perfect score of 100.
For each finding whose status is 'finding', subtract the weight for its severity.
Deductions are capped so the score does not go below 0.
Passed checks and inconclusive checks have no weight.

Severity weights (defined in config.py):
  critical       -30
  high           -20
  medium         -10
  low             -5
  informational   -1

The formula, weights, and limitations are documented here and in
docs/ARCHITECTURE.md so the score is transparent and reproducible.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import config
from scanner.security_checks import Finding


@dataclass
class RiskReport:
    """Aggregated risk assessment for a scan."""
    score: int                              # 0–100; higher = fewer detected issues
    grade: str                              # A+, A, B, C, D, F
    total_findings: int = 0
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    passed_count: int = 0
    inconclusive_count: int = 0
    error_count: int = 0
    total_deduction: int = 0
    summary: str = ""


# Severity ordering for display purposes
SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]


def calculate_risk(findings: list[Finding]) -> RiskReport:
    """
    Calculate a deterministic risk score from a list of :class:`Finding` objects.

    Parameters
    ----------
    findings : list[Finding]
        All findings returned by the scanner, including passed and inconclusive checks.

    Returns
    -------
    RiskReport
        A fully populated :class:`RiskReport`.
    """
    counts: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    passed = 0
    inconclusive = 0
    error = 0
    deduction = 0

    for f in findings:
        if f.status == "finding":
            sev = f.severity.lower()
            counts[sev] = counts.get(sev, 0) + 1
            deduction += config.SEVERITY_WEIGHTS.get(sev, 0)
        elif f.status == "passed":
            passed += 1
        elif f.status == "inconclusive":
            inconclusive += 1
        elif f.status == "error":
            error += 1

    deduction = min(deduction, config.MAX_DEDUCTION)
    score = max(0, 100 - deduction)
    grade = _score_to_grade(score)

    total_findings = sum(counts.values())

    summary_parts: list[str] = []
    for sev in SEVERITY_ORDER:
        if counts[sev] > 0:
            summary_parts.append(f"{counts[sev]} {sev}")

    summary = (
        f"Score: {score}/100 ({grade}). "
        f"Findings: {total_findings} "
        f"({', '.join(summary_parts) if summary_parts else 'none'}). "
        f"Passed: {passed}. Inconclusive: {inconclusive}."
    )

    return RiskReport(
        score=score,
        grade=grade,
        total_findings=total_findings,
        findings_by_severity=counts,
        passed_count=passed,
        inconclusive_count=inconclusive,
        error_count=error,
        total_deduction=deduction,
        summary=summary,
    )


def severity_color(severity: str) -> str:
    """Return a hex colour string for a given severity level (for UI rendering)."""
    colours = {
        "critical": "#EF4444",
        "high": "#F97316",
        "medium": "#F59E0B",
        "low": "#38BDF8",
        "informational": "#94A3B8",
    }
    return colours.get(severity.lower(), "#94A3B8")


def grade_color(grade: str) -> str:
    """Return a hex colour for a score grade."""
    grade_colours = {
        "A+": "#22C55E",
        "A":  "#10B981",
        "B":  "#3B82F6",
        "C":  "#F59E0B",
        "D":  "#F97316",
        "F":  "#EF4444",
    }
    return grade_colours.get(grade, "#94A3B8")


def _score_to_grade(score: int) -> str:
    """Convert a numeric score (0–100) to a letter grade."""
    if score >= 90:
        return "A+"
    if score >= 80:
        return "A"
    if score >= 70:
        return "B"
    if score >= 55:
        return "C"
    if score >= 35:
        return "D"
    return "F"

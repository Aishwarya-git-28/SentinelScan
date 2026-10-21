"""
utils/formatting.py
Display-formatting helpers for the SentinelScan Streamlit interface.
"""

from __future__ import annotations

from scanner.security_checks import Finding
from scanner.risk_engine import SEVERITY_ORDER


# Standard emojis for compatibility and clean status indicators
SEVERITY_EMOJI: dict[str, str] = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "informational": "⚪",
}

STATUS_EMOJI: dict[str, str] = {
    "finding": "⚠️",
    "passed": "✅",
    "inconclusive": "❓",
    "error": "❌",
}

# Semantic color mappings matching the design system
SEVERITY_COLORS: dict[str, str] = {
    "critical": "#EF4444",
    "high": "#F97316",
    "medium": "#F59E0B",
    "low": "#38BDF8",
    "informational": "#94A3B8",
}

SEVERITY_BADGE_CSS: dict[str, str] = {
    "critical": "background:rgba(239, 68, 68, 0.15);color:#F87171;border:1px solid rgba(239, 68, 68, 0.35);padding:2px 8px;border-radius:4px;font-size:0.75em;font-weight:600;letter-spacing:0.03em;",
    "high": "background:rgba(249, 115, 22, 0.15);color:#FB923C;border:1px solid rgba(249, 115, 22, 0.35);padding:2px 8px;border-radius:4px;font-size:0.75em;font-weight:600;letter-spacing:0.03em;",
    "medium": "background:rgba(245, 158, 11, 0.15);color:#FBBF24;border:1px solid rgba(245, 158, 11, 0.35);padding:2px 8px;border-radius:4px;font-size:0.75em;font-weight:600;letter-spacing:0.03em;",
    "low": "background:rgba(56, 189, 248, 0.15);color:#38BDF8;border:1px solid rgba(56, 189, 248, 0.35);padding:2px 8px;border-radius:4px;font-size:0.75em;font-weight:600;letter-spacing:0.03em;",
    "informational": "background:rgba(148, 163, 184, 0.15);color:#CBD5E1;border:1px solid rgba(148, 163, 184, 0.35);padding:2px 8px;border-radius:4px;font-size:0.75em;font-weight:600;letter-spacing:0.03em;",
}


def severity_badge(severity: str) -> str:
    """Return a styled HTML badge string for *severity*."""
    sev = severity.lower()
    css = SEVERITY_BADGE_CSS.get(sev, "background:#1E293B;color:#CBD5E1;padding:2px 8px;border-radius:4px;font-size:0.75em;")
    label = severity.upper()
    return f'<span style="{css}">{label}</span>'


def status_badge(status: str) -> str:
    """Return a styled HTML badge string for check status."""
    st_lower = status.lower()
    if st_lower == "finding":
        return '<span class="badge badge-high">ISSUE</span>'
    elif st_lower == "passed":
        return '<span class="badge badge-passed">PASSED</span>'
    elif st_lower == "inconclusive":
        return '<span class="badge badge-info">INCONCLUSIVE</span>'
    return '<span class="badge badge-critical">ERROR</span>'


def format_finding_title(finding: Finding) -> str:
    """Format a finding title with its ID and title for display."""
    emoji = SEVERITY_EMOJI.get(finding.severity.lower(), "⚪")
    status = STATUS_EMOJI.get(finding.status, "")
    return f"{status} {emoji} [{finding.finding_id}] {finding.title}"


def score_gauge_color(score: int) -> str:
    """Return a CSS color string for a score value matching the design system."""
    if score >= 85:
        return "#22C55E"
    if score >= 70:
        return "#3B82F6"
    if score >= 50:
        return "#F59E0B"
    return "#EF4444"


def truncate(text: str, max_len: int = 120) -> str:
    """Return *text* truncated to *max_len* characters with an ellipsis."""
    if not text:
        return ""
    if len(text) <= max_len:
        return text
    return text[:max_len].rstrip() + "…"


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Sort findings: findings first by severity, then passed, then inconclusive."""
    def key(f: Finding):
        sev_rank = SEVERITY_ORDER.index(f.severity.lower()) if f.severity.lower() in SEVERITY_ORDER else 99
        status_rank = 0 if f.status == "finding" else (1 if f.status == "inconclusive" else 2)
        return (status_rank, sev_rank)
    return sorted(findings, key=key)

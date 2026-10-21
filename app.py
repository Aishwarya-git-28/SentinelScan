"""
app.py — SentinelScan Streamlit Application Entry Point
Identify. Understand. Secure.

Run with:
    python -m streamlit run app.py
"""

from __future__ import annotations

import inspect
from pathlib import Path
import time
from typing import Optional

import altair as alt
import pandas as pd
import streamlit as st

import config
from scanner.scanner_service import ScanResult, run_scan
from scanner.report_generator import (
    generate_json, generate_csv, generate_pdf, REPORTLAB_AVAILABLE,
)
from scanner.risk_engine import severity_color, grade_color, SEVERITY_ORDER
from scanner.security_checks import Finding
from utils.formatting import (
    severity_badge, status_badge, format_finding_title, score_gauge_color,
    sort_findings, SEVERITY_EMOJI, STATUS_EMOJI, truncate,
)
from utils.demo_data import get_demo_scan_result


# ── Page configuration ────────────────────────────────────────────────────────
st.set_page_config(
    page_title="SentinelScan — Web Security Scanner",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ── Layout Compatibility Helper ───────────────────────────────────────────────
_ST_SUPPORTS_WIDTH = "width" in inspect.signature(st.button).parameters

def _fw_kw() -> dict:
    """Return compatible full-width argument for Streamlit elements."""
    return {"width": "stretch"} if _ST_SUPPORTS_WIDTH else {"use_container_width": True}


# ── Load Custom CSS ───────────────────────────────────────────────────────────
def _load_styles():
    """Inject the production cybersecurity dashboard stylesheet."""
    css_file = Path(__file__).parent / "assets" / "style.css"
    if css_file.exists():
        st.markdown(
            f"<style>{css_file.read_text(encoding='utf-8')}</style>",
            unsafe_allow_html=True,
        )


# ── Session State Helpers ─────────────────────────────────────────────────────
def _init_state():
    defaults = {
        "scan_result": None,
        "scan_history": [],
        "active_tab": "home",
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


# ── Standardized Page Header ──────────────────────────────────────────────────
def _render_page_header(title: str, subtitle: str, badge_html: Optional[str] = None):
    """Render a clean, aligned header section across every page using native Streamlit primitives."""
    if badge_html:
        col_t, col_b = st.columns([0.84, 0.16])
        with col_t:
            st.title(title)
        with col_b:
            st.markdown(
                f"<div style='margin-top: 1.25rem; text-align: right;'>{badge_html}</div>",
                unsafe_allow_html=True,
            )
    else:
        st.title(title)
    st.caption(subtitle)
    st.divider()


# ── Sidebar Navigation ────────────────────────────────────────────────────────
def _render_sidebar():
    with st.sidebar:
        # Brand box
        st.markdown(
            f"""<div class="sidebar-brand-box">
                <div class="sidebar-brand-title"><span>🛡</span> SentinelScan</div>
                <div class="sidebar-brand-tagline">{config.APP_TAGLINE}</div>
                <div class="sidebar-version-pill">v{config.APP_VERSION}</div>
            </div>""",
            unsafe_allow_html=True,
        )

        st.caption("NAVIGATION")
        pages = [
            ("🏠 Dashboard", "home"),
            ("🔍 Scanner", "scanner"),
            ("📊 Results", "results"),
            ("📋 Findings", "findings"),
            ("📥 Reports", "reports"),
            ("ℹ️ About", "about"),
        ]

        current_page = st.session_state.active_tab
        for label, key in pages:
            is_active = (current_page == key)
            btn_label = f"▸ {label}" if is_active else label
            if st.button(btn_label, key=f"nav_{key}", **_fw_kw()):
                st.session_state.active_tab = key
                st.rerun()

        # Last scan status card in sidebar
        if st.session_state.scan_result:
            r: ScanResult = st.session_state.scan_result
            mode_badge = "badge-demo" if r.scan_mode == "demo" else "badge-live"
            mode_text = "DEMO" if r.scan_mode == "demo" else "LIVE"
            score_val = r.risk_report.score if r.risk_report else 0
            grade_val = r.risk_report.grade if r.risk_report else "N/A"
            target_disp = truncate(r.normalized_url or r.target_url, 22)

            with st.container(border=True):
                st.markdown(
                    f"""<div style="font-size: 0.72rem; text-transform: uppercase; color: var(--text-muted); font-weight: 600; margin-bottom: 4px; display: flex; justify-content: space-between; align-items: center;">
                        <span>Latest Scan</span>
                        <span class="badge {mode_badge}">{mode_text}</span>
                    </div>
                    <div style="font-size: 0.82rem; font-family: monospace; color: var(--accent-primary); margin-bottom: 6px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="{r.normalized_url or r.target_url}">
                        {target_disp}
                    </div>
                    <div style="display: flex; align-items: center; justify-content: space-between;">
                        <span style="font-size: 1.15rem; font-weight: 700; color: {score_gauge_color(score_val)};">{score_val}<span style="font-size: 0.75rem; color: var(--text-muted);">/100</span></span>
                        <span class="badge" style="background: rgba(38, 54, 80, 0.6); color: var(--text-primary); border: 1px solid var(--border-subtle);">Grade {grade_val}</span>
                    </div>""",
                    unsafe_allow_html=True,
                )

        # Authorized use advisory
        st.markdown(
            """<div class="sidebar-advisory-card">
                <strong style="color: var(--text-secondary);">Authorized Testing Only</strong><br/>
                Scan only domains you own or have explicit authorization to assess.
            </div>""",
            unsafe_allow_html=True,
        )


# ── Home Dashboard ────────────────────────────────────────────────────────────
def _render_home():
    _render_page_header(
        title="Security Posture Dashboard",
        subtitle="Automated, non-destructive web security configuration assessments and defensive intelligence.",
    )

    # Hero / Overview Banner Card
    with st.container(border=True):
        col_hero_text, col_hero_badge = st.columns([0.8, 0.2])
        with col_hero_text:
            st.markdown("### Defensive Web Configuration Scanner")
            st.markdown(
                "SentinelScan evaluates observable HTTP headers, TLS certificate configurations, "
                "cookie security flags, and cross-origin resource sharing policies. It provides a "
                "transparent 0–100 risk score and step-by-step remediation advice without intrusive exploitation."
            )
        with col_hero_badge:
            st.markdown(
                "<div style='text-align: right; padding-top: 8px;'><span class='badge badge-passed'>Non-Destructive</span><br/><br/><span class='badge badge-info'>Zero Cloud APIs</span></div>",
                unsafe_allow_html=True,
            )

    # 3-Column Feature Grid
    col_feat1, col_feat2, col_feat3 = st.columns(3)

    with col_feat1:
        with st.container(border=True):
            st.markdown("**Core Security Checks** 🔒")
            st.markdown(
                "- HTTP Security Headers (CSP, HSTS, XFO)\n"
                "- TLS Certificate validity & expiration\n"
                "- Cookie flags (Secure, HttpOnly, SameSite)\n"
                "- CORS origin configuration review\n"
                "- Server version & framework disclosure\n"
                "- HTTP to HTTPS redirect enforcement"
            )

    with col_feat2:
        with st.container(border=True):
            st.markdown("**Safety Architecture** 🛡")
            st.markdown(
                "- SSRF Defense: Blocks private & loopback IPs\n"
                "- DNS resolution verification on all targets\n"
                "- Redirect destination safety checks\n"
                "- Strict response body size limit (5 MB)\n"
                "- Zero injection attacks or fuzzing payloads\n"
                "- Explicit scan authorization required"
            )

    with col_feat3:
        with st.container(border=True):
            st.markdown("**Actionable Intelligence** 📊")
            st.markdown(
                "- Transparent, deterministic 0–100 scoring\n"
                "- Plain-English risk explanations\n"
                "- Tailored server remediation snippets\n"
                "- Full export to JSON, CSV, and PDF\n"
                "- Completely functional offline demo mode\n"
                "- 139 automated regression tests"
            )

    # Quick Start Actions Bar
    col_act1, col_act2 = st.columns(2)
    with col_act1:
        if st.button("🚀 Configure New Live Scan", key="home_scan_btn", **_fw_kw()):
            st.session_state.active_tab = "scanner"
            st.rerun()
    with col_act2:
        if st.button("▶ Run Offline Demo Scan", key="home_demo", **_fw_kw()):
            _run_demo_scan()
            st.session_state.active_tab = "results"
            st.rerun()

    # Session Scan History Section
    if st.session_state.scan_history:
        st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)
        st.markdown("#### Session History")
        history_rows = []
        for r in reversed(st.session_state.scan_history[-5:]):
            score = f"{r.risk_report.score}/100" if r.risk_report else "N/A"
            grade = r.risk_report.grade if r.risk_report else "—"
            history_rows.append({
                "Target URL": r.normalized_url or r.target_url,
                "Scan Mode": r.scan_mode.upper(),
                "Score": score,
                "Grade": grade,
                "Duration": f"{r.duration_seconds}s",
                "Timestamp": r.timestamp[:19].replace("T", " "),
                "Status": "Success" if r.success else "Failed",
            })
        st.dataframe(pd.DataFrame(history_rows), hide_index=True, **_fw_kw())


# ── Scanner Page ──────────────────────────────────────────────────────────────
def _render_scanner():
    _render_page_header(
        title="Security Scanner",
        subtitle="Specify a target domain for live configuration analysis or explore offline demo fixtures.",
    )

    tab_live, tab_demo = st.tabs(["🔴 Live Target Scan", "🎭 Offline Demo Mode"])

    with tab_live:
        with st.container(border=True):
            st.markdown("#### Target Configuration")
            with st.form("live_scan_form", clear_on_submit=False):
                url_input = st.text_input(
                    "Website URL",
                    placeholder="https://example.com",
                    help="Enter a fully-qualified domain name. HTTPS or HTTP are accepted.",
                )

                st.warning(
                    "⚠️ **Authorization Requirement:** You must own the target website or possess explicit, "
                    "written authorization to perform security testing. Unauthorized scanning may violate computer crime statutes."
                )

                confirmed = st.checkbox(
                    "I confirm that I own this website or have explicit written authorization to assess it, and accept full responsibility for this scan."
                )

                submit = st.form_submit_button("🚀 Launch Security Scan", type="primary")

        if submit:
            if not url_input.strip():
                st.error("Please provide a valid website URL before initiating a scan.")
            elif not confirmed:
                st.warning("You must confirm target authorization before proceeding with a live scan.")
            else:
                _run_live_scan(url_input.strip())

    with tab_demo:
        with st.container(border=True):
            st.markdown("#### Offline Demonstration Fixture")
            st.caption("Pre-packaged assessment dataset representing an illustrative web application.")
            st.markdown(
                "<p style='font-size: 0.9rem; color: var(--text-secondary); line-height: 1.6;'>"
                "Demo mode loads a pre-packaged assessment dataset representing an illustrative e-commerce web application. "
                "It allows full evaluation of the scoring engine, severity distribution charts, finding inspection, "
                "and report generation controls without making outbound network requests."
                "</p>",
                unsafe_allow_html=True,
            )
            st.info("Target: `https://example-demo-target.invalid` (Zero outbound network traffic)")
            if st.button("▶ Load Illustrative Demo Results", key="scanner_demo", type="primary"):
                _run_demo_scan()
                st.session_state.active_tab = "results"
                st.rerun()


def _run_live_scan(url: str):
    """Execute a live network scan and update state."""
    progress_bar = st.progress(0, text="Initializing scan pipeline…")
    status_box = st.empty()

    try:
        progress_bar.progress(15, text="Validating target URL and DNS resolution…")
        time.sleep(0.15)

        progress_bar.progress(35, text="Inspecting HTTP headers & TLS certificate…")
        status_box.info(f"Targeting: `{url}`")

        result = run_scan(url)

        progress_bar.progress(85, text="Evaluating findings & calculating risk score…")
        time.sleep(0.15)
        progress_bar.progress(100, text="Assessment complete.")

        st.session_state.scan_result = result
        st.session_state.scan_history.append(result)

        if result.success:
            status_box.success(
                f"Scan finished in {result.duration_seconds}s. "
                f"Overall Score: {result.risk_report.score}/100 ({result.risk_report.grade})"
            )
            st.session_state.active_tab = "results"
            time.sleep(0.6)
            st.rerun()
        else:
            status_box.error(f"Scan aborted: {result.error_message}")

    except Exception as exc:  # noqa: BLE001
        progress_bar.empty()
        st.error(f"Scan pipeline encountered an unexpected error: {exc}")


def _run_demo_scan():
    """Load offline demo fixture dataset."""
    result = get_demo_scan_result()
    st.session_state.scan_result = result
    st.session_state.scan_history.append(result)


# ── Results Dashboard ─────────────────────────────────────────────────────────
def _render_results():
    result: Optional[ScanResult] = st.session_state.scan_result

    if result is None:
        _render_page_header(
            title="Scan Results",
            subtitle="No assessment data available. Initiate a scan from the Scanner page or explore demo results.",
        )
        with st.container(border=True):
            st.markdown("### No Active Scan Results")
            st.caption("Run a live security assessment against an authorized domain or load offline demo fixtures to view the dashboard.")
            col_btn1, col_btn2 = st.columns(2)
            with col_btn1:
                if st.button("Go to Scanner", **_fw_kw()):
                    st.session_state.active_tab = "scanner"
                    st.rerun()
            with col_btn2:
                if st.button("Load Demo Results", **_fw_kw()):
                    _run_demo_scan()
                    st.rerun()
        return

    _render_page_header(
        title="Scan Results",
        subtitle="Security configuration analysis and posture evaluation.",
    )

    # Demo Banner if in demo mode
    if result.scan_mode == "demo":
        st.markdown(
            """<div class="demo-banner-box">
                <div class="demo-banner-text">
                    <strong>Demo Dataset Notice:</strong> These results are generated from local illustrative fixtures for demonstration purposes. No live network traffic was transmitted.
                </div>
                <span class="badge badge-demo">OFFLINE</span>
            </div>""",
            unsafe_allow_html=True,
        )

    # Failed Scan Callout
    if not result.success:
        st.error(f"Assessment Failure: {result.error_message}")
        return

    rr = result.risk_report
    if not rr:
        st.warning("Assessment finished but risk calculation was unavailable.")
        return

    # ── Section A: Scan Summary Header Strip ──────────────────────────────────
    target_clean = result.normalized_url or result.target_url
    mode_badge_html = (
        '<span class="badge badge-demo">DEMO MODE</span>'
        if result.scan_mode == "demo"
        else '<span class="badge badge-live">LIVE SCAN</span>'
    )
    status_code_str = f"{result.http_status_code} OK" if result.http_status_code else "N/A"
    ts_clean = result.timestamp[:19].replace("T", " ")

    summary_html = (
        "<div class='scan-summary-strip'>"
        f"<div class='summary-meta-item' style='flex: 2; min-width: 220px;'><span class='summary-meta-label'>Target URL</span><span class='summary-meta-url' title='{target_clean}'>{target_clean}</span></div>"
        f"<div class='summary-meta-item'><span class='summary-meta-label'>Scan Mode</span><span class='summary-meta-value'>{mode_badge_html}</span></div>"
        f"<div class='summary-meta-item'><span class='summary-meta-label'>HTTP Status</span><span class='summary-meta-value' style='color: var(--color-success); font-family: monospace;'>{status_code_str}</span></div>"
        f"<div class='summary-meta-item'><span class='summary-meta-label'>Duration</span><span class='summary-meta-value' style='font-family: monospace;'>{result.duration_seconds}s</span></div>"
        f"<div class='summary-meta-item' style='min-width: 160px;'><span class='summary-meta-label'>Timestamp</span><span class='summary-meta-value' style='font-size: 0.85rem; color: var(--text-secondary);'>{ts_clean}</span></div>"
        "</div>"
    )
    st.markdown(summary_html, unsafe_allow_html=True)

    # ── Section B: Posture Section (Score, Breakdown, Chart) ──────────────────
    col_score, col_breakdown, col_chart = st.columns([1.1, 1.2, 1.7])

    with col_score:
        score_val = rr.score
        s_color = score_gauge_color(score_val)
        g_color = grade_color(rr.grade)
        status_text = (
            "Excellent Security Posture" if score_val >= 90 else
            "Good Configuration" if score_val >= 80 else
            "Moderate Configuration Weaknesses" if score_val >= 70 else
            "Multiple Security Issues" if score_val >= 50 else
            "Critical Posture Weaknesses"
        )

        with st.container(border=True):
            st.markdown(
                f"""<div style="font-size: 0.78rem; font-weight: 600; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.05em; margin-bottom: 8px;">Overall Posture</div>
                <div class="score-display-card">
                    <div class="score-number-row">
                        <span class="score-number-big" style="color: {s_color};">{score_val}</span>
                        <span class="score-denominator">/ 100</span>
                    </div>
                    <div style="margin: 8px 0;">
                        <span class="badge-grade" style="background: rgba(38, 54, 80, 0.45); color: {g_color}; border: 1px solid {g_color};">
                            GRADE {rr.grade}
                        </span>
                    </div>
                    <div class="score-bar-track">
                        <div class="score-bar-fill" style="width: {score_val}%; background-color: {s_color};"></div>
                    </div>
                    <div class="score-status-desc">{status_text}</div>
                </div>""",
                unsafe_allow_html=True,
            )

    with col_breakdown:
        crit_c = rr.findings_by_severity.get("critical", 0)
        high_c = rr.findings_by_severity.get("high", 0)
        med_c = rr.findings_by_severity.get("medium", 0)
        low_c = rr.findings_by_severity.get("low", 0)
        info_c = rr.findings_by_severity.get("informational", 0)

        with st.container(border=True):
            st.markdown(
                f"""<div style="font-size: 0.78rem; font-weight: 600; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.05em; margin-bottom: 8px; display: flex; justify-content: space-between;">
                    <span>Findings Breakdown</span>
                    <span style="font-family: monospace;">{rr.total_findings} Total</span>
                </div>
                <div class="stat-list">
                    <div class="stat-row">
                        <span class="stat-row-label">
                            <span class="stat-dot" style="background-color: var(--color-critical);"></span> Critical
                        </span>
                        <span class="stat-row-count" style="color: {'var(--color-critical)' if crit_c else 'var(--text-muted)'};">{crit_c}</span>
                    </div>
                    <div class="stat-row">
                        <span class="stat-row-label">
                            <span class="stat-dot" style="background-color: var(--color-high);"></span> High
                        </span>
                        <span class="stat-row-count" style="color: {'var(--color-high)' if high_c else 'var(--text-muted)'};">{high_c}</span>
                    </div>
                    <div class="stat-row">
                        <span class="stat-row-label">
                            <span class="stat-dot" style="background-color: var(--color-medium);"></span> Medium
                        </span>
                        <span class="stat-row-count" style="color: {'var(--color-medium)' if med_c else 'var(--text-muted)'};">{med_c}</span>
                    </div>
                    <div class="stat-row">
                        <span class="stat-row-label">
                            <span class="stat-dot" style="background-color: var(--color-low);"></span> Low
                        </span>
                        <span class="stat-row-count" style="color: {'var(--color-low)' if low_c else 'var(--text-muted)'};">{low_c}</span>
                    </div>
                    <div class="stat-row">
                        <span class="stat-row-label">
                            <span class="stat-dot" style="background-color: var(--color-info);"></span> Informational
                        </span>
                        <span class="stat-row-count" style="color: var(--text-muted);">{info_c}</span>
                    </div>
                    <div class="stat-row" style="margin-top: 6px; padding-top: 8px; border-top: 1px solid var(--border-subtle); border-bottom: none;">
                        <span class="stat-row-label" style="color: var(--color-success);">
                            <span class="stat-dot" style="background-color: var(--color-success);"></span> Passed Checks
                        </span>
                        <span class="stat-row-count" style="color: var(--color-success);">{rr.passed_count}</span>
                    </div>
                </div>""",
                unsafe_allow_html=True,
            )

    with col_chart:
        with st.container(border=True):
            st.markdown(
                "<div style='font-size: 0.78rem; font-weight: 600; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.05em; margin-bottom: 8px;'>Severity Distribution</div>",
                unsafe_allow_html=True,
            )

            chart_df = pd.DataFrame([
                {"Severity": "Critical", "Count": crit_c, "Color": "#EF4444"},
                {"Severity": "High", "Count": high_c, "Color": "#F97316"},
                {"Severity": "Medium", "Count": med_c, "Color": "#F59E0B"},
                {"Severity": "Low", "Count": low_c, "Color": "#38BDF8"},
                {"Severity": "Info", "Count": info_c, "Color": "#94A3B8"},
            ])

            if rr.total_findings > 0:
                chart = (
                    alt.Chart(chart_df)
                    .mark_bar(cornerRadiusTopRight=3, cornerRadiusBottomRight=3, height=14)
                    .encode(
                        y=alt.Y(
                            "Severity:N",
                            sort=["Critical", "High", "Medium", "Low", "Info"],
                            title=None,
                            axis=alt.Axis(
                                labelColor="#94A3B8",
                                labelFontSize=11,
                                domainColor="#263650",
                                tickColor="#263650",
                            ),
                        ),
                        x=alt.X(
                            "Count:Q",
                            title=None,
                            axis=alt.Axis(
                                labelColor="#64748B",
                                tickMinStep=1,
                                gridColor="#182742",
                                domainColor="#263650",
                            ),
                        ),
                        color=alt.Color("Color:N", scale=None),
                        tooltip=["Severity:N", "Count:Q"],
                    )
                    .properties(height=165)
                    .configure_view(strokeWidth=0)
                    .configure(background="#111C32")
                )
                st.altair_chart(chart, theme=None, **_fw_kw())
            else:
                st.markdown(
                    """<div style="height: 150px; display: flex; flex-direction: column; align-items: center; justify-content: center; text-align: center;">
                        <div style="color: var(--color-success); font-size: 1.8rem; margin-bottom: 6px;">✓</div>
                        <div style="color: var(--color-success); font-size: 0.95rem; font-weight: 600;">Zero Weaknesses Detected</div>
                        <div style="color: var(--text-muted); font-size: 0.8rem;">All tested headers & configurations are properly secured.</div>
                    </div>""",
                    unsafe_allow_html=True,
                )

    # ── Section C: Full-Width Assessment Summary ──────────────────────────────
    with st.container(border=True):
        st.markdown(
            f"""<div style="display: flex; align-items: flex-start; gap: 12px;">
                <span style="font-size: 1.25rem; line-height: 1.2;">📋</span>
                <div>
                    <div style="font-size: 0.78rem; font-weight: 600; text-transform: uppercase; color: var(--accent-primary); letter-spacing: 0.04em; margin-bottom: 4px;">
                        Executive Assessment Summary
                    </div>
                    <div style="font-size: 0.92rem; color: var(--text-primary); line-height: 1.5;">
                        {rr.summary}
                    </div>
                </div>
            </div>""",
            unsafe_allow_html=True,
        )

    # ── Section D: Quick Findings Overview Table ──────────────────────────────
    active_findings = [f for f in result.findings if f.status == "finding"]
    if active_findings:
        st.markdown("#### Detected Weaknesses Overview")
        overview_data = []
        for f in sort_findings(active_findings):
            overview_data.append({
                "ID": f.finding_id,
                "Severity": f.severity.upper(),
                "Category": f.category,
                "Weakness Title": f.title,
                "Confidence": f.confidence.capitalize(),
            })
        st.dataframe(pd.DataFrame(overview_data), hide_index=True, **_fw_kw())
    else:
        st.info("No active security weaknesses were detected on this target.")

    # Action navigation buttons
    col_nav_a, col_nav_b = st.columns(2)
    with col_nav_a:
        if st.button("🔍 Explore Detailed Findings & Remediation", **_fw_kw()):
            st.session_state.active_tab = "findings"
            st.rerun()
    with col_nav_b:
        if st.button("📥 Download Formal Scan Reports", **_fw_kw()):
            st.session_state.active_tab = "reports"
            st.rerun()


# ── Detailed Findings Page ────────────────────────────────────────────────────
def _render_findings():
    result: Optional[ScanResult] = st.session_state.scan_result

    if result is None:
        _render_page_header(
            title="Detailed Security Findings",
            subtitle="No assessment data available. Initiate a scan to view security findings.",
        )
        st.info("Run a live scan or load demo data from the Scanner page to review detailed findings.")
        return

    _render_page_header(
        title="Detailed Security Findings",
        subtitle="In-depth analysis, evidence observed, and remediation instructions for every evaluated check.",
    )

    if result.scan_mode == "demo":
        st.markdown(
            """<div class="demo-banner-box">
                <div class="demo-banner-text">
                    <strong>Demo Dataset:</strong> Findings below represent illustrative configurations for offline testing.
                </div>
                <span class="badge badge-demo">ILLUSTRATIVE</span>
            </div>""",
            unsafe_allow_html=True,
        )

    # ── Filter Bar Card ───────────────────────────────────────────────────────
    with st.container(border=True):
        st.markdown(
            "<div style='font-size: 0.78rem; font-weight: 600; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.05em; margin-bottom: 12px;'>Filter & Search Findings</div>",
            unsafe_allow_html=True,
        )

        all_categories = sorted({f.category for f in result.findings})
        f_col1, f_col2, f_col3 = st.columns([1, 1, 1.4])

        with f_col1:
            severity_filter = st.multiselect(
                "Filter by Severity",
                options=["critical", "high", "medium", "low", "informational"],
                default=[],
                format_func=lambda s: s.upper(),
            )
        with f_col2:
            status_filter = st.multiselect(
                "Filter by Status",
                options=["finding", "passed", "inconclusive", "error"],
                default=[],
                format_func=lambda s: s.capitalize(),
            )
        with f_col3:
            category_filter = st.multiselect(
                "Filter by Category",
                options=all_categories,
                default=[],
            )

        search_query = st.text_input("Search checks by keyword or title", placeholder="Filter by finding ID, title, or evidence...")

    # Apply filters
    filtered = sort_findings(result.findings)
    if severity_filter:
        filtered = [f for f in filtered if f.severity.lower() in severity_filter]
    if status_filter:
        filtered = [f for f in filtered if f.status in status_filter]
    if category_filter:
        filtered = [f for f in filtered if f.category in category_filter]
    if search_query:
        term = search_query.lower()
        filtered = [
            f for f in filtered
            if term in f.title.lower() or term in f.short_description.lower() or term in f.finding_id.lower()
        ]

    # Result counter
    st.caption(f"Displaying {len(filtered)} of {len(result.findings)} evaluated checks")

    # ── Render Finding Cards ──────────────────────────────────────────────────
    for finding in filtered:
        _render_finding_card(finding)

    if not filtered:
        with st.container(border=True):
            st.markdown(
                "<p style='color: var(--text-secondary); text-align: center; margin: 16px 0;'>No checks match the specified filter criteria.</p>",
                unsafe_allow_html=True,
            )


def _render_finding_card(finding: Finding):
    """Render an individual finding inside a styled expander."""
    status_label = finding.status.capitalize()
    sev_upper = finding.severity.upper()
    sev_clr = severity_color(finding.severity)

    # Header label
    expander_title = f"[{finding.finding_id}] {finding.title} — {sev_upper}"
    is_expanded = (finding.status == "finding" and finding.severity in ("critical", "high"))

    with st.expander(expander_title, expanded=is_expanded):
        # 4-Column Metadata Strip
        meta_html = (
            "<div style='display: flex; flex-wrap: wrap; gap: 20px; padding: 4px 0 12px 0; border-bottom: 1px solid var(--border-subtle); margin-bottom: 12px;'>"
            f"<div><span style='font-size: 0.72rem; text-transform: uppercase; color: var(--text-muted); font-weight: 600; display: block;'>Severity</span><span style='color: {sev_clr}; font-weight: 700; font-size: 0.88rem;'>{sev_upper}</span></div>"
            f"<div><span style='font-size: 0.72rem; text-transform: uppercase; color: var(--text-muted); font-weight: 600; display: block;'>Status</span><span style='color: var(--text-primary); font-size: 0.88rem;'>{status_label}</span></div>"
            f"<div><span style='font-size: 0.72rem; text-transform: uppercase; color: var(--text-muted); font-weight: 600; display: block;'>Category</span><span style='color: var(--text-secondary); font-size: 0.88rem;'>{finding.category}</span></div>"
            f"<div><span style='font-size: 0.72rem; text-transform: uppercase; color: var(--text-muted); font-weight: 600; display: block;'>Confidence</span><span style='color: var(--text-secondary); font-size: 0.88rem;'>{finding.confidence.capitalize()}</span></div>"
            "</div>"
        )
        st.markdown(meta_html, unsafe_allow_html=True)

        st.markdown(f"**Description:** {finding.short_description}")

        if finding.evidence:
            st.markdown("**Evidence Observed:**")
            st.code(finding.evidence, language="text")

        if finding.why_it_matters:
            why_html = f"<div class='finding-box'><strong style='color: var(--accent-primary);'>Why It Matters:</strong><br/>{finding.why_it_matters}</div>"
            st.markdown(why_html, unsafe_allow_html=True)

        if finding.remediation and finding.status == "finding":
            rem_html = f"<div class='finding-box-remediation'><strong style='color: var(--color-success);'>Recommended Remediation:</strong><br/>{finding.remediation}</div>"
            st.markdown(rem_html, unsafe_allow_html=True)


# ── Reports & Export Page ─────────────────────────────────────────────────────
def _render_reports():
    result: Optional[ScanResult] = st.session_state.scan_result

    if result is None:
        _render_page_header(
            title="Reports & Data Export",
            subtitle="No assessment data available for report generation. Run a scan first.",
        )
        st.info("Initiate a scan from the Scanner page or explore demo results to generate reports.")
        return

    _render_page_header(
        title="Reports & Data Export",
        subtitle="Export comprehensive security reports in machine-readable and executive formats.",
    )

    if not result.success:
        st.error(f"Cannot export reports because the scan failed: {result.error_message}")
        return

    target = result.normalized_url or result.target_url
    ts_safe = result.timestamp[:19].replace(":", "-").replace("T", "_")
    filename_base = f"sentinelscan_{ts_safe}"
    score_val = result.risk_report.score if result.risk_report else 0
    grade_val = result.risk_report.grade if result.risk_report else "N/A"

    # Metadata Strip
    meta_strip_html = (
        "<div class='scan-summary-strip' style='margin-bottom: 24px;'>"
        f"<div class='summary-meta-item' style='flex: 2;'><span class='summary-meta-label'>Target Domain</span><span class='summary-meta-url'>{target}</span></div>"
        f"<div class='summary-meta-item'><span class='summary-meta-label'>Score</span><span class='summary-meta-value' style='color: {score_gauge_color(score_val)}; font-weight: 700;'>{score_val}/100</span></div>"
        f"<div class='summary-meta-item'><span class='summary-meta-label'>Grade</span><span class='summary-meta-value' style='font-weight: 700;'>{grade_val}</span></div>"
        f"<div class='summary-meta-item'><span class='summary-meta-label'>Findings</span><span class='summary-meta-value'>{result.risk_report.total_findings if result.risk_report else 0} detected</span></div>"
        "</div>"
    )
    st.markdown(meta_strip_html, unsafe_allow_html=True)

    # 3 Balanced Download Cards
    col_rep1, col_rep2, col_rep3 = st.columns(3)

    # ── JSON Export Card ──────────────────────────────────────────────────────
    with col_rep1:
        with st.container(border=True):
            st.markdown(
                """<div style="font-size: 0.74rem; font-weight: 600; text-transform: uppercase; color: var(--text-muted); display: flex; justify-content: space-between; margin-bottom: 6px;">
                    <span>Machine Readable</span>
                    <span class="badge badge-info">JSON</span>
                </div>
                <h4 style="margin: 0 0 6px 0; color: var(--text-primary); font-size: 1.05rem;">JSON Report</h4>
                <p style="font-size: 0.85rem; color: var(--text-secondary); line-height: 1.5; margin-bottom: 16px;">
                    Complete structured telemetry including target metadata, timestamps, risk score,
                    and raw findings array. Suitable for SIEM or automated CI/CD ingestion.
                </p>""",
                unsafe_allow_html=True,
            )
            try:
                json_payload = generate_json(result)
                st.download_button(
                    label="⬇️ Download JSON",
                    data=json_payload.encode("utf-8"),
                    file_name=f"{filename_base}.json",
                    mime="application/json",
                    **_fw_kw(),
                )
            except Exception as exc:
                st.error(f"JSON generation error: {exc}")

    # ── CSV Export Card ───────────────────────────────────────────────────────
    with col_rep2:
        with st.container(border=True):
            st.markdown(
                """<div style="font-size: 0.74rem; font-weight: 600; text-transform: uppercase; color: var(--text-muted); display: flex; justify-content: space-between; margin-bottom: 6px;">
                    <span>Tabular Spreadsheet</span>
                    <span class="badge badge-info">CSV</span>
                </div>
                <h4 style="margin: 0 0 6px 0; color: var(--text-primary); font-size: 1.05rem;">CSV Export</h4>
                <p style="font-size: 0.85rem; color: var(--text-secondary); line-height: 1.5; margin-bottom: 16px;">
                    Flattened spreadsheet export containing one row per security check. Includes finding ID,
                    category, severity, observed evidence, and remediation steps for Excel/Sheets.
                </p>""",
                unsafe_allow_html=True,
            )
            try:
                csv_payload = generate_csv(result)
                st.download_button(
                    label="⬇️ Download CSV",
                    data=csv_payload.encode("utf-8"),
                    file_name=f"{filename_base}.csv",
                    mime="text/csv",
                    **_fw_kw(),
                )
            except Exception as exc:
                st.error(f"CSV generation error: {exc}")

    # ── PDF Export Card ───────────────────────────────────────────────────────
    with col_rep3:
        with st.container(border=True):
            st.markdown(
                """<div style="font-size: 0.74rem; font-weight: 600; text-transform: uppercase; color: var(--text-muted); display: flex; justify-content: space-between; margin-bottom: 6px;">
                    <span>Executive Document</span>
                    <span class="badge badge-info">PDF</span>
                </div>
                <h4 style="margin: 0 0 6px 0; color: var(--text-primary); font-size: 1.05rem;">PDF Summary</h4>
                <p style="font-size: 0.85rem; color: var(--text-secondary); line-height: 1.5; margin-bottom: 16px;">
                    Formatted multi-page document featuring branded cover page, metadata tables, executive
                    summary, detailed findings table, methodology, and legal disclaimers.
                </p>""",
                unsafe_allow_html=True,
            )
            if REPORTLAB_AVAILABLE:
                try:
                    pdf_payload = generate_pdf(result)
                    if pdf_payload:
                        st.download_button(
                            label="⬇️ Download PDF",
                            data=pdf_payload,
                            file_name=f"{filename_base}.pdf",
                            mime="application/pdf",
                            **_fw_kw(),
                        )
                    else:
                        st.warning("PDF generator produced empty content.")
                except Exception as exc:
                    st.error(f"PDF compilation error: {exc}")
            else:
                st.warning("ReportLab dependency not available for PDF export.")

    # Methodology & Disclaimer Card
    with st.container(border=True):
        st.markdown("**Report Methodology & Disclaimers**")
        st.caption(config.REPORT_DISCLAIMER)


# ── About & Methodology Page ──────────────────────────────────────────────────
def _render_about():
    _render_page_header(
        title="About SentinelScan & Methodology",
        subtitle="Architecture, evaluation criteria, deterministic scoring algorithms, and defensive security scope.",
    )

    tab_overview, tab_scoring, tab_limitations = st.tabs([
        "📖 Scope & Architecture",
        "📐 Scoring Methodology",
        "⚠️ Safety & Disclaimers",
    ])

    with tab_overview:
        with st.container(border=True):
            st.markdown(f"#### SentinelScan v{config.APP_VERSION}")
            st.markdown(
                "Developed as a cybersecurity assessment tool for website owners, developers, and learners. "
                "SentinelScan inspects publicly accessible HTTP response metadata to uncover common configuration gaps."
            )
            st.markdown("##### Evaluated Security Vectors")
            st.markdown(
                "- **Content-Security-Policy:** Mitigates cross-site scripting (XSS) and unauthorized data injection.\n"
                "- **Strict-Transport-Security:** Enforces encrypted HTTPS connections and blocks SSL-stripping.\n"
                "- **X-Frame-Options & CSP frame-ancestors:** Protects against clickjacking and malicious iframe embedding.\n"
                "- **X-Content-Type-Options:** Blocks MIME-type sniffing attacks across modern user agents.\n"
                "- **TLS Certificate Validity:** Inspects CA trust chains, SAN coverage, and impending certificate expiration.\n"
                "- **Cookie Security Flags:** Checks Secure, HttpOnly, and SameSite attributes against session theft."
            )

    with tab_scoring:
        with st.container(border=True):
            st.markdown("#### Deterministic Scoring Algorithm")
            st.markdown(
                "The posture score begins at **100 points**. Deductions are subtracted based on the severity of identified weaknesses:\n\n"
                "- **Critical (-30 pts):** Severe flaw (e.g. expired TLS certificate).\n"
                "- **High (-20 pts):** High impact weakness (e.g. missing CSP, insecure HTTP transport).\n"
                "- **Medium (-10 pts):** Moderate risk (e.g. missing HSTS, missing XFO/frame-ancestors).\n"
                "- **Low (-5 pts):** Low risk gap (e.g. missing X-Content-Type-Options, server banner leak).\n"
                "- **Informational (-1 pt):** Informational observations."
            )
            st.info("Formula: `Score = max(0, 100 - sum(deductions))`. Passed and inconclusive checks incur 0 penalty.")

    with tab_limitations:
        with st.container(border=True):
            st.markdown("#### Operational Scope & Limitations")
            st.markdown(
                "SentinelScan is an educational, configuration-inspection scanner. It is designed to be safe, "
                "non-destructive, and strictly non-invasive.\n\n"
                "- **Single Endpoint:** Evaluates only the specified URL; does not crawl linked paths.\n"
                "- **Public Metadata Only:** Cannot assess authenticated session workflows or deep server-side logic flaws.\n"
                "- **Not a Penetration Test:** Automated configuration inspection cannot guarantee an absence of vulnerabilities."
            )
            st.warning("⚠️ **Authorized Testing Notice:** Ensure you have explicit written authorization prior to assessing third-party systems.")


# ── App Router ────────────────────────────────────────────────────────────────
def main():
    _init_state()
    _load_styles()
    _render_sidebar()

    current_page = st.session_state.active_tab
    if current_page == "home":
        _render_home()
    elif current_page == "scanner":
        _render_scanner()
    elif current_page == "results":
        _render_results()
    elif current_page == "findings":
        _render_findings()
    elif current_page == "reports":
        _render_reports()
    elif current_page == "about":
        _render_about()
    else:
        _render_home()


if __name__ == "__main__":
    main()

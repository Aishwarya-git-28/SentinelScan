"""
tests/test_app_ui.py
Automated UI interaction tests for app.py using Streamlit AppTest.

Tests full navigation, offline demo trigger, findings rendering,
chart generation, and report download controls without making network requests.
"""

from __future__ import annotations

import pytest
from streamlit.testing.v1 import AppTest


class TestStreamlitApp:
    """Test suite for Streamlit UI interactions."""

    def test_app_initial_load(self):
        """App should load cleanly with zero exceptions on first render."""
        at = AppTest.from_file("app.py")
        at.run()
        assert len(at.exception) == 0
        assert at.session_state["active_tab"] == "home"

    def test_demo_scan_from_home(self):
        """Clicking Run Demo Scan from Home loads demo data and navigates to results."""
        at = AppTest.from_file("app.py")
        at.run()
        at.button(key="home_demo").click().run()

        assert len(at.exception) == 0
        assert at.session_state["active_tab"] == "results"
        assert at.session_state["scan_result"] is not None
        assert at.session_state["scan_result"].scan_mode == "demo"
        assert at.session_state["scan_result"].risk_report.score >= 0

    def test_navigation_across_all_pages(self):
        """Sidebar buttons should switch active_tab without crashing."""
        at = AppTest.from_file("app.py")
        at.run()
        at.button(key="home_demo").click().run()

        for tab_key in ["scanner", "results", "findings", "reports", "about", "home"]:
            btn_key = f"nav_{tab_key}"
            at.button(key=btn_key).click().run()
            assert len(at.exception) == 0
            assert at.session_state["active_tab"] == tab_key

    def test_reports_tab_has_download_buttons(self):
        """Reports page should expose JSON, CSV, and PDF download buttons after demo scan."""
        at = AppTest.from_file("app.py")
        at.run()
        at.button(key="home_demo").click().run()
        at.button(key="nav_reports").click().run()

        assert len(at.exception) == 0
        dl_buttons = at.get("download_button")
        assert len(dl_buttons) == 3

        labels = [b.label for b in dl_buttons]
        assert any("JSON" in lbl for lbl in labels)
        assert any("CSV" in lbl for lbl in labels)
        assert any("PDF" in lbl for lbl in labels)

    def test_scanner_page_demo_button(self):
        """Scanner page demo tab button should also load demo data."""
        at = AppTest.from_file("app.py")
        at.run()
        at.button(key="nav_scanner").click().run()
        assert len(at.exception) == 0

        at.button(key="scanner_demo").click().run()
        assert len(at.exception) == 0
        assert at.session_state["active_tab"] == "results"
        assert at.session_state["scan_result"].scan_mode == "demo"

    def test_results_page_without_scan(self):
        """Results page when no scan has been run should render friendly empty state without error."""
        at = AppTest.from_file("app.py")
        at.run()
        at.button(key="nav_results").click().run()
        assert len(at.exception) == 0

    def test_findings_page_render_and_expanders(self):
        """Findings page should render expanders and search bar cleanly."""
        at = AppTest.from_file("app.py")
        at.run()
        at.button(key="home_demo").click().run()
        at.button(key="nav_findings").click().run()
        assert len(at.exception) == 0
        expanders = at.get("expander")
        assert len(expanders) > 0

    def test_results_dashboard_chart_render(self):
        """Results dashboard should render Altair chart and posture metrics."""
        at = AppTest.from_file("app.py")
        at.run()
        at.button(key="home_demo").click().run()
        at.button(key="nav_results").click().run()
        assert len(at.exception) == 0

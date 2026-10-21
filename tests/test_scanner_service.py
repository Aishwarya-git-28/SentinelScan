"""
tests/test_scanner_service.py
Tests for scanner/scanner_service.py — integration tests using mocks.
No real HTTP requests are made.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests as req

from scanner.scanner_service import run_scan, ScanResult
from scanner.security_checks import Finding
from scanner.url_validator import ValidationResult


# ── Helpers ───────────────────────────────────────────────────────────────────

def _mock_validation_success(url="https://example.com"):
    """Return a successful ValidationResult."""
    return ValidationResult(
        valid=True,
        normalized_url=url,
        hostname="example.com",
        scheme="https",
        port=None,
        resolved_ips=["93.184.216.34"],
    )


def _make_mock_response(status_code=200, headers=None, is_redirect=False,
                        location="", url="https://example.com"):
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    h = dict(headers or {})
    if location:
        h["Location"] = location
    mock_resp.headers = h
    mock_resp.is_redirect = is_redirect
    mock_resp.raw = MagicMock()
    mock_resp.raw.headers = {}
    mock_resp.url = url
    mock_resp.iter_content.return_value = iter([b"<html></html>"])
    mock_resp._content = b"<html></html>"
    mock_resp._content_consumed = True
    return mock_resp


# ── run_scan ──────────────────────────────────────────────────────────────────

class TestRunScan:
    def test_invalid_url_returns_failed_result(self):
        result = run_scan("not-a-url://invalid")
        assert isinstance(result, ScanResult)
        assert result.success is False
        assert result.error_message != ""

    def test_private_ip_url_returns_failed_result(self):
        with patch(
            "scanner.url_validator._resolve_hostname",
            return_value=(["127.0.0.1"], None),
        ):
            result = run_scan("http://localhost/")
        assert result.success is False
        assert "blocked" in result.error_message.lower() or "127" in result.error_message

    def test_network_failure_returns_failed_result(self):
        with patch("scanner.scanner_service.validate_url",
                   return_value=_mock_validation_success()):
            with patch("scanner.scanner_service.safe_get",
                       return_value=(None, "Connection refused")):
                result = run_scan("https://example.com")
        assert result.success is False
        assert "Connection refused" in result.error_message

    def test_successful_scan_returns_findings(self):
        mock_resp = _make_mock_response(200, headers={
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
        })
        with patch("scanner.scanner_service.validate_url", return_value=_mock_validation_success()):
            with patch("scanner.scanner_service.safe_get", return_value=(mock_resp, None)):
                with patch("scanner.tls_checker.check_tls_certificate", return_value=[]):
                    result = run_scan("https://example.com")

        assert result.success is True
        assert isinstance(result.findings, list)
        assert len(result.findings) > 0
        assert result.risk_report is not None

    def test_scan_result_has_timestamp(self):
        mock_resp = _make_mock_response()
        with patch("scanner.scanner_service.validate_url", return_value=_mock_validation_success()):
            with patch("scanner.scanner_service.safe_get", return_value=(mock_resp, None)):
                with patch("scanner.tls_checker.check_tls_certificate", return_value=[]):
                    result = run_scan("https://example.com")
        assert result.timestamp != ""

    def test_scan_result_has_duration(self):
        mock_resp = _make_mock_response()
        with patch("scanner.scanner_service.validate_url", return_value=_mock_validation_success()):
            with patch("scanner.scanner_service.safe_get", return_value=(mock_resp, None)):
                with patch("scanner.tls_checker.check_tls_certificate", return_value=[]):
                    result = run_scan("https://example.com")
        assert result.duration_seconds >= 0

    def test_one_check_failing_doesnt_crash_scan(self):
        """A single check raising an exception should not abort the whole scan."""
        mock_resp = _make_mock_response()
        with patch("scanner.scanner_service.validate_url", return_value=_mock_validation_success()):
            with patch("scanner.scanner_service.safe_get", return_value=(mock_resp, None)):
                with patch(
                    "scanner.scanner_service.check_content_security_policy",
                    side_effect=RuntimeError("Unexpected error in CSP check"),
                ):
                    with patch("scanner.tls_checker.check_tls_certificate", return_value=[]):
                        result = run_scan("https://example.com")
        assert result.success is True
        # Should still have other findings; the failed one becomes an error Finding
        error_findings = [f for f in result.findings if f.status == "error"]
        assert len(error_findings) >= 1

    def test_scan_mode_is_live(self):
        mock_resp = _make_mock_response()
        with patch("scanner.scanner_service.validate_url", return_value=_mock_validation_success()):
            with patch("scanner.scanner_service.safe_get", return_value=(mock_resp, None)):
                with patch("scanner.tls_checker.check_tls_certificate", return_value=[]):
                    result = run_scan("https://example.com")
        assert result.scan_mode == "live"

    def test_timeout_error_is_reported_cleanly(self):
        with patch("scanner.scanner_service.validate_url", return_value=_mock_validation_success()):
            with patch(
                "scanner.scanner_service.safe_get",
                return_value=(None, "Request timed out after 15s."),
            ):
                result = run_scan("https://example.com")
        assert result.success is False
        assert "timed out" in result.error_message.lower()

    def test_empty_url_is_rejected(self):
        result = run_scan("")
        assert result.success is False

    def test_http_403_response_does_not_crash(self):
        """A 403 status code is a valid HTTP response, not a scanner error."""
        mock_resp = _make_mock_response(403)
        with patch("scanner.scanner_service.validate_url", return_value=_mock_validation_success()):
            with patch("scanner.scanner_service.safe_get", return_value=(mock_resp, None)):
                with patch("scanner.tls_checker.check_tls_certificate", return_value=[]):
                    result = run_scan("https://example.com")
        assert result.success is True


# ── Demo mode ─────────────────────────────────────────────────────────────────

class TestDemoMode:
    def test_demo_returns_scan_result(self):
        from utils.demo_data import get_demo_scan_result
        result = get_demo_scan_result()
        assert isinstance(result, ScanResult)

    def test_demo_scan_mode_is_demo(self):
        from utils.demo_data import get_demo_scan_result
        result = get_demo_scan_result()
        assert result.scan_mode == "demo"

    def test_demo_has_findings(self):
        from utils.demo_data import get_demo_scan_result
        result = get_demo_scan_result()
        assert len(result.findings) > 0

    def test_demo_has_risk_report(self):
        from utils.demo_data import get_demo_scan_result
        result = get_demo_scan_result()
        assert result.risk_report is not None
        assert 0 <= result.risk_report.score <= 100

    def test_demo_url_is_clearly_fake(self):
        from utils.demo_data import get_demo_scan_result
        result = get_demo_scan_result()
        # Demo should point to an obviously non-real URL
        assert ".invalid" in result.target_url or "demo" in result.target_url.lower()

    def test_demo_is_deterministic(self):
        from utils.demo_data import get_demo_scan_result
        r1 = get_demo_scan_result()
        r2 = get_demo_scan_result()
        assert r1.risk_report.score == r2.risk_report.score
        assert r1.risk_report.grade == r2.risk_report.grade
        assert len(r1.findings) == len(r2.findings)

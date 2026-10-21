"""
tests/test_security_checks.py
Tests for scanner/security_checks.py

All tests use synthetic header dicts and mock responses.
No real HTTP requests are made.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from scanner.security_checks import (
    check_content_security_policy,
    check_strict_transport_security,
    check_x_content_type_options,
    check_x_frame_options,
    check_referrer_policy,
    check_permissions_policy,
    check_cookies,
    check_cors,
    check_server_header,
    check_x_powered_by,
    check_redirect_to_https,
    Finding,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_response(status_code=200, headers=None, set_cookie=None, is_redirect=False, location=""):
    """Build a mock requests.Response for testing."""
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    h = dict(headers or {})
    if location:
        h["Location"] = location
    mock_resp.headers = h
    mock_resp.is_redirect = is_redirect
    # Simulate no cookies by default
    mock_resp.raw = MagicMock()
    mock_resp.raw.headers = {}
    mock_resp.url = "https://example.com"
    return mock_resp


# ── Content-Security-Policy ───────────────────────────────────────────────────

class TestCheckContentSecurityPolicy:
    def test_missing_csp_is_finding(self):
        finding = check_content_security_policy({})
        assert finding.status == "finding"
        assert finding.severity == "high"
        assert "HDR-001" in finding.finding_id

    def test_present_csp_is_passed(self):
        headers = {"Content-Security-Policy": "default-src 'self'"}
        finding = check_content_security_policy(headers)
        assert finding.status == "passed"

    def test_unsafe_inline_csp_is_medium_finding(self):
        headers = {"Content-Security-Policy": "default-src 'self' 'unsafe-inline'"}
        finding = check_content_security_policy(headers)
        assert finding.status == "finding"
        assert finding.severity == "medium"
        assert "unsafe-inline" in finding.short_description

    def test_unsafe_eval_csp_is_medium_finding(self):
        headers = {"Content-Security-Policy": "default-src 'self' 'unsafe-eval'"}
        finding = check_content_security_policy(headers)
        assert finding.status == "finding"
        assert finding.severity == "medium"

    def test_case_insensitive_header_lookup(self):
        headers = {"content-security-policy": "default-src 'self'"}
        finding = check_content_security_policy(headers)
        assert finding.status == "passed"


# ── Strict-Transport-Security ─────────────────────────────────────────────────

class TestCheckStrictTransportSecurity:
    def test_missing_hsts_on_https_is_medium_finding(self):
        finding = check_strict_transport_security({}, "https")
        assert finding.status == "finding"
        assert finding.severity == "medium"

    def test_hsts_on_http_is_inconclusive(self):
        finding = check_strict_transport_security({}, "http")
        assert finding.status == "inconclusive"

    def test_adequate_hsts_is_passed(self):
        headers = {"Strict-Transport-Security": "max-age=31536000; includeSubDomains"}
        finding = check_strict_transport_security(headers, "https")
        assert finding.status == "passed"

    def test_short_max_age_is_low_finding(self):
        headers = {"Strict-Transport-Security": "max-age=300"}
        finding = check_strict_transport_security(headers, "https")
        assert finding.status == "finding"
        assert finding.severity == "low"


# ── X-Content-Type-Options ────────────────────────────────────────────────────

class TestCheckXContentTypeOptions:
    def test_missing_header_is_low_finding(self):
        finding = check_x_content_type_options({})
        assert finding.status == "finding"
        assert finding.severity == "low"

    def test_nosniff_is_passed(self):
        headers = {"X-Content-Type-Options": "nosniff"}
        finding = check_x_content_type_options(headers)
        assert finding.status == "passed"

    def test_wrong_value_is_low_finding(self):
        headers = {"X-Content-Type-Options": "sniff"}
        finding = check_x_content_type_options(headers)
        assert finding.status == "finding"


# ── X-Frame-Options ───────────────────────────────────────────────────────────

class TestCheckXFrameOptions:
    def test_missing_header_no_csp_is_medium(self):
        finding = check_x_frame_options({})
        assert finding.status == "finding"
        assert finding.severity == "medium"

    def test_xfo_present_is_passed(self):
        headers = {"X-Frame-Options": "SAMEORIGIN"}
        finding = check_x_frame_options(headers)
        assert finding.status == "passed"

    def test_csp_frame_ancestors_satisfies_check(self):
        headers = {"Content-Security-Policy": "frame-ancestors 'self'"}
        finding = check_x_frame_options(headers)
        assert finding.status == "passed"


# ── Referrer-Policy ───────────────────────────────────────────────────────────

class TestCheckReferrerPolicy:
    def test_missing_is_low_finding(self):
        finding = check_referrer_policy({})
        assert finding.status == "finding"
        assert finding.severity == "low"

    def test_strict_value_is_passed(self):
        headers = {"Referrer-Policy": "strict-origin-when-cross-origin"}
        finding = check_referrer_policy(headers)
        assert finding.status == "passed"

    def test_no_referrer_is_passed(self):
        headers = {"Referrer-Policy": "no-referrer"}
        finding = check_referrer_policy(headers)
        assert finding.status == "passed"


# ── Permissions-Policy ────────────────────────────────────────────────────────

class TestCheckPermissionsPolicy:
    def test_missing_is_low_finding(self):
        finding = check_permissions_policy({})
        assert finding.status == "finding"
        assert finding.severity == "low"

    def test_present_is_passed(self):
        headers = {"Permissions-Policy": "camera=(), microphone=()"}
        finding = check_permissions_policy(headers)
        assert finding.status == "passed"


# ── Cookie checks ─────────────────────────────────────────────────────────────

class TestCheckCookies:
    def test_no_cookies_returns_informational_passed(self):
        mock_resp = _make_response()
        findings = check_cookies(mock_resp)
        assert len(findings) == 1
        assert findings[0].status == "passed"
        assert findings[0].finding_id == "CKI-000"

    def test_insecure_cookie_is_medium_finding(self):
        mock_resp = _make_response()
        mock_resp.headers = {"set-cookie": "sessionid=abc; HttpOnly; Path=/"}
        findings = check_cookies(mock_resp)
        # Should find at least one issue: Secure missing
        finding_issues = [f for f in findings if f.status == "finding"]
        assert len(finding_issues) >= 1
        assert any("secure" in f.short_description.lower() for f in finding_issues)

    def test_secure_cookie_is_passed(self):
        mock_resp = _make_response()
        mock_resp.headers = {
            "set-cookie": "tok=xyz; Secure; HttpOnly; SameSite=Strict; Path=/"
        }
        findings = check_cookies(mock_resp)
        assert any(f.status == "passed" for f in findings)


# ── CORS ──────────────────────────────────────────────────────────────────────

class TestCheckCors:
    def test_no_cors_headers_is_passed(self):
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.headers = {}
        mock_resp.status_code = 200
        mock_session.options.return_value = mock_resp

        finding = check_cors("https://example.com", mock_session)
        assert finding.status == "passed"

    def test_wildcard_cors_is_low_finding(self):
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.headers = {"Access-Control-Allow-Origin": "*"}
        mock_resp.status_code = 200
        mock_session.options.return_value = mock_resp

        finding = check_cors("https://example.com", mock_session)
        assert finding.status == "finding"
        assert finding.severity == "low"

    def test_wildcard_with_credentials_is_high(self):
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        }
        mock_resp.status_code = 200
        mock_session.options.return_value = mock_resp

        finding = check_cors("https://example.com", mock_session)
        assert finding.status == "finding"
        assert finding.severity == "high"

    def test_cors_connection_error_is_inconclusive(self):
        import requests as req
        mock_session = MagicMock()
        mock_session.options.side_effect = req.exceptions.ConnectionError("refused")

        finding = check_cors("https://example.com", mock_session)
        assert finding.status == "inconclusive"


# ── Server header ─────────────────────────────────────────────────────────────

class TestCheckServerHeader:
    def test_absent_server_header_is_passed(self):
        finding = check_server_header({})
        assert finding.status == "passed"

    def test_detailed_server_header_is_low_finding(self):
        headers = {"Server": "Apache/2.4.54 (Ubuntu)"}
        finding = check_server_header(headers)
        assert finding.status == "finding"
        assert finding.severity == "low"

    def test_generic_server_header_is_informational_passed(self):
        headers = {"Server": "nginx"}
        finding = check_server_header(headers)
        # Generic/short value should be informational passed
        assert finding.status == "passed"


# ── X-Powered-By ─────────────────────────────────────────────────────────────

class TestCheckXPoweredBy:
    def test_absent_is_passed(self):
        finding = check_x_powered_by({})
        assert finding.status == "passed"

    def test_present_is_low_finding(self):
        headers = {"X-Powered-By": "PHP/8.1.0"}
        finding = check_x_powered_by(headers)
        assert finding.status == "finding"
        assert finding.severity == "low"


# ── Redirect to HTTPS ─────────────────────────────────────────────────────────

class TestCheckRedirectToHttps:
    def test_https_target_is_passed(self):
        mock_resp = _make_response()
        finding = check_redirect_to_https("https://example.com", mock_resp)
        assert finding.status == "passed"

    def test_http_no_redirect_is_high_finding(self):
        mock_resp = _make_response(status_code=200, is_redirect=False)
        finding = check_redirect_to_https("http://example.com", mock_resp)
        assert finding.status == "finding"
        assert finding.severity == "high"

    def test_http_redirects_to_https_is_passed(self):
        mock_resp = _make_response(
            status_code=301,
            is_redirect=True,
            location="https://example.com",
        )
        finding = check_redirect_to_https("http://example.com", mock_resp)
        assert finding.status == "passed"

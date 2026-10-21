"""
tests/test_url_validator.py
Tests for scanner/url_validator.py

All tests use mocked network calls; no real HTTP requests are made.
"""

from __future__ import annotations

import socket
from unittest.mock import patch, MagicMock

import pytest

from scanner.url_validator import (
    validate_url,
    validate_redirect_url,
    safe_get,
    build_session,
    _is_blocked_ip,
    _is_valid_hostname,
)


# ── validate_url ──────────────────────────────────────────────────────────────

class TestValidateUrl:
    """Tests for the validate_url function."""

    def _mock_resolve(self, ip="93.184.216.34"):
        """Return a patch context manager that makes DNS resolve to a safe IP."""
        return patch(
            "scanner.url_validator._resolve_hostname",
            return_value=([ip], None),
        )

    def test_valid_https_url(self):
        with self._mock_resolve():
            result = validate_url("https://example.com")
        assert result.valid is True
        assert result.scheme == "https"
        assert result.hostname == "example.com"

    def test_valid_http_url(self):
        with self._mock_resolve():
            result = validate_url("http://example.com")
        assert result.valid is True
        assert result.scheme == "http"

    def test_url_without_scheme_gets_https_prepended(self):
        with self._mock_resolve():
            result = validate_url("example.com")
        assert result.valid is True
        assert result.scheme == "https"

    def test_valid_url_with_path_and_port(self):
        with self._mock_resolve():
            result = validate_url("https://example.com:8443/path?query=1")
        assert result.valid is True
        assert result.port == 8443

    def test_unsupported_scheme_ftp_rejected(self):
        result = validate_url("ftp://example.com/file.txt")
        assert result.valid is False
        assert "ftp" in result.error_message.lower()

    def test_unsupported_scheme_file_rejected(self):
        result = validate_url("file:///etc/passwd")
        assert result.valid is False

    def test_empty_string_rejected(self):
        result = validate_url("")
        assert result.valid is False
        assert "non-empty" in result.error_message.lower()

    def test_non_string_rejected(self):
        result = validate_url(None)  # type: ignore[arg-type]
        assert result.valid is False

    def test_missing_hostname_rejected(self):
        result = validate_url("https:///path")
        assert result.valid is False

    def test_localhost_rejected(self):
        with patch(
            "scanner.url_validator._resolve_hostname",
            return_value=(["127.0.0.1"], None),
        ):
            result = validate_url("http://localhost/")
        assert result.valid is False
        assert "blocked" in result.error_message.lower() or "127" in result.error_message

    def test_private_ip_10_x_rejected(self):
        with patch(
            "scanner.url_validator._resolve_hostname",
            return_value=(["10.0.0.1"], None),
        ):
            result = validate_url("http://internal.corp/")
        assert result.valid is False

    def test_private_ip_192_168_rejected(self):
        with patch(
            "scanner.url_validator._resolve_hostname",
            return_value=(["192.168.1.100"], None),
        ):
            result = validate_url("http://router.local/")
        assert result.valid is False

    def test_link_local_ip_rejected(self):
        with patch(
            "scanner.url_validator._resolve_hostname",
            return_value=(["169.254.1.1"], None),
        ):
            result = validate_url("http://metadata.local/")
        assert result.valid is False

    def test_dns_failure_returns_invalid(self):
        with patch(
            "scanner.url_validator._resolve_hostname",
            return_value=([], "Name or service not known"),
        ):
            result = validate_url("https://this-domain-does-not-exist.invalid/")
        assert result.valid is False
        assert "dns" in result.error_message.lower() or "resolution" in result.error_message.lower()

    def test_whitespace_is_stripped(self):
        with self._mock_resolve():
            result = validate_url("  https://example.com  ")
        assert result.valid is True


class TestValidateRedirectUrl:
    def test_valid_redirect_accepted(self):
        with patch(
            "scanner.url_validator._resolve_hostname",
            return_value=(["93.184.216.34"], None),
        ):
            result = validate_redirect_url("https://example.com/new-path", "example.com")
        assert result.valid is True

    def test_private_redirect_blocked(self):
        with patch(
            "scanner.url_validator._resolve_hostname",
            return_value=(["192.168.0.1"], None),
        ):
            result = validate_redirect_url("http://192.168.0.1/", "example.com")
        assert result.valid is False


# ── _is_blocked_ip ────────────────────────────────────────────────────────────

class TestIsBlockedIp:
    def test_loopback_127_blocked(self):
        blocked, _ = _is_blocked_ip("127.0.0.1")
        assert blocked is True

    def test_private_10_blocked(self):
        blocked, _ = _is_blocked_ip("10.10.10.10")
        assert blocked is True

    def test_private_172_blocked(self):
        blocked, _ = _is_blocked_ip("172.16.0.1")
        assert blocked is True

    def test_private_192_168_blocked(self):
        blocked, _ = _is_blocked_ip("192.168.100.1")
        assert blocked is True

    def test_public_ip_allowed(self):
        blocked, _ = _is_blocked_ip("93.184.216.34")
        assert blocked is False

    def test_cloudflare_allowed(self):
        blocked, _ = _is_blocked_ip("1.1.1.1")
        assert blocked is False

    def test_ipv6_loopback_blocked(self):
        blocked, _ = _is_blocked_ip("::1")
        assert blocked is True

    def test_ipv6_link_local_blocked(self):
        blocked, _ = _is_blocked_ip("fe80::1")
        assert blocked is True

    def test_invalid_ip_blocked(self):
        blocked, _ = _is_blocked_ip("not-an-ip")
        assert blocked is True


# ── _is_valid_hostname ────────────────────────────────────────────────────────

class TestIsValidHostname:
    def test_simple_domain(self):
        assert _is_valid_hostname("example.com") is True

    def test_subdomain(self):
        assert _is_valid_hostname("www.sub.example.com") is True

    def test_raw_ipv4(self):
        assert _is_valid_hostname("1.2.3.4") is True

    def test_invalid_with_spaces(self):
        assert _is_valid_hostname("exam ple.com") is False

    def test_label_starting_with_hyphen(self):
        assert _is_valid_hostname("-bad.com") is False


# ── safe_get ──────────────────────────────────────────────────────────────────

class TestSafeGet:
    def _make_mock_response(self, status_code=200, headers=None, content=b"OK",
                            is_redirect=False, location=""):
        mock_resp = MagicMock()
        mock_resp.status_code = status_code
        mock_resp.headers = headers or {}
        mock_resp.is_redirect = is_redirect
        mock_resp.iter_content.return_value = iter([content])
        mock_resp._content = content
        mock_resp._content_consumed = True
        mock_resp.url = "https://example.com"
        return mock_resp

    def test_successful_get(self):
        mock_resp = self._make_mock_response(200)
        session = MagicMock()
        session.get.return_value = mock_resp
        resp, err = safe_get("https://example.com", session)
        assert err is None
        assert resp is not None

    def test_connection_error_handled(self):
        import requests as req
        session = MagicMock()
        session.get.side_effect = req.exceptions.ConnectionError("refused")
        resp, err = safe_get("https://example.com", session)
        assert resp is None
        assert err is not None
        assert "connection" in err.lower()

    def test_timeout_handled(self):
        import requests as req
        session = MagicMock()
        session.get.side_effect = req.exceptions.Timeout()
        resp, err = safe_get("https://example.com", session)
        assert resp is None
        assert "timed out" in err.lower() or "timeout" in err.lower()

    def test_ssl_error_handled(self):
        import requests as req
        session = MagicMock()
        session.get.side_effect = req.exceptions.SSLError("cert failed")
        resp, err = safe_get("https://example.com", session)
        assert resp is None
        assert "ssl" in err.lower() or "tls" in err.lower()

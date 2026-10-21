"""
scanner/scanner_service.py
Orchestrates the full scan pipeline for SentinelScan.

Coordinates URL validation, individual security checks, TLS inspection,
and risk scoring into a single ScanResult object.
"""

from __future__ import annotations

import datetime
import time
import traceback
from dataclasses import dataclass, field
from typing import Optional

import config
from scanner.security_checks import (
    Finding,
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
)
from scanner.tls_checker import check_tls_certificate
from scanner.risk_engine import RiskReport, calculate_risk
from scanner.url_validator import validate_url, safe_get, build_session


@dataclass
class ScanResult:
    """Complete result of a SentinelScan security assessment."""
    target_url: str
    normalized_url: str
    timestamp: str
    duration_seconds: float
    scan_mode: str                  # "live" or "demo"
    success: bool
    error_message: str = ""
    findings: list[Finding] = field(default_factory=list)
    risk_report: Optional[RiskReport] = None
    resolved_ips: list[str] = field(default_factory=list)
    http_status_code: Optional[int] = None
    final_url: str = ""             # URL after following redirects


def run_scan(raw_url: str) -> ScanResult:
    """
    Run the full SentinelScan security assessment against *raw_url*.

    Steps:
    1. Validate the URL (rejects private/loopback destinations).
    2. Perform the initial HTTP request.
    3. Run each security check module.
    4. Calculate the risk score.
    5. Return a fully populated ScanResult.

    This function never raises; failures are reported in ScanResult.error_message.
    """
    start_time = time.monotonic()
    ts = datetime.datetime.now(datetime.timezone.utc).astimezone().isoformat()

    # ── Step 1: Validate URL ──────────────────────────────────────────────────
    validation = validate_url(raw_url)
    if not validation.valid:
        return ScanResult(
            target_url=raw_url,
            normalized_url="",
            timestamp=ts,
            duration_seconds=round(time.monotonic() - start_time, 2),
            scan_mode="live",
            success=False,
            error_message=f"URL validation failed: {validation.error_message}",
        )

    url = validation.normalized_url

    # ── Step 2: Initial HTTP request ──────────────────────────────────────────
    session = build_session()
    response, req_error = safe_get(url, session, allow_redirects=True)

    if req_error or response is None:
        return ScanResult(
            target_url=raw_url,
            normalized_url=url,
            timestamp=ts,
            duration_seconds=round(time.monotonic() - start_time, 2),
            scan_mode="live",
            success=False,
            error_message=f"Network request failed: {req_error}",
            resolved_ips=validation.resolved_ips,
        )

    headers = dict(response.headers)
    findings: list[Finding] = []

    # ── Step 3: Security checks ───────────────────────────────────────────────

    # HTTP security headers
    _safe_append(findings, lambda: check_content_security_policy(headers))
    _safe_append(findings, lambda: check_strict_transport_security(headers, validation.scheme))
    _safe_append(findings, lambda: check_x_content_type_options(headers))
    _safe_append(findings, lambda: check_x_frame_options(headers))
    _safe_append(findings, lambda: check_referrer_policy(headers))
    _safe_append(findings, lambda: check_permissions_policy(headers))

    # Cookie security
    _safe_extend(findings, lambda: check_cookies(response))

    # CORS
    _safe_append(findings, lambda: check_cors(url, session))

    # Information disclosure
    _safe_append(findings, lambda: check_server_header(headers))
    _safe_append(findings, lambda: check_x_powered_by(headers))

    # Transport / redirect
    _safe_append(findings, lambda: check_redirect_to_https(url, response))

    # TLS certificate
    _safe_extend(findings, lambda: check_tls_certificate(url))

    # ── Step 4: Risk scoring ──────────────────────────────────────────────────
    risk_report = calculate_risk(findings)

    duration = round(time.monotonic() - start_time, 2)

    return ScanResult(
        target_url=raw_url,
        normalized_url=url,
        timestamp=ts,
        duration_seconds=duration,
        scan_mode="live",
        success=True,
        findings=findings,
        risk_report=risk_report,
        resolved_ips=validation.resolved_ips,
        http_status_code=response.status_code,
        final_url=response.url,
    )


# ── Private helpers ───────────────────────────────────────────────────────────

def _safe_append(findings: list[Finding], fn) -> None:
    """
    Call *fn()* and append the single Finding result.
    If *fn* raises, append an error Finding instead of crashing the whole scan.
    """
    try:
        result = fn()
        if result is not None:
            findings.append(result)
    except Exception as exc:  # noqa: BLE001
        findings.append(Finding(
            finding_id="ERR-001",
            title="Check failed with unexpected error",
            category="Scanner Error",
            severity="informational",
            status="error",
            short_description=f"A security check raised an unexpected exception: {exc}",
            evidence=traceback.format_exc()[-500:],
            why_it_matters="The check could not complete; its result is unavailable.",
            remediation="Review the scanner logs for diagnostic information.",
            confidence="low",
        ))


def _safe_extend(findings: list[Finding], fn) -> None:
    """
    Call *fn()* and extend findings with the returned list.
    If *fn* raises, append an error Finding.
    """
    try:
        results = fn()
        if results:
            findings.extend(results)
    except Exception as exc:  # noqa: BLE001
        findings.append(Finding(
            finding_id="ERR-001",
            title="Check failed with unexpected error",
            category="Scanner Error",
            severity="informational",
            status="error",
            short_description=f"A security check raised an unexpected exception: {exc}",
            evidence=traceback.format_exc()[-500:],
            why_it_matters="The check could not complete; its result is unavailable.",
            remediation="Review the scanner logs for diagnostic information.",
            confidence="low",
        ))

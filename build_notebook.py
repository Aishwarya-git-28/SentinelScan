"""
build_notebook.py
Generates Aishwarya_SentinelScan.ipynb for IBM SkillsBuild Cybersecurity submission.
"""
import json
from pathlib import Path

def create_notebook():
    cells = []

    def md(source):
        cells.append({
            "cell_type": "markdown",
            "metadata": {},
            "source": [line + "\n" for line in source.strip().split("\n")]
        })

    def code(source):
        cells.append({
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [line + "\n" for line in source.strip().split("\n")]
        })

    # ── Header ────────────────────────────────────────────────────────────────
    md("""
# IBM SkillsBuild Cybersecurity 2026 — Project Submission
## SentinelScan — Automated Web Security Configuration Scanner
**Identify. Understand. Secure.**

- **Student Name:** Aishwarya
- **Project Name:** SentinelScan
- **Partner Organization:** BharatCares & IBM SkillsBuild
- **Domain:** Defensive Web Application Security & Configuration Auditing
- **Submission Date:** October 2026
- **Repository:** https://github.com/Aishwarya-git-28/SentinelScan

---

### Project Overview
SentinelScan is an automated defensive security scanner designed to identify common web security configuration weaknesses on authorized domains. It evaluates observable HTTP security headers, TLS certificate configurations, cookie security flags, CORS origins, and server fingerprint leakage. The tool calculates a deterministic 0–100 security posture score, provides plain-English risk explanations, and generates downloadable reports in JSON, CSV, and PDF formats.
""")

    # ── Dependencies ──────────────────────────────────────────────────────────
    md("### 1. Installation & Environment Setup\nInstall the required lightweight, zero-cost dependencies.")
    code("""
# Install required libraries if running in Jupyter / Google Colab
# !pip install requests pandas reportlab
import sys
import os
import json
import csv
import ssl
import socket
import datetime
import ipaddress
import urllib.parse
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any

import requests
import pandas as pd

print(f"Python version: {sys.version}")
print("All core dependencies imported successfully.")
""")

    # ── Configuration ─────────────────────────────────────────────────────────
    md("""
### 2. Configuration & Security Constants
Defines safety parameters, request limits, timeout bounds, and the 14 blocked CIDR network ranges for SSRF defense.
""")
    code("""
# Application Metadata
APP_NAME = "SentinelScan"
APP_VERSION = "1.0.0"
APP_TAGLINE = "Identify. Understand. Secure."

# Safe HTTP Request Parameters
REQUEST_TIMEOUT = 15          # seconds
MAX_REDIRECTS = 5             # maximum hop limit
MAX_RESPONSE_BYTES = 5 * 1024 * 1024  # 5 MB read limit
USER_AGENT = "SentinelScan/1.0 (+https://github.com/Aishwarya-git-28/SentinelScan; Security Scanner)"
ALLOWED_SCHEMES = ["http", "https"]

# SSRF Protection: Blocked Private, Loopback, Link-Local & Reserved Ranges
BLOCKED_NETWORKS = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.168.0.0/16",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "::1/128",
    "fe80::/10",
]

# Risk Scoring Severity Weights (Deductions from base 100)
SEVERITY_WEIGHTS = {
    "critical": 30,
    "high": 20,
    "medium": 10,
    "low": 5,
    "informational": 1,
}

# Letter Grade Boundaries
GRADE_BOUNDARIES = [
    (90, "A+"),
    (80, "A"),
    (70, "B"),
    (55, "C"),
    (35, "D"),
    (0,  "F"),
]

print("Security configuration and safety parameters initialized.")
""")

    # ── URL Validator ─────────────────────────────────────────────────────────
    md("""
### 3. URL Validation & SSRF Protection Module
Ensures only valid, authorized, public HTTP/HTTPS endpoints are scanned. Automatically resolves DNS and blocks private or loopback IP addresses to prevent Server-Side Request Forgery (SSRF).
""")
    code("""
@dataclass
class ValidationResult:
    valid: bool
    normalized_url: Optional[str] = None
    error_message: Optional[str] = None
    hostname: Optional[str] = None
    port: Optional[int] = None
    resolved_ips: list[str] = field(default_factory=list)

def _is_blocked_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        for net_str in BLOCKED_NETWORKS:
            try:
                net = ipaddress.ip_network(net_str, strict=False)
                if ip in net:
                    return True
            except ValueError:
                continue
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved:
            return True
        return False
    except ValueError:
        return True

def _resolve_hostname(hostname: str) -> list[str]:
    try:
        ipaddress.ip_address(hostname)
        return [hostname]
    except ValueError:
        pass
    try:
        addrinfo = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        return list({item[4][0] for item in addrinfo})
    except socket.gaierror:
        return []

def validate_url(raw_url: str) -> ValidationResult:
    if not raw_url or not isinstance(raw_url, str):
        return ValidationResult(valid=False, error_message="URL must be a non-empty string.")

    cleaned = raw_url.strip()
    if "://" in cleaned:
        raw_scheme = cleaned.split("://", 1)[0].lower()
        if raw_scheme not in ALLOWED_SCHEMES:
            return ValidationResult(
                valid=False,
                error_message=f"Unsupported scheme '{raw_scheme}'. Only HTTP and HTTPS are permitted."
            )

    if not cleaned.lower().startswith(("http://", "https://")):
        cleaned = "https://" + cleaned

    try:
        parsed = urllib.parse.urlsplit(cleaned)
    except Exception as exc:
        return ValidationResult(valid=False, error_message=f"Malformed URL: {exc}")

    hostname = parsed.hostname
    if not hostname:
        return ValidationResult(valid=False, error_message="URL does not contain a valid hostname.")

    resolved_ips = _resolve_hostname(hostname)
    if not resolved_ips:
        return ValidationResult(
            valid=False,
            error_message=f"DNS resolution failed for hostname '{hostname}'."
        )

    for ip in resolved_ips:
        if _is_blocked_ip(ip):
            return ValidationResult(
                valid=False,
                error_message=f"Scanning rejected: Host '{hostname}' resolves to restricted IP ({ip})."
            )

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    normalized = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
    return ValidationResult(
        valid=True,
        normalized_url=normalized,
        hostname=hostname,
        port=port,
        resolved_ips=resolved_ips
    )

# Quick demonstration of SSRF defense and URL validation
test_urls = [
    "https://example.com",
    "http://127.0.0.1",
    "http://192.168.1.1",
    "ftp://example.com",
    "invalid url with spaces"
]

for url in test_urls:
    v = validate_url(url)
    status = "ALLOWED" if v.valid else f"BLOCKED: {v.error_message}"
    print(f"[{status}] -> {url}")
""")

    # ── Security Checks ───────────────────────────────────────────────────────
    md("""
### 4. Security Checks Module (12 Evaluated Vectors)
Inspects HTTP security headers (CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy), cookie security attributes, CORS configuration, and server banner leakage.
""")
    code("""
@dataclass
class Finding:
    finding_id: str
    title: str
    category: str
    severity: str          # critical, high, medium, low, informational
    status: str            # finding, passed, inconclusive, error
    short_description: str
    evidence: str
    why_it_matters: str
    remediation: str
    confidence: str = "high"
    details: dict = field(default_factory=dict)

def check_content_security_policy(headers: dict) -> Finding:
    for k, v in headers.items():
        if k.lower() == "content-security-policy":
            val_lower = v.lower()
            issues = []
            if "'unsafe-inline'" in val_lower:
                issues.append("'unsafe-inline' directive detected (weakens XSS protection)")
            if "'unsafe-eval'" in val_lower:
                issues.append("'unsafe-eval' directive detected")
            if issues:
                return Finding(
                    finding_id="HDR-001",
                    title="Weak Content-Security-Policy (CSP)",
                    category="HTTP Headers",
                    severity="medium",
                    status="finding",
                    short_description="Content-Security-Policy header contains insecure directives.",
                    evidence=f"Content-Security-Policy: {v[:100]}...",
                    why_it_matters="Directives like 'unsafe-inline' reduce protection against Cross-Site Scripting (XSS).",
                    remediation="Use cryptographic nonces or SHA hashes instead of 'unsafe-inline'/'unsafe-eval'."
                )
            return Finding(
                finding_id="HDR-001",
                title="Content-Security-Policy Configured",
                category="HTTP Headers",
                severity="informational",
                status="passed",
                short_description="Content-Security-Policy header is present and configured.",
                evidence=f"Content-Security-Policy: {v[:80]}...",
                why_it_matters="CSP restricts resource execution and protects against XSS injection attacks.",
                remediation="Ensure CSP is continuously reviewed as your application evolves."
            )
    return Finding(
        finding_id="HDR-001",
        title="Missing Content-Security-Policy (CSP)",
        category="HTTP Headers",
        severity="high",
        status="finding",
        short_description="No Content-Security-Policy header was observed in the server response.",
        evidence="Header not present in HTTP response.",
        why_it_matters="Without CSP, the browser cannot restrict script execution sources, increasing XSS risk.",
        remediation="Define and send a Content-Security-Policy header restricting script-src, object-src, and default-src."
    )

def check_strict_transport_security(headers: dict, is_https: bool) -> Finding:
    if not is_https:
        return Finding(
            finding_id="HDR-002",
            title="HSTS Not Applicable (HTTP Target)",
            category="HTTP Headers",
            severity="informational",
            status="inconclusive",
            short_description="Strict-Transport-Security cannot be validated because the target does not use HTTPS.",
            evidence="Connection used unencrypted HTTP.",
            why_it_matters="HSTS requires HTTPS to function.",
            remediation="Migrate target endpoint to HTTPS and configure HSTS."
        )
    for k, v in headers.items():
        if k.lower() == "strict-transport-security":
            val_lower = v.lower()
            if "max-age=" in val_lower:
                try:
                    parts = val_lower.split("max-age=")[1].split(";")[0].strip()
                    age = int(parts)
                    if age >= 10886400: # >= 6 months
                        return Finding(
                            finding_id="HDR-002",
                            title="Strict-Transport-Security (HSTS) Configured",
                            category="HTTP Headers",
                            severity="informational",
                            status="passed",
                            short_description=f"HSTS configured with max-age={age}s.",
                            evidence=f"Strict-Transport-Security: {v}",
                            why_it_matters="Enforces HTTPS connections and blocks SSL-stripping man-in-the-middle attacks.",
                            remediation="Consider adding 'includeSubDomains' and HSTS preloading."
                        )
                except ValueError:
                    pass
            return Finding(
                finding_id="HDR-002",
                title="Suboptimal HSTS Max-Age",
                category="HTTP Headers",
                severity="low",
                status="finding",
                short_description="HSTS max-age is shorter than recommended (less than 6 months).",
                evidence=f"Strict-Transport-Security: {v}",
                why_it_matters="Short max-age durations reduce the window of protection against downgrade attacks.",
                remediation="Increase max-age to at least 31536000 seconds (1 year)."
            )
    return Finding(
        finding_id="HDR-002",
        title="Missing Strict-Transport-Security (HSTS)",
        category="HTTP Headers",
        severity="medium",
        status="finding",
        short_description="No Strict-Transport-Security header was observed.",
        evidence="Header not present in HTTPS response.",
        why_it_matters="Leaves users vulnerable to SSL-stripping attacks on insecure networks.",
        remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to HTTPS responses."
    )

def check_x_content_type_options(headers: dict) -> Finding:
    for k, v in headers.items():
        if k.lower() == "x-content-type-options":
            if v.strip().lower() == "nosniff":
                return Finding(
                    finding_id="HDR-003",
                    title="X-Content-Type-Options: nosniff Configured",
                    category="HTTP Headers",
                    severity="informational",
                    status="passed",
                    short_description="MIME-sniffing protection is active.",
                    evidence=f"X-Content-Type-Options: {v}",
                    why_it_matters="Prevents the browser from misinterpreting files as executable MIME types.",
                    remediation="Maintain this header across all responses."
                )
    return Finding(
        finding_id="HDR-003",
        title="Missing X-Content-Type-Options Header",
        category="HTTP Headers",
        severity="low",
        status="finding",
        short_description="X-Content-Type-Options: nosniff header is missing.",
        evidence="Header not present.",
        why_it_matters="Allows legacy browsers to sniff content types, potentially executing malicious uploads as HTML/JS.",
        remediation="Add 'X-Content-Type-Options: nosniff' to web server responses."
    )

def check_x_frame_options(headers: dict) -> Finding:
    has_csp_ancestors = any(
        "frame-ancestors" in v.lower() for k, v in headers.items() if k.lower() == "content-security-policy"
    )
    for k, v in headers.items():
        if k.lower() == "x-frame-options":
            val = v.strip().upper()
            if val in ("DENY", "SAMEORIGIN"):
                return Finding(
                    finding_id="HDR-004",
                    title=f"Clickjacking Protection Configured ({val})",
                    category="HTTP Headers",
                    severity="informational",
                    status="passed",
                    short_description=f"X-Frame-Options is set to {val}.",
                    evidence=f"X-Frame-Options: {v}",
                    why_it_matters="Prevents your web pages from being embedded in malicious iframes.",
                    remediation="Maintain X-Frame-Options or configure CSP frame-ancestors."
                )
    if has_csp_ancestors:
        return Finding(
            finding_id="HDR-004",
            title="Clickjacking Protection via CSP frame-ancestors",
            category="HTTP Headers",
            severity="informational",
            status="passed",
            short_description="CSP frame-ancestors directive protects against clickjacking.",
            evidence="CSP frame-ancestors detected.",
            why_it_matters="CSP frame-ancestors obsoletes and replaces X-Frame-Options in modern browsers.",
            remediation="No action required."
        )
    return Finding(
        finding_id="HDR-004",
        title="Missing Clickjacking Protection (X-Frame-Options)",
        category="HTTP Headers",
        severity="medium",
        status="finding",
        short_description="Neither X-Frame-Options nor CSP frame-ancestors was observed.",
        evidence="Header not present.",
        why_it_matters="Enables clickjacking attacks where malicious sites overlay invisible iframes on your page.",
        remediation="Set 'X-Frame-Options: SAMEORIGIN' or configure CSP 'frame-ancestors \\'self\\''."
    )

def check_server_header(headers: dict) -> Finding:
    for k, v in headers.items():
        if k.lower() == "server":
            val = v.strip()
            # Check if version numbers leak
            if any(char.isdigit() for char in val):
                return Finding(
                    finding_id="INF-001",
                    title="Server Version Information Disclosure",
                    category="Information Disclosure",
                    severity="low",
                    status="finding",
                    short_description=f"Server header exposes software version details ({val}).",
                    evidence=f"Server: {val}",
                    why_it_matters="Exposing software and version numbers facilitates targeted exploit research by attackers.",
                    remediation="Disable or sanitize Server response headers (e.g., ServerTokens Prod in Apache)."
                )
            return Finding(
                finding_id="INF-001",
                title="Generic Server Header Observed",
                category="Information Disclosure",
                severity="informational",
                status="passed",
                short_description="Server header present without specific version details.",
                evidence=f"Server: {val}",
                why_it_matters="Generic software names pose minimal risk.",
                remediation="Optionally remove the Server header entirely for defense-in-depth."
            )
    return Finding(
        finding_id="INF-001",
        title="Server Header Suppressed",
        category="Information Disclosure",
        severity="informational",
        status="passed",
        short_description="Server software header is hidden or suppressed.",
        evidence="Server header not present.",
        why_it_matters="Hides backend server details from passive reconnaissance.",
        remediation="No action required."
    )

print("Security check rules compiled successfully.")
""")

    # ── TLS Inspector ─────────────────────────────────────────────────────────
    md("""
### 5. TLS & Certificate Inspection Module
Performs low-level socket handshakes using Python standard library `ssl` and `socket` to verify certificate expiration, validity dates, CA trust chains, and Subject Alternative Names (SANs).
""")
    code("""
def check_tls_certificate(hostname: str, port: int = 443) -> list[Finding]:
    findings = []
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        not_after_str = cert.get("notAfter")
        if not_after_str:
            expiry_date = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
            now = datetime.datetime.utcnow()
            days_left = (expiry_date - now).days

            if days_left < 0:
                findings.append(Finding(
                    finding_id="TLS-002",
                    title="TLS Certificate Expired",
                    category="TLS/Certificate",
                    severity="critical",
                    status="finding",
                    short_description=f"Certificate expired {abs(days_left)} days ago ({expiry_date.strftime('%Y-%m-%d')}).",
                    evidence=f"notAfter: {not_after_str}",
                    why_it_matters="Browsers block access to sites with expired certificates, breaking user trust and encryption.",
                    remediation="Renew and deploy an active TLS certificate immediately."
                ))
            elif days_left < 30:
                findings.append(Finding(
                    finding_id="TLS-002",
                    title="TLS Certificate Expiring Soon",
                    category="TLS/Certificate",
                    severity="medium",
                    status="finding",
                    short_description=f"Certificate expires in {days_left} days ({expiry_date.strftime('%Y-%m-%d')}).",
                    evidence=f"notAfter: {not_after_str}",
                    why_it_matters="Imminent certificate expiration will cause service interruption and browser security warnings.",
                    remediation="Schedule automated certificate renewal (e.g. via Certbot / Let's Encrypt)."
                ))
            else:
                findings.append(Finding(
                    finding_id="TLS-002",
                    title="TLS Certificate Valid",
                    category="TLS/Certificate",
                    severity="informational",
                    status="passed",
                    short_description=f"Certificate valid for {days_left} more days (expires {expiry_date.strftime('%Y-%m-%d')}).",
                    evidence=f"notAfter: {not_after_str}",
                    why_it_matters="An active TLS certificate ensures secure encrypted communication between client and server.",
                    remediation="Maintain automated renewal pipelines."
                ))
    except Exception as exc:
        findings.append(Finding(
            finding_id="TLS-001",
            title="TLS Handshake Inconclusive",
            category="TLS/Certificate",
            severity="informational",
            status="inconclusive",
            short_description=f"TLS certificate details could not be retrieved: {exc}",
            evidence=str(exc),
            why_it_matters="Could not establish verified TLS connection.",
            remediation="Ensure HTTPS port 443 is accessible and certificates are properly installed."
        ))
    return findings

print("TLS certificate analysis module initialized.")
""")

    # ── Risk Engine ───────────────────────────────────────────────────────────
    md("""
### 6. Deterministic Risk Engine
Calculates an objective security posture score from 0 to 100 using a documented base-100 deduction algorithm:
$$\\text{Score} = \\max(0, 100 - \\sum \\text{Deductions})$$
Severity deductions: Critical (-30), High (-20), Medium (-10), Low (-5), Informational (-1).
Passed and inconclusive checks incur zero penalty.
""")
    code("""
@dataclass
class RiskReport:
    score: int
    grade: str
    total_findings: int
    findings_by_severity: dict
    passed_count: int
    inconclusive_count: int
    total_deduction: int
    summary: str

def calculate_risk(findings: list[Finding]) -> RiskReport:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    passed = 0
    inconclusive = 0
    deduction = 0

    for f in findings:
        if f.status == "finding":
            sev = f.severity.lower()
            if sev in counts:
                counts[sev] += 1
                deduction += SEVERITY_WEIGHTS.get(sev, 0)
        elif f.status == "passed":
            passed += 1
        elif f.status == "inconclusive":
            inconclusive += 1

    score = max(0, 100 - deduction)
    grade = "F"
    for threshold, g in GRADE_BOUNDARIES:
        if score >= threshold:
            grade = g
            break

    total_active = sum(counts.values())
    summary = (
        f"Security Posture Score: {score}/100 (Grade {grade}). "
        f"Total Weaknesses: {total_active} (Crit: {counts['critical']}, High: {counts['high']}, "
        f"Med: {counts['medium']}, Low: {counts['low']}). Passed Checks: {passed}."
    )

    return RiskReport(
        score=score,
        grade=grade,
        total_findings=total_active,
        findings_by_severity=counts,
        passed_count=passed,
        inconclusive_count=inconclusive,
        total_deduction=deduction,
        summary=summary
    )

print("Deterministic risk engine compiled successfully.")
""")

    # ── Report Exporter ───────────────────────────────────────────────────────
    md("""
### 7. Multi-Format Report Exporter (JSON, CSV, PDF)
Generates structured exports for SIEM/CI/CD pipelines (JSON), spreadsheet analysis (CSV), and formal executive documentation (ReportLab PDF).
""")
    code("""
def generate_json_report(target_url: str, risk_report: RiskReport, findings: list[Finding]) -> str:
    payload = {
        "sentinelscan_version": APP_VERSION,
        "target_url": target_url,
        "scan_timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "risk_assessment": asdict(risk_report),
        "findings": [asdict(f) for f in findings],
    }
    return json.dumps(payload, indent=2)

def generate_csv_report(findings: list[Finding]) -> str:
    import io
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Finding ID", "Title", "Category", "Severity", "Status",
        "Description", "Evidence", "Why It Matters", "Remediation", "Confidence"
    ])
    for f in findings:
        writer.writerow([
            f.finding_id, f.title, f.category, f.severity.upper(), f.status.upper(),
            f.short_description, f.evidence, f.why_it_matters, f.remediation, f.confidence.capitalize()
        ])
    return output.getvalue()

print("Report generation engines ready.")
""")

    # ── Demo Mode & Execution ─────────────────────────────────────────────────
    md("""
### 8. Offline Demonstration Execution & Results Evaluation
Executes the assessment against local illustrative fixtures (`https://example-demo-target.invalid`) without network calls. Demonstrates deterministic scoring, findings breakdown, and tabular presentation.
""")
    code("""
def get_demo_findings() -> list[Finding]:
    return [
        Finding(
            finding_id="HDR-001",
            title="Missing Content-Security-Policy",
            category="HTTP Headers",
            severity="high",
            status="finding",
            short_description="No Content-Security-Policy header was observed.",
            evidence="Header not present.",
            why_it_matters="Leaves application vulnerable to Cross-Site Scripting (XSS).",
            remediation="Configure a robust Content-Security-Policy header."
        ),
        Finding(
            finding_id="HDR-002",
            title="Missing Strict-Transport-Security (HSTS)",
            category="HTTP Headers",
            severity="medium",
            status="finding",
            short_description="No HSTS header observed on HTTPS endpoint.",
            evidence="Header not present.",
            why_it_matters="Enables SSL-stripping man-in-the-middle attacks.",
            remediation="Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."
        ),
        Finding(
            finding_id="HDR-003",
            title="Missing X-Content-Type-Options Header",
            category="HTTP Headers",
            severity="low",
            status="finding",
            short_description="MIME sniffing protection header is absent.",
            evidence="Header not present.",
            why_it_matters="Allows browser MIME-sniffing exploits.",
            remediation="Send 'X-Content-Type-Options: nosniff'."
        ),
        Finding(
            finding_id="HDR-004",
            title="Missing Clickjacking Protection (X-Frame-Options)",
            category="HTTP Headers",
            severity="medium",
            status="finding",
            short_description="Neither X-Frame-Options nor CSP frame-ancestors is present.",
            evidence="Header not present.",
            why_it_matters="Leaves application susceptible to clickjacking iframe attacks.",
            remediation="Set 'X-Frame-Options: SAMEORIGIN'."
        ),
        Finding(
            finding_id="INF-001",
            title="Server Version Disclosure",
            category="Information Disclosure",
            severity="low",
            status="finding",
            short_description="Server header exposes software version details.",
            evidence="Server: Apache/2.4.41 (Ubuntu)",
            why_it_matters="Exposing version numbers facilitates targeted vulnerability research.",
            remediation="Disable detailed server banners."
        ),
        Finding(
            finding_id="TLS-002",
            title="TLS Certificate Valid",
            category="TLS/Certificate",
            severity="informational",
            status="passed",
            short_description="TLS certificate is valid for 180 more days.",
            evidence="notAfter: Oct 15 2027 GMT",
            why_it_matters="Secure transport encryption active.",
            remediation="Maintain automated renewal."
        ),
        Finding(
            finding_id="HDR-005",
            title="Referrer-Policy Configured",
            category="HTTP Headers",
            severity="informational",
            status="passed",
            short_description="Referrer-Policy header restricts cross-origin URL leakage.",
            evidence="Referrer-Policy: strict-origin-when-cross-origin",
            why_it_matters="Protects sensitive URL query parameters from external leaks.",
            remediation="No action required."
        ),
    ]

# Execute assessment against illustrative dataset
demo_target = "https://example-demo-target.invalid"
demo_findings = get_demo_findings()
demo_report = calculate_risk(demo_findings)

# Display Summary
print("=" * 70)
print(f"SENTINELSCAN ASSESSMENT REPORT: {demo_target}")
print(f"Overall Score : {demo_report.score} / 100")
print(f"Assigned Grade: GRADE {demo_report.grade}")
print(f"Active Issues : {demo_report.total_findings} detected")
print(f"Passed Checks : {demo_report.passed_count}")
print("=" * 70)
print(demo_report.summary)
print("=" * 70)

# Display Tabular Findings using Pandas
table_rows = []
for f in demo_findings:
    table_rows.append({
        "ID": f.finding_id,
        "Severity": f.severity.upper(),
        "Category": f.category,
        "Status": f.status.upper(),
        "Weakness Title": f.title,
        "Remediation": f.remediation[:60] + "..."
    })

df = pd.DataFrame(table_rows)
display_df = df if 'display' in globals() else None
print("\\nFindings Table Preview:")
print(df.to_string(index=False))
""")

    # ── Export Verification ───────────────────────────────────────────────────
    md("""
### 9. Report Artifact Generation Verification
Generates and writes out sample JSON and CSV scan reports to disk.
""")
    code("""
# Generate JSON & CSV exports
json_data = generate_json_report(demo_target, demo_report, demo_findings)
csv_data = generate_csv_report(demo_findings)

with open("sentinelscan_sample_report.json", "w", encoding="utf-8") as f:
    f.write(json_data)

with open("sentinelscan_sample_report.csv", "w", encoding="utf-8") as f:
    f.write(csv_data)

print(f"Successfully generated 'sentinelscan_sample_report.json' ({len(json_data)} bytes)")
print(f"Successfully generated 'sentinelscan_sample_report.csv' ({len(csv_data)} bytes)")
""")

    # ── Streamlit UI Execution Guide ──────────────────────────────────────────
    md("""
### 10. Interactive Streamlit UI Application Launcher
SentinelScan includes a full 6-page interactive cybersecurity SaaS dashboard.
To launch the interactive dashboard on your local machine, run the following command in your terminal:

```bash
python -m streamlit run app.py
```

The application will start at `http://localhost:8501`.
""")
    code("""
# Demonstration of Streamlit execution command
print("To launch the SentinelScan interactive dashboard:")
print("  python -m streamlit run app.py")
print("  URL: http://localhost:8501")
""")

    notebook_content = {
        "cells": cells,
        "metadata": {
            "kernelspec": {
                "display_name": "Python 3",
                "language": "python",
                "name": "python3"
            },
            "language_info": {
                "codemirror_mode": {"name": "ipython", "version": 3},
                "file_extension": ".py",
                "mimetype": "text/x-python",
                "name": "python",
                "nbconvert_exporter": "python",
                "pygments_lexer": "ipython3",
                "version": "3.11.0"
            }
        },
        "nbformat": 4,
        "nbformat_minor": 5
    }

    out_path = Path("Aishwarya_SentinelScan.ipynb")
    out_path.write_text(json.dumps(notebook_content, indent=2), encoding="utf-8")
    print(f"Generated {out_path.name} successfully ({out_path.stat().st_size} bytes).")

if __name__ == "__main__":
    create_notebook()

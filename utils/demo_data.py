"""
utils/demo_data.py
Offline demo data for SentinelScan.

This module provides a pre-built ScanResult that can be displayed
without making any real network requests.

ALL findings in this module are clearly labeled as illustrative examples.
They do not represent any real website, service, or organisation.
"""

from __future__ import annotations

import config
from scanner.scanner_service import ScanResult
from scanner.security_checks import Finding
from scanner.risk_engine import calculate_risk


def get_demo_scan_result() -> ScanResult:
    """
    Return a realistic-looking ScanResult built from offline fixture data.

    The result is clearly marked scan_mode="demo" and carries findings that
    illustrate the full range of severity levels and categories.

    No network request is made. No real website is represented.
    """
    findings: list[Finding] = [
        # ── HTTP Security Headers ────────────────────────────────────────────
        Finding(
            finding_id="HDR-001",
            title="Content-Security-Policy header present but potentially weak",
            category="HTTP Security Headers",
            severity="medium",
            status="finding",
            short_description=(
                "CSP header found but contains 'unsafe-inline', which weakens "
                "protection against XSS attacks."
            ),
            evidence="Content-Security-Policy: default-src 'self' 'unsafe-inline' https:",
            why_it_matters=(
                "The 'unsafe-inline' directive allows inline scripts, which is the primary "
                "vector for XSS attacks. A CSP with 'unsafe-inline' provides significantly "
                "weaker protection than one without it."
            ),
            remediation=(
                "Remove 'unsafe-inline' from your CSP. Use nonces or hashes for any "
                "necessary inline scripts. Consider using a strict CSP with a nonce-based approach."
            ),
            confidence="high",
        ),
        Finding(
            finding_id="HDR-002",
            title="Strict-Transport-Security header absent",
            category="HTTP Security Headers",
            severity="medium",
            status="finding",
            short_description="The HSTS header is missing on this HTTPS endpoint.",
            evidence="Header not found in HTTP response.",
            why_it_matters=(
                "Without HSTS, browsers may downgrade future connections to HTTP if tricked "
                "by a network attacker (SSL stripping). HSTS prevents this by telling browsers "
                "to always use HTTPS."
            ),
            remediation=(
                "Add: `Strict-Transport-Security: max-age=31536000; includeSubDomains`. "
                "Consider adding `preload` after testing with https://hstspreload.org/."
            ),
            confidence="high",
        ),
        Finding(
            finding_id="HDR-003",
            title="X-Content-Type-Options set to nosniff",
            category="HTTP Security Headers",
            severity="informational",
            status="passed",
            short_description="X-Content-Type-Options is correctly set to 'nosniff'.",
            evidence="X-Content-Type-Options: nosniff",
            why_it_matters="Prevents MIME-type sniffing by the browser.",
            remediation="No action required.",
            confidence="high",
        ),
        Finding(
            finding_id="HDR-004",
            title="X-Frame-Options header absent",
            category="HTTP Security Headers",
            severity="medium",
            status="finding",
            short_description="Neither X-Frame-Options nor CSP frame-ancestors is set.",
            evidence="Header not found in HTTP response.",
            why_it_matters=(
                "Without clickjacking protection, an attacker could embed this page "
                "in an invisible iframe and trick users into performing unintended actions."
            ),
            remediation=(
                "Add `X-Frame-Options: SAMEORIGIN` or use "
                "`Content-Security-Policy: frame-ancestors 'self'` for finer control."
            ),
            confidence="high",
        ),
        Finding(
            finding_id="HDR-005",
            title="Referrer-Policy header present",
            category="HTTP Security Headers",
            severity="informational",
            status="passed",
            short_description="Referrer-Policy is set to 'strict-origin-when-cross-origin'.",
            evidence="Referrer-Policy: strict-origin-when-cross-origin",
            why_it_matters="Controls how much referrer information is shared.",
            remediation="No action required.",
            confidence="high",
        ),
        Finding(
            finding_id="HDR-006",
            title="Permissions-Policy header absent",
            category="HTTP Security Headers",
            severity="low",
            status="finding",
            short_description="No Permissions-Policy header is set.",
            evidence="Header not found in HTTP response.",
            why_it_matters=(
                "Without a Permissions-Policy, the page and its embedded frames can "
                "access powerful browser APIs (camera, microphone, geolocation) without restriction."
            ),
            remediation=(
                "Add: `Permissions-Policy: camera=(), microphone=(), geolocation=()` "
                "and allow only what is needed."
            ),
            confidence="high",
        ),
        # ── TLS / Certificate ────────────────────────────────────────────────
        Finding(
            finding_id="TLS-002",
            title="TLS certificate is valid and not near expiry",
            category="TLS / Certificate",
            severity="informational",
            status="passed",
            short_description="Certificate valid until 2027-06-15 (237 days remaining).",
            evidence="NotAfter: 2027-06-15T00:00:00+00:00",
            why_it_matters="A valid, non-expiring certificate maintains user trust.",
            remediation="No immediate action required.",
            confidence="high",
        ),
        Finding(
            finding_id="TLS-003",
            title="TLS certificate details",
            category="TLS / Certificate",
            severity="informational",
            status="passed",
            short_description="Certificate subject and issuer recorded.",
            evidence=(
                "Subject: commonName=example-demo.invalid, organizationName=Demo Corp\n"
                "Issuer: commonName=R11, organizationName=Let's Encrypt\n"
                "SANs: example-demo.invalid, www.example-demo.invalid"
            ),
            why_it_matters="Identifies which CA issued the certificate.",
            remediation="No action required.",
            confidence="high",
        ),
        # ── Cookie Security ──────────────────────────────────────────────────
        Finding(
            finding_id="CKI-001",
            title="Cookie 'sessionid' has security attribute issues",
            category="Cookie Security",
            severity="medium",
            status="finding",
            short_description=(
                "Cookie 'sessionid': Secure attribute is missing; SameSite attribute is missing."
            ),
            evidence="Set-Cookie: sessionid=abc123; HttpOnly; Path=/",
            why_it_matters=(
                "Missing Secure allows the session cookie to be transmitted over HTTP, "
                "where it could be intercepted by a network attacker. Missing SameSite "
                "may enable Cross-Site Request Forgery (CSRF) attacks."
            ),
            remediation=(
                "Add the Secure attribute to ensure the cookie is only sent over HTTPS. "
                "Add SameSite=Strict or SameSite=Lax to reduce CSRF risk."
            ),
            confidence="high",
        ),
        Finding(
            finding_id="CKI-002",
            title="Cookie 'analytics_id' has secure attributes",
            category="Cookie Security",
            severity="informational",
            status="passed",
            short_description="Cookie 'analytics_id' has Secure, HttpOnly, and SameSite set.",
            evidence="Set-Cookie: analytics_id=xyz; Secure; HttpOnly; SameSite=Lax; Path=/",
            why_it_matters="Well-configured cookies reduce session-theft and CSRF risk.",
            remediation="No action required.",
            confidence="high",
        ),
        # ── CORS ─────────────────────────────────────────────────────────────
        Finding(
            finding_id="CRS-001",
            title="CORS: wildcard origin (Access-Control-Allow-Origin: *)",
            category="CORS Configuration",
            severity="low",
            status="finding",
            short_description=(
                "The API endpoint returns a wildcard CORS origin. Risk depends on "
                "resource sensitivity and whether credentials are involved."
            ),
            evidence="Access-Control-Allow-Origin: *",
            why_it_matters=(
                "A wildcard ACAO allows any origin to read the response via browser JavaScript. "
                "For public API endpoints this may be intentional; for sensitive endpoints it is risky."
            ),
            remediation=(
                "If this endpoint serves sensitive data, restrict ACAO to specific trusted origins. "
                "For truly public data endpoints, a wildcard may be acceptable."
            ),
            confidence="medium",
        ),
        # ── Information Disclosure ───────────────────────────────────────────
        Finding(
            finding_id="INF-001",
            title="Server header discloses software and possibly version",
            category="Information Disclosure",
            severity="low",
            status="finding",
            short_description="Server header reveals: 'Apache/2.4.54 (Ubuntu)'.",
            evidence="Server: Apache/2.4.54 (Ubuntu)",
            why_it_matters=(
                "Disclosing the server software and version allows attackers to look up "
                "known CVEs for that specific version."
            ),
            remediation=(
                "Configure your web server to suppress or genericise the Server header. "
                "In Apache: set `ServerTokens Prod` in httpd.conf."
            ),
            confidence="medium",
        ),
        Finding(
            finding_id="INF-002",
            title="X-Powered-By header not disclosed",
            category="Information Disclosure",
            severity="informational",
            status="passed",
            short_description="X-Powered-By header is absent.",
            evidence="Header not found.",
            why_it_matters="Not disclosing framework versions reduces attacker reconnaissance.",
            remediation="No action required.",
            confidence="high",
        ),
        # ── Transport Security ───────────────────────────────────────────────
        Finding(
            finding_id="TRP-001",
            title="Target is already HTTPS",
            category="Transport Security",
            severity="informational",
            status="passed",
            short_description="The scan target uses HTTPS.",
            evidence="URL scheme: https",
            why_it_matters="HTTPS encrypts traffic between the browser and the server.",
            remediation="No action required for transport security.",
            confidence="high",
        ),
    ]

    risk_report = calculate_risk(findings)

    return ScanResult(
        target_url=config.DEMO_TARGET_URL,
        normalized_url=config.DEMO_TARGET_URL,
        timestamp=config.DEMO_TIMESTAMP,
        duration_seconds=2.41,
        scan_mode="demo",
        success=True,
        findings=findings,
        risk_report=risk_report,
        resolved_ips=[],
        http_status_code=200,
        final_url=config.DEMO_TARGET_URL,
    )

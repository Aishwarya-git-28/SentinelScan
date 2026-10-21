"""
scanner/security_checks.py
Individual security checks for SentinelScan.

Each public function returns a :class:`Finding` dataclass.
All checks are non-destructive and configuration-inspection only.
No attack payloads are sent.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

import requests

import config


# ── Finding model ─────────────────────────────────────────────────────────────

@dataclass
class Finding:
    """Represents the result of a single security check."""
    finding_id: str
    title: str
    category: str
    severity: str          # critical | high | medium | low | informational
    status: str            # finding | passed | inconclusive | error
    short_description: str
    evidence: str
    why_it_matters: str
    remediation: str
    confidence: str        # high | medium | low
    details: dict = field(default_factory=dict)


# ── A: HTTP Security Headers ──────────────────────────────────────────────────

def check_content_security_policy(headers: dict[str, str]) -> Finding:
    header_name = "Content-Security-Policy"
    value = _get_header(headers, header_name)

    if value is None:
        return Finding(
            finding_id="HDR-001",
            title="Content-Security-Policy header absent",
            category="HTTP Security Headers",
            severity="high",
            status="finding",
            short_description="The Content-Security-Policy (CSP) header is not present.",
            evidence="Header not found in HTTP response.",
            why_it_matters=(
                "Without a CSP, the browser has no declarative policy restricting which "
                "resources it may load. This increases exposure to Cross-Site Scripting "
                "(XSS) and data-injection attacks."
            ),
            remediation=(
                "Add a Content-Security-Policy header. Start with a restrictive policy "
                "such as `default-src 'self'` and progressively allow necessary origins. "
                "Reference: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"
            ),
            confidence="high",
        )

    weak_directives: list[str] = []
    if "unsafe-inline" in value:
        weak_directives.append("'unsafe-inline'")
    if "unsafe-eval" in value:
        weak_directives.append("'unsafe-eval'")
    if re.search(r"default-src\s+\*", value):
        weak_directives.append("wildcard default-src")

    if weak_directives:
        return Finding(
            finding_id="HDR-001",
            title="Content-Security-Policy header present but potentially weak",
            category="HTTP Security Headers",
            severity="medium",
            status="finding",
            short_description=(
                f"CSP header found but contains potentially permissive directives: "
                f"{', '.join(weak_directives)}."
            ),
            evidence=f"{header_name}: {value[:300]}",
            why_it_matters=(
                "Directives such as 'unsafe-inline' and 'unsafe-eval' significantly weaken "
                "CSP protection against XSS attacks. A wildcard (*) for default-src allows "
                "resources from any origin."
            ),
            remediation=(
                "Remove 'unsafe-inline' and 'unsafe-eval' where possible. Use nonces or "
                "hashes for inline scripts. Avoid wildcard (*) in sensitive directives."
            ),
            confidence="medium",
        )

    return Finding(
        finding_id="HDR-001",
        title="Content-Security-Policy header present",
        category="HTTP Security Headers",
        severity="informational",
        status="passed",
        short_description="A Content-Security-Policy header was found.",
        evidence=f"{header_name}: {value[:300]}",
        why_it_matters="CSP helps mitigate XSS and data-injection attacks.",
        remediation="Continue reviewing the policy periodically as the application evolves.",
        confidence="high",
    )


def check_strict_transport_security(headers: dict[str, str], scheme: str) -> Finding:
    header_name = "Strict-Transport-Security"
    value = _get_header(headers, header_name)

    if scheme == "http":
        return Finding(
            finding_id="HDR-002",
            title="HSTS not applicable over plain HTTP",
            category="HTTP Security Headers",
            severity="informational",
            status="inconclusive",
            short_description="The target was reached over HTTP. HSTS is only sent over HTTPS.",
            evidence="Scan performed over HTTP; HSTS header not expected.",
            why_it_matters=(
                "HSTS instructs browsers to always use HTTPS for future connections. "
                "It can only be delivered and enforced over a validated HTTPS connection."
            ),
            remediation=(
                "Enable HTTPS and serve the HSTS header from your HTTPS endpoint with a "
                "max-age of at least 31536000 (one year). Consider adding includeSubDomains "
                "and preload directives once tested."
            ),
            confidence="high",
        )

    if value is None:
        return Finding(
            finding_id="HDR-002",
            title="Strict-Transport-Security header absent",
            category="HTTP Security Headers",
            severity="medium",
            status="finding",
            short_description="The HSTS header is missing on this HTTPS endpoint.",
            evidence="Header not found in HTTP response.",
            why_it_matters=(
                "Without HSTS, browsers may downgrade future connections to HTTP if tricked "
                "by a network attacker (SSL stripping). HSTS prevents this."
            ),
            remediation=(
                "Add the header: `Strict-Transport-Security: max-age=31536000; "
                "includeSubDomains`. Consider the `preload` directive after testing."
            ),
            confidence="high",
        )

    max_age_match = re.search(r"max-age=(\d+)", value, re.IGNORECASE)
    max_age = int(max_age_match.group(1)) if max_age_match else 0
    if max_age < 15768000:  # less than 6 months
        return Finding(
            finding_id="HDR-002",
            title="Strict-Transport-Security max-age is low",
            category="HTTP Security Headers",
            severity="low",
            status="finding",
            short_description=f"HSTS max-age is only {max_age} seconds (< 6 months recommended).",
            evidence=f"{header_name}: {value}",
            why_it_matters=(
                "A short max-age limits how long browsers remember the HSTS policy, "
                "reducing its effectiveness against SSL-stripping attacks."
            ),
            remediation="Set max-age to at least 31536000 (one year).",
            confidence="high",
        )

    return Finding(
        finding_id="HDR-002",
        title="Strict-Transport-Security header present",
        category="HTTP Security Headers",
        severity="informational",
        status="passed",
        short_description="HSTS header found with adequate max-age.",
        evidence=f"{header_name}: {value}",
        why_it_matters="HSTS reduces the risk of protocol downgrade and SSL-stripping attacks.",
        remediation="No immediate action required. Review annually.",
        confidence="high",
    )


def check_x_content_type_options(headers: dict[str, str]) -> Finding:
    header_name = "X-Content-Type-Options"
    value = _get_header(headers, header_name)

    if value is None:
        return Finding(
            finding_id="HDR-003",
            title="X-Content-Type-Options header absent",
            category="HTTP Security Headers",
            severity="low",
            status="finding",
            short_description="X-Content-Type-Options is not set.",
            evidence="Header not found in HTTP response.",
            why_it_matters=(
                "Without this header, some browsers may perform MIME-type sniffing and "
                "execute content as a different type than declared, enabling certain attacks."
            ),
            remediation="Add the header: `X-Content-Type-Options: nosniff`.",
            confidence="high",
        )

    if value.strip().lower() == "nosniff":
        return Finding(
            finding_id="HDR-003",
            title="X-Content-Type-Options set to nosniff",
            category="HTTP Security Headers",
            severity="informational",
            status="passed",
            short_description="X-Content-Type-Options is correctly set to 'nosniff'.",
            evidence=f"{header_name}: {value}",
            why_it_matters="Prevents MIME-type sniffing by the browser.",
            remediation="No action required.",
            confidence="high",
        )

    return Finding(
        finding_id="HDR-003",
        title="X-Content-Type-Options has unexpected value",
        category="HTTP Security Headers",
        severity="low",
        status="finding",
        short_description=f"X-Content-Type-Options is '{value}' (expected 'nosniff').",
        evidence=f"{header_name}: {value}",
        why_it_matters="The only valid, effective value is 'nosniff'.",
        remediation="Set the header to exactly: `X-Content-Type-Options: nosniff`.",
        confidence="high",
    )


def check_x_frame_options(headers: dict[str, str]) -> Finding:
    header_name = "X-Frame-Options"
    csp_value = _get_header(headers, "Content-Security-Policy") or ""
    has_csp_frame_ancestors = "frame-ancestors" in csp_value.lower()
    value = _get_header(headers, header_name)

    if value is None and not has_csp_frame_ancestors:
        return Finding(
            finding_id="HDR-004",
            title="X-Frame-Options header absent",
            category="HTTP Security Headers",
            severity="medium",
            status="finding",
            short_description="Neither X-Frame-Options nor CSP frame-ancestors is set.",
            evidence="Header not found in HTTP response.",
            why_it_matters=(
                "Without clickjacking protection, an attacker could embed this page "
                "in an invisible iframe and trick users into clicking hidden elements "
                "(clickjacking)."
            ),
            remediation=(
                "Add `X-Frame-Options: DENY` or `X-Frame-Options: SAMEORIGIN`, "
                "or use `Content-Security-Policy: frame-ancestors 'self'` for finer control."
            ),
            confidence="high",
        )

    if has_csp_frame_ancestors:
        return Finding(
            finding_id="HDR-004",
            title="Clickjacking protection provided by CSP frame-ancestors",
            category="HTTP Security Headers",
            severity="informational",
            status="passed",
            short_description="CSP frame-ancestors directive provides clickjacking protection.",
            evidence=f"Content-Security-Policy includes frame-ancestors.",
            why_it_matters="frame-ancestors in CSP supersedes X-Frame-Options in modern browsers.",
            remediation="No action required. Verify browsers in scope support CSP frame-ancestors.",
            confidence="high",
        )

    return Finding(
        finding_id="HDR-004",
        title="X-Frame-Options header present",
        category="HTTP Security Headers",
        severity="informational",
        status="passed",
        short_description=f"X-Frame-Options is set to '{value}'.",
        evidence=f"{header_name}: {value}",
        why_it_matters="Helps prevent clickjacking attacks.",
        remediation="No immediate action required.",
        confidence="high",
    )


def check_referrer_policy(headers: dict[str, str]) -> Finding:
    header_name = "Referrer-Policy"
    value = _get_header(headers, header_name)
    strict_values = {
        "no-referrer", "no-referrer-when-downgrade",
        "origin", "origin-when-cross-origin",
        "same-origin", "strict-origin", "strict-origin-when-cross-origin",
    }

    if value is None:
        return Finding(
            finding_id="HDR-005",
            title="Referrer-Policy header absent",
            category="HTTP Security Headers",
            severity="low",
            status="finding",
            short_description="No Referrer-Policy is set.",
            evidence="Header not found in HTTP response.",
            why_it_matters=(
                "Without a Referrer-Policy, the browser may send the full URL "
                "of the previous page in the Referer header, potentially leaking "
                "sensitive path or query-string information to third parties."
            ),
            remediation=(
                "Add `Referrer-Policy: strict-origin-when-cross-origin` as a balanced default."
            ),
            confidence="high",
        )

    policy = value.strip().lower().split(",")[0].strip()
    if policy in strict_values:
        return Finding(
            finding_id="HDR-005",
            title="Referrer-Policy header present",
            category="HTTP Security Headers",
            severity="informational",
            status="passed",
            short_description=f"Referrer-Policy is set to '{value}'.",
            evidence=f"{header_name}: {value}",
            why_it_matters="Controls how much referrer information is shared with other sites.",
            remediation="No action required.",
            confidence="high",
        )

    return Finding(
        finding_id="HDR-005",
        title="Referrer-Policy may be overly permissive",
        category="HTTP Security Headers",
        severity="low",
        status="finding",
        short_description=f"Referrer-Policy is set to '{value}', which may leak URL information.",
        evidence=f"{header_name}: {value}",
        why_it_matters=(
            "Policies such as 'unsafe-url' or 'no-restriction' send the full URL "
            "to all external parties."
        ),
        remediation="Use `strict-origin-when-cross-origin` or a stricter policy.",
        confidence="medium",
    )


def check_permissions_policy(headers: dict[str, str]) -> Finding:
    header_name = "Permissions-Policy"
    # Some sites use the older Feature-Policy header
    value = _get_header(headers, header_name) or _get_header(headers, "Feature-Policy")

    if value is None:
        return Finding(
            finding_id="HDR-006",
            title="Permissions-Policy header absent",
            category="HTTP Security Headers",
            severity="low",
            status="finding",
            short_description="No Permissions-Policy (formerly Feature-Policy) header is set.",
            evidence="Header not found in HTTP response.",
            why_it_matters=(
                "Permissions-Policy lets you control access to powerful browser APIs "
                "(camera, microphone, geolocation, etc.) for the page and its embedded frames."
            ),
            remediation=(
                "Consider adding a Permissions-Policy header to restrict unnecessary API access. "
                "Example: `Permissions-Policy: camera=(), microphone=(), geolocation=()`."
            ),
            confidence="high",
        )

    return Finding(
        finding_id="HDR-006",
        title="Permissions-Policy header present",
        category="HTTP Security Headers",
        severity="informational",
        status="passed",
        short_description="A Permissions-Policy header was found.",
        evidence=f"Permissions-Policy: {value[:200]}",
        why_it_matters="Restricts access to sensitive browser APIs.",
        remediation="Review the policy periodically and restrict unnecessary features.",
        confidence="medium",
    )


# ── B: Cookie security ────────────────────────────────────────────────────────

def check_cookies(response: requests.Response) -> list[Finding]:
    """
    Inspect Set-Cookie headers returned by the server.
    Returns one Finding per cookie, plus a summary finding if no cookies exist.
    """
    findings: list[Finding] = []
    cookie_headers = response.headers.getlist("Set-Cookie") if hasattr(response.headers, "getlist") else []

    # requests CaseInsensitiveDict doesn't have getlist; extract manually
    if not cookie_headers:
        raw_headers = response.raw.headers if hasattr(response, "raw") and response.raw else {}
        if hasattr(raw_headers, "getlist"):
            cookie_headers = raw_headers.getlist("Set-Cookie")
        else:
            cookie_headers = [v for k, v in (response.headers.items() if response.headers else [])
                              if k.lower() == "set-cookie"]

    if not cookie_headers:
        findings.append(Finding(
            finding_id="CKI-000",
            title="No cookies set by server response",
            category="Cookie Security",
            severity="informational",
            status="passed",
            short_description="The server did not set any cookies in this response.",
            evidence="No Set-Cookie header observed.",
            why_it_matters=(
                "Cookies may be set on authenticated or dynamic pages not captured "
                "by this initial request. This check only inspects cookies set in "
                "the observable response."
            ),
            remediation="No action required for this check.",
            confidence="medium",
        ))
        return findings

    for idx, raw in enumerate(cookie_headers, start=1):
        attrs = _parse_cookie_attributes(raw)
        name = attrs.get("name", f"cookie_{idx}")
        issues: list[str] = []
        remediations: list[str] = []

        has_secure = "secure" in attrs
        has_httponly = "httponly" in attrs
        samesite = attrs.get("samesite", "").lower()

        if not has_secure:
            issues.append("Secure attribute is missing")
            remediations.append(
                "Add the Secure attribute so the cookie is only sent over HTTPS."
            )
        if not has_httponly:
            issues.append("HttpOnly attribute is missing")
            remediations.append(
                "Add the HttpOnly attribute to prevent JavaScript access to the cookie."
            )
        if samesite not in ("strict", "lax"):
            if samesite == "none":
                issues.append("SameSite=None requires Secure and may expose the cookie to CSRF")
                remediations.append("Consider SameSite=Strict or SameSite=Lax where possible.")
            else:
                issues.append("SameSite attribute is missing or unrecognised")
                remediations.append(
                    "Add SameSite=Strict or SameSite=Lax to reduce CSRF exposure."
                )

        if issues:
            severity = "medium" if (not has_secure or not has_httponly) else "low"
            findings.append(Finding(
                finding_id=f"CKI-{idx:03d}",
                title=f"Cookie '{name}' has security attribute issues",
                category="Cookie Security",
                severity=severity,
                status="finding",
                short_description=f"Cookie '{name}': {'; '.join(issues)}.",
                evidence=f"Set-Cookie: {raw[:300]}",
                why_it_matters=(
                    "Missing Secure allows cookie transmission over HTTP. "
                    "Missing HttpOnly exposes cookies to JavaScript (XSS risk). "
                    "Weak or absent SameSite may enable Cross-Site Request Forgery."
                ),
                remediation="\n".join(remediations),
                confidence="high",
                details=attrs,
            ))
        else:
            findings.append(Finding(
                finding_id=f"CKI-{idx:03d}",
                title=f"Cookie '{name}' has secure attributes",
                category="Cookie Security",
                severity="informational",
                status="passed",
                short_description=f"Cookie '{name}' has Secure, HttpOnly, and SameSite set.",
                evidence=f"Set-Cookie: {raw[:300]}",
                why_it_matters="Well-configured cookies reduce session-theft and CSRF risk.",
                remediation="No action required.",
                confidence="high",
                details=attrs,
            ))

    return findings


def _parse_cookie_attributes(raw_header: str) -> dict[str, str]:
    """Parse a Set-Cookie header string into a dict of attributes."""
    parts = [p.strip() for p in raw_header.split(";")]
    attrs: dict[str, str] = {}
    if parts:
        name_val = parts[0].split("=", 1)
        attrs["name"] = name_val[0].strip()
        attrs["value_present"] = "yes" if len(name_val) > 1 else "no"
    for part in parts[1:]:
        lower = part.lower()
        if "=" in lower:
            k, v = lower.split("=", 1)
            attrs[k.strip()] = v.strip()
        else:
            attrs[lower.strip()] = "true"
    return attrs


# ── C: CORS configuration ─────────────────────────────────────────────────────

def check_cors(url: str, session) -> Finding:
    """
    Conservative CORS check using a controlled preflight-like OPTIONS request.
    Does not send credentials or destructive payloads.
    """
    try:
        resp = session.options(
            url,
            headers={
                "Origin": "https://cors-probe.sentinelscan.invalid",
                "Access-Control-Request-Method": "GET",
            },
            timeout=config.REQUEST_TIMEOUT,
            verify=config.VERIFY_TLS,
            allow_redirects=False,
        )
    except Exception as exc:  # noqa: BLE001
        return Finding(
            finding_id="CRS-001",
            title="CORS check inconclusive — connection error",
            category="CORS Configuration",
            severity="informational",
            status="inconclusive",
            short_description=f"Could not complete CORS probe: {exc}",
            evidence=str(exc),
            why_it_matters=(
                "CORS controls which external origins can read responses via browser "
                "JavaScript. Misconfiguration can expose sensitive data."
            ),
            remediation="Ensure your server explicitly allows only trusted origins.",
            confidence="low",
        )

    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

    if acao == "*" and acac == "true":
        return Finding(
            finding_id="CRS-001",
            title="CORS: wildcard origin with credentials allowed",
            category="CORS Configuration",
            severity="high",
            status="finding",
            short_description=(
                "The server returns Access-Control-Allow-Origin: * together with "
                "Access-Control-Allow-Credentials: true."
            ),
            evidence=(
                f"Access-Control-Allow-Origin: {acao}\n"
                f"Access-Control-Allow-Credentials: {acac}"
            ),
            why_it_matters=(
                "Although browsers block this combination per the CORS specification, "
                "a misconfigured server may be attempting an unsafe policy. "
                "Review whether this combination reflects the intended policy."
            ),
            remediation=(
                "Specify exact allowed origins rather than using the wildcard (*). "
                "Only set Allow-Credentials: true when strictly required and with a "
                "validated, specific origin."
            ),
            confidence="high",
        )

    if acao == "*":
        return Finding(
            finding_id="CRS-001",
            title="CORS: wildcard origin (Access-Control-Allow-Origin: *)",
            category="CORS Configuration",
            severity="low",
            status="finding",
            short_description=(
                "The server returns a wildcard CORS origin for this endpoint. "
                "Risk depends on the resource's sensitivity and whether credentials are involved."
            ),
            evidence=f"Access-Control-Allow-Origin: {acao}",
            why_it_matters=(
                "A wildcard ACAO allows any origin to read the response via browser "
                "JavaScript. For purely public endpoints (e.g., a public API) this may be "
                "intentional. For authenticated or sensitive endpoints it is risky."
            ),
            remediation=(
                "If this endpoint serves sensitive data, restrict ACAO to specific trusted "
                "origins. For truly public data endpoints, a wildcard may be acceptable."
            ),
            confidence="medium",
        )

    if acao:
        return Finding(
            finding_id="CRS-001",
            title="CORS: specific origin reflected",
            category="CORS Configuration",
            severity="informational",
            status="passed",
            short_description=f"Server reflects a specific CORS origin: {acao[:100]}.",
            evidence=f"Access-Control-Allow-Origin: {acao}",
            why_it_matters="Specific origin allowlisting is the recommended CORS approach.",
            remediation=(
                "Verify this is an explicitly maintained allowlist, not an automatic "
                "echo of the request Origin header."
            ),
            confidence="medium",
        )

    return Finding(
        finding_id="CRS-001",
        title="CORS: no CORS headers observed",
        category="CORS Configuration",
        severity="informational",
        status="passed",
        short_description="No CORS headers were returned in response to the OPTIONS probe.",
        evidence=f"Status: {resp.status_code}; no ACAO header.",
        why_it_matters="Absence of CORS headers means cross-origin browser requests will be blocked.",
        remediation="No action required if cross-origin access is not intended.",
        confidence="medium",
    )


# ── D: Additional safe checks ─────────────────────────────────────────────────

def check_server_header(headers: dict[str, str]) -> Finding:
    value = _get_header(headers, "Server")

    if value is None:
        return Finding(
            finding_id="INF-001",
            title="Server header not disclosed",
            category="Information Disclosure",
            severity="informational",
            status="passed",
            short_description="The Server header is absent — no server software is disclosed.",
            evidence="Header not found.",
            why_it_matters="Not disclosing server software reduces attacker reconnaissance.",
            remediation="No action required.",
            confidence="high",
        )

    version_pattern = re.search(r"[\d.]+", value)
    if version_pattern and len(value) > 10:
        return Finding(
            finding_id="INF-001",
            title="Server header discloses software and possibly version",
            category="Information Disclosure",
            severity="low",
            status="finding",
            short_description=f"Server header reveals: '{value}'.",
            evidence=f"Server: {value}",
            why_it_matters=(
                "Disclosing the server software and version number helps attackers "
                "look up known CVEs for that specific version."
            ),
            remediation=(
                "Configure your web server to suppress or genericise the Server header. "
                "In Apache: `ServerTokens Prod`. In Nginx: `server_tokens off`."
            ),
            confidence="medium",
        )

    return Finding(
        finding_id="INF-001",
        title="Server header present but generic",
        category="Information Disclosure",
        severity="informational",
        status="passed",
        short_description=f"Server header is present but reveals minimal information: '{value}'.",
        evidence=f"Server: {value}",
        why_it_matters="Generic server headers reveal little useful reconnaissance information.",
        remediation="No immediate action required.",
        confidence="medium",
    )


def check_x_powered_by(headers: dict[str, str]) -> Finding:
    value = _get_header(headers, "X-Powered-By")

    if value is None:
        return Finding(
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
        )

    return Finding(
        finding_id="INF-002",
        title="X-Powered-By header discloses technology stack",
        category="Information Disclosure",
        severity="low",
        status="finding",
        short_description=f"X-Powered-By reveals: '{value}'.",
        evidence=f"X-Powered-By: {value}",
        why_it_matters=(
            "Disclosing the framework (e.g., PHP/8.1.0) allows targeted exploitation "
            "of known vulnerabilities in that specific version."
        ),
        remediation=(
            "Remove the X-Powered-By header. In PHP: set `expose_php = Off` in php.ini. "
            "In Express.js: `app.disable('x-powered-by')`."
        ),
        confidence="high",
    )


def check_redirect_to_https(url: str, response: requests.Response) -> Finding:
    """Check whether an HTTP URL automatically redirects to HTTPS."""
    from urllib.parse import urlparse
    scheme = urlparse(url).scheme.lower()

    if scheme == "https":
        return Finding(
            finding_id="TRP-001",
            title="Target is already HTTPS",
            category="Transport Security",
            severity="informational",
            status="passed",
            short_description="The scan target uses HTTPS.",
            evidence=f"URL scheme: {scheme}",
            why_it_matters="HTTPS encrypts traffic between the browser and the server.",
            remediation="No action required for transport security.",
            confidence="high",
        )

    # Check if HTTP response redirects to HTTPS
    location = response.headers.get("Location", "")
    if response.is_redirect and location.lower().startswith("https://"):
        return Finding(
            finding_id="TRP-001",
            title="HTTP redirects to HTTPS",
            category="Transport Security",
            severity="informational",
            status="passed",
            short_description="The HTTP endpoint redirects to an HTTPS URL.",
            evidence=f"Location: {location}",
            why_it_matters="Redirecting HTTP to HTTPS ensures encrypted transport.",
            remediation=(
                "Ensure the redirect is permanent (301) and that HSTS is set "
                "on the HTTPS endpoint."
            ),
            confidence="high",
        )

    return Finding(
        finding_id="TRP-001",
        title="HTTP endpoint does not redirect to HTTPS",
        category="Transport Security",
        severity="high",
        status="finding",
        short_description="The HTTP URL does not appear to redirect to HTTPS.",
        evidence=f"Status: {response.status_code}; Location: {location or 'none'}",
        why_it_matters=(
            "Unencrypted HTTP allows attackers on the network path to intercept "
            "or modify traffic (man-in-the-middle attack)."
        ),
        remediation=(
            "Configure your web server to redirect all HTTP traffic to HTTPS permanently "
            "(HTTP 301). Then add the HSTS header on the HTTPS endpoint."
        ),
        confidence="high",
    )


# ── Private helpers ───────────────────────────────────────────────────────────

def _get_header(headers: dict[str, str], name: str) -> Optional[str]:
    """Case-insensitive header lookup."""
    name_lower = name.lower()
    for k, v in headers.items():
        if k.lower() == name_lower:
            return v
    return None

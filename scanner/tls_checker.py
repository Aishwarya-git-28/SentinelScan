"""
scanner/tls_checker.py
TLS and HTTPS certificate inspection for SentinelScan.

Uses Python's ssl and socket modules to retrieve certificate details.
No private key material is accessed or displayed.
"""

from __future__ import annotations

import datetime
import socket
import ssl
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import config
from scanner.security_checks import Finding


@dataclass
class CertificateInfo:
    """Parsed certificate details."""
    subject: dict = field(default_factory=dict)
    issuer: dict = field(default_factory=dict)
    not_before: Optional[datetime.datetime] = None
    not_after: Optional[datetime.datetime] = None
    san_domains: list[str] = field(default_factory=list)
    serial_number: str = ""
    expired: bool = False
    days_remaining: int = 0
    error: Optional[str] = None


def check_tls_certificate(url: str) -> list[Finding]:
    """
    Inspect the TLS certificate for the given URL.

    Returns a list of Findings covering:
    - HTTPS availability
    - Certificate validity
    - Expiration status
    - Hostname verification
    """
    findings: list[Finding] = []
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()

    # Only inspect TLS when the URL is HTTPS
    if scheme != "https":
        findings.append(Finding(
            finding_id="TLS-001",
            title="Site does not use HTTPS",
            category="TLS / Certificate",
            severity="high",
            status="finding",
            short_description="The target URL uses plain HTTP, not HTTPS.",
            evidence=f"URL scheme: {scheme}",
            why_it_matters=(
                "HTTP transmits all data — including login credentials, cookies, "
                "and form submissions — in plaintext. An attacker with network access "
                "can intercept, read, or modify this traffic."
            ),
            remediation=(
                "Obtain a TLS certificate (free options include Let's Encrypt) and "
                "configure your web server to serve content over HTTPS. "
                "Redirect all HTTP traffic to HTTPS with a 301 response."
            ),
            confidence="high",
        ))
        return findings

    hostname = parsed.hostname or ""
    port = parsed.port or 443
    cert_info = _get_certificate_info(hostname, port)

    if cert_info.error:
        findings.append(Finding(
            finding_id="TLS-001",
            title="TLS certificate could not be retrieved",
            category="TLS / Certificate",
            severity="high",
            status="inconclusive",
            short_description=f"Could not retrieve the TLS certificate: {cert_info.error}",
            evidence=cert_info.error,
            why_it_matters=(
                "A certificate that cannot be retrieved may indicate a misconfiguration, "
                "an expired or self-signed certificate, or a connection problem."
            ),
            remediation=(
                "Verify that a valid, CA-signed TLS certificate is installed and that "
                "your server is configured to present it correctly."
            ),
            confidence="medium",
        ))
        return findings

    # Certificate retrieved — now check validity
    now = datetime.datetime.now(datetime.timezone.utc)

    # Expiry check
    if cert_info.not_after:
        if cert_info.expired:
            findings.append(Finding(
                finding_id="TLS-002",
                title="TLS certificate has expired",
                category="TLS / Certificate",
                severity="critical",
                status="finding",
                short_description=(
                    f"Certificate expired on {cert_info.not_after.strftime('%Y-%m-%d')}."
                ),
                evidence=f"NotAfter: {cert_info.not_after.isoformat()}",
                why_it_matters=(
                    "An expired certificate causes browsers to display security warnings "
                    "and may prevent users from accessing the site. It also signals "
                    "that certificate management processes may be inadequate."
                ),
                remediation=(
                    "Renew the TLS certificate immediately. Consider automating renewal "
                    "using certbot or a similar ACME client."
                ),
                confidence="high",
            ))
        elif cert_info.days_remaining <= config.CERT_EXPIRY_WARNING_DAYS:
            findings.append(Finding(
                finding_id="TLS-002",
                title=f"TLS certificate expires soon ({cert_info.days_remaining} days)",
                category="TLS / Certificate",
                severity="medium",
                status="finding",
                short_description=(
                    f"Certificate expires in {cert_info.days_remaining} days "
                    f"({cert_info.not_after.strftime('%Y-%m-%d')})."
                ),
                evidence=f"NotAfter: {cert_info.not_after.isoformat()}",
                why_it_matters=(
                    "If the certificate is not renewed before expiry, browsers will "
                    "begin showing security warnings and may block access to the site."
                ),
                remediation=(
                    "Renew the certificate before it expires. Consider automated renewal "
                    "to avoid future lapses."
                ),
                confidence="high",
            ))
        else:
            findings.append(Finding(
                finding_id="TLS-002",
                title="TLS certificate is valid and not near expiry",
                category="TLS / Certificate",
                severity="informational",
                status="passed",
                short_description=(
                    f"Certificate valid until {cert_info.not_after.strftime('%Y-%m-%d')} "
                    f"({cert_info.days_remaining} days remaining)."
                ),
                evidence=f"NotAfter: {cert_info.not_after.isoformat()}",
                why_it_matters="A valid, non-expiring certificate maintains user trust.",
                remediation="No immediate action required.",
                confidence="high",
            ))

    # Subject / issuer summary
    subject_str = _format_dn(cert_info.subject)
    issuer_str = _format_dn(cert_info.issuer)
    findings.append(Finding(
        finding_id="TLS-003",
        title="TLS certificate details",
        category="TLS / Certificate",
        severity="informational",
        status="passed",
        short_description="Certificate subject and issuer recorded.",
        evidence=(
            f"Subject: {subject_str}\n"
            f"Issuer: {issuer_str}\n"
            f"SANs: {', '.join(cert_info.san_domains[:10])}"
        ),
        why_it_matters="Identifies which CA issued the certificate and the covered domains.",
        remediation="Verify the issuer is a trusted CA and SANs match all served domains.",
        confidence="high",
        details={
            "subject": subject_str,
            "issuer": issuer_str,
            "san_domains": cert_info.san_domains,
            "not_before": cert_info.not_before.isoformat() if cert_info.not_before else "",
            "not_after": cert_info.not_after.isoformat() if cert_info.not_after else "",
            "days_remaining": cert_info.days_remaining,
        },
    ))

    return findings


# ── Private helpers ───────────────────────────────────────────────────────────

def _get_certificate_info(hostname: str, port: int) -> CertificateInfo:
    """Retrieve and parse TLS certificate details using ssl/socket."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=config.REQUEST_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                der_cert = tls_sock.getpeercert()
    except ssl.SSLCertVerificationError as exc:
        return CertificateInfo(error=f"Certificate verification failed: {exc}")
    except ssl.SSLError as exc:
        return CertificateInfo(error=f"SSL error: {exc}")
    except socket.timeout:
        return CertificateInfo(error=f"Connection timed out after {config.REQUEST_TIMEOUT}s.")
    except OSError as exc:
        return CertificateInfo(error=f"Network error: {exc}")
    except Exception as exc:  # noqa: BLE001
        return CertificateInfo(error=f"Unexpected error: {exc}")

    if not der_cert:
        return CertificateInfo(error="No certificate data returned by the server.")

    return _parse_certificate(der_cert)


def _parse_certificate(cert: dict) -> CertificateInfo:
    """Parse a certificate dict as returned by ssl.getpeercert()."""
    info = CertificateInfo()

    # Subject
    subject_tuples = cert.get("subject", ())
    info.subject = {k: v for entry in subject_tuples for k, v in entry}

    # Issuer
    issuer_tuples = cert.get("issuer", ())
    info.issuer = {k: v for entry in issuer_tuples for k, v in entry}

    # Validity dates
    not_before_str = cert.get("notBefore", "")
    not_after_str = cert.get("notAfter", "")
    info.not_before = _parse_ssl_date(not_before_str)
    info.not_after = _parse_ssl_date(not_after_str)

    now = datetime.datetime.now(datetime.timezone.utc)
    if info.not_after:
        info.expired = info.not_after < now
        delta = info.not_after - now
        info.days_remaining = max(0, delta.days)

    # SANs
    san_entries = cert.get("subjectAltName", ())
    info.san_domains = [v for kind, v in san_entries if kind.lower() == "dns"]

    # Serial number
    info.serial_number = str(cert.get("serialNumber", ""))

    return info


def _parse_ssl_date(date_str: str) -> Optional[datetime.datetime]:
    """Parse the date format used by ssl.getpeercert() (e.g. 'Oct 21 12:00:00 2025 GMT')."""
    if not date_str:
        return None
    formats = [
        "%b %d %H:%M:%S %Y %Z",
        "%Y-%m-%dT%H:%M:%S",
    ]
    for fmt in formats:
        try:
            dt = datetime.datetime.strptime(date_str.strip(), fmt)
            return dt.replace(tzinfo=datetime.timezone.utc)
        except ValueError:
            continue
    return None


def _format_dn(dn_dict: dict) -> str:
    """Format a DN dict as a readable string."""
    parts = []
    for key in ("commonName", "organizationName", "countryName"):
        if key in dn_dict:
            parts.append(f"{key}={dn_dict[key]}")
    return ", ".join(parts) if parts else str(dn_dict)

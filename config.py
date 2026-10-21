"""
SentinelScan — Configuration
Central configuration constants for the scanner application.
"""

from __future__ import annotations

# ── Application identity ──────────────────────────────────────────────────────
APP_NAME = "SentinelScan"
APP_VERSION = "1.0.0"
APP_TAGLINE = "Identify. Understand. Secure."
USER_AGENT = f"{APP_NAME}/{APP_VERSION} (Educational Security Scanner; non-commercial)"

# ── HTTP request settings ─────────────────────────────────────────────────────
REQUEST_TIMEOUT: int = 15          # seconds per request
MAX_RESPONSE_BYTES: int = 5 * 1024 * 1024   # 5 MB cap
MAX_REDIRECTS: int = 5
MAX_CHECKS_PER_SCAN: int = 20      # safety ceiling on request count
VERIFY_TLS: bool = True            # never disable TLS verification for live scans

# ── Network safety ────────────────────────────────────────────────────────────
# CIDR ranges that must never be targeted by the scanner
BLOCKED_NETWORKS: list[str] = [
    "127.0.0.0/8",      # loopback
    "10.0.0.0/8",       # RFC 1918 private
    "172.16.0.0/12",    # RFC 1918 private
    "192.168.0.0/16",   # RFC 1918 private
    "169.254.0.0/16",   # link-local
    "100.64.0.0/10",    # shared address (carrier-grade NAT)
    "198.18.0.0/15",    # benchmarking
    "192.0.2.0/24",     # TEST-NET-1
    "198.51.100.0/24",  # TEST-NET-2
    "203.0.113.0/24",   # TEST-NET-3
    "240.0.0.0/4",      # reserved
    "::1/128",          # IPv6 loopback
    "fc00::/7",         # IPv6 unique local
    "fe80::/10",        # IPv6 link-local
]
ALLOWED_SCHEMES: list[str] = ["http", "https"]
MAX_HOSTNAME_LENGTH: int = 253

# ── Scoring ───────────────────────────────────────────────────────────────────
SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 30,
    "high": 20,
    "medium": 10,
    "low": 5,
    "informational": 1,
}
MAX_DEDUCTION: int = 100

# ── TLS certificate ───────────────────────────────────────────────────────────
CERT_EXPIRY_WARNING_DAYS: int = 30   # warn when cert expires within this window

# ── Demo mode ─────────────────────────────────────────────────────────────────
DEMO_TARGET_URL = "https://example-demo-target.invalid"
DEMO_TIMESTAMP = "2026-10-21T18:45:00+05:30"

# ── Report defaults ───────────────────────────────────────────────────────────
REPORT_DISCLAIMER = (
    "This report was produced by SentinelScan, an automated configuration-check "
    "tool developed for educational purposes. The findings represent detected "
    "configuration weaknesses observed at the time of the scan. They do not "
    "constitute a comprehensive penetration test, an official security audit, "
    "or a guarantee that the target is secure or insecure. Always consult a "
    "qualified security professional before drawing conclusions."
)

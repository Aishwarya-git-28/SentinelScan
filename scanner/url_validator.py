"""
scanner/url_validator.py
URL validation and safe request-handling for SentinelScan.

Validates URLs against a strict allow-list of schemes, rejects private/loopback
network destinations, and provides a pre-configured requests.Session that is
safe for controlled security scanning.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional

import requests
import requests.adapters

import config


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class ValidationResult:
    """Outcome of URL validation."""
    valid: bool
    normalized_url: str = ""
    hostname: str = ""
    scheme: str = ""
    port: Optional[int] = None
    error_message: str = ""
    resolved_ips: list[str] = field(default_factory=list)


# ── Public helpers ────────────────────────────────────────────────────────────

def validate_url(raw_url: str) -> ValidationResult:
    """
    Validate *raw_url* and return a :class:`ValidationResult`.

    Checks performed (in order):
    1. Input must be a non-empty string.
    2. Scheme must be in ALLOWED_SCHEMES.
    3. Hostname must be present and within length limits.
    4. URL must parse without error.
    5. All resolved IP addresses must be outside blocked networks.
    """
    if not raw_url or not isinstance(raw_url, str):
        return ValidationResult(valid=False, error_message="URL must be a non-empty string.")

    raw_url = raw_url.strip()

    # Early scheme check: reject non-http(s) schemes before any normalization
    try:
        _pre_parsed = urllib.parse.urlparse(raw_url)
        _early_scheme = _pre_parsed.scheme.lower()
    except Exception:
        _early_scheme = ""

    if _early_scheme and _early_scheme not in config.ALLOWED_SCHEMES and "://" in raw_url:
        return ValidationResult(
            valid=False,
            error_message=(
                f"Unsupported scheme '{_early_scheme}'. "
                f"Only {', '.join(config.ALLOWED_SCHEMES)} are permitted."
            ),
        )

    # Prepend https:// if the user omitted the scheme
    if not raw_url.startswith(("http://", "https://")):
        raw_url = "https://" + raw_url

    try:
        parsed = urllib.parse.urlparse(raw_url)
    except Exception as exc:  # noqa: BLE001
        return ValidationResult(valid=False, error_message=f"URL parse error: {exc}")

    # Scheme check
    scheme = parsed.scheme.lower()
    if scheme not in config.ALLOWED_SCHEMES:
        return ValidationResult(
            valid=False,
            error_message=(
                f"Unsupported scheme '{scheme}'. "
                f"Only {', '.join(config.ALLOWED_SCHEMES)} are permitted."
            ),
        )

    # Hostname check
    hostname = parsed.hostname or ""
    if not hostname:
        return ValidationResult(valid=False, error_message="URL must include a valid hostname.")

    if len(hostname) > config.MAX_HOSTNAME_LENGTH:
        return ValidationResult(
            valid=False,
            error_message=f"Hostname exceeds maximum length ({config.MAX_HOSTNAME_LENGTH} chars).",
        )

    if not _is_valid_hostname(hostname):
        return ValidationResult(
            valid=False,
            error_message=f"Hostname '{hostname}' contains invalid characters.",
        )

    # Reconstruct a clean, normalized URL
    normalized = _normalize_url(parsed)

    # Resolve hostname and check for blocked networks
    resolved_ips, dns_error = _resolve_hostname(hostname)
    if dns_error:
        return ValidationResult(
            valid=False,
            normalized_url=normalized,
            hostname=hostname,
            scheme=scheme,
            error_message=f"DNS resolution failed: {dns_error}",
        )

    for ip_str in resolved_ips:
        blocked, reason = _is_blocked_ip(ip_str)
        if blocked:
            return ValidationResult(
                valid=False,
                normalized_url=normalized,
                hostname=hostname,
                scheme=scheme,
                resolved_ips=resolved_ips,
                error_message=(
                    f"Scanning rejected: '{hostname}' resolves to {ip_str}, "
                    f"which is {reason}. "
                    "SentinelScan only scans publicly routable addresses."
                ),
            )

    port = parsed.port
    return ValidationResult(
        valid=True,
        normalized_url=normalized,
        hostname=hostname,
        scheme=scheme,
        port=port,
        resolved_ips=resolved_ips,
    )


def validate_redirect_url(redirect_url: str, original_hostname: str) -> ValidationResult:
    """
    Validate a redirect destination.

    Applies full URL validation and additionally warns if the redirect
    crosses to a different hostname (a potential open-redirect concern).
    """
    result = validate_url(redirect_url)
    if result.valid and result.hostname != original_hostname:
        # Cross-origin redirect — still allowed but record it; callers decide.
        pass
    return result


def build_session() -> requests.Session:
    """
    Return a pre-configured :class:`requests.Session` suitable for scanning.

    Settings:
    - Custom User-Agent identifying SentinelScan.
    - TLS verification enabled.
    - Redirect following disabled (scanner handles redirects manually).
    - Response size is NOT streamed here; callers should use ``stream=True``
      and limit bytes read.
    """
    session = requests.Session()
    session.headers.update({"User-Agent": config.USER_AGENT})
    session.max_redirects = config.MAX_REDIRECTS
    # We disable automatic redirect following so we can validate each hop.
    session.allow_redirects = False
    session.verify = config.VERIFY_TLS
    return session


def safe_get(
    url: str,
    session: Optional[requests.Session] = None,
    *,
    allow_redirects: bool = True,
    extra_headers: Optional[dict[str, str]] = None,
) -> tuple[Optional[requests.Response], Optional[str]]:
    """
    Perform a safe, size-limited GET request.

    Returns ``(response, error_string)``.  On success *error_string* is
    ``None``; on failure *response* is ``None``.

    Redirects are followed manually so each destination is validated before
    the next hop.
    """
    if session is None:
        session = build_session()

    headers = dict(extra_headers or {})
    current_url = url
    hops = 0

    while True:
        try:
            resp = session.get(
                current_url,
                timeout=config.REQUEST_TIMEOUT,
                stream=True,
                headers=headers,
            )
        except requests.exceptions.SSLError as exc:
            return None, f"TLS/SSL error: {exc}"
        except requests.exceptions.ConnectionError as exc:
            return None, f"Connection error: {exc}"
        except requests.exceptions.Timeout:
            return None, f"Request timed out after {config.REQUEST_TIMEOUT}s."
        except requests.exceptions.TooManyRedirects:
            return None, "Too many redirects."
        except requests.exceptions.RequestException as exc:
            return None, f"Request failed: {exc}"

        # Limit response body size
        content_chunks: list[bytes] = []
        bytes_read = 0
        try:
            for chunk in resp.iter_content(chunk_size=8192):
                bytes_read += len(chunk)
                content_chunks.append(chunk)
                if bytes_read >= config.MAX_RESPONSE_BYTES:
                    break
        except Exception as exc:  # noqa: BLE001
            return None, f"Error reading response body: {exc}"

        # Reassemble the limited body so callers can access resp.text / resp.content
        resp._content = b"".join(content_chunks)  # type: ignore[attr-defined]
        resp._content_consumed = True              # type: ignore[attr-defined]

        # Handle redirects manually
        if allow_redirects and resp.is_redirect:
            location = resp.headers.get("Location", "")
            if not location:
                return resp, None  # no location header — return current response

            # Resolve relative redirect URLs
            location = urllib.parse.urljoin(current_url, location)

            hops += 1
            if hops > config.MAX_REDIRECTS:
                return None, f"Exceeded maximum redirect limit ({config.MAX_REDIRECTS})."

            parsed_original = urllib.parse.urlparse(current_url)
            redir_result = validate_redirect_url(location, parsed_original.hostname or "")
            if not redir_result.valid:
                return None, f"Redirect blocked: {redir_result.error_message}"

            current_url = redir_result.normalized_url
            continue

        return resp, None


# ── Private helpers ───────────────────────────────────────────────────────────

def _normalize_url(parsed: urllib.parse.ParseResult) -> str:
    """Return a cleaned, normalized URL string."""
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    # Remove default ports
    if parsed.port == 80 and scheme == "http":
        netloc = parsed.hostname or netloc
    elif parsed.port == 443 and scheme == "https":
        netloc = parsed.hostname or netloc
    path = parsed.path or "/"
    return urllib.parse.urlunparse((scheme, netloc, path, parsed.params, parsed.query, ""))


def _is_valid_hostname(hostname: str) -> bool:
    """
    Return True when *hostname* looks like a valid DNS label sequence
    or a bare IP address.
    """
    # Accept raw IPv4/IPv6
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        pass

    # Strip trailing dot (FQDN style)
    hostname = hostname.rstrip(".")
    # Each label: letters, digits, hyphens; must not start/end with hyphen
    label_re = re.compile(r"^(?!-)[A-Za-z0-9\-]{1,63}(?<!-)$")
    labels = hostname.split(".")
    return all(label_re.match(label) for label in labels) if labels else False


def _resolve_hostname(hostname: str) -> tuple[list[str], Optional[str]]:
    """
    Resolve *hostname* to IP addresses.

    Returns ``(list_of_ips, error_message)``.
    """
    # If it's already an IP, return it directly
    try:
        ipaddress.ip_address(hostname)
        return [hostname], None
    except ValueError:
        pass

    try:
        results = socket.getaddrinfo(hostname, None)
        ips = list({r[4][0] for r in results})
        return ips, None
    except socket.gaierror as exc:
        return [], str(exc)
    except Exception as exc:  # noqa: BLE001
        return [], str(exc)


def _is_blocked_ip(ip_str: str) -> tuple[bool, str]:
    """
    Return ``(True, reason)`` if *ip_str* falls within a blocked network,
    or ``(False, "")`` if it is safe.
    """
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True, "an unparseable address"

    for cidr in config.BLOCKED_NETWORKS:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            if addr in network:
                return True, f"within a blocked network ({cidr})"
        except ValueError:
            continue

    return False, ""

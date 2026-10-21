# SentinelScan — Architecture Documentation

## Overview

SentinelScan uses a layered, modular architecture. Each layer has a single responsibility.
No layer reaches downward past its immediate dependency.

```
┌──────────────────────────────────────┐
│            app.py (UI Layer)          │
│         Streamlit Dashboard           │
└──────────────────┬───────────────────┘
                   │ imports
┌──────────────────▼───────────────────┐
│      scanner/scanner_service.py       │
│         Orchestration Layer           │
└──┬───────────┬───────────┬───────────┘
   │           │           │
   ▼           ▼           ▼
url_validator  security_checks  tls_checker
   │               │                │
   └───────────────▼────────────────┘
               risk_engine.py
                   │
           report_generator.py
```

## Module Responsibilities

### `config.py`
Central configuration. All tuneable constants (timeouts, blocked networks, severity weights, app version) live here. No other module contains magic numbers.

### `scanner/url_validator.py`
- `validate_url(raw_url)` → `ValidationResult`
  - Rejects bad schemes, missing hostnames, malformed URLs
  - Resolves DNS and checks all resolved IPs against `BLOCKED_NETWORKS`
  - Normalises the URL
- `validate_redirect_url(redirect_url, original_hostname)` → `ValidationResult`
- `build_session()` → `requests.Session`
  - Preconfigured with User-Agent, TLS verification on, manual redirect mode
- `safe_get(url, session, ...)` → `(Response | None, error_str | None)`
  - Size-limited, manually follows redirects (validating each hop)
  - Catches SSL, connection, timeout, and general request errors

### `scanner/security_checks.py`
Contains one pure function per check. Each function accepts headers/response/url and returns a `Finding` dataclass.

**Finding fields:**
| Field | Type | Purpose |
|-------|------|---------|
| finding_id | str | Unique ID (e.g. HDR-001) |
| title | str | Human-readable title |
| category | str | Check category |
| severity | str | critical/high/medium/low/informational |
| status | str | finding/passed/inconclusive/error |
| short_description | str | One-sentence summary |
| evidence | str | Observed header/value |
| why_it_matters | str | Plain-English explanation |
| remediation | str | Actionable fix guidance |
| confidence | str | high/medium/low |
| details | dict | Extra parsed data |

### `scanner/tls_checker.py`
- `check_tls_certificate(url)` → `list[Finding]`
  - Uses `ssl.create_default_context()` + `socket.create_connection()` to retrieve the peer certificate
  - Returns findings for expiry, near-expiry, certificate details
  - Gracefully handles SSL errors, timeouts, and DNS failures

### `scanner/risk_engine.py`
- `calculate_risk(findings)` → `RiskReport`
  - Pure function; deterministic for the same input
  - Applies severity weights from `config.SEVERITY_WEIGHTS`
  - Clamps score to [0, 100]
  - Converts score to grade (A+, A, B, C, D, F)

### `scanner/scanner_service.py`
- `run_scan(raw_url)` → `ScanResult`
  - Calls `validate_url`, `safe_get`, all check functions, `calculate_risk`
  - Uses `_safe_append` / `_safe_extend` helpers to catch individual check failures without aborting the scan
  - Always returns a `ScanResult`; never raises

### `scanner/report_generator.py`
- `generate_json(result)` → `str`
- `generate_csv(result)` → `str`
- `generate_pdf(result)` → `bytes | None`
  - Returns `None` if ReportLab is not installed
  - Uses `reportlab.platypus` for structured layout

### `utils/demo_data.py`
- `get_demo_scan_result()` → `ScanResult`
  - Returns a pre-built result with `scan_mode="demo"`
  - No network requests made
  - Uses `.invalid` TLD to clearly signal it is not a real target

### `utils/formatting.py`
UI helper functions for Streamlit rendering.

## Data Flow (Live Scan)

```
1. User enters URL and confirms authorization in app.py
2. app.py calls scanner_service.run_scan(url)
3. run_scan calls validate_url(url)
   a. Rejects bad schemes → returns ScanResult(success=False)
   b. Resolves DNS → rejects private IPs → returns ScanResult(success=False)
   c. Returns ValidationResult(valid=True, normalized_url=...)
4. run_scan calls safe_get(url, session)
   a. On network error → returns ScanResult(success=False)
   b. On success → returns requests.Response
5. run_scan calls each check function in sequence
   a. Each returns a Finding
   b. Exceptions are caught and converted to error Findings
6. run_scan calls calculate_risk(findings) → RiskReport
7. Returns ScanResult(success=True, findings=..., risk_report=...)
8. app.py renders the Results, Findings, and Reports pages
```

## Security Architecture

### SSRF Protection
1. `validate_url` resolves the hostname via `socket.getaddrinfo`
2. Every resolved IP is checked against `config.BLOCKED_NETWORKS` (18 CIDR ranges)
3. Redirect destinations are validated with `validate_redirect_url` before each hop
4. Maximum redirects: configurable (default: 5)

### Input Safety
- URL parsing uses Python stdlib `urllib.parse` — no string concatenation
- Response body is size-limited (default: 5 MB)
- Report output escapes `< > &` for PDF rendering
- No authentication headers, cookies, or secrets are included in reports

### TLS Safety
- `ssl.create_default_context()` uses system CA store with full verification
- TLS verification is never disabled for live scans
- Certificate data accessed: subject, issuer, SANs, validity dates only — no private keys

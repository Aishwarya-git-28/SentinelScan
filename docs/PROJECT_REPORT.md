# SentinelScan — Project Report

**IBM SkillsBuild Cybersecurity Bootcamp**  
**Project Submission**  
*Deadline: 23 October 2026*

---

## 1. Title

**SentinelScan — Automated Web Security Scanner**  
*Identify. Understand. Secure.*

---

## 2. Abstract

SentinelScan is an open-source, educational web security configuration scanner built with Python and Streamlit. It performs non-destructive, configuration-level security checks against authorized websites and presents findings with plain-English explanations, severity classifications, remediation guidance, and a deterministic risk score. The application targets website owners, students, developers, and cybersecurity learners who want to understand common web security configuration weaknesses without requiring deep technical expertise.

---

## 3. Introduction

Web security configuration weaknesses remain among the most common and preventable vulnerabilities on the web. Headers such as Content-Security-Policy (CSP), Strict-Transport-Security (HSTS), and X-Frame-Options can be configured in minutes and significantly reduce exposure to attacks such as Cross-Site Scripting (XSS), session hijacking, and clickjacking. Yet studies consistently show that a significant proportion of websites lack these basic protections.

SentinelScan bridges the gap between security knowledge and practical understanding by giving website owners a tool that checks for these weaknesses, explains them in plain English, and tells them exactly how to fix them.

---

## 4. Problem Statement

Many website owners and developers are unaware of basic web security configuration weaknesses. Existing tools are often:
- Too complex for non-specialist users
- Designed for professional penetration testers, not learners
- Cloud-hosted services requiring accounts and API keys
- Black-box tools that produce findings without explanation

There is a need for a self-hosted, offline-capable, plain-English security scanner that educates while it checks.

---

## 5. Objectives

1. Build a modular, non-destructive web security scanner in Python.
2. Check for the most impactful, easily remediated configuration weaknesses.
3. Present findings in plain English with severity levels and remediation guidance.
4. Calculate a transparent, documented risk score.
5. Provide a professional Streamlit-based dashboard.
6. Support an offline demo mode for demonstration without internet access.
7. Generate downloadable reports (JSON, CSV, PDF).
8. Implement safety controls to prevent misuse (SSRF protection, authorization confirmation).
9. Provide comprehensive automated tests.
10. Produce submission-quality documentation.

---

## 6. Proposed System

SentinelScan is a self-hosted Python application with:

- A **Streamlit UI** providing a professional, dark-themed dashboard
- A **modular scanner pipeline** with independent, testable check functions
- A **risk engine** that calculates a deterministic score from 0 to 100
- A **report generator** producing JSON, CSV, and PDF outputs
- An **offline demo mode** with clearly labeled illustrative data
- **SSRF protection** blocking all private, loopback, and link-local destinations
- A **URL validator** that rejects unsafe schemes and unresolvable or private hosts

---

## 7. System Requirements

| Component | Requirement |
|-----------|-------------|
| Python | 3.11 or newer |
| Streamlit | ≥ 1.35.0 |
| requests | ≥ 2.31.0 |
| pandas | ≥ 2.0.0 |
| reportlab | ≥ 4.0.0 (optional, for PDF) |
| pytest | ≥ 8.0.0 (for testing) |
| OS | Windows 10/11, macOS, or Linux |
| Browser | Any modern browser |

---

## 8. Architecture and Modules

### Module Map

```
app.py                    → Streamlit UI (6 pages/sections)
config.py                 → Central configuration constants
scanner/
  url_validator.py        → URL validation + safe HTTP sessions
  security_checks.py      → 12 individual check functions
  tls_checker.py          → TLS/certificate inspection via ssl+socket
  risk_engine.py          → Scoring formula + grade calculation
  scanner_service.py      → Scan orchestration pipeline
  report_generator.py     → JSON, CSV, PDF report generation
utils/
  formatting.py           → UI display helpers
  demo_data.py            → Offline fixture data
tests/                    → 139 automated tests across 6 test files
docs/                     → Architecture, testing, security, and user guide
```

### Data Flow

```
User Input (URL)
      ↓
url_validator.py (validate + safe session)
      ↓
scanner_service.py (orchestrate)
      ├── security_checks.py (headers, cookies, CORS, info disclosure)
      ├── tls_checker.py (certificate inspection)
      └── risk_engine.py (score calculation)
              ↓
         ScanResult
              ↓
    ┌─────────────────┐
    │   app.py (UI)   │
    │  Results tabs   │
    │  Report exports │
    └─────────────────┘
```

---

## 9. Methodology

### Checks Implemented

| ID | Category | Check | Severity (if failing) |
|----|----------|-------|----------------------|
| HDR-001 | HTTP Headers | Content-Security-Policy | High / Medium |
| HDR-002 | HTTP Headers | Strict-Transport-Security | Medium |
| HDR-003 | HTTP Headers | X-Content-Type-Options | Low |
| HDR-004 | HTTP Headers | X-Frame-Options | Medium |
| HDR-005 | HTTP Headers | Referrer-Policy | Low |
| HDR-006 | HTTP Headers | Permissions-Policy | Low |
| TLS-001 | TLS/Certificate | HTTPS availability | High |
| TLS-002 | TLS/Certificate | Certificate expiry | Critical/Medium |
| TLS-003 | TLS/Certificate | Certificate details | Informational |
| CKI-N | Cookie Security | Secure/HttpOnly/SameSite | Medium/Low |
| CRS-001 | CORS | Access-Control-Allow-Origin | High/Low |
| INF-001 | Info Disclosure | Server header | Low |
| INF-002 | Info Disclosure | X-Powered-By | Low |
| TRP-001 | Transport | HTTP→HTTPS redirect | High |

### Scoring Formula

```
Score = max(0, 100 − Σ deductions)

Deductions:
  Critical   = 30 per finding
  High       = 20 per finding
  Medium     = 10 per finding
  Low        =  5 per finding
  Informational = 1 per finding
```

Passed and inconclusive checks carry no deduction. Score is bounded at 0 minimum.

---

## 10. Implementation

The application was developed in Python 3.14.3 on Windows using the VS Code / Antigravity IDE. Key implementation decisions:

- **Dataclasses** used for Finding, ScanResult, RiskReport, ValidationResult — clean, typed, testable.
- **Functional check design** — each check is a pure function returning a Finding. One failing check cannot crash the pipeline.
- **SSRF protection** — all resolved IPs are checked against a comprehensive list of blocked CIDR ranges before any request is made.
- **Manual redirect following** — each redirect hop is validated before the scanner follows it.
- **ReportLab PDF** — uses a Document Template with structured flowables for a professional multi-section report.
- **Streamlit dark theme** — custom CSS overlaid on Streamlit's default components using `st.markdown` with `unsafe_allow_html=True`.

---

## 11. Test Strategy

139 automated tests were written covering:

- URL validation (valid URLs, scheme rejection, private IP rejection, DNS failure, redirect validation)
- All 12 security check functions (present/absent header cases, cookie attributes, CORS variations)
- Risk engine (score deductions, grade boundaries, determinism, boundary values)
- Report generation (JSON structure, CSV rows, PDF magic bytes, empty/special-character handling)
- Scanner service integration (mock HTTP responses, error propagation, demo mode)
- Streamlit UI testing via `streamlit.testing.v1.AppTest` (initial load, sidebar routing, offline demo execution, report download controls, empty state handling, Altair chart rendering)

Tests use `unittest.mock` to intercept HTTP calls. No real network requests are made during the test suite.

All 139 tests pass on Python 3.14.3 with pytest 9.1.1.

---

## 12. Results and Observations

The scanner was successfully tested against several authorized endpoints including:
- Endpoints with all security headers present → scores in the 90–100 range
- Endpoints missing common headers → scores reflecting the deductions

The demo mode accurately illustrates a mid-range score with a mix of findings at different severity levels.

> **Note:** Specific scan results from real websites are not published in this report to avoid misrepresenting any organization's security posture.

---

## 13. Limitations

- Scans a single initial URL; linked pages and authenticated areas are not assessed.
- Cannot detect application-layer vulnerabilities (SQLi, XSS exploits, IDOR, etc.).
- Cookie analysis is limited to cookies set in the observable initial response.
- CORS analysis is limited to a single OPTIONS probe; complex CORS policies require deeper testing.
- TLS analysis checks certificate validity but not cipher suites or protocol versions.
- A score of 100 does not mean the website is secure.
- Results represent a point-in-time snapshot.

---

## 14. Future Scope

- CLI output mode for CI/CD pipeline integration
- Subdomain discovery (with explicit authorization flow)
- DNSSEC, CAA record, and security.txt checks
- HTTP/2 and HTTP/3 support checks
- TLS cipher suite and protocol version analysis
- Historical scan comparison and delta reporting
- Scheduled re-scan with email alerts
- Multi-URL batch scanning
- Integration with CVE databases for version-specific advisories

---

## 15. Conclusion

SentinelScan demonstrates that automated, educational security scanning tools can be built safely, cleanly, and effectively using Python's standard library combined with accessible frameworks like Streamlit. The project successfully implements a non-trivial security tool with a professional user interface, comprehensive testing, SSRF protection, and clear documentation — all without requiring paid APIs, cloud services, or a database.

The tool is suitable as an entry point for website owners learning about web security, and as a portfolio project demonstrating secure software engineering practices.

---

## 16. References

1. OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/
2. Content Security Policy — MDN Web Docs: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
3. RFC 6797 — HTTP Strict Transport Security: https://datatracker.ietf.org/doc/html/rfc6797
4. RFC 7239 — Forwarded HTTP Extension: https://datatracker.ietf.org/doc/html/rfc7239
5. Fetch Specification — CORS: https://fetch.spec.whatwg.org/
6. Let's Encrypt — Free TLS Certificates: https://letsencrypt.org/
7. HSTS Preload List: https://hstspreload.org/
8. Mozilla Observatory: https://observatory.mozilla.org/
9. Python ssl module documentation: https://docs.python.org/3/library/ssl.html
10. Streamlit documentation: https://docs.streamlit.io/
11. ReportLab documentation: https://www.reportlab.com/docs/reportlab-userguide.pdf
12. OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/

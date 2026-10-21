# 🛡 SentinelScan — Automated Web Security Scanner

> **Identify. Understand. Secure.**

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/UI-Streamlit-red)](https://streamlit.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

SentinelScan is an open-source, educational web security configuration scanner built for the **IBM SkillsBuild Cybersecurity Bootcamp**. It performs non-destructive, automated security checks on a website's HTTP configuration and produces a clear risk score with actionable remediation advice.

---

## ⚠️ Authorized Use Notice

> **You must only scan websites you own or have explicit, written permission to assess.**
> Unauthorized scanning may violate computer misuse laws and website terms of service.
> The developers accept no liability for unauthorized or unlawful use of this tool.

---

## 🎯 Problem Statement

Most website owners and developers lack visibility into basic web security configuration weaknesses. Headers that can be set in minutes — like Content-Security-Policy or Strict-Transport-Security — are frequently absent. Developers often need an accessible, plain-English tool to understand what is missing and why it matters.

## 💡 Proposed Solution

SentinelScan provides a professional, web-based dashboard that:
1. Accepts a URL with an authorization confirmation
2. Performs a set of safe, non-destructive configuration checks
3. Calculates a transparent, documented risk score
4. Explains each finding in plain English with remediation guidance
5. Exports a downloadable report in JSON, CSV, or PDF format

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔒 HTTP Security Headers | CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy |
| 🌐 TLS / Certificate | Validity, expiration, hostname verification |
| 🍪 Cookie Security | Secure, HttpOnly, SameSite attribute review |
| 🔗 CORS Configuration | Access-Control-Allow-Origin analysis |
| 🔍 Info Disclosure | Server and X-Powered-By header review |
| ↩️ Transport Security | HTTP→HTTPS redirect behaviour |
| 📊 Risk Scoring | 0–100 score with grade (A+, A, B, C, D, F) |
| 🎭 Demo Mode | Offline illustrative results — no internet required |
| 📥 Reports | JSON, CSV, and PDF export |
| 🛡 SSRF Protection | Private/loopback IP blocking, redirect validation |

---

## 🏗 Architecture

```
SentinelScan/
├── app.py                    # Streamlit UI entry point
├── config.py                 # Central configuration constants
├── requirements.txt
├── pytest.ini
├── scanner/
│   ├── url_validator.py      # URL validation & safe HTTP requests
│   ├── security_checks.py    # Individual security check functions
│   ├── tls_checker.py        # TLS/certificate inspection
│   ├── risk_engine.py        # Deterministic scoring engine
│   ├── scanner_service.py    # Scan orchestration pipeline
│   └── report_generator.py  # JSON, CSV, PDF reports
├── utils/
│   ├── formatting.py         # UI display helpers
│   └── demo_data.py          # Offline demo fixture data
├── tests/
│   ├── test_url_validator.py
│   ├── test_security_checks.py
│   ├── test_risk_engine.py
│   ├── test_reports.py
│   ├── test_scanner_service.py
│   └── test_app_ui.py
└── docs/
    ├── PROJECT_REPORT.md
    ├── ARCHITECTURE.md
    ├── TESTING.md
    ├── SECURITY_AND_LIMITATIONS.md
    └── USER_GUIDE.md
```

---

## 🖥 System Requirements

- **OS:** Windows 10/11, macOS, or Linux
- **Python:** 3.11 or newer (Python 3.14 tested)
- **Network:** Internet access for live scans; none required for demo mode
- **RAM:** 512 MB minimum
- **Browser:** Any modern browser for the Streamlit UI

---

## 🚀 Installation (Windows)

### 1. Verify Python

```powershell
python --version
```

If Python is not installed, download it from https://www.python.org/downloads/

### 2. Create a virtual environment

```powershell
py -m venv .venv
```

### 3. Activate the virtual environment

```powershell
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks the script, run this alternative instead:

```powershell
.\.venv\Scripts\activate.bat
```

Or if execution policy prevents both, run:
```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

### 4. Install dependencies

```powershell
python -m pip install -r requirements.txt
```

---

## ▶️ Running the Application

```powershell
python -m streamlit run app.py
```

The terminal will display:

```
  You can now view your Streamlit app in your browser.
  Local URL: http://localhost:8501
```

Open **http://localhost:8501** in your browser.

---

## 🎭 Demo Mode (No Internet Required)

1. Click **🔍 Scanner** in the sidebar
2. Select the **🎭 Demo Mode** tab
3. Click **▶ Load Demo Results**
4. Explore findings, scores, and downloads

Demo results are clearly labeled as illustrative — no real website is scanned.

---

## 🔍 Live Scan (Authorized Sites Only)

1. Click **🔍 Scanner** → **🔴 Live Scan** tab
2. Enter your website URL (e.g., `https://your-website.com`)
3. Check the authorization confirmation checkbox
4. Click **🚀 Start Scan**
5. Results appear in **📊 Results** and **📋 Findings**

---

## 📥 Exporting Reports

1. Complete a scan (live or demo)
2. Navigate to **📥 Reports**
3. Click **⬇️ Download JSON**, **⬇️ Download CSV**, or **⬇️ Download PDF**

---

## 🧪 Running Tests

```powershell
python -m pytest -v
```

All tests use mocked HTTP responses. No real network requests are made during testing.

---

## 🧮 Scoring Formula

```
Score = max(0, 100 − Σ deductions)
```

| Severity | Deduction |
|----------|-----------|
| Critical | −30 |
| High | −20 |
| Medium | −10 |
| Low | −5 |
| Informational | −1 |

Passed checks and inconclusive checks carry no deduction.

---

## ⚠️ Limitations

- Scans a single URL — linked pages are not crawled
- Cannot detect application-layer vulnerabilities (SQLi, XSS exploits, etc.)
- Cannot access authenticated pages or cookies set after login
- A score of 100 does not guarantee the website is secure
- Results reflect a point-in-time snapshot; server configuration may change
- Does not replace a professional penetration test or security audit

---

## 🔮 Future Enhancements

- Subdomain enumeration (with explicit authorization flow)
- HTTP/2 and HTTP/3 support checks
- Security.txt / robots.txt review
- DNSSEC check
- Historical scan comparison
- Scheduled re-scan alerts
- CI/CD integration mode (CLI output)

---

## 📚 References

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [Mozilla Observatory](https://observatory.mozilla.org/)
- [Content Security Policy — MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [HSTS Preload List](https://hstspreload.org/)
- [RFC 6797 — HTTP Strict Transport Security](https://datatracker.ietf.org/doc/html/rfc6797)
- [Fetch Specification — CORS](https://fetch.spec.whatwg.org/)
- [Let's Encrypt](https://letsencrypt.org/)

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

> Automated configuration checks performed by SentinelScan do not constitute a professional
> security audit or a guarantee that any website is fully secure.

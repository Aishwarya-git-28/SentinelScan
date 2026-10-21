# SentinelScan — User Guide

## Getting Started

### Launch the Application

```powershell
python -m streamlit run app.py
```

Open `http://localhost:8501` in your browser.

---

## Navigation

Use the **sidebar** on the left to navigate between pages:

| Page | Purpose |
|------|---------|
| 🏠 Home | Overview, quick start, session scan history |
| 🔍 Scanner | Live scan input or demo mode |
| 📊 Results | Score, grade, findings summary, severity chart |
| 📋 Findings | Detailed findings with filtering and search |
| 📥 Reports | Download JSON, CSV, or PDF reports |
| ℹ️ About | Methodology, scoring formula, limitations |

---

## Demo Mode (No Internet Required)

1. Click **🔍 Scanner** in the sidebar
2. Select the **🎭 Demo Mode** tab
3. Click **▶ Load Demo Results**
4. Navigate to **📊 Results**, **📋 Findings**, and **📥 Reports** to explore

The demo uses pre-built illustrative data. A bright orange banner is always shown:
> "🎭 DEMO MODE — These are illustrative results, not a live scan."

---

## Live Scan (Authorized Sites Only)

> ⚠️ Only scan websites you own or have explicit written permission to assess.

1. Click **🔍 Scanner** → **🔴 Live Scan** tab
2. Enter your website URL (e.g., `https://your-website.com`)
   - HTTPS and HTTP URLs are both accepted
   - Private/local addresses are automatically blocked
3. Check the authorization confirmation checkbox
4. Click **🚀 Start Scan**
5. Wait for the progress bar to complete (typically 5–20 seconds)
6. Results open automatically

---

## Understanding the Score

- **Score: 0–100** — Higher is better (fewer detected issues)
- **Grade: A+, A, B, C, D, F** — Letter grade equivalent

| Score | Grade | Meaning |
|-------|-------|---------|
| 90–100 | A+ | Very few or no detected issues |
| 80–89 | A | Minor issues only |
| 70–79 | B | Some low-to-medium issues |
| 55–69 | C | Notable medium issues |
| 35–54 | D | Significant issues present |
| 0–34 | F | Critical/high issues detected |

**A score of 100 does not mean the website is fully secure.**

---

## Understanding Findings

Each finding has:

| Field | Meaning |
|-------|---------|
| **Severity** | Critical / High / Medium / Low / Informational |
| **Status** | Finding (issue) / Passed / Inconclusive |
| **Evidence** | The actual observed header or value |
| **Why It Matters** | Plain-English explanation of the risk |
| **Remediation** | Exact steps to fix the issue |
| **Confidence** | How certain the check is (High/Medium/Low) |

### Filtering Findings

In the **📋 Findings** page:
- Filter by **Severity** to focus on the most critical issues
- Filter by **Status** to see only active findings or only passed checks
- Filter by **Category** to look at one check area at a time
- Use the **Search** box to find findings by title keyword

---

## Downloading Reports

1. Complete any scan (live or demo)
2. Navigate to **📥 Reports**
3. Choose a format:
   - **JSON** — Full machine-readable data, includes all fields
   - **CSV** — Spreadsheet format, one row per finding
   - **PDF** — Professional report with cover, summary, and findings table
4. Click the download button

Report filenames use the scan timestamp (e.g., `sentinelscan_2026-10-21_18-45-00.json`).

---

## Interpreting Specific Checks

### Content-Security-Policy (CSP)
A CSP header tells browsers what scripts, styles, and resources are allowed. Without one, XSS attacks are easier. A CSP with `'unsafe-inline'` is significantly weaker than one without it.

### Strict-Transport-Security (HSTS)
HSTS tells browsers to always use HTTPS for this domain, even if someone tries to redirect to HTTP. It must be served over HTTPS with a max-age of at least 6 months to be effective.

### X-Content-Type-Options
The value `nosniff` prevents browsers from guessing the content type, which can enable certain attacks. This is a one-liner fix.

### X-Frame-Options / frame-ancestors
Prevents other websites from embedding your page in an invisible iframe (clickjacking). Set to `SAMEORIGIN` or use CSP `frame-ancestors 'self'`.

### TLS Certificate
An expired certificate causes browsers to block access and show security warnings. A certificate expiring within 30 days is a warning sign.

### Cookie Attributes
- **Secure** — Cookie is only sent over HTTPS
- **HttpOnly** — Cookie cannot be read by JavaScript (protects against XSS theft)
- **SameSite=Strict/Lax** — Reduces CSRF exposure

### CORS
A wildcard `Access-Control-Allow-Origin: *` allows any website to read your API responses via JavaScript. This is acceptable for truly public APIs but risky for authenticated or sensitive endpoints.

---

## Troubleshooting

| Problem | Solution |
|---------|---------|
| "URL validation failed: Scanning rejected" | The URL resolves to a private/loopback address. Only public websites can be scanned. |
| "Connection error" | The website may be down, blocking scanners, or unreachable from your network. |
| "TLS certificate could not be retrieved" | The certificate may be invalid or the server may not support TLS handshakes from the scanner's connection. |
| App won't start | Ensure `streamlit` is installed: `pip install streamlit` |
| PDF download button not shown | ReportLab is not installed. Run: `pip install reportlab` |
| Tests fail | Run `python -m pytest -v` and check the output. Ensure you are in the project root directory. |

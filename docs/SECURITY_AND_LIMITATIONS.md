# SentinelScan — Security Considerations and Limitations

## What SentinelScan IS

SentinelScan is an **educational, configuration-inspection tool** for authorized use on websites you own or have explicit written permission to assess. It inspects publicly visible HTTP response metadata.

## What SentinelScan IS NOT

- A penetration testing tool
- An exploit framework
- A vulnerability scanner
- A web crawler
- A password or credential tester
- An official security certification
- A replacement for a professional security audit

## Safety Controls Implemented

### 1. SSRF (Server-Side Request Forgery) Protection
- All resolved IP addresses are checked against 18 blocked CIDR ranges before any request
- Blocked ranges include: loopback (127.0.0.0/8), private (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), link-local (169.254.0.0/16), and several reserved ranges
- Redirect destinations are fully validated (including IP resolution) before each hop is followed
- Maximum redirect hops: 5 (configurable)

### 2. Scheme Restriction
- Only `http://` and `https://` URLs are accepted
- `file://`, `ftp://`, `gopher://`, and all other schemes are rejected

### 3. Response Size Limiting
- Response body reads are capped at 5 MB (configurable)
- Prevents memory exhaustion from large responses

### 4. TLS Security
- TLS verification is always enabled for live scans
- Uses the system CA store via `ssl.create_default_context()`
- No self-signed certificate bypass is provided

### 5. User Authorization Confirmation
- Live scans require the user to check an explicit authorization confirmation checkbox
- Demo mode (offline data) never requires this confirmation

### 6. No Attack Payloads
- No fuzzing, injection strings, exploit code, or malicious content is sent
- CORS check uses a clearly labeled, non-credential OPTIONS request

### 7. Report Safety
- Reports escape `< > &` for PDF rendering
- No authentication headers, session cookies, or secrets are included in reports
- Report filenames use sanitized timestamps (no user input in filenames)

## Known Limitations

### What Cannot Be Detected
- SQL injection, stored/reflected XSS vulnerabilities
- Authentication and authorisation weaknesses
- Business logic flaws
- Server-side code vulnerabilities
- Database misconfigurations
- Vulnerabilities behind login forms
- All cookies (only cookies in the observable initial response)
- The full effectiveness of a Content-Security-Policy
- TLS cipher suite and protocol version weaknesses (e.g., use of TLS 1.0/1.1)

### Scan Coverage
- Single URL only — linked pages are not crawled
- Results are a point-in-time snapshot
- A/B testing, CDN caching, or geolocation-based headers may cause inconsistent results

### Score Interpretation
- A score of 100 does NOT mean the website is secure
- A score of 0 does NOT mean the website is actively compromised
- The score measures detected configuration-level issues only

## Authorized Use Requirements

1. You must own the target website OR have explicit written permission from the owner to scan it.
2. You accept full responsibility for any scan you initiate.
3. Unauthorized scanning may violate:
   - The Computer Misuse Act 1990 (UK)
   - The Computer Fraud and Abuse Act (USA)
   - The General Data Protection Regulation (EU)
   - Equivalent legislation in your jurisdiction
   - Website terms of service

The developers of SentinelScan accept no liability for unauthorized or unlawful use.

## Responsible Disclosure

If you discover a security issue in SentinelScan itself, please report it responsibly by opening a GitHub issue labeled `[security]` rather than disclosing it publicly.

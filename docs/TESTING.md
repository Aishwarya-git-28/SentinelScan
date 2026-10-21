# SentinelScan — Testing Guide

## Running the Tests

```powershell
# From the project root (with virtualenv activated)
python -m pytest -v
```

Output shows individual test pass/fail status.

```powershell
# Quick summary only
python -m pytest -q

# Stop on first failure
python -m pytest -x
```

## Test Coverage Summary

**Total: 139 tests | 0 failures on Python 3.14.3 + pytest 9.1.1**

| Test File | Tests | Coverage |
|-----------|-------|----------|
| `test_url_validator.py` | 28 | URL validation, scheme rejection, IP blocking, DNS failure, safe_get error handling |
| `test_security_checks.py` | 45 | All 12 security check functions with present/absent/edge cases |
| `test_risk_engine.py` | 25 | Scoring formula, grade boundaries, determinism, edge cases |
| `test_reports.py` | 21 | JSON structure, CSV rows, PDF generation, empty/special-character handling |
| `test_scanner_service.py` | 17 | Integration tests, demo mode, error propagation, single-check failure resilience |
| `test_app_ui.py` | 8 | Streamlit AppTest UI loading, navigation, demo trigger, report downloads, chart & findings rendering |

## Test Design Principles

1. **No real network requests** — All tests use `unittest.mock.patch` or mock objects.
2. **Deterministic** — Tests do not depend on external state or timing.
3. **Isolated** — Each test creates its own fixtures; no shared mutable state between tests.
4. **Correct patch paths** — Mocks patch names in the namespace where they are used (`scanner.scanner_service.safe_get`), not where they are defined.
5. **Edge case coverage** — Empty findings, special characters in evidence, PDF with zero findings, etc.

## What Is NOT Tested

The following are not tested in the automated suite (by design):

- Live network requests against real websites
- Streamlit UI rendering (requires a browser; beyond pytest scope)
- OS-level DNS resolution behavior
- Actual TLS handshakes (only the response processing is tested)

## Adding New Tests

When adding a new security check:
1. Create the check function in `scanner/security_checks.py`
2. Add a test class in `tests/test_security_checks.py`
3. Test at minimum: header present (passing), header absent (finding), edge case
4. Use `_make_response()` helper to create mock responses

When adding a new report format:
1. Add a test class in `tests/test_reports.py`
2. Test: valid output, empty findings, special characters, large inputs

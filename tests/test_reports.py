"""
tests/test_reports.py
Tests for scanner/report_generator.py — JSON, CSV, and PDF generation.
"""

from __future__ import annotations

import csv
import io
import json

import pytest

from scanner.scanner_service import ScanResult
from scanner.security_checks import Finding
from scanner.risk_engine import calculate_risk
from scanner.report_generator import (
    generate_json, generate_csv, generate_pdf, REPORTLAB_AVAILABLE,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _make_finding(fid="HDR-001", title="Test Finding", category="Headers",
                  severity="medium", status="finding"):
    return Finding(
        finding_id=fid,
        title=title,
        category=category,
        severity=severity,
        status=status,
        short_description="A test finding for report generation testing.",
        evidence="Test-Header: missing",
        why_it_matters="Needed for testing.",
        remediation="Add the header.",
        confidence="high",
    )


def _make_scan_result(findings=None, success=True) -> ScanResult:
    if findings is None:
        findings = [_make_finding()]
    risk = calculate_risk(findings)
    return ScanResult(
        target_url="https://test.example.com",
        normalized_url="https://test.example.com/",
        timestamp="2026-10-21T18:00:00+00:00",
        duration_seconds=1.23,
        scan_mode="demo",
        success=success,
        findings=findings,
        risk_report=risk,
        resolved_ips=["93.184.216.34"],
        http_status_code=200,
        final_url="https://test.example.com/",
    )


# ── JSON ──────────────────────────────────────────────────────────────────────

class TestGenerateJson:
    def test_returns_valid_json_string(self):
        result = _make_scan_result()
        output = generate_json(result)
        assert isinstance(output, str)
        parsed = json.loads(output)
        assert isinstance(parsed, dict)

    def test_contains_target_url(self):
        result = _make_scan_result()
        output = generate_json(result)
        parsed = json.loads(output)
        assert parsed["target_url"] == "https://test.example.com"

    def test_contains_findings(self):
        result = _make_scan_result()
        output = generate_json(result)
        parsed = json.loads(output)
        assert "findings" in parsed
        assert len(parsed["findings"]) == 1
        assert parsed["findings"][0]["finding_id"] == "HDR-001"

    def test_contains_risk_report(self):
        result = _make_scan_result()
        output = generate_json(result)
        parsed = json.loads(output)
        assert "risk_report" in parsed
        assert isinstance(parsed["risk_report"]["score"], int)

    def test_empty_findings_generates_without_error(self):
        result = _make_scan_result(findings=[])
        output = generate_json(result)
        parsed = json.loads(output)
        assert parsed["findings"] == []

    def test_contains_disclaimer(self):
        result = _make_scan_result()
        output = generate_json(result)
        parsed = json.loads(output)
        assert "disclaimer" in parsed
        assert len(parsed["disclaimer"]) > 10

    def test_special_characters_in_evidence_dont_crash(self):
        f = _make_finding()
        f.evidence = "Special chars: < > & \" ' \n\t emoji: 🛡"
        result = _make_scan_result(findings=[f])
        output = generate_json(result)
        assert json.loads(output) is not None

    def test_long_url_handled(self):
        result = _make_scan_result()
        result.target_url = "https://" + "a" * 500 + ".example.com"
        output = generate_json(result)
        assert json.loads(output) is not None


# ── CSV ───────────────────────────────────────────────────────────────────────

class TestGenerateCsv:
    def test_returns_string(self):
        result = _make_scan_result()
        output = generate_csv(result)
        assert isinstance(output, str)

    def test_has_header_row(self):
        result = _make_scan_result()
        output = generate_csv(result)
        reader = csv.DictReader(io.StringIO(output))
        fieldnames = reader.fieldnames or []
        assert "finding_id" in fieldnames
        assert "severity" in fieldnames
        assert "title" in fieldnames

    def test_has_correct_data_row(self):
        result = _make_scan_result()
        output = generate_csv(result)
        rows = list(csv.DictReader(io.StringIO(output)))
        assert len(rows) == 1
        assert rows[0]["finding_id"] == "HDR-001"
        assert rows[0]["severity"] == "medium"

    def test_multiple_findings_produce_multiple_rows(self):
        findings = [_make_finding("HDR-001"), _make_finding("HDR-002")]
        result = _make_scan_result(findings=findings)
        output = generate_csv(result)
        rows = list(csv.DictReader(io.StringIO(output)))
        assert len(rows) == 2

    def test_empty_findings_produces_blank_row(self):
        result = _make_scan_result(findings=[])
        output = generate_csv(result)
        # Should not crash; produces header + one blank row
        rows = list(csv.DictReader(io.StringIO(output)))
        assert len(rows) == 1


# ── PDF ───────────────────────────────────────────────────────────────────────

class TestGeneratePdf:
    def test_returns_bytes_when_reportlab_available(self):
        if not REPORTLAB_AVAILABLE:
            pytest.skip("ReportLab not installed; PDF tests skipped.")
        result = _make_scan_result()
        pdf_bytes = generate_pdf(result)
        assert pdf_bytes is not None
        assert isinstance(pdf_bytes, bytes)
        assert len(pdf_bytes) > 100

    def test_pdf_starts_with_pdf_magic_bytes(self):
        if not REPORTLAB_AVAILABLE:
            pytest.skip("ReportLab not installed; PDF tests skipped.")
        result = _make_scan_result()
        pdf_bytes = generate_pdf(result)
        assert pdf_bytes is not None
        assert pdf_bytes[:4] == b"%PDF"

    def test_pdf_with_empty_findings_does_not_crash(self):
        if not REPORTLAB_AVAILABLE:
            pytest.skip("ReportLab not installed; PDF tests skipped.")
        result = _make_scan_result(findings=[])
        pdf_bytes = generate_pdf(result)
        assert pdf_bytes is not None
        assert len(pdf_bytes) > 100

    def test_pdf_with_demo_scan_mode_does_not_crash(self):
        if not REPORTLAB_AVAILABLE:
            pytest.skip("ReportLab not installed; PDF tests skipped.")
        result = _make_scan_result()
        result.scan_mode = "demo"
        pdf_bytes = generate_pdf(result)
        assert pdf_bytes is not None

    def test_pdf_with_special_characters_does_not_crash(self):
        if not REPORTLAB_AVAILABLE:
            pytest.skip("ReportLab not installed; PDF tests skipped.")
        f = _make_finding()
        f.evidence = "Special: < > & 'quote' \"double\" emoji:🛡"
        f.why_it_matters = "Test with special chars: <script>alert(1)</script>"
        result = _make_scan_result(findings=[f])
        pdf_bytes = generate_pdf(result)
        assert pdf_bytes is not None

    def test_returns_none_when_reportlab_unavailable(self):
        """Verify that generate_pdf returns None when ReportLab is not installed."""
        import scanner.report_generator as rg
        original = rg.REPORTLAB_AVAILABLE
        try:
            rg.REPORTLAB_AVAILABLE = False
            result = _make_scan_result()
            pdf_bytes = generate_pdf(result)
            assert pdf_bytes is None
        finally:
            rg.REPORTLAB_AVAILABLE = original

from pathlib import Path

from guarddoc.core.i18n import Language
from guarddoc.core.models import Severity
from guarddoc.scanners.pdf import PdfScanner


def test_pdf_scanner_detects_embedded_javascript(tmp_path: Path) -> None:
    pdf_file = tmp_path / "sample_js.pdf"
    pdf_file.write_bytes(
        b"%PDF-1.4\n1 0 obj\n<< /Type /Action /S /JavaScript /JS (app.alert(1);) >>\nendobj\n%%EOF"
    )

    scanner = PdfScanner()
    assert scanner.is_supported(pdf_file, "application/pdf")

    threats = scanner.scan(pdf_file, mime_type="application/pdf", lang=Language.EN)
    assert len(threats) >= 1

    rule_ids = [t.rule_id for t in threats]
    assert any("PDF-JAVASCRIPT" in r or "PDF-JS" in r or "PDF-EMBEDDED-JS" in r for r in rule_ids)
    assert all(t.scanner_name == "PdfScanner" for t in threats)
    assert any(t.severity in (Severity.HIGH, Severity.CRITICAL) for t in threats)


def test_pdf_scanner_detects_openaction_and_aa(tmp_path: Path) -> None:
    pdf_file = tmp_path / "sample_auto.pdf"
    pdf_file.write_bytes(b"%PDF-1.7\n<< /Type /Catalog /OpenAction 2 0 R /AA << >> >>\n%%EOF")

    scanner = PdfScanner()
    threats = scanner.scan(pdf_file, mime_type="application/pdf", lang=Language.PL)

    assert len(threats) >= 1
    rule_ids = [t.rule_id for t in threats]
    assert any(
        "OPENACTION" in r or "OPEN-ACTION" in r or "ADDITIONAL-ACTIONS" in r for r in rule_ids
    )
    assert all(t.scanner_name == "PdfScanner" for t in threats)


def test_pdf_scanner_allows_benign_overleaf_latex_pdf(tmp_path: Path) -> None:
    """Overleaf LaTeX PDFs use /OpenAction with /GoTo for initial page view and should be safe."""
    latex_pdf = tmp_path / "overleaf_paper.pdf"
    latex_pdf.write_bytes(
        b"%PDF-1.5\n"
        b"1 0 obj\n<< /Type /Catalog /OpenAction [ 3 0 R /Fit ] /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [ 3 0 R ] >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>\nendobj\n"
        b"4 0 obj\n<< /Length 12 >>\nstream\n/GoTo /Fit\nendstream\nendobj\n"
        b"%%EOF"
    )

    scanner = PdfScanner()
    threats = scanner.scan(latex_pdf, mime_type="application/pdf", lang=Language.EN)
    assert len(threats) == 0


def test_pdf_scanner_clean_pdf(tmp_path: Path) -> None:
    clean_pdf = tmp_path / "clean.pdf"
    clean_pdf.write_bytes(b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n%%EOF")

    scanner = PdfScanner()
    threats = scanner.scan(clean_pdf, mime_type="application/pdf", lang=Language.EN)
    assert len(threats) == 0


def test_pdf_scanner_handles_none_mime_type(tmp_path: Path) -> None:
    pdf_file = tmp_path / "document.pdf"
    pdf_file.write_bytes(b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n%%EOF")

    scanner = PdfScanner()
    # Ensure checking support and scanning with mime_type=None doesn't raise TypeError
    assert scanner.is_supported(pdf_file, None) is True
    threats = scanner.scan(pdf_file, mime_type=None, lang=Language.EN)
    assert len(threats) == 0


def test_pdf_scanner_skips_non_pdf(tmp_path: Path) -> None:
    txt_file = tmp_path / "doc.txt"
    txt_file.write_text("Hello World with /JS and /OpenAction inside text", encoding="utf-8")

    scanner = PdfScanner()
    assert scanner.is_supported(txt_file, "text/plain") is False

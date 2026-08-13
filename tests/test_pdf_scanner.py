from pathlib import Path

from guarddoc.core.i18n import Language
from guarddoc.scanners.pdf import PdfScanner

VALID_MINIMAL_PDF = (
    b"%PDF-1.4\n"
    b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    b"2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n"
    b"xref\n0 3\n"
    b"0000000000 65535 f \n"
    b"0000000009 00000 n \n"
    b"0000000058 00000 n \n"
    b"trailer\n<< /Size 3 /Root 1 0 R >>\n"
    b"startxref\n109\n"
    b"%%EOF\n"
)


def test_pdf_scanner_clean_file(tmp_path: Path) -> None:
    clean_pdf = tmp_path / "clean.pdf"
    clean_pdf.write_bytes(VALID_MINIMAL_PDF)

    scanner = PdfScanner()
    threats = scanner.scan(clean_pdf, mime_type="application/pdf")

    assert len(threats) == 0


def test_pdf_scanner_detects_js_and_openaction(tmp_path: Path) -> None:
    suspicious_pdf = tmp_path / "malicious.pdf"
    suspicious_pdf.write_bytes(
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /OpenAction 2 0 R /JS (app.alert('Hacked')) >>\nendobj\n"
        b"xref\n0 2\n0000000000 65535 f \n0000000009 00000 n \ntrailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n80\n%%EOF"
    )

    scanner = PdfScanner()
    threats = scanner.scan(suspicious_pdf, mime_type="application/pdf")

    rule_ids = [t.rule_id for t in threats]
    assert "PDF-EMBEDDED-JS" in rule_ids
    assert "PDF-OPEN-ACTION" in rule_ids


def test_pdf_scanner_detects_js_english_i18n(tmp_path: Path) -> None:
    suspicious_pdf = tmp_path / "malicious_en.pdf"
    suspicious_pdf.write_bytes(b"%PDF-1.4\n1 0 obj\n<< /JS (app.alert('Hacked')) >>\nendobj\n%%EOF")

    scanner = PdfScanner()
    threats = scanner.scan(suspicious_pdf, mime_type="application/pdf", lang=Language.EN)

    assert len(threats) == 1
    assert threats[0].rule_id == "PDF-EMBEDDED-JS"
    assert "JavaScript script detected" in threats[0].title

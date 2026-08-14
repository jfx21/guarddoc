from pathlib import Path
from guarddoc.core.i18n import Language
from guarddoc.core.models import Severity
from guarddoc.scanners.pdf import PdfScanner


def test_pdf_scanner_detects_embedded_javascript(tmp_path: Path) -> None:
    pdf_file = tmp_path / "sample_js.pdf"
    pdf_file.write_bytes(
        b"%PDF-1.4\n1 0 obj\n<< /Type /Action /S /JavaScript /JS (app.alert(1);) >>\nendobj"
    )

    scanner = PdfScanner()
    assert scanner.is_supported(pdf_file, "application/pdf")

    threats = scanner.scan(pdf_file, mime_type="application/pdf", lang=Language.EN)
    assert len(threats) == 1
    assert threats[0].rule_id == "PDF-EMBEDDED-JS"
    assert threats[0].severity == Severity.HIGH
    assert threats[0].scanner_name == "PdfScanner"


def test_pdf_scanner_detects_openaction_and_aa(tmp_path: Path) -> None:
    pdf_file = tmp_path / "sample_auto.pdf"
    pdf_file.write_bytes(b"%PDF-1.7\n<< /Type /Catalog /OpenAction 2 0 R /AA << >> >>")

    scanner = PdfScanner()
    threats = scanner.scan(pdf_file, mime_type="application/pdf", lang=Language.PL)
    assert len(threats) == 1
    assert threats[0].rule_id == "PDF-OPEN-ACTION"
    assert threats[0].severity == Severity.HIGH


def test_pdf_scanner_clean_pdf(tmp_path: Path) -> None:
    clean_pdf = tmp_path / "clean.pdf"
    clean_pdf.write_bytes(b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj")

    scanner = PdfScanner()
    threats = scanner.scan(clean_pdf, mime_type="application/pdf", lang=Language.EN)
    assert len(threats) == 0


def test_pdf_scanner_skips_non_pdf(tmp_path: Path) -> None:
    txt_file = tmp_path / "doc.txt"
    txt_file.write_text("Hello World with /JS inside text")

    scanner = PdfScanner()
    threats = scanner.scan(txt_file, mime_type="text/plain", lang=Language.EN)
    assert len(threats) == 0

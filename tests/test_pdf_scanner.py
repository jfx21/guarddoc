from pathlib import Path

from guarddoc.core.models import Severity
from guarddoc.scanners.pdf import PdfScanner

# Poprawny, minimalistyczny plik PDF zgodny ze specyfikacją ISO (posiada tabelę xref)
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
    # Symulacja złośliwego pliku PDF z JavaScriptem i automatycznym otwarciem
    suspicious_pdf = tmp_path / "malicious.pdf"
    suspicious_pdf.write_bytes(
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /OpenAction 2 0 R /JS (app.alert('Hacked')) >>\nendobj\n"
        b"xref\n0 2\n0000000000 65535 f \n0000000009 00000 n \ntrailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n80\n%%EOF"
    )

    scanner = PdfScanner()
    threats = scanner.scan(suspicious_pdf, mime_type="application/pdf")

    rule_ids = [t.rule_id for t in threats]
    assert "PDF-RAW-JS" in rule_ids
    assert "PDF-RAW-OPENACTION" in rule_ids


def test_pdf_scanner_detects_launch_critical(tmp_path: Path) -> None:
    launch_pdf = tmp_path / "launch.pdf"
    launch_pdf.write_bytes(
        b"%PDF-1.4\n1 0 obj\n<< /Launch << /F (cmd.exe) >> >>\nendobj\n"
        b"xref\n0 2\n0000000000 65535 f \n0000000009 00000 n \ntrailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n60\n%%EOF"
    )

    scanner = PdfScanner()
    threats = scanner.scan(launch_pdf, mime_type="application/pdf")

    critical_threats = [t for t in threats if t.severity == Severity.CRITICAL]
    assert len(critical_threats) == 1
    assert critical_threats[0].rule_id == "PDF-RAW-LAUNCH"

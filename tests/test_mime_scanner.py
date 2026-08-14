from pathlib import Path
from guarddoc.core.i18n import Language
from guarddoc.core.models import Severity
from guarddoc.scanners.mime import MimeScanner


def test_mime_scanner_detects_spoofed_executable(tmp_path: Path) -> None:
    fake_pdf = tmp_path / "invoice.pdf"
    fake_pdf.write_bytes(b"\x7fELFfakebinary")

    scanner = MimeScanner()
    threats = scanner.scan(
        file_path=fake_pdf,
        mime_type="application/x-mach-binary",
        lang=Language.PL,
    )

    assert len(threats) == 1
    assert threats[0].rule_id == "MIME-SPOOF-CRITICAL"
    assert threats[0].severity == Severity.CRITICAL
    assert threats[0].scanner_name == "MimeScanner"


def test_mime_scanner_ignores_benign_matching_files(tmp_path: Path) -> None:
    safe_txt = tmp_path / "notes.txt"
    safe_txt.write_text("Just notes")

    scanner = MimeScanner()
    threats = scanner.scan(
        file_path=safe_txt,
        mime_type="text/plain",
        lang=Language.EN,
    )

    assert len(threats) == 0

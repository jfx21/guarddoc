from pathlib import Path

from guarddoc.core.models import Severity
from guarddoc.scanners.mime import MimeScanner


def test_mime_scanner_valid_txt(tmp_path: Path) -> None:
    txt_file = tmp_path / "valid.txt"
    txt_file.write_text("Czysty plik tekstowy bez zagrożeń.")

    scanner = MimeScanner()
    threats = scanner.scan(txt_file, mime_type="text/plain")

    assert len(threats) == 0


def test_mime_scanner_executable_spoofing(tmp_path: Path) -> None:
    # Tworzymy plik z rozszerzeniem .pdf, ale nagłówkiem skryptu powłoki (shebang)
    fake_pdf = tmp_path / "faktura.pdf"
    fake_pdf.write_text("#!/bin/bash\necho 'Malware execution'")

    scanner = MimeScanner()
    threats = scanner.scan(fake_pdf, mime_type="text/x-shellscript")

    assert len(threats) == 1
    assert threats[0].rule_id == "MIME-SPOOF-CRITICAL"
    assert threats[0].severity == Severity.CRITICAL

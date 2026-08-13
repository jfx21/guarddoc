from pathlib import Path

from guarddoc.core.i18n import Language
from guarddoc.core.models import Severity
from guarddoc.scanners.mime import MimeScanner


def test_mime_scanner_valid_txt(tmp_path: Path) -> None:
    txt_file = tmp_path / "valid.txt"
    txt_file.write_text("Czysty plik tekstowy bez zagrożeń.", encoding="utf-8")

    scanner = MimeScanner()
    threats = scanner.scan(txt_file, mime_type="text/plain")

    assert len(threats) == 0


def test_mime_scanner_executable_spoofing(tmp_path: Path) -> None:
    # Tworzymy plik z rozszerzeniem .pdf, ale nagłówkiem skryptu powłoki (shebang)
    fake_pdf = tmp_path / "faktura.pdf"
    fake_pdf.write_text("#!/bin/bash\necho 'Malware execution'", encoding="utf-8")

    scanner = MimeScanner()

    # Domyślne skanowanie (język polski)
    threats_pl = scanner.scan(fake_pdf, mime_type="text/x-shellscript")

    assert len(threats_pl) == 1
    assert threats_pl[0].rule_id == "MIME-SPOOF-CRITICAL"
    assert threats_pl[0].severity == Severity.CRITICAL
    assert "Wykryto plik wykonywalny" in threats_pl[0].title


def test_mime_scanner_executable_spoofing_english(tmp_path: Path) -> None:
    fake_pdf = tmp_path / "invoice.pdf"
    fake_pdf.write_text("#!/bin/bash\necho 'Malware execution'", encoding="utf-8")

    scanner = MimeScanner()

    # Skanowanie z wymuszeniem języka angielskiego
    threats_en = scanner.scan(fake_pdf, mime_type="text/x-shellscript", lang=Language.EN)

    assert len(threats_en) == 1
    assert threats_en[0].rule_id == "MIME-SPOOF-CRITICAL"
    assert threats_en[0].severity == Severity.CRITICAL
    assert "Executable file masquerading" in threats_en[0].title

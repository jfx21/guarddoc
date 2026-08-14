from pathlib import Path

from guarddoc.core.i18n import Language
from guarddoc.core.models import Severity
from guarddoc.scanners.text import TextScanner


def test_text_scanner_detects_rtlo_in_content(tmp_path: Path) -> None:
    rtlo_file = tmp_path / "notes.txt"
    rtlo_file.write_text("Normal text with hidden \u202e exe extension", encoding="utf-8")

    scanner = TextScanner()
    threats = scanner.scan(rtlo_file, lang=Language.EN)

    assert len(threats) == 1
    assert threats[0].rule_id == "TXT-UNICODE-RTLO"
    assert threats[0].severity == Severity.HIGH
    assert threats[0].scanner_name == "TextScanner"


def test_text_scanner_detects_rtlo_in_filename(tmp_path: Path) -> None:
    rtlo_name_file = tmp_path / "test_\u202egpj.exe"
    rtlo_name_file.write_text("benign content", encoding="utf-8")

    scanner = TextScanner()
    threats = scanner.scan(rtlo_name_file, lang=Language.PL)

    assert len(threats) == 1
    assert threats[0].rule_id == "TXT-UNICODE-RTLO"
    assert threats[0].severity == Severity.HIGH


def test_text_scanner_detects_shebang(tmp_path: Path) -> None:
    script_file = tmp_path / "payload.sh"
    script_file.write_text("#!/bin/bash\necho 'hello'", encoding="utf-8")

    scanner = TextScanner()
    threats = scanner.scan(script_file, lang=Language.EN)

    assert len(threats) == 1
    assert threats[0].rule_id == "TXT-SHEBANG"
    assert threats[0].severity == Severity.MEDIUM


def test_text_scanner_clean_text(tmp_path: Path) -> None:
    clean_file = tmp_path / "clean.txt"
    clean_file.write_text("Just ordinary plain text.", encoding="utf-8")

    scanner = TextScanner()
    threats = scanner.scan(clean_file, lang=Language.EN)

    assert len(threats) == 0

from pathlib import Path

from guarddoc.core.i18n import Language
from guarddoc.core.models import Severity
from guarddoc.scanners.text import TextScanner


def test_text_scanner_clean_file(tmp_path: Path) -> None:
    clean_txt = tmp_path / "normal.txt"
    clean_txt.write_text("To jest zwykły, bezpieczny dokument tekstowy.", encoding="utf-8")

    scanner = TextScanner()
    threats = scanner.scan(clean_txt, mime_type="text/plain")

    assert len(threats) == 0


def test_text_scanner_detects_rtlo(tmp_path: Path) -> None:
    # Tworzymy plik ze znakiem U+202E (Right-To-Left Override)
    rtlo_txt = tmp_path / "spoofed.txt"
    rtlo_txt.write_text("Dokument \u202etxt.exe", encoding="utf-8")

    scanner = TextScanner()
    threats = scanner.scan(rtlo_txt, mime_type="text/plain")

    high_threats = [t for t in threats if t.severity == Severity.HIGH]
    assert len(high_threats) == 1
    assert high_threats[0].rule_id == "TXT-UNICODE-RTLO"


def test_text_scanner_detects_shebang_script(tmp_path: Path) -> None:
    script_txt = tmp_path / "script.txt"
    script_txt.write_text("#!/bin/bash\nrm -rf /", encoding="utf-8")

    scanner = TextScanner()
    threats = scanner.scan(script_txt, mime_type="text/plain")

    rule_ids = [t.rule_id for t in threats]
    assert "TXT-SHEBANG" in rule_ids


def test_text_scanner_i18n_english(tmp_path: Path) -> None:
    script_txt = tmp_path / "script_en.txt"
    script_txt.write_text("#!/bin/bash\necho 'Hello'", encoding="utf-8")

    scanner = TextScanner()
    threats = scanner.scan(script_txt, mime_type="text/plain", lang=Language.EN)

    assert len(threats) == 1
    assert threats[0].rule_id == "TXT-SHEBANG"
    assert "Executable Shebang script detected" in threats[0].title

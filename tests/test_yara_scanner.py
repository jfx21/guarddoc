from pathlib import Path

from guarddoc.core.i18n import Language
from guarddoc.core.models import Severity
from guarddoc.scanners.yara_scanner import YaraScanner


def test_yara_scanner_eicar_detection(tmp_path: Path) -> None:
    # 1. Tworzymy tymczasowy katalog reguł YARA
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    rule_file = rules_dir / "eicar.yar"
    rule_file.write_text(
        """
        rule EICAR_Test {
            meta:
                description = "EICAR Test File Detected"
                severity = "CRITICAL"
            strings:
                $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
            condition:
                $eicar
        }
        """,
        encoding="utf-8",
    )

    # 2. Tworzymy plik testowy EICAR
    eicar_file = tmp_path / "eicar.com"
    eicar_file.write_text("EICAR-STANDARD-ANTIVIRUS-TEST-FILE", encoding="utf-8")

    # 3. Skanujemy plik z użyciem domyślnego języka oraz z opcjonalną flagą lang
    scanner = YaraScanner(rules_dir=rules_dir)
    threats = scanner.scan(eicar_file, mime_type="text/plain", lang=Language.PL)

    assert len(threats) == 1
    assert threats[0].rule_id == "YARA-EICAR_TEST"
    assert threats[0].severity == Severity.CRITICAL
    assert threats[0].description == "EICAR Test File Detected"


def test_yara_scanner_clean_file(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    rule_file = rules_dir / "sample.yar"
    rule_file.write_text(
        """
        rule Dummy_Rule {
            strings:
                $a = "BAD_PATTERN_XYZ"
            condition:
                $a
        }
        """,
        encoding="utf-8",
    )

    clean_file = tmp_path / "safe.txt"
    clean_file.write_text("To jest czysty plik bez złych wzorców.", encoding="utf-8")

    scanner = YaraScanner(rules_dir=rules_dir)
    threats = scanner.scan(clean_file, mime_type="text/plain")

    assert len(threats) == 0

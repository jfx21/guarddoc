from pathlib import Path

import pytest

from guarddoc.core.i18n import Language
from guarddoc.core.models import Severity
from guarddoc.scanners.yara_scanner import YARA_AVAILABLE, YaraScanner


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python is not installed")
def test_yara_scanner_matches_custom_rule(tmp_path: Path) -> None:
    # 1. Stwórz tymczasowy plik z regułą YARA
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    rule_file = rules_dir / "webshell.yar"
    rule_file.write_text(
        """
        rule WebShell_PHP {
            meta:
                title = "PHP WebShell Pattern"
                description = "Detected suspicious eval(base64_decode) construct."
                severity = "CRITICAL"
            strings:
                $eval = "eval(base64_decode("
            condition:
                $eval
        }
        """
    )

    # 2. Stwórz plik ze złośliwym payloadem
    malicious_file = tmp_path / "shell.php"
    malicious_file.write_text("<?php eval(base64_decode('payload')); ?>")

    scanner = YaraScanner(rules_dir=rules_dir)
    assert scanner.is_supported(malicious_file) is True

    threats = scanner.scan(malicious_file, lang=Language.EN)
    assert len(threats) == 1
    assert threats[0].rule_id == "YARA-WEBSHELL_PHP"
    assert threats[0].severity == Severity.CRITICAL
    assert threats[0].title == "PHP WebShell Pattern"
    assert threats[0].scanner_name == "YaraScanner"


def test_yara_scanner_handles_empty_or_missing_directory(tmp_path: Path) -> None:
    non_existent_rules = tmp_path / "missing_rules"
    scanner = YaraScanner(rules_dir=non_existent_rules)

    sample_file = tmp_path / "sample.txt"
    sample_file.write_text("hello")

    assert scanner.is_supported(sample_file) is False
    threats = scanner.scan(sample_file, lang=Language.EN)
    assert len(threats) == 0

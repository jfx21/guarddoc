from pathlib import Path
import pytest

from guarddoc.core.engine import Engine
from guarddoc.core.i18n import Language
from guarddoc.core.models import Severity, Threat
from guarddoc.scanners.base import BaseScanner


class CrashingScanner(BaseScanner):
    name = "CrashingScanner"
    description = "Simulates an unexpected parser crash"

    def scan(
        self, file_path: Path, mime_type: str = "unknown", lang: Language = Language.PL
    ) -> list[Threat]:
        raise ValueError("Corrupted byte structure")


class CleanScanner(BaseScanner):
    name = "CleanScanner"
    description = "Simulates normal scan"

    def is_supported(self, file_path: Path, mime_type: str) -> bool:
        return mime_type == "text/plain"

    def scan(
        self, file_path: Path, mime_type: str = "unknown", lang: Language = Language.PL
    ) -> list[Threat]:
        return [
            Threat(
                rule_id="RULE-001",
                scanner_name=self.name,
                title="Test Alert",
                description="Test Description",
                severity=Severity.LOW,
            )
        ]


def test_engine_raises_filenotfound_on_missing_file(tmp_path: Path) -> None:
    engine = Engine()
    missing_file = tmp_path / "non_existent.txt"
    with pytest.raises(FileNotFoundError):
        engine.scan_file(missing_file)


def test_engine_catches_scanner_crash_and_emits_threat(tmp_path: Path) -> None:
    test_file = tmp_path / "corrupt.bin"
    test_file.write_bytes(b"\x00\xff")

    engine = Engine(scanners=[CrashingScanner()])
    result = engine.scan_file(test_file, lang=Language.EN)

    assert len(result.errors) == 1
    assert "Corrupted byte structure" in result.errors[0]

    crash_threats = [
        t for t in result.threats if getattr(t, "rule_id", None) == "SCANNER-CRASH-001"
    ]
    assert len(crash_threats) == 1
    assert crash_threats[0].severity == Severity.MEDIUM
    assert "Parsing crash" in crash_threats[0].title


def test_engine_skips_unsupported_mime(tmp_path: Path) -> None:
    test_file = tmp_path / "sample.pdf"
    test_file.write_bytes(b"%PDF-1.4")

    engine = Engine(scanners=[CleanScanner()])
    result = engine.scan_file(test_file, mime_type="application/pdf")

    assert len(result.threats) == 0

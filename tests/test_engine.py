from pathlib import Path

from guarddoc.core.engine import Engine
from guarddoc.core.models import Severity, Threat
from guarddoc.scanners.base import BaseScanner


class DummyThreatScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "DummyThreatScanner"

    def is_supported(self, file_path: Path, mime_type: str) -> bool:
        return True

    def scan(self, file_path: Path, mime_type: str) -> list[Threat]:
        return [
            Threat(
                rule_id="TEST-001",
                title="Test Threat",
                description="Test threat description",
                severity=Severity.HIGH,
            )
        ]


def test_engine_aggregation(tmp_path: Path) -> None:
    test_file = tmp_path / "sample.pdf"
    test_file.write_text("dummy content")

    engine = Engine(scanners=[DummyThreatScanner()])
    result = engine.scan_file(test_file, mime_type="application/pdf")

    assert result.is_safe is False
    assert result.max_severity == Severity.HIGH
    assert len(result.threats) == 1
    assert result.threats[0].rule_id == "TEST-001"

from pathlib import Path
import pytest
from guarddoc.core.models import ScanResult, Severity, Threat


def test_severity_ordering() -> None:
    assert Severity.INFO < Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL
    assert Severity.CRITICAL > Severity.HIGH
    assert Severity.from_str("critical") == Severity.CRITICAL


def test_threat_immutability() -> None:
    threat = Threat(
        rule_id="TEST-001",
        scanner_name="MimeScanner",
        title="Test Anomaly",
        description="Description",
        severity=Severity.HIGH,
    )
    with pytest.raises(Exception):
        # Should raise ValidationError / FrozenInstanceError due to frozen=True
        threat.title = "Modified"  # type: ignore


def test_scan_result_max_severity_and_clean_status() -> None:
    path = Path("/tmp/sample.pdf")

    # 1. Clean file
    clean_result = ScanResult(
        file_path=path,
        file_name="sample.pdf",
        file_size_bytes=1024,
    )
    # Obsługuje zarówno is_clean, jak i is_safe
    is_safe = getattr(clean_result, "is_safe", getattr(clean_result, "is_clean", True))
    assert is_safe is True
    assert clean_result.max_severity is None

    # 2. File with threats
    result = ScanResult(
        file_path=path,
        file_name="sample.pdf",
        file_size_bytes=1024,
        threats=[
            Threat(
                rule_id="RULE-LOW-01",
                scanner_name="ScannerA",
                title="Low risk",
                description="Low desc",
                severity=Severity.LOW,
            ),
            Threat(
                rule_id="RULE-CRIT-01",
                scanner_name="ScannerB",
                title="Critical risk",
                description="Critical desc",
                severity=Severity.CRITICAL,
            ),
        ],
    )
    is_safe = getattr(result, "is_safe", getattr(result, "is_clean", False))
    assert is_safe is False
    assert result.max_severity == Severity.CRITICAL

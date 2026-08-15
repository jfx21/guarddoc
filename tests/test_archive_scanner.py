import zipfile
from pathlib import Path

from guarddoc.core.models import Severity
from guarddoc.scanners.archive import ArchiveScanner


def test_archive_detects_double_extension_spoof(tmp_path: Path) -> None:
    zip_path = tmp_path / "phishing.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("Invoice_2026.pdf.exe", b"MZ fake binary")

    scanner = ArchiveScanner()
    threats = scanner.scan(zip_path, mime_type="application/zip")

    assert len(threats) == 1
    assert threats[0].rule_id == "ARCHIVE-DOUBLE-EXTENSION-SPOOF"
    assert threats[0].severity == Severity.CRITICAL


def test_archive_detects_zip_slip(tmp_path: Path) -> None:
    zip_path = tmp_path / "exploit.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("../../etc/passwd", b"root:x:0:0::/root:/bin/bash")

    scanner = ArchiveScanner()
    threats = scanner.scan(zip_path, mime_type="application/zip")

    assert len(threats) == 1
    assert threats[0].rule_id == "ARCHIVE-ZIP-SLIP"
    assert threats[0].severity == Severity.CRITICAL


def test_archive_installer_is_low_severity(tmp_path: Path) -> None:
    zip_path = tmp_path / "installer.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("setup.exe", b"MZ legitimate setup binary")

    scanner = ArchiveScanner()
    threats = scanner.scan(zip_path, mime_type="application/zip")

    assert len(threats) == 1
    assert threats[0].rule_id == "ARCHIVE-CONTAINS-BINARY"
    assert threats[0].severity == Severity.LOW

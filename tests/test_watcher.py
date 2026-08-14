import os
import stat
from pathlib import Path
from unittest.mock import patch
from watchdog.events import FileCreatedEvent

from guarddoc.core.i18n import Language
from guarddoc.core.models import ScanResult, Severity, Threat
from guarddoc.watcher import DownloadFolderHandler, isolate_file


def test_isolate_file_removes_all_permissions(tmp_path: Path) -> None:
    sample_file = tmp_path / "bad.exe"
    sample_file.write_text("evil payload")

    # Give normal permissions
    os.chmod(sample_file, 0o755)
    assert os.stat(sample_file).st_mode & 0o777 != 0o000

    # Quarantine file
    isolate_file(sample_file, lang=Language.EN)
    assert stat.S_IMODE(os.stat(sample_file).st_mode) == 0o000

    # Cleanup permissions so pytest can clean tmp_path
    os.chmod(sample_file, 0o644)


def test_handler_ignores_temp_extensions(tmp_path: Path) -> None:
    temp_file = tmp_path / "download.crdownload"
    temp_file.write_text("incomplete download")

    handler = DownloadFolderHandler(quarantine=True, lang=Language.EN)

    with patch("guarddoc.watcher.scan_single_file") as mock_scan:
        event = FileCreatedEvent(str(temp_file))
        handler.on_created(event)
        mock_scan.assert_not_called()


def test_handler_quarantines_critical_threat(tmp_path: Path) -> None:
    malicious_file = tmp_path / "invoice.pdf"
    malicious_file.write_text("fake pdf")

    handler = DownloadFolderHandler(quarantine=True, lang=Language.EN)

    mock_result = ScanResult(
        file_path=malicious_file,
        threats=[
            Threat(
                rule_id="CRIT-001",
                scanner_name="MockScanner",
                title="Critical Threat",
                description="Desc",
                severity=Severity.CRITICAL,
            )
        ],
    )

    with patch("guarddoc.watcher.scan_single_file", return_value=mock_result), patch(
        "guarddoc.watcher.send_system_notification"
    ) as mock_notify, patch("guarddoc.watcher.isolate_file") as mock_isolate:
        event = FileCreatedEvent(str(malicious_file))
        handler.on_created(event)

        mock_notify.assert_called_once()
        mock_isolate.assert_called_once_with(malicious_file, lang=Language.EN)

from pathlib import Path
from unittest.mock import patch

from watchdog.events import FileCreatedEvent

from guarddoc.watcher import DownloadFolderHandler, send_system_notification


def test_send_system_notification_does_not_raise() -> None:
    """Testuje, czy wysyłanie powiadomienia nie zgłasza nieobsłużonego wyjątku."""
    with patch("subprocess.run") as mock_run:
        send_system_notification("Test Title", "Test Message")
        assert mock_run.called


def test_watcher_detects_new_malicious_file_and_quarantines(tmp_path: Path) -> None:
    """Testuje wykrycie złośliwego pliku przez watchera i odebranie uprawnień (kwarantannę)."""
    bad_file = tmp_path / "incoming_faktura.pdf"
    bad_file.write_text("#!/bin/bash\necho 'Infekcja'", encoding="utf-8")

    handler = DownloadFolderHandler(quarantine=True)

    event = FileCreatedEvent(str(bad_file))

    with patch("guarddoc.watcher.send_system_notification"):
        handler.on_created(event)

    mode = bad_file.stat().st_mode & 0o777
    assert mode == 0o000

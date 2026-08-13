from pathlib import Path
from unittest.mock import patch

from watchdog.events import FileCreatedEvent

from guarddoc.core.i18n import Language
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

    with (
        patch("guarddoc.watcher.send_system_notification") as mock_notify,
        patch("magic.from_file", return_value="text/x-shellscript"),
    ):
        handler.on_created(event)
        assert mock_notify.called

    mode = bad_file.stat().st_mode & 0o777
    assert mode == 0o000


def test_watcher_i18n_english_notification(tmp_path: Path) -> None:
    """Testuje, czy watcher z flagą lang=Language.EN generuje angielskie powiadomienia."""
    bad_file = tmp_path / "incoming_invoice.pdf"
    bad_file.write_text("#!/bin/bash\necho 'Infekcja'", encoding="utf-8")

    handler = DownloadFolderHandler(quarantine=True, lang=Language.EN)
    event = FileCreatedEvent(str(bad_file))

    with (
        patch("guarddoc.watcher.send_system_notification") as mock_notify,
        patch("magic.from_file", return_value="text/x-shellscript"),
    ):
        handler.on_created(event)

        assert mock_notify.called
        title, msg = mock_notify.call_args[0]
        assert title == "GuardDoc Security Alert"
        assert "Threat detected" in msg

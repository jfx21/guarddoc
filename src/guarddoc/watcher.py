import os
import platform
import subprocess
import time
from pathlib import Path

from rich.console import Console
from watchdog.events import FileCreatedEvent, FileSystemEventHandler
from watchdog.observers import Observer

from guarddoc.core.i18n import Language, get_text
from guarddoc.core.models import Severity
from guarddoc.core.services import build_engine, scan_single_file

console = Console()

IGNORED_EXTENSIONS = {".crdownload", ".download", ".tmp", ".part", ".filepart"}


def send_system_notification(title: str, message: str) -> None:
    """Wysyła natywne powiadomienie systemowe (macOS / Linux)."""
    current_os = platform.system()
    try:
        if current_os == "Darwin":  # macOS
            script = f'display notification "{message}" with title "{title}"'
            subprocess.run(["osascript", "-e", script], check=False)
        elif current_os == "Linux":  # Linux
            subprocess.run(["notify-send", title, message], check=False)
    except Exception as exc:  # noqa: BLE001
        console.print(
            f"[dim red]Nie udało się wysłać powiadomienia systemowego: {exc}[/dim red]",
            stderr=True,
        )


def isolate_file(file_path: Path, lang: Language = Language.PL) -> None:
    """Aplikuje kwarantannę na pliku poprzez odebranie wszystkich uprawnień odczytu i wykonania."""
    try:
        os.chmod(file_path, 0o000)
    except Exception as exc:  # noqa: BLE001
        err_msg = get_text(
            "WATCHER-ERR-QUARANTINE",
            lang=lang,
            filepath=str(file_path),
            error=str(exc),
        )
        console.print(f"[bold red]{err_msg}[/bold red]")


class DownloadFolderHandler(FileSystemEventHandler):
    """Obserwator zdarzeń w katalogu pobierania."""

    def __init__(self, quarantine: bool = True, lang: Language = Language.PL) -> None:
        super().__init__()
        self.engine = build_engine()
        self.quarantine = quarantine
        self.lang = lang

    def on_created(self, event: FileCreatedEvent) -> None:  # type: ignore[override]
        if event.is_directory:
            return

        file_path = Path(event.src_path)

        if file_path.suffix.lower() in IGNORED_EXTENSIONS:
            return

        if not file_path.exists():
            return

        new_file_msg = get_text("WATCHER-NEW-FILE", lang=self.lang, filename=file_path.name)
        console.print(f"[dim]{new_file_msg}[/dim]")

        result = scan_single_file(self.engine, file_path, lang=self.lang)

        if not result.is_safe:
            severity_val = (
                result.max_severity.value
                if isinstance(result.max_severity, Severity)
                else str(result.max_severity)
            )

            alert_title = get_text("WATCHER-ALERT-TITLE", lang=self.lang)
            alert_msg = get_text(
                "WATCHER-THREAT-MSG",
                lang=self.lang,
                severity=severity_val,
                filename=file_path.name,
            )

            console.print(f"[bold red]{alert_msg}[/bold red]")
            send_system_notification(alert_title, alert_msg)

            severity_str = str(severity_val).upper()
            if self.quarantine and severity_str in ("HIGH", "CRITICAL", "MEDIUM"):
                isolate_file(file_path, lang=self.lang)
                quarantine_msg = get_text(
                    "WATCHER-QUARANTINE", lang=self.lang, filename=file_path.name
                )
                console.print(f"[bold yellow]{quarantine_msg}[/bold yellow]")


def start_watcher(directory: Path, quarantine: bool = True, lang: Language = Language.PL) -> None:
    """Uruchamia ciągły proces obserwujący dany katalog."""
    event_handler = DownloadFolderHandler(quarantine=quarantine, lang=lang)
    observer = Observer()
    observer.schedule(event_handler, str(directory), recursive=False)

    observer.start()

    started_msg = get_text("WATCHER-STARTED", lang=lang, directory=str(directory))
    stop_hint = get_text("WATCHER-STOP-HINT", lang=lang)

    console.print(f"[bold green]{started_msg}[/bold green]")
    console.print(f"[dim]{stop_hint}[/dim]\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        stopping_msg = get_text("WATCHER-STOPPING", lang=lang)
        console.print(f"\n[yellow]{stopping_msg}[/yellow]")

    observer.join()

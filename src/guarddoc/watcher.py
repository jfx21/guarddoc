import os
import platform
import subprocess
import time
from pathlib import Path

from rich.console import Console
from watchdog.events import FileCreatedEvent, FileSystemEventHandler
from watchdog.observers import Observer

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


def isolate_file(file_path: Path) -> None:
    """Aplikuje kwarantannę na pliku poprzez odebranie wszystkich uprawnień odczytu i wykonania."""
    try:
        os.chmod(file_path, 0o000)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[bold red]Błąd nakładania kwarantanny na {file_path}:[/bold red] {exc}")


class DownloadFolderHandler(FileSystemEventHandler):
    """Obserwator zdarzeń w katalogu pobierania."""

    def __init__(self, quarantine: bool = True) -> None:
        super().__init__()
        self.engine = build_engine()
        self.quarantine = quarantine

    def on_created(self, event: FileCreatedEvent) -> None:  # type: ignore[override]
        if event.is_directory:
            return

        file_path = Path(event.src_path)

        if file_path.suffix.lower() in IGNORED_EXTENSIONS:
            return

        time.sleep(1.0)

        if not file_path.exists():
            return

        console.print(f"[dim]Nowy plik w katalogu:[────────] {file_path.name}[/dim]")

        result = scan_single_file(self.engine, file_path)

        if not result.is_safe:
            msg = f"Wykryto zagrożenie ({result.max_severity}) w pliku {file_path.name}!"
            console.print(f"[bold red]⚠️  {msg}[/bold red]")

            send_system_notification("GuardDoc Security Alert", msg)

            if self.quarantine and result.max_severity in (
                Severity.HIGH,
                Severity.CRITICAL,
            ):
                isolate_file(file_path)
                console.print(
                    f"[bold yellow]🔒 Nałożono kwarantannę (chmod 000) na plik:[/bold yellow] {file_path.name}"
                )


def start_watcher(directory: Path, quarantine: bool = True) -> None:
    """Uruchamia ciągły proces obserwujący dany katalog."""
    event_handler = DownloadFolderHandler(quarantine=quarantine)
    observer = Observer()
    observer.schedule(event_handler, str(directory), recursive=False)

    observer.start()
    console.print(
        f"[bold green]✓ GuardDoc Daemon uruchomiony.[/bold green] Obserwacja katalogu: [cyan]{directory}[/cyan]"
    )
    console.print("[dim]Naciśnij Ctrl+C, aby zatrzymać daemona.[/dim]\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        console.print("\n[yellow]Zatrzymywanie daemona GuardDoc...[/yellow]")

    observer.join()

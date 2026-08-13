from pathlib import Path
from typing import Annotated

import magic
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from guarddoc.core.engine import Engine
from guarddoc.core.models import Severity
from guarddoc.scanners.mime import MimeScanner
from guarddoc.scanners.pdf import PdfScanner

app = typer.Typer(
    name="guarddoc",
    help="GuardDoc: File Security Analysis & Malware Triage CLI",
    add_completion=False,
)
console = Console()


@app.command()
def scan(
    target: Annotated[Path, typer.Argument(help="Ścieżka do pliku do przeskanowania")],
) -> None:
    """Skanuje podany plik pod kątem zagrożeń i podrobionych rozszerzeń."""
    if not target.exists():
        console.print(f"[bold red]Błąd:[/bold red] Plik '{target}' nie istnieje.")
        raise typer.Exit(code=1)

    # Inicjalizacja silnika i rejestracja skanerów
    engine = Engine()
    engine.register_scanner(MimeScanner())
    engine.register_scanner(PdfScanner())

    # Wstępne wyznaczenie MIME type
    detected_mime = magic.from_file(str(target), mime=True)

    # Uruchomienie skanowania
    result = engine.scan_file(target, mime_type=detected_mime)

    # Wizualizacja wyników w terminalu
    info_table = Table(title="Metadane Pliku", show_header=True)
    info_table.add_column("Właściwość", style="cyan")
    info_table.add_column("Wartość", style="bold white")

    info_table.add_row("Ścieżka", str(result.file_path))
    info_table.add_row("Rozmiar", f"{result.file_size_bytes / 1024:.2f} KB")
    info_table.add_row("MIME Type (Magic Bytes)", result.mime_type)

    console.print(info_table)
    console.print()

    if result.is_safe:
        console.print(
            Panel(
                "[bold green]✓ Brak wykrytych zagrożeń ani podejrzanych obiektów.[/bold green]",
                title="Status Bezpieczeństwa",
                border_style="green",
            )
        )
    else:
        threat_details = []
        for threat in result.threats:
            color = "red" if threat.severity in (Severity.CRITICAL, Severity.HIGH) else "yellow"
            threat_details.append(
                f"• [{color}][{threat.severity}][/{color}] [bold]{threat.title}[/bold]\n  {threat.description}"
            )

        panel_text = "\n\n".join(threat_details)
        console.print(
            Panel(
                panel_text,
                title=f"[bold red] DETEKCJA ZAGROŻEŃ (Max Severity: {result.max_severity})[/bold red]",
                border_style="red",
            )
        )


if __name__ == "__main__":
    app()

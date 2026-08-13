import json
from pathlib import Path
from typing import Annotated

import magic
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from guarddoc.core.engine import Engine
from guarddoc.core.models import ScanResult, Severity
from guarddoc.scanners.mime import MimeScanner
from guarddoc.scanners.pdf import PdfScanner
from guarddoc.scanners.text import TextScanner
from guarddoc.scanners.yara_scanner import YaraScanner

app = typer.Typer(
    name="guarddoc",
    help="GuardDoc: File Security Analysis & Malware Triage CLI",
    add_completion=False,
)
console = Console()


def build_engine() -> Engine:
    """Tworzy i konfiguruje silnik ze wszystkimi skanerami."""
    engine = Engine()
    engine.register_scanner(MimeScanner())
    engine.register_scanner(PdfScanner())
    engine.register_scanner(TextScanner())
    engine.register_scanner(YaraScanner(rules_dir="rules"))
    return engine


def scan_single_file(engine: Engine, file_path: Path) -> ScanResult:
    """Skanuje pojedynczy plik."""
    try:
        detected_mime = magic.from_file(str(file_path), mime=True)
    except Exception:  # noqa: BLE001 - domyślny fallback przy błędzie libmagic
        detected_mime = "unknown"

    return engine.scan_file(file_path, mime_type=detected_mime)


@app.command()
def scan(
    target: Annotated[Path, typer.Argument(help="Ścieżka do pliku lub katalogu do przeskanowania")],
    recursive: Annotated[
        bool, typer.Option("--recursive", "-r", help="Skanuj katalogi rekurencyjnie")
    ] = False,
    json_output: Annotated[
        bool, typer.Option("--json", "-j", help="Formatuj wynik jako JSON")
    ] = False,
    output_file: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Ścieżka do pliku, w którym zostanie zapisany raport"),
    ] = None,
) -> None:
    """Skanuje plik lub katalog pod kątem zagrożeń, niebezpiecznych obiektów i podszywania się pod rozszerzenia."""
    if not target.exists():
        console.print(f"[bold red]Błąd:[/bold red] Ścieżka '{target}' nie istnieje.")
        raise typer.Exit(code=1)

    engine = build_engine()
    results: list[ScanResult] = []

    # 1. Zbiorcza lista plików do przeskanowania
    if target.is_file():
        files_to_scan = [target]
    elif target.is_dir():
        pattern = "**/*" if recursive else "*"
        files_to_scan = [p for p in target.glob(pattern) if p.is_file()]
    else:
        console.print(
            f"[bold red]Błąd:[/bold red] Ścieżka '{target}' nie jest plikiem ani katalogiem."
        )
        raise typer.Exit(code=1)

    if not files_to_scan:
        console.print(
            "[bold yellow]Ostrzeżenie:[/bold yellow] Nie znaleziono żadnych plików do przeskanowania."
        )
        raise typer.Exit(code=0)

    # 2. Wykonanie skanowania
    for file_path in files_to_scan:
        res = scan_single_file(engine, file_path)
        results.append(res)

    # 3. Format wyjściowy JSON
    if json_output or output_file:
        export_data = [res.model_dump(mode="json") for res in results]
        json_str = json.dumps(export_data, indent=2, ensure_ascii=False)

        if output_file:
            output_file.write_text(json_str, encoding="utf-8")
            if not json_output:
                console.print(
                    f"[bold green]✓ Raport z analizy został zapisany do pliku:[/bold green] {output_file}"
                )

        if json_output:
            print(json_str)
            return

    # 4. Format wizualny w terminalu (Rich Console)
    if len(results) == 1 and target.is_file():
        _render_single_result(results[0])
    else:
        _render_batch_results(results, target)


def _render_single_result(result: ScanResult) -> None:
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
                "[bold green]✓ Brak wykrytych zagrożeń ani podejrzanych znaków/skryptów.[/bold green]",
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
                title=f"[bold red]⚠️ DETEKCJA ZAGROŻEŃ (Max Severity: {result.max_severity})[/bold red]",
                border_style="red",
            )
        )


def _render_batch_results(results: list[ScanResult], target: Path) -> None:
    summary_table = Table(title=f"Wyniki skanowania katalogu: {target}", show_header=True)
    summary_table.add_column("Plik", style="bold white")
    summary_table.add_column("MIME", style="cyan")
    summary_table.add_column("Status", style="bold")
    summary_table.add_column("Max Severity", style="bold")
    summary_table.add_column("Liczba Detekcji", justify="right")

    unsafe_count = 0

    for res in results:
        if res.is_safe:
            status_str = "[green]BEZPIECZNY[/green]"
            sev_str = "[dim]NONE[/dim]"
        else:
            unsafe_count += 1
            status_str = "[red]ZAGROŻENIE[/red]"
            color = "red" if res.max_severity in (Severity.CRITICAL, Severity.HIGH) else "yellow"
            sev_str = f"[{color}]{res.max_severity}[/{color}]"

        summary_table.add_row(
            res.file_name,
            res.mime_type,
            status_str,
            sev_str,
            str(len(res.threats)),
        )

    console.print(summary_table)
    console.print()

    total = len(results)
    if unsafe_count > 0:
        console.print(
            f"[bold red]⚠️ Wykryto podejrzane pliki: {unsafe_count} z {total} przeanalizowanych.[/bold red]"
        )
    else:
        console.print(
            f"[bold green]✓ Przeanalizowano {total} plików. Brak wykrytych zagrożeń.[/bold green]"
        )


if __name__ == "__main__":
    app()

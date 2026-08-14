from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, List, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from guarddoc.core.i18n import Language
from guarddoc.core.models import ScanResult, Severity
from guarddoc.core.services import build_engine, scan_single_file
from guarddoc.watcher import start_watcher

app = typer.Typer(
    name="guarddoc",
    help="GuardDoc: File Security Analysis & Malware Triage CLI",
    add_completion=False,
)
console = Console()


@app.command()
def scan(
    target: Annotated[
        Path,
        typer.Argument(help="Target file or directory path to analyze"),
    ],
    recursive: Annotated[
        bool,
        typer.Option(
            "-r",
            "--recursive",
            help="Scan directories recursively",
        ),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Format output as JSON"),
    ] = False,
    output: Annotated[
        Optional[Path],
        typer.Option("-o", "--output", help="Save report to specified output path"),
    ] = None,
    lang: Annotated[
        Language,
        typer.Option("-l", "--lang", help="Report and message language (pl/en)"),
    ] = Language.PL,
) -> None:
    """Scans a file or directory for threats and suspicious patterns."""
    if not target.exists():
        err_msg = (
            f"Ścieżka '{target}' nie istnieje."
            if lang == Language.PL
            else f"Path '{target}' does not exist."
        )
        console.print(f"[bold red]Błąd / Error:[/bold red] {err_msg}")
        raise typer.Exit(code=1)

    engine = build_engine()
    results: List[ScanResult] = []

    if target.is_file():
        results.append(scan_single_file(engine, target, lang=lang))
    elif target.is_dir():
        pattern = "**/*" if recursive else "*"
        for path in sorted(target.glob(pattern)):
            if path.is_file():
                results.append(scan_single_file(engine, path, lang=lang))

    if json_output:
        json_data = [r.model_dump(mode="json") for r in results]
        json_str = json.dumps(json_data, indent=2, ensure_ascii=False)

        if output:
            output.write_text(json_str, encoding="utf-8")
            saved_msg = (
                f"Raport JSON zapisany w: {output}"
                if lang == Language.PL
                else f"JSON report saved to: {output}"
            )
            console.print(f"[bold green]{saved_msg}[/bold green]")
        else:
            console.print_json(json_str)
    else:
        if len(results) == 1:
            _render_single_result(results[0], lang=lang)
        else:
            _render_batch_results(results, target, lang=lang)


def _render_single_result(result: ScanResult, lang: Language = Language.PL) -> None:
    """Renders scan details for a single target file."""
    title_meta = "Metadane Pliku" if lang == Language.PL else "File Metadata"
    col_prop = "Właściwość" if lang == Language.PL else "Property"
    col_val = "Wartość" if lang == Language.PL else "Value"

    info_table = Table(title=title_meta, show_header=True)
    info_table.add_column(col_prop, style="cyan")
    info_table.add_column(col_val, style="bold white")

    label_path = "Ścieżka" if lang == Language.PL else "Path"
    label_size = "Rozmiar" if lang == Language.PL else "Size"

    size_display = (
        f"{result.file_size_bytes / 1024:.2f} KB" if result.file_size_bytes is not None else "N/A"
    )

    info_table.add_row(label_path, str(result.file_path))
    info_table.add_row(label_size, size_display)
    info_table.add_row("MIME Type (Magic Bytes)", str(result.mime_type or "unknown"))
    if getattr(result, "sha256", None):
        info_table.add_row("SHA-256", str(result.sha256))

    console.print(info_table)
    console.print()

    # Support both is_safe and is_clean
    is_safe = getattr(result, "is_safe", getattr(result, "is_clean", len(result.threats) == 0))

    if is_safe:
        status_title = "Status Bezpieczeństwa" if lang == Language.PL else "Security Status"
        safe_msg = (
            "✓ Brak wykrytych zagrożeń ani podejrzanych znaków/skryptów."
            if lang == Language.PL
            else "✓ No threats or suspicious characters/scripts detected."
        )
        console.print(
            Panel(
                f"[bold green]{safe_msg}[/bold green]",
                title=status_title,
                border_style="green",
            )
        )
    else:
        threat_details = []
        for threat in result.threats:
            color = "red" if threat.severity in (Severity.CRITICAL, Severity.HIGH) else "yellow"
            sev_name = (
                threat.severity.name if hasattr(threat.severity, "name") else str(threat.severity)
            )
            threat_details.append(
                f"• [{color}][{sev_name}][/{color}] [bold]{threat.title}[/bold]\n  {threat.description}"
            )

        panel_text = "\n\n".join(threat_details)
        max_sev_name = (
            result.max_severity.name
            if hasattr(result.max_severity, "name")
            else str(result.max_severity)
        )
        panel_title = (
            f"DETEKCJA ZAGROŻEŃ (Max Severity: {max_sev_name})"
            if lang == Language.PL
            else f"THREAT DETECTION (Max Severity: {max_sev_name})"
        )
        console.print(
            Panel(
                panel_text,
                title=f"[bold red]{panel_title}[/bold red]",
                border_style="red",
            )
        )


def _render_batch_results(
    results: List[ScanResult], target: Path, lang: Language = Language.PL
) -> None:
    """Renders summary table for directory batch scanning."""
    table_title = (
        f"Wyniki skanowania katalogu: {target}"
        if lang == Language.PL
        else f"Directory scan results: {target}"
    )
    col_file = "Plik" if lang == Language.PL else "File"
    col_status = "Status"
    col_count = "Liczba Detekcji" if lang == Language.PL else "Detections Count"

    summary_table = Table(title=table_title, show_header=True)
    summary_table.add_column(col_file, style="bold white")
    summary_table.add_column("MIME", style="cyan")
    summary_table.add_column(col_status, style="bold")
    summary_table.add_column("Max Severity", style="bold")
    summary_table.add_column(col_count, justify="right")

    unsafe_count = 0

    for res in results:
        is_safe = getattr(res, "is_safe", getattr(res, "is_clean", len(res.threats) == 0))
        file_name = getattr(res, "file_name", res.file_path.name)
        mime_type = str(res.mime_type or "unknown")

        if is_safe:
            status_str = (
                "[green]BEZPIECZNY[/green]" if lang == Language.PL else "[green]SAFE[/green]"
            )
            sev_str = "[dim]NONE[/dim]"
        else:
            unsafe_count += 1
            status_str = "[red]ZAGROŻENIE[/red]" if lang == Language.PL else "[red]THREAT[/red]"
            color = "red" if res.max_severity in (Severity.CRITICAL, Severity.HIGH) else "yellow"
            sev_name = (
                res.max_severity.name
                if hasattr(res.max_severity, "name")
                else str(res.max_severity)
            )
            sev_str = f"[{color}]{sev_name}[/{color}]"

        summary_table.add_row(
            file_name,
            mime_type,
            status_str,
            sev_str,
            str(len(res.threats)),
        )

    console.print(summary_table)
    console.print()

    total = len(results)
    if unsafe_count > 0:
        msg = (
            f"Wykryto podejrzane pliki: {unsafe_count} z {total} przeanalizowanych."
            if lang == Language.PL
            else f"Suspicious files detected: {unsafe_count} out of {total} analyzed."
        )
        console.print(f"[bold red]{msg}[/bold red]")
    else:
        msg = (
            f"Przeanalizowano {total} plików. Brak wykrytych zagrożeń."
            if lang == Language.PL
            else f"Analyzed {total} files. No threats detected."
        )
        console.print(f"[bold green]✓ {msg}[/bold green]")


@app.command()
def watch(
    directory: Annotated[
        Optional[Path],
        typer.Argument(help="Directory to watch in background (default ~/Downloads)"),
    ] = None,
    quarantine: Annotated[
        bool,
        typer.Option(
            "--quarantine/--no-quarantine",
            help="Automatically quarantine (chmod 000) malicious files",
        ),
    ] = True,
    lang: Annotated[
        Language,
        typer.Option("-l", "--lang", help="Language for notifications and alerts (pl/en)"),
    ] = Language.PL,
) -> None:
    """Runs a background filesystem daemon watching for incoming files."""
    target_dir = directory or (Path.home() / "Downloads")

    if not target_dir.exists() or not target_dir.is_dir():
        err_msg = (
            f"Katalog '{target_dir}' nie istnieje."
            if lang == Language.PL
            else f"Directory '{target_dir}' does not exist."
        )
        console.print(f"[bold red]Błąd / Error:[/bold red] {err_msg}")
        raise typer.Exit(code=1)

    start_watcher(target_dir, quarantine=quarantine, lang=lang)


if __name__ == "__main__":
    app()

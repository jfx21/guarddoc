from __future__ import annotations

import json
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from guarddoc.core.config import AppConfig, get_config_path
from guarddoc.core.i18n import Language
from guarddoc.core.models import ScanResult, Severity
from guarddoc.core.services import build_engine, scan_single_file
from guarddoc.watcher import start_watcher

HELP_DESCRIPTION = """
[bold cyan]GuardDoc[/bold cyan] is a lightweight, local file security analyzer and malware triage CLI tool.
It inspects document byte patterns, detects MIME spoofing, scans macros, and applies YARA rules.
"""

HELP_EPILOG = """
[bold yellow]Common Examples:[/bold yellow]
  • Scan a single file:
    [green]$ guarddoc scan /path/to/invoice.pdf[/green]

  • Scan a folder recursively and output JSON:
    [green]$ guarddoc scan ~/Downloads -r --json -o report.json[/green]

  • Scan in English / Polish:
    [green]$ guarddoc scan invoice.pdf --lang en[/green]

  • Monitor ~/Downloads in the background with auto-quarantine:
    [green]$ guarddoc watch ~/Downloads --quarantine[/green]

  • Configure persistent settings:
    [green]$ guarddoc config set --lang en[/green]

[dim]For detailed options of a specific command, run:[/dim]
  [green]$ guarddoc scan --help[/green]
  [green]$ guarddoc watch --help[/green]
"""

app = typer.Typer(
    name="guarddoc",
    help=HELP_DESCRIPTION,
    epilog=HELP_EPILOG,
    no_args_is_help=True,
    rich_markup_mode="rich",
    add_completion=False,
)

config_app = typer.Typer(help="Manage GuardDoc persistent configuration.")
app.add_typer(config_app, name="config")

console = Console()


def get_app_version() -> str:
    try:
        return version("guarddoc")
    except PackageNotFoundError:
        return "0.1.0-dev"


def version_callback(value: bool) -> None:
    if value:
        console.print("[bold cyan]GuardDoc[/bold cyan] version [bold green]{app_ver}[/bold green]")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool | None,
        typer.Option(
            "--version",
            "-v",
            help="Show the application version and exit.",
            callback=version_callback,
            is_eager=True,
        ),
    ] = None,
) -> None:
    """GuardDoc: Local Security Analysis & Malware Triage Tool."""


@app.command(
    help="Scans a file or directory for malicious byte patterns, macros, and anomalies.",
    epilog="[dim]Example: guarddoc scan samples/ -r --json[/dim]",
)
def scan(
    target: Annotated[
        Path,
        typer.Argument(
            help="Target file or directory path to analyze",
            show_default=False,
        ),
    ],
    recursive: Annotated[
        bool,
        typer.Option(
            "-r",
            "--recursive",
            help="Scan directories recursively.",
        ),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            help="Format scan output as structured JSON to stdout.",
        ),
    ] = False,
    output: Annotated[
        Path | None,
        typer.Option(
            "-o",
            "--output",
            help="Save the scan report directly to a file (JSON format).",
        ),
    ] = None,
    rules_dir: Annotated[
        Path | None,
        typer.Option(
            "--rules-dir",
            help="Custom directory containing YARA rules (.yar/.yara).",
        ),
    ] = None,
    lang: Annotated[
        str | None,
        typer.Option(
            "-l",
            "--lang",
            help="Report and message language (pl/en). Defaults to config value.",
        ),
    ] = None,
) -> None:
    """Scans a file or directory for threats and suspicious patterns."""
    cfg = AppConfig.load()

    # Determine language preference: CLI argument > Saved config
    if lang is not None:
        selected_lang = Language.EN if lang.lower().strip() == "en" else Language.PL
    else:
        selected_lang = cfg.lang

    effective_rules_dir = rules_dir or Path(cfg.rules_dir)

    if not target.exists():
        err_msg = (
            f"Ścieżka '{target}' nie istnieje."
            if selected_lang == Language.PL
            else f"Path '{target}' does not exist."
        )
        console.print(f"[bold red]Błąd / Error:[/bold red] {err_msg}")
        raise typer.Exit(code=1)

    engine = build_engine(rules_dir=effective_rules_dir)
    results: list[ScanResult] = []

    if target.is_file():
        results.append(scan_single_file(engine, target, lang=selected_lang))
    elif target.is_dir():
        pattern = "**/*" if recursive else "*"
        for path in sorted(target.glob(pattern)):
            if path.is_file():
                results.append(scan_single_file(engine, path, lang=selected_lang))

    if json_output or output:
        json_data = [r.model_dump(mode="json") for r in results]
        json_str = json.dumps(json_data, indent=2, ensure_ascii=False)

        if output:
            output.write_text(json_str, encoding="utf-8")
            saved_msg = (
                f"Raport JSON zapisany w: {output}"
                if selected_lang == Language.PL
                else f"JSON report saved to: {output}"
            )
            console.print(f"[bold green]{saved_msg}[/bold green]")
        else:
            console.print_json(json_str)
    else:
        if len(results) == 1:
            _render_single_result(results[0], lang=selected_lang)
        else:
            _render_batch_results(results, target, lang=selected_lang)


def _render_single_result(result: ScanResult, lang: Language = Language.PL) -> None:
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
    results: list[ScanResult], target: Path, lang: Language = Language.PL
) -> None:
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


@app.command(
    help="Runs a background daemon watching a folder for new incoming files.",
    epilog="[dim]Example: guarddoc watch ~/Downloads --quarantine[/dim]",
)
def watch(
    directory: Annotated[
        Path | None,
        typer.Argument(help="Directory to watch in background (default: ~/Downloads)"),
    ] = None,
    quarantine: Annotated[
        bool,
        typer.Option(
            "--quarantine/--no-quarantine",
            help="Automatically quarantine (chmod 000) malicious files.",
        ),
    ] = True,
    lang: Annotated[
        str | None,
        typer.Option(
            "-l",
            "--lang",
            help="Language for notifications and alerts (pl/en). Defaults to config.",
        ),
    ] = None,
) -> None:
    """Runs a background filesystem daemon watching for incoming files."""
    cfg = AppConfig.load()
    selected_lang = (
        (Language.EN if lang.lower().strip() == "en" else Language.PL)
        if lang is not None
        else cfg.lang
    )

    target_dir = directory or (Path.home() / "Downloads")

    if not target_dir.exists() or not target_dir.is_dir():
        err_msg = (
            f"Katalog '{target_dir}' nie istnieje."
            if selected_lang == Language.PL
            else f"Directory '{target_dir}' does not exist."
        )
        console.print(f"[bold red]Błąd / Error:[/bold red] {err_msg}")
        raise typer.Exit(code=1)

    start_watcher(target_dir, quarantine=quarantine, lang=selected_lang)


@config_app.command(name="show")
def config_show() -> None:
    """Show current configuration and file path."""
    cfg = AppConfig.load()
    console.print(f"[bold cyan]Config file:[/bold cyan] {get_config_path()}")
    console.print(f"  [bold]Language (lang):[/bold] {cfg.lang.value}")
    console.print(f"  [bold]Rules Directory:[/bold] {cfg.rules_dir}")


@config_app.command(name="set")
def config_set(
    lang: Annotated[
        str | None,
        typer.Option("--lang", "-l", help="Default language (pl / en)"),
    ] = None,
    rules_dir: Annotated[
        str | None,
        typer.Option("--rules-dir", help="Default YARA rules directory"),
    ] = None,
) -> None:
    """Update and save persistent configuration settings."""
    cfg = AppConfig.load()

    if lang is not None:
        selected_lang = lang.lower().strip()
        if selected_lang not in ("pl", "en"):
            console.print("[red]Error:[/red] Supported languages are 'pl' and 'en'.")
            raise typer.Exit(1)
        cfg.lang = Language.EN if selected_lang == "en" else Language.PL

    if rules_dir is not None:
        cfg.rules_dir = rules_dir

    cfg.save()
    console.print(f"[green]✓[/green] Configuration saved to [bold]{get_config_path()}[/bold]")


if __name__ == "__main__":
    app()

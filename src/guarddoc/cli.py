from __future__ import annotations

import json
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Annotated

import typer

from guarddoc.core.config import AppConfig, get_config_path
from guarddoc.core.i18n import Language
from guarddoc.core.models import ScanResult
from guarddoc.core.services import build_engine, scan_single_file
from guarddoc.views import console, render_batch_results, render_single_result
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


def get_app_version() -> str:
    try:
        return version("guarddoc")
    except PackageNotFoundError:
        return "0.1.0-dev"


def version_callback(value: bool) -> None:
    if value:
        app_ver = get_app_version()
        console.print(f"[bold cyan]GuardDoc[/bold cyan] version [bold green]{app_ver}[/bold green]")
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
    selected_lang = (
        (Language.EN if lang.lower().strip() == "en" else Language.PL)
        if lang is not None
        else cfg.lang
    )

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
        if len(results) == 1 and target.is_file():
            render_single_result(results[0], lang=selected_lang)
        else:
            render_batch_results(results, target, lang=selected_lang)


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
        typer.Option("-l", "--lang", help="Default language (pl / en)"),
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

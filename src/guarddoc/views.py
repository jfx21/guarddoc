from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from guarddoc.core.i18n import Language
from guarddoc.core.models import ScanResult, Severity

console = Console()


def render_single_result(result: ScanResult, lang: Language = Language.PL) -> None:
    """Renders detailed metadata and threat detection panels for a single file."""
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


def render_batch_results(
    results: list[ScanResult], target: Path, lang: Language = Language.PL
) -> None:
    """Renders tabular summary for directory scan results."""
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

from __future__ import annotations

from pathlib import Path

from guarddoc.core.i18n import Language
from guarddoc.core.models import ScanResult, Severity, Threat
from guarddoc.scanners.base import BaseScanner


class Engine:
    """Engine orchestrating scanner execution over a target file."""

    def __init__(self, scanners: list[BaseScanner] | None = None) -> None:
        self.scanners: list[BaseScanner] = scanners or []

    def register_scanner(self, scanner: BaseScanner) -> None:
        """Registers a new scanner module in the engine."""
        self.scanners.append(scanner)

    def scan_file(
        self,
        file_path: Path,
        mime_type: str = "unknown",
        lang: Language = Language.PL,
    ) -> ScanResult:
        """Executes a full scan on the target file using registered scanners with i18n support."""
        resolved_path = file_path.resolve()

        if not resolved_path.exists() or not resolved_path.is_file():
            raise FileNotFoundError(f"File does not exist or is not a regular file: {file_path}")

        result = ScanResult(
            file_path=resolved_path,
            file_name=resolved_path.name,
            file_size_bytes=resolved_path.stat().st_size,
            mime_type=mime_type,
        )

        for scanner in self.scanners:
            # Check if scanner dependencies are met
            if hasattr(scanner, "is_available") and not scanner.is_available:
                continue

            # Check if scanner supports this file/mime type
            is_supported_fn = getattr(scanner, "is_supported", None)
            if callable(is_supported_fn) and not is_supported_fn(resolved_path, mime_type):
                continue

            try:
                # Call scan method
                detected_threats = scanner.scan(resolved_path, mime_type=mime_type, lang=lang)  # type: ignore[call-arg]
                for threat in detected_threats:
                    if hasattr(result, "add_threat"):
                        result.add_threat(threat)
                    else:
                        result.threats.append(threat)

            except Exception as exc:  # noqa: BLE001
                scanner_name = getattr(scanner, "name", scanner.__class__.__name__)
                error_msg = f"Error in scanner [{scanner_name}]: {exc!s}"
                result.errors.append(error_msg)

                crash_title = (
                    f"Awaria parsowania w module {scanner_name}"
                    if lang == Language.PL
                    else f"Parsing crash in {scanner_name} module"
                )
                crash_desc = (
                    "Plik spowodował nieobsłużony błąd skanera. Może to świadczyć o próbie uszkodzenia parsera (Exploit/Malformed Structure)."
                    if lang == Language.PL
                    else "File caused an unhandled scanner error. This may indicate an attempt to exploit the parser (Exploit/Malformed Structure)."
                )

                crash_threat = Threat(
                    rule_id="SCANNER-CRASH-001",
                    title=crash_title,
                    description=crash_desc,
                    severity=Severity.MEDIUM,
                    context={"error": str(exc)},
                    scanner_name=scanner_name,
                )

                if hasattr(result, "add_threat"):
                    result.add_threat(crash_threat)
                else:
                    result.threats.append(crash_threat)

        return result

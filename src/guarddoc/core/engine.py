from pathlib import Path

from guarddoc.core.i18n import Language
from guarddoc.core.models import ScanResult, Severity, Threat
from guarddoc.scanners.base import BaseScanner


class Engine:
    """Silnik orkiestrujący pracę skanerów na wskazanym pliku."""

    def __init__(self, scanners: list[BaseScanner] | None = None) -> None:
        self.scanners: list[BaseScanner] = scanners or []

    def register_scanner(self, scanner: BaseScanner) -> None:
        """Rejestruje nowy moduł skanujący w silniku."""
        self.scanners.append(scanner)

    def scan_file(
        self,
        file_path: Path,
        mime_type: str = "unknown",
        lang: Language = Language.PL,
    ) -> ScanResult:
        """Wykonuje pełne skanowanie pliku przy użyciu zarejestrowanych skanerów z opcją i18n."""
        resolved_path = file_path.resolve()

        if not resolved_path.exists() or not resolved_path.is_file():
            raise FileNotFoundError(
                f"Plik nie istnieje lub nie jest plikiem regularnym: {file_path}"
            )

        result = ScanResult(
            file_path=resolved_path,
            file_name=resolved_path.name,
            file_size_bytes=resolved_path.stat().st_size,
            mime_type=mime_type,
        )

        for scanner in self.scanners:
            is_supported_fn = getattr(scanner, "is_supported", None)
            if callable(is_supported_fn) and not is_supported_fn(resolved_path, mime_type):
                continue

            try:
                detected_threats = scanner.scan(resolved_path, mime_type, lang=lang)
                for threat in detected_threats:
                    result.add_threat(threat)
            except Exception as exc:  # noqa: BLE001
                scanner_name = getattr(scanner, "name", scanner.__class__.__name__)
                error_msg = f"Błąd w skanerze [{scanner_name}]: {exc!s}"
                result.errors.append(error_msg)

                crash_title = (
                    f"Awaria parsowania w module {scanner.name}"
                    if lang == Language.PL
                    else f"Parsing crash in {scanner.name} module"
                )
                crash_desc = (
                    "Plik spowodował nieobsłużony błąd skanera. Może to świadczyć o próbie uszkodzenia parsera (Exploit/Malformed Structure)."
                    if lang == Language.PL
                    else "File caused an unhandled scanner error. This may indicate an attempt to exploit the parser (Exploit/Malformed Structure)."
                )

                result.add_threat(
                    Threat(
                        rule_id="SCANNER-CRASH-001",
                        title=crash_title,
                        description=crash_desc,
                        severity=Severity.MEDIUM,
                        context={"error": str(exc)},
                    )
                )

        return result

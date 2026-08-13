from pathlib import Path

from guarddoc.core.models import ScanResult, Severity, Threat
from guarddoc.scanners.base import BaseScanner


class Engine:
    """Silnik orkiestrujący pracę skanerów na wskazanym pliku."""

    def __init__(self, scanners: list[BaseScanner] | None = None) -> None:
        self.scanners: list[BaseScanner] = scanners or []

    def register_scanner(self, scanner: BaseScanner) -> None:
        """Rejestruje nowy moduł skanujący w silniku."""
        self.scanners.append(scanner)

    def scan_file(self, file_path: Path, mime_type: str = "unknown") -> ScanResult:
        """Wykonuje pełne skanowanie pliku przy użyciu zarejestrowanych skanerów."""
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
            if not scanner.is_supported(resolved_path, mime_type):
                continue

            try:
                detected_threats = scanner.scan(resolved_path, mime_type)
                for threat in detected_threats:
                    result.add_threat(threat)
            except Exception as exc:  # noqa: BLE001 - celowe wyłapywanie dowolnej awarii zewnętrznego parsera
                error_msg = f"Błąd w skanerze [{scanner.name}]: {exc!s}"
                result.errors.append(error_msg)
                result.add_threat(
                    Threat(
                        rule_id="SCANNER-CRASH-001",
                        title=f"Awaria parsowania w module {scanner.name}",
                        description="Plik spowodował nieobsłużony błąd skanera. Może to świadczyć o próbie uszkodzenia parsera (Exploit/Malformed Structure).",
                        severity=Severity.MEDIUM,
                        context={"error": str(exc)},
                    )
                )

        return result

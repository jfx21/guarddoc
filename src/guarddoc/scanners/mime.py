from pathlib import Path

import magic

from guarddoc.core.models import Severity, Threat
from guarddoc.scanners.base import BaseScanner

ALLOWED_MIME_MAP: dict[str, set[str]] = {
    ".pdf": {"application/pdf"},
    ".txt": {"text/plain"},
    ".csv": {"text/csv", "text/plain"},
    ".json": {"application/json", "text/plain"},
    ".xml": {"text/xml", "application/xml", "text/plain"},
    ".png": {"image/png"},
    ".jpg": {"image/jpeg"},
    ".jpeg": {"image/jpeg"},
}

DANGEROUS_EXECUTABLE_MIMES: set[str] = {
    "application/x-executable",
    "application/x-mach-binary",
    "application/x-dosexec",
    "application/x-sharedlib",
    "application/x-sh",
    "text/x-shellscript",
    "application/x-python-code",
}


class MimeScanner(BaseScanner):
    """Skaner weryfikujący zgodność typu nagłówka pliku (Magic Bytes) z jego rozszerzeniem."""

    @property
    def name(self) -> str:
        return "MimeScanner"

    def is_supported(self, file_path: Path, mime_type: str) -> bool:
        return True

    def scan(self, file_path: Path, mime_type: str) -> list[Threat]:
        threats: list[Threat] = []
        extension = file_path.suffix.lower()

        try:
            detected_mime = magic.from_file(str(file_path), mime=True)
            detected_desc = magic.from_file(str(file_path), mime=False)
        except Exception as exc:  # noqa: BLE001 - wyłapujemy błędy odczytu biblioteki libmagic
            threats.append(
                Threat(
                    rule_id="MIME-MAGIC-ERR",
                    title="Błąd analizy bajtów nagłówkowych",
                    description="Nie udało się odczytać struktury Magic Bytes pliku.",
                    severity=Severity.LOW,
                    context={"error": str(exc)},
                )
            )
            return threats

        if extension in ALLOWED_MIME_MAP and detected_mime in DANGEROUS_EXECUTABLE_MIMES:
            threats.append(
                Threat(
                    rule_id="MIME-SPOOF-CRITICAL",
                    title="Wykryto plik wykonywalny podszywający się pod dokument!",
                    description=(
                        f"Plik ma rozszerzenie '{extension}', ale jego wewnętrzna struktura "
                        f"to plik wykonywalny/skrypt ({detected_mime}). Jest to wysoce prawdopodobna próba infekcji."
                    ),
                    severity=Severity.CRITICAL,
                    context={
                        "extension": extension,
                        "detected_mime": detected_mime,
                        "description": detected_desc,
                    },
                )
            )
            return threats

        if extension in ALLOWED_MIME_MAP:
            allowed_set = ALLOWED_MIME_MAP[extension]
            if detected_mime not in allowed_set:
                threats.append(
                    Threat(
                        rule_id="MIME-MISMATCH-HIGH",
                        title="Niezgodność typu nagłówka z rozszerzeniem pliku",
                        description=(
                            f"Rozszerzenie '{extension}' oczekuje typu z grupy {allowed_set}, "
                            f"ale odczytano bajty odpowiadające '{detected_mime}'."
                        ),
                        severity=Severity.HIGH,
                        context={
                            "extension": extension,
                            "expected_mime": list(allowed_set),
                            "detected_mime": detected_mime,
                            "description": detected_desc,
                        },
                    )
                )

        return threats

import re
from pathlib import Path

from pypdf import PdfReader

from guarddoc.core.models import Severity, Threat
from guarddoc.scanners.base import BaseScanner

SUSPICIOUS_PDF_OBJECTS: dict[str, dict[str, str | Severity]] = {
    "/JS": {
        "title": "Wykryto obiekt JavaScript (/JS)",
        "description": "Plik PDF zawiera osadzony skrypt JavaScript. Może być użyty do eksploitacji podatności w przeglądarce PDF lub do phishingu.",
        "severity": Severity.HIGH,
    },
    "/JavaScript": {
        "title": "Wykryto deklarację /JavaScript",
        "description": "Plik wywołuje bezpośrednie akcje skryptowe JavaScript.",
        "severity": Severity.HIGH,
    },
    "/OpenAction": {
        "title": "Wykryto automatyczną akcję (/OpenAction)",
        "description": "Dokument wykonuje określoną akcję (np. uruchomienie kodu/skryptu) natychmiast po otwarciu, bez wiedzy użytkownika.",
        "severity": Severity.HIGH,
    },
    "/AA": {
        "title": "Wykryto akcje zdarzeniowe (/AA - Additional Actions)",
        "description": "Dokument zawiera wyzwalacze akcji powiązane ze zdarzeniami (np. najechanie kursorem, zmiana strony).",
        "severity": Severity.MEDIUM,
    },
    "/Launch": {
        "title": "Wykryto próbę uruchomienia programu zewnętrznego (/Launch)",
        "description": "KRYTYCZNE: Plik próbuje uruchomić zewnętrzny program systemowy lub komendę w konsoli (np. cmd.exe, bash).",
        "severity": Severity.CRITICAL,
    },
    "/EmbeddedFiles": {
        "title": "Wykryto ukryte załączniki wewnątrz PDF (/EmbeddedFiles)",
        "description": "PDF zawiera osadzone pliki. Napastnicy często ukrywają wewnątrz pliki wykonywalne exe/scr/sh lub złośliwe pliki ZIP.",
        "severity": Severity.HIGH,
    },
    "/URI": {
        "title": "Wykryto zewnętrzne łącze URL (/URI)",
        "description": "Plik zawiera odnośnik sieciowy. Warto sprawdzić, czy nie prowadzi do stron phishingowych.",
        "severity": Severity.INFO,
    },
}


class PdfScanner(BaseScanner):
    """Skaner analizujący statyczną strukturę plików PDF pod kątem niebezpiecznych obiektów i akcji."""

    @property
    def name(self) -> str:
        return "PdfScanner"

    def is_supported(self, file_path: Path, mime_type: str) -> bool:
        return mime_type == "application/pdf" or file_path.suffix.lower() == ".pdf"

    def scan(self, file_path: Path, mime_type: str) -> list[Threat]:
        threats: list[Threat] = []

        # 1. Poziom Niskopoziomowy: Skanowanie surowych bajtów pliku (odporne na uszkodzenia nagłówków)
        try:
            with open(file_path, "rb") as f:
                raw_bytes = f.read()

            raw_text = raw_bytes.decode("latin-1", errors="ignore")

            for keyword, meta in SUSPICIOUS_PDF_OBJECTS.items():
                matches = len(re.findall(re.escape(keyword), raw_text))
                if matches > 0:
                    threats.append(
                        Threat(
                            rule_id=f"PDF-RAW-{keyword.strip('/').upper()}",
                            title=str(meta["title"]),
                            description=f"{meta['description']} (Wykryto {matches} wystąpień w kodzie pliku).",
                            severity=meta["severity"],  # type: ignore[arg-type]
                            context={"keyword": keyword, "occurrences": matches},
                        )
                    )

        except Exception as exc:  # noqa: BLE001 - celowe łapanie błędu I/O pliku
            threats.append(
                Threat(
                    rule_id="PDF-READ-ERR",
                    title="Błąd odczytu bajtów PDF",
                    description="Nie udało się otworzyć lub odczytać pliku w trybie binarnym.",
                    severity=Severity.LOW,
                    context={"error": str(exc)},
                )
            )
            return threats

        # 2. Poziom Strukturalny: Parsowanie obiektów przez PyPDF
        try:
            reader = PdfReader(str(file_path))
            num_pages = len(reader.pages)

            if reader.is_encrypted:
                threats.append(
                    Threat(
                        rule_id="PDF-ENCRYPTED",
                        title="Plik PDF jest zaszyfrowany/chroniony hasłem",
                        description="Zaszyfrowane pliki PDF uniemożliwiają głęboką statyczną analizę zawartości.",
                        severity=Severity.MEDIUM,
                        context={"pages": num_pages},
                    )
                )

        except Exception as exc:  # noqa: BLE001 - malformed PDF może wywołać nieobsłużony błąd w pypdf
            threats.append(
                Threat(
                    rule_id="PDF-PARSE-CORRUPTED",
                    title="Błąd strukturalny pliku PDF (Malformed Structure)",
                    description="Parser PDF nie mógł zbudować drzewa obiektów. Może to świadczyć o celowym uszkodzeniu nagłówka w celu ominięcia analizy.",
                    severity=Severity.MEDIUM,
                    context={"error": str(exc)},
                )
            )

        return threats

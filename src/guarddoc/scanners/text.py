import re
from pathlib import Path

from guarddoc.core.models import Severity, Threat
from guarddoc.scanners.base import BaseScanner

# Złośliwe znaki sterujące Unicode (Bidi Control, Zero-Width, Spoofing)
DANGEROUS_UNICODE_CHARS: dict[str, dict[str, str | Severity]] = {
    "\u202e": {
        "title": "Wykryto znak RTLO (Right-To-Left Override U+202E)",
        "description": "KRYTYCZNE: Znak ten służy do odwracania kolejności tekstu i jest powszechnie używany do ukrywania prawdziwego rozszerzenia pliku (np. udawanie .txt zamiast .exe).",
        "severity": Severity.CRITICAL,
    },
    "\u202d": {
        "title": "Wykryto znak Left-To-Right Override (U+202D)",
        "description": "Niestandardowy znak sterujący kierunkiem tekstu Unicode.",
        "severity": Severity.MEDIUM,
    },
    "\u200b": {
        "title": "Wykryto spację o zerowej szerokości (Zero-Width Space U+200B)",
        "description": "Niewidoczny znak używany do obfuskacji kodu lub omijania filtrów anty-spamowych.",
        "severity": Severity.MEDIUM,
    },
    "\u200c": {
        "title": "Wykryto niewidoczny znak Zero-Width Non-Joiner (U+200C)",
        "description": "Niewidoczny separator znaków używany w technikach obfuskacji.",
        "severity": Severity.MEDIUM,
    },
    "\ufeff": {
        "title": "Wykryto ZWNBSP / Byte Order Mark (U+FEFF)",
        "description": "Znak BOM wewnątrz treści tekstu (nie na początku) może służyć do ukrywania intencji.",
        "severity": Severity.LOW,
    },
}

# Wzorce niebezpiecznych skryptów i komend w plikach tekstowych
SUSPICIOUS_TEXT_PATTERNS: list[dict[str, str | Severity]] = [
    {
        "pattern": r"^#!/(?:bin|usr/bin)/(?:bash|sh|zsh|python|perl|ruby)",
        "rule_id": "TXT-SHEBANG",
        "title": "Wykryto nagłówek wykonywalny (Shebang)",
        "description": "Plik tekstowy rozpoczyna się od deklaracji interpretera powłoki (np. #!/bin/bash). Może być wykonywalny w systemach macOS/Linux.",
        "severity": Severity.HIGH,
    },
    {
        "pattern": r"(?:powershell\.exe|cmd\.exe|-ExecutionPolicy\s+Bypass)",
        "rule_id": "TXT-WIN-SHELL",
        "title": "Wykryto komendy powłoki Windows (PowerShell/CMD)",
        "description": "Zawartość pliku tekstowego zawiera odwołania do wywołań powłoki systemowej.",
        "severity": Severity.HIGH,
    },
    {
        "pattern": r"<script[\s>]",
        "rule_id": "TXT-HTML-SCRIPT",
        "title": "Wykryto znacznik skryptu HTML (<script>)",
        "description": "Plik tekstowy zawiera osadzony kod HTML/JavaScript (ryzyko XSS / phishing).",
        "severity": Severity.MEDIUM,
    },
    {
        "pattern": r"eval\s*\(",
        "rule_id": "TXT-EVAL-FUNC",
        "title": "Wykryto funkcję dynamicznego wykonywania kodu (eval)",
        "description": "Obecność funkcji eval() często wskazuje na ukryty/zagęszczony kod skryptowy.",
        "severity": Severity.MEDIUM,
    },
]


class TextScanner(BaseScanner):
    """Skaner analizujący pliki tekstowe pod kątem niewidocznych znaków Unicode i ukrytych skryptów."""

    @property
    def name(self) -> str:
        return "TextScanner"

    def is_supported(self, file_path: Path, mime_type: str) -> bool:
        return mime_type.startswith("text/") or file_path.suffix.lower() in (
            ".txt",
            ".csv",
            ".log",
            ".json",
            ".xml",
        )

    def scan(self, file_path: Path, mime_type: str) -> list[Threat]:
        threats: list[Threat] = []

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            # 1. Weryfikacja niedozwolonych znaków Unicode
            for char, meta in DANGEROUS_UNICODE_CHARS.items():
                count = content.count(char)
                if count > 0:
                    threats.append(
                        Threat(
                            rule_id=f"TXT-UNICODE-{ord(char):X}",
                            title=str(meta["title"]),
                            description=f"{meta['description']} (Wykryto wystąpień: {count}).",
                            severity=meta["severity"],  # type: ignore[arg-type]
                            context={"char_code": f"U+{ord(char):04X}", "count": count},
                        )
                    )

            # 2. Skanowanie wzorców złośliwych komend / skryptów
            for item in SUSPICIOUS_TEXT_PATTERNS:
                pattern = str(item["pattern"])
                if re.search(pattern, content, re.IGNORECASE | re.MULTILINE):
                    threats.append(
                        Threat(
                            rule_id=str(item["rule_id"]),
                            title=str(item["title"]),
                            description=str(item["description"]),
                            severity=item["severity"],  # type: ignore[arg-type]
                            context={"pattern": pattern},
                        )
                    )

        except Exception as exc:  # noqa: BLE001 - celowo przechwytujemy błędy odczytu plików I/O
            threats.append(
                Threat(
                    rule_id="TXT-READ-ERR",
                    title="Błąd odczytu pliku tekstowego",
                    description="Nie udało się otworzyć lub odczytać zawartości pliku tekstowego.",
                    severity=Severity.LOW,
                    context={"error": str(exc)},
                )
            )

        return threats

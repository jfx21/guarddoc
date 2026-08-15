from enum import Enum
from typing import Any


class Language(str, Enum):
    PL = "pl"
    EN = "en"


MESSAGES: dict[str, dict[Language, str]] = {
    "MIME-SPOOF-TITLE": {
        Language.PL: "Wykryto plik wykonywalny podszywający się pod dokument!",
        Language.EN: "Executable file masquerading as a document detected!",
    },
    "MIME-SPOOF-DESC": {
        Language.PL: "Plik ma rozszerzenie '{ext}', ale jego wewnętrzna struktura to plik wykonywalny/skrypt ({mime}).",
        Language.EN: "The file has extension '{ext}', but its internal structure is an executable/script ({mime}).",
    },
    "PDF-JS-TITLE": {
        Language.PL: "Wykryto skrypt JavaScript w pliku PDF",
        Language.EN: "JavaScript script detected in PDF file",
    },
    "PDF-JS-DESC": {
        Language.PL: "Plik PDF zawiera obiekty /JS lub /JavaScript pozwalające na wykonywanie kodu.",
        Language.EN: "PDF file contains /JS or /JavaScript objects allowing code execution.",
    },
    "PDF-OPENACTION-TITLE": {
        Language.PL: "Wykryto automatyczną akcję uruchamiania (/OpenAction)",
        Language.EN: "Automated launch action detected (/OpenAction)",
    },
    "PDF-OPENACTION-DESC": {
        Language.PL: "Plik PDF wywołuje akcje natychmiast po otwarciu dokumentu.",
        Language.EN: "PDF file triggers actions immediately upon opening.",
    },
    "TEXT-RTLO-TITLE": {
        Language.PL: "Wykryto atak Unicode RTLO (Right-To-Left Override)",
        Language.EN: "Unicode RTLO (Right-To-Left Override) attack detected",
    },
    "TEXT-RTLO-DESC": {
        Language.PL: "Zastosowano znak U+202E do maskowania prawdziwego rozszerzenia pliku.",
        Language.EN: "Character U+202E was used to mask the real file extension.",
    },
    "TEXT-SHEBANG-TITLE": {
        Language.PL: "Wykryto skrypt wykonywalny Shebang",
        Language.EN: "Executable Shebang script detected",
    },
    "TEXT-SHEBANG-DESC": {
        Language.PL: "Plik tekstowy rozpoczyna się od nagłówka wykonywalnego #!/bin/...",
        Language.EN: "Text file starts with an executable header #!/bin/...",
    },
    "WATCHER-ALERT-TITLE": {
        Language.PL: "GuardDoc: Alert Bezpieczeństwa",
        Language.EN: "GuardDoc Security Alert",
    },
    "WATCHER-THREAT-MSG": {
        Language.PL: "Wykryto zagrożenie ({severity}) w pliku {filename}!",
        Language.EN: "Threat detected ({severity}) in file {filename}!",
    },
    "WATCHER-QUARANTINE": {
        Language.PL: "Nałożono kwarantannę (chmod 000) na plik: {filename}",
        Language.EN: "Quarantine applied (chmod 000) to file: {filename}",
    },
    # Komunikaty konsoli Watchera
    "WATCHER-NEW-FILE": {
        Language.PL: "Nowy plik w katalogu: {filename}",
        Language.EN: "New file in directory: {filename}",
    },
    "WATCHER-ERR-QUARANTINE": {
        Language.PL: "Błąd nakładania kwarantanny na {filepath}: {error}",
        Language.EN: "Error applying quarantine to {filepath}: {error}",
    },
    "WATCHER-STARTED": {
        Language.PL: "GuardDoc Daemon uruchomiony. Obserwacja katalogu: {directory}",
        Language.EN: "GuardDoc Daemon started. Monitoring directory: {directory}",
    },
    "WATCHER-STOP-HINT": {
        Language.PL: "Naciśnij Ctrl+C, aby zatrzymać daemona.",
        Language.EN: "Press Ctrl+C to stop the daemon.",
    },
    "WATCHER-STOPPING": {
        Language.PL: "Zatrzymywanie daemona GuardDoc...",
        Language.EN: "Stopping GuardDoc daemon...",
    },
    # Office Scanner
    "OFFICE-VBA-MACRO-TITLE": {
        Language.PL: "Wykryto osadzone makra VBA w dokumencie Office",
        Language.EN: "Embedded VBA macros detected in Office document",
    },
    "OFFICE-VBA-MACRO-DESC": {
        Language.PL: "Dokument zawiera kod skryptowy VBA, który może automatycznie wykonać polecenia w systemie.",
        Language.EN: "Document contains VBA script code that may automatically execute commands on your system.",
    },
    "OFFICE-OLE-OBJECT-TITLE": {
        Language.PL: "Wykryto ukryty obiekt OLE / plik wykonywalny w dokumencie",
        Language.EN: "Hidden OLE object / executable detected in document",
    },
    "OFFICE-OLE-OBJECT-DESC": {
        Language.PL: "Dokument zawiera osadzony plik binarny lub zewnętrzny obiekt OLE.",
        Language.EN: "Document contains an embedded binary file or external OLE object.",
    },
    # Archive Scanner
    "ARCHIVE-EXECUTABLE-INSIDE-TITLE": {
        Language.PL: "Wykryto plik wykonywalny lub skrypt wewnątrz archiwum",
        Language.EN: "Executable file or script detected inside archive",
    },
    "ARCHIVE-EXECUTABLE-INSIDE-DESC": {
        Language.PL: "Archiwum zawiera potencjalnie niebezpieczny plik wykonywalny lub skrypt.",
        Language.EN: "Archive contains a potentially dangerous executable file or script.",
    },
    "ARCHIVE-ZIP-SLIP-TITLE": {
        Language.PL: "Wykryto próbę ataku Zip Slip (niebezpieczna ścieżka pliku)",
        Language.EN: "Zip Slip path traversal attack detected in archive",
    },
    "ARCHIVE-ZIP-SLIP-DESC": {
        Language.PL: "Plik w archiwum zawiera odwołania do katalogów nadrzędnych (../), co może pozwolić na nadpisanie plików systemowych.",
        Language.EN: "Archive entry contains parent directory references (../) which may overwrite system files upon extraction.",
    },
    "ARCHIVE-BOMB-TITLE": {
        Language.PL: "Podejrzenie bomby dekompresyjnej (Zip Bomb)",
        Language.EN: "Suspected decompression bomb (Zip Bomb)",
    },
    "ARCHIVE-BOMB-DESC": {
        Language.PL: "Archiwum posiada nienaturalnie wysoki współczynnik kompresji lub zawiera zbyt dużą liczbę plików.",
        Language.EN: "Archive has an abnormally high compression ratio or exceeds safe entry limits.",
    },
}


def get_text(key: str, lang: Language = Language.PL, **kwargs: Any) -> str:
    """Pobiera przetłumaczony tekst na podstawie klucza i wybranego języka."""
    translations = MESSAGES.get(key, {})
    template = translations.get(lang, translations.get(Language.EN, key))
    if kwargs:
        return template.format(**kwargs)
    return template

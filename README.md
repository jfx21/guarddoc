# GuardDoc

**GuardDoc** to lekkie, modularne narzędzie CLI do analizy bezpieczeństwa i wstępnej weryfikacji załączników (**Document Malware Triage**) dedykowane dla systemów **macOS** oraz **Linux**.

Narzędzie służy do natychmiastowego prześwietlania pobranych dokumentów (`.pdf`, `.txt`, `.csv`, `.json` itp.) pod kątem ukrytych skryptów, oszustw w rozszerzeniach plików (**Extension Spoofing / Magic Bytes**), złośliwych akcji automatycznych oraz dopasowań reguł **YARA**.

---

## Główne Cechy (Key Features)

* **Weryfikacja MIME Bytes (Spoofing Detection):** Wykrywa pliki wykonywalne (ELF, Mach-O, EXE, skrypty Shell) podszywające się pod niegroźne dokumenty tekstowe lub pliki PDF.
* **Głęboka Analiza PDF:** Skanuje surową strukturę bajtową oraz obiekty PDF pod kątem groźnych słów kluczowych ze specyfikacji ISO:
  * `/JS` oraz `/JavaScript` (osadzony kod skryptowy)
  * `/OpenAction` oraz `/AA` (kod uruchamiany automatycznie po otwarciu)
  * `/Launch` (próby wywołania zewnętrznych komend systemowych)
  * `/EmbeddedFiles` (ukryte pliki wewnątrz dokumentu PDF)
* **Analiza Tekstowa i Unicode:** Wykrywa ataki typu **Right-To-Left Override (`U+202E`)**, niewidoczne znaki Unicode (Zero-Width Spaces), nagłówki Shebang (`#!/bin/bash`) oraz komendy powłoki.
* **Integracja z YARA:** Automatycznie kompiluje i stosuje reguły YARA z katalogu `rules/` do detekcji złożonych wzorców malware'u.
* **Formatowanie JSON & Rekurencyjność:** Pozwala skanować całe drzewa katalogów (np. `~/Downloads`) oraz generować ustrukturyzowane raporty JSON pod kątem integracji z systemami SIEM/SOAR.

---

## Architektura Systemu (System Architecture)

GuardDoc wykorzystuje architekturę typu `src-layout` z odseparowanym silnikiem orkiestrującym oraz niezależnymi modułami skanującymi:

```text
               ┌────────────────────────┐
               │    GuardDoc CLI        │
               └───────────┬────────────┘
                           │
                           ▼
               ┌────────────────────────┐
               │    Engine Orchestrator │
               └───────────┬────────────┘
                           │
       ┌───────────────────┼───────────────────┬───────────────────┐
       ▼                   ▼                   ▼                   ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│ MimeScanner  │    │  PdfScanner  │    │ TextScanner  │    │ YaraScanner  │
└──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘
 (Magic Bytes)       (ISO PDF Spec)      (Unicode/RTLO)      (YARA Rules)
```

Silnik kieruje się zasadą izolacji błędów: awaria lub uszkodzenie nagłówka pliku w jednym z zewnętrznych parserów nie przerywa działania aplikacji i jest rejestrowana jako potencjalna próba ominięcia analizy (Malformed Structure).

## Instalacja (Installation)
### Wymagania Systemowe
System musi posiadać zainstalowaną bibliotekę libmagic:

```bash
# macOS (Homebrew)
brew install libmagic

# Ubuntu / Debian
sudo apt install libmagic1
```

### Instalacja za pomocą uv (Rekomendowane)
# Sklonuj repozytorium
```bash
git clone [https://github.com/jfx21/guarddoc.git](https://github.com/jfx21/guarddoc.git)
cd guarddoc

# Utwórz środowisko i zainstaluj pakiet w trybie deweloperskim
uv pip install -e ".[dev]"
```

## Użycie (Usage)

### 1. Skanowanie pojedynczego pliku

```bash
guarddoc scan ~/Downloads/faktura_2026.pdf
```

### 2. Rekurencyjne skanowanie całego folderu Pobrane
```bash
guarddoc scan ~/Downloads --recursive
```

### 3. Generowanie raportu w formacie JSON
```bash
guarddoc scan ~/Downloads --recursive --json --output raport.json
```

## Przykład wyniku JSON
```json
[
  {
    "file_path": "/Users/user/Downloads/faktura_2026.pdf",
    "file_name": "faktura_2026.pdf",
    "file_size_bytes": 102400,
    "mime_type": "text/x-shellscript",
    "is_safe": false,
    "max_severity": "CRITICAL",
    "threats": [
      {
        "rule_id": "MIME-SPOOF-CRITICAL",
        "title": "Wykryto plik wykonywalny podszywający się pod dokument!",
        "description": "Plik ma rozszerzenie '.pdf', ale jego wewnętrzna struktura to plik wykonywalny/skrypt (text/x-shellscript).",
        "severity": "CRITICAL",
        "context": {
          "extension": ".pdf",
          "detected_mime": "text/x-shellscript"
        }
      }
    ],
    "errors": []
  }
]
```

## Testowanie i Jakość Kodu
Projekt posiada zestaw testów jednostkowych oraz integracyjnych End-to-End (E2E):
```bash
# Uruchomienie testów
uv run pytest

# Kontrola lintera Ruff
uv run ruff check src/ tests/
```

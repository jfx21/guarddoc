# GuardDoc
[![CI](https://github.com/jfx21/guarddoc/actions/workflows/ci.yml/badge.svg)](https://github.com/jfx21/guarddoc/actions/workflows/ci.yml)
[![Python Version](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

[ English ] | [ [Polska wersja poniżej](#guarddoc---polska-wersja) ]

**GuardDoc** is a lightweight, modular CLI tool for security analysis, initial attachment verification (**Document Malware Triage**), and real-time directory watching designed for **macOS** and **Linux** systems.

The tool instantly inspects downloaded documents (`.pdf`, `.docx`, `.docm`, `.xlsx`, `.xlsm`, `.txt`, `.csv`, `.json`, etc.) for hidden scripts, VBA macros, extension spoofing (**Extension Spoofing / Magic Bytes**), malicious automated actions, and **YARA** rule matches.

---

## Key Features

* **MIME Bytes Verification (Spoofing Detection):** Detects executable files (ELF, Mach-O, EXE, Shell scripts) masquerading as harmless text documents, Office files, or PDFs.
* **Office Document Inspection (VBA & OLE):** Scans MS Office documents (`.docx`, `.docm`, `.xls`, `.xlsm`, etc.) for hidden VBA macros (`vbaProject.bin`), embedded binaries, and dangerous OLE objects.
* **Deep PDF Analysis:** Scans raw byte structures and PDF objects for dangerous ISO specification keywords (`/JS`, `/JavaScript`, `/OpenAction`, `/AA`, `/Launch`, `/EmbeddedFiles`).
* **Text and Unicode Analysis:** Detects **Right-To-Left Override (`U+202E`)** attacks, invisible Unicode characters (Zero-Width Spaces), Shebang headers (`#!/bin/bash`), and shell commands.
* **YARA Integration:** Automatically compiles and applies YARA rules from the `rules/` directory to detect complex malware patterns.
* **Real-Time Directory Watcher (Daemon):** Continuous background monitoring of incoming files (e.g., `~/Downloads`) with automatic quarantine (`chmod 000`) and native desktop notifications (macOS / Linux).
* **Multi-language Support (i18n):** Full support for English and Polish languages (`-l / --lang [pl|en]`) in reports, terminal UI, and desktop notifications.
* **JSON Formatting & Recursion:** Allows scanning entire directory trees and generating structured JSON reports for integration with SIEM/SOAR systems.
* **Archive Inspection (Hidden Binaries & Zip Slip):** Inspects `.zip`, `.tar`, `.tar.gz`, and `.tgz` archives for hidden executable files (`.exe`, `.scr`, `.sh`, `.vbs`), path traversal vulnerabilities (**Zip Slip** `../`), and compression bombs (**Zip Bomb**).

---

## System Architecture

GuardDoc uses a `src-layout` architecture with a separated orchestrator engine, i18n localization core, and independent scanner modules:

```text
               ┌────────────────────────┐
               │    GuardDoc CLI        │
               └───────────┬────────────┘
                           │
             ┌─────────────┴─────────────┐
             ▼                           ▼
  ┌─────────────────────┐     ┌─────────────────────┐
  │ guarddoc scan (CLI) │     │ guarddoc watch (D)  │
  └──────────┬──────────┘     └──────────┬──────────┘
             │                           │
             └─────────────┬─────────────┘
                           ▼
               ┌────────────────────────┐
               │  Engine & i18n Core    │
               └───────────┬────────────┘
                           │
    ┌──────────────┬───────┴───────┬──────────────┬──────────────┐
    ▼              ▼               ▼              ▼              ▼
┌──────────┐ ┌───────────┐   ┌──────────────┐┌───────────┐  ┌───────────┐
│MimeScanner││PdfScanner │   │OfficeScanner ││TextScanner│  │YaraScanner│
└──────────┘ └───────────┘   └──────────────┘└───────────┘  └───────────┘
(MagicBytes) (ISO PDF Spec)   (VBA / OLE)    (Unicode/RTLO) (YARA Rules)
```

The engine follows the **error isolation principle**: a failure or corrupted file header in one of the external parsers does not halt the application and is recorded as a potential analysis evasion attempt (*Malformed Structure*).

---

## Installation

### System Requirements

The system must have the `libmagic` library installed:

```bash
# macOS (Homebrew)
brew install libmagic

# Ubuntu / Debian
sudo apt install libmagic1
```

### Installation using uv (Recommended)

```bash
# Clone the repository
git clone https://github.com/jfx21/guarddoc.git
cd guarddoc

# Install globally in an isolated environment
uv tool install --force .

# Ensure ~/.local/bin is in your PATH (if not already added)
uv tool update-shell
```

### Update
To update your global installation to the later version:
```bash
cd /path/to/guarddoc
git pull
uv tool install --force .
```


### Local Development Mode
```bash
# Sync dependencies and create venv
uv sync --all-extras

# Run directly via uv
uv run guarddoc --help

# Or install in editable mode inside your active environment
uv pip install -e .
```

---

## Usage

### 1. Single File Scanning (English / Polish)

```bash
# Default (Polish)
guarddoc scan ~/Downloads/invoice_2026.pdf

# English output
guarddoc scan ~/Downloads/invoice_2026.docm --lang en
```

### 2. Recursive Scanning of the Entire Downloads Directory

```bash
guarddoc scan ~/Downloads --recursive
```

### 3. Generating a JSON Report (English for SIEM/SOAR)

```bash
guarddoc scan ~/Downloads --recursive --json --lang en --output report.json
```

### 4. Background Real-Time Directory Watcher

Monitor a directory (defaults to `~/Downloads`) in real time with automatic quarantine (`chmod 000`) on detected threats and localized notifications:

```bash
guarddoc watch ~/Downloads --quarantine --lang en
```

### Help & other commands
```bash
# Display help and available commands
guarddoc --help

# Check version
guarddoc --version
```

---

## Testing and Code Quality

The project includes a comprehensive set of unit and End-to-End (E2E) integration tests:

```bash
# Run tests
uv run pytest

# Check code with Ruff linter
uv run ruff check src/ tests/
# Ruff fix
uv run ruff check --fix
```

---
---

# GuardDoc - Polska Wersja

**GuardDoc** to lekkie, modularne narzędzie CLI do analizy bezpieczeństwa, wstępnej weryfikacji załączników (**Document Malware Triage**) oraz stałego monitorowania katalogów w czasie rzeczywistym dla systemów **macOS** oraz **Linux**.

Narzędzie służy do natychmiastowego prześwietlania pobranych dokumentów (`.pdf`, `.docx`, `.docm`, `.xlsx`, `.xlsm`, `.txt`, `.csv`, `.json` itp.) pod kątem ukrytych skryptów, makr VBA, oszustw w rozszerzeniach plików (**Extension Spoofing / Magic Bytes**), złośliwych akcji automatycznych oraz dopasowań reguł **YARA**.

---

## Główne Funkcjonalności

* **Weryfikacja MIME Bytes (Spoofing Detection):** Wykrywa pliki wykonywalne (ELF, Mach-O, EXE, skrypty Shell) podszywające się pod niegroźne dokumenty tekstowe, arkusze kalkulacyjne czy pliki PDF.
* **Analiza Dokumentów Office (VBA & OLE):** Prześwietla dokumenty MS Office (`.docx`, `.docm`, `.xls`, `.xlsm` itp.) pod kątem osadzonych makr VBA (`vbaProject.bin`), osadzonych plików binarnych oraz niebezpiecznych obiektów OLE.
* **Głęboka Analiza PDF:** Skanuje surową strukturę bajtową oraz obiekty PDF pod kątem groźnych słów kluczowych ze specyfikacji ISO (`/JS`, `/JavaScript`, `/OpenAction`, `/AA`, `/Launch`, `/EmbeddedFiles`).
* **Analiza Tekstowa i Unicode:** Wykrywa ataki typu **Right-To-Left Override (`U+202E`)**, niewidoczne znaki Unicode (Zero-Width Spaces), nagłówki Shebang (`#!/bin/bash`) oraz komendy powłoki.
* **Integracja z YARA:** Automatycznie kompiluje i stosuje reguły YARA z katalogu `rules/` do detekcji złożonych wzorców malware'u.
* **Ochrona w Czasie Rzeczywistym (Watcher Daemon):** Ciągła obserwacja wybranego folderu (np. `~/Downloads`) w tle z opcją automatycznej kwarantanny (`chmod 000`) i natywnymi powiadomieniami systemowymi (macOS / Linux).
* **Obsługa Wielojęzyczności (i18n):** Pełne wsparcie dla języka polskiego i angielskiego (`-l / --lang [pl|en]`) w raportach, interfejsie konsolowym oraz powiadomieniach.
* **Formatowanie JSON & Rekurencyjność:** Pozwala skanować całe drzewa katalogów oraz generować ustrukturyzowane raporty JSON pod kątem integracji z systemami SIEM/SOAR.
* **Archive Inspection (Hidden Binaries & Zip Slip):** Inspects `.zip`, `.tar`, `.tar.gz`, and `.tgz` archives for hidden executable files (`.exe`, `.scr`, `.sh`, `.vbs`), path traversal vulnerabilities (**Zip Slip** `../`), and compression bombs (**Zip Bomb**).

---

## Architektura Systemu

GuardDoc wykorzystuje architekturę typu `src-layout` z odseparowanym silnikiem orkiestrującym, modułem i18n oraz niezależnymi modułami skanującymi:

```text
               ┌────────────────────────┐
               │    GuardDoc CLI        │
               └───────────┬────────────┘
                           │
             ┌─────────────┴─────────────┐
             ▼                           ▼
  ┌─────────────────────┐     ┌─────────────────────┐
  │ guarddoc scan (CLI) │     │ guarddoc watch (D)  │
  └──────────┬──────────┘     └──────────┬──────────┘
             │                           │
             └─────────────┬─────────────┘
                           ▼
               ┌────────────────────────┐
               │  Engine & i18n Core    │
               └───────────┬────────────┘
                           │
    ┌──────────────┬───────┴───────┬──────────────┬──────────────┐
    ▼              ▼               ▼              ▼              ▼
┌──────────┐ ┌───────────┐   ┌──────────────┐┌───────────┐  ┌───────────┐
│MimeScanner││PdfScanner │   │OfficeScanner ││TextScanner│  │YaraScanner│
└──────────┘ └───────────┘   └──────────────┘└───────────┘  └───────────┘
(MagicBytes) (ISO PDF Spec)   (VBA / OLE)    (Unicode/RTLO) (YARA Rules)
```

Silnik kieruje się zasadą **izolacji błędów**: awaria lub uszkodzenie nagłówka pliku w jednym z zewnętrznych parserów nie przerywa działania aplikacji i jest rejestrowana jako potencjalna próba ominięcia analizy (*Malformed Structure*).

---

## Instalacja

### Wymagania Systemowe

System musi posiadać zainstalowaną bibliotekę `libmagic`:

```bash
# macOS (Homebrew)
brew install libmagic

# Ubuntu / Debian
sudo apt install libmagic1
```

### Instalacja za pomocą uv (Rekomendowane)

```bash
# Sklonuj repozytorium
git clone https://github.com/jfx21/guarddoc.git
cd guarddoc

# Zainstaluj globalnie w odizolowanym środowisku
uv tool install --force .

# Dodaj ~/.local/bin do zmiennej PATH (jeśli jeszcze nie dodano)
uv tool update-shell
```

### Tryb deweloperski
```bash
# Synchronizacja zależności i środowiska venv
uv sync --all-extras

# Uruchamianie bezpośrednio przez uv
uv run guarddoc --help

# Lub instalacja w trybie edytowalnym w aktywnym venvie
uv pip install -e .
```

### Aktualizacja
Aby zaktualizować wersje lokalnego guarddoc'a:
```bash
cd /path/to/guarddoc
git pull
uv tool install --force .
```

---

## Użycie

### 1. Skanowanie pojedynczego pliku

```bash
# Domyślnie język polski
guarddoc scan ~/Downloads/faktura_2026.pdf

# Plik pakietu Office z makrem
guarddoc scan ~/Downloads/oferta.docm --lang pl
```

### 2. Rekurencyjne skanowanie całego folderu Pobrane

```bash
guarddoc scan ~/Downloads --recursive
```

### 3. Generowanie raportu w formacie JSON

```bash
guarddoc scan ~/Downloads --recursive --json --lang pl --output raport.json
```

### 4. Obserwacja katalogu w tle (Ochrona w czasie rzeczywistym)

Uruchomienie obserwatora folderu (domyślnie `~/Downloads`) w tle z automatyczną kwarantanną (`chmod 000`) w przypadku wykrycia zagrożeń oraz wybranym językiem alertów:

```bash
guarddoc watch ~/Downloads --quarantine --lang pl
```

### Pomoc i inne komendy
```bash
# Wyświetlenie pomocy i dostępnych komend
guarddoc --help

# Sprawdzenie wersji
guarddoc --version
```

---

## Testowanie i Jakość Kodu

Projekt posiada zestaw testów jednostkowych oraz integracyjnych End-to-End (E2E):

```bash
# Uruchomienie testów
uv run pytest

# Kontrola lintera Ruff
uv run ruff check src/ tests/

# Ruff fix
uv run ruff check --fix
```

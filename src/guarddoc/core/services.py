from pathlib import Path

import magic

from guarddoc.core.engine import Engine
from guarddoc.core.models import ScanResult
from guarddoc.scanners.mime import MimeScanner
from guarddoc.scanners.pdf import PdfScanner
from guarddoc.scanners.text import TextScanner
from guarddoc.scanners.yara_scanner import YaraScanner


def build_engine(rules_dir: Path | str = "rules") -> Engine:
    """Tworzy i konfiguruje silnik ze wszystkimi skanerami."""
    engine = Engine()
    engine.register_scanner(MimeScanner())
    engine.register_scanner(PdfScanner())
    engine.register_scanner(TextScanner())
    engine.register_scanner(YaraScanner(rules_dir=rules_dir))
    return engine


def scan_single_file(engine: Engine, file_path: Path) -> ScanResult:
    """Skanuje pojedynczy plik."""
    try:
        detected_mime = magic.from_file(str(file_path), mime=True)
    except Exception:  # noqa: BLE001 - fallback przy błędzie libmagic
        detected_mime = "unknown"

    return engine.scan_file(file_path, mime_type=detected_mime)

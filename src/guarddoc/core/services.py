from __future__ import annotations

from pathlib import Path

from guarddoc.core.engine import Engine
from guarddoc.core.i18n import Language
from guarddoc.core.models import ScanResult
from guarddoc.scanners.archive import ArchiveScanner
from guarddoc.scanners.base import BaseScanner
from guarddoc.scanners.mime import MimeScanner
from guarddoc.scanners.office import OfficeScanner
from guarddoc.scanners.pdf import PdfScanner
from guarddoc.scanners.text import TextScanner
from guarddoc.scanners.yara_scanner import YaraScanner


def get_default_scanners(rules_dir: Path | str = "rules") -> list[BaseScanner]:
    """Instantiate and return the standard suite of scanners.

    :param rules_dir: Directory containing compiled or raw YARA rules.
    :return: List of initialized BaseScanner instances.
    """
    rules_path = Path(rules_dir)
    return [
        MimeScanner(),
        PdfScanner(),
        TextScanner(),
        OfficeScanner(),
        ArchiveScanner(),
        YaraScanner(rules_dir=rules_path),
    ]


def build_engine(
    rules_dir: Path | str = "rules",
    custom_scanners: list[BaseScanner] | None = None,
) -> Engine:
    """Creates and configures the scan engine with registered scanners.

    :param rules_dir: Directory containing YARA rules.
    :param custom_scanners: Optional explicit list of scanners to register.
    :return: Configured Engine instance.
    """
    engine = Engine()
    scanners = custom_scanners if custom_scanners is not None else get_default_scanners(rules_dir)

    for scanner in scanners:
        engine.register_scanner(scanner)

    return engine


def scan_single_file(
    engine: Engine,
    file_path: Path | str,
    lang: Language = Language.EN,
) -> ScanResult:
    """Scans a single file using the provided engine and target report language.

    :param engine: Configured Engine instance.
    :param file_path: Path to the target file.
    :param lang: Output language for generated descriptions and titles.
    :return: Completed ScanResult.
    """
    target_path = Path(file_path).resolve()

    # Safely probe MIME type via MimeScanner or fallback without crashing on missing libmagic
    detected_mime: str | None = None
    mime_scanner = next((s for s in engine.scanners if isinstance(s, MimeScanner)), None)
    if mime_scanner and mime_scanner.is_available:
        detected_mime = mime_scanner.get_mime_type(target_path)

    return engine.scan_file(target_path, mime_type=detected_mime, lang=lang)

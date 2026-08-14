from __future__ import annotations

from pathlib import Path
from typing import List

from guarddoc.core.i18n import Language, get_text
from guarddoc.core.models import Severity, Threat
from guarddoc.scanners.base import BaseScanner


class PdfScanner(BaseScanner):
    """Scanner analyzing PDF object structure for dangerous active content and triggers."""

    name: str = "PdfScanner"
    description: str = (
        "Detects embedded JavaScript, OpenAction triggers, and suspicious PDF objects"
    )

    def is_supported(self, file_path: Path, mime_type: str = "unknown") -> bool:
        """Checks if the file is a PDF based on extension or MIME type."""
        return file_path.suffix.lower() == ".pdf" or "pdf" in mime_type.lower()

    def scan(
        self,
        file_path: Path,
        mime_type: str = "unknown",
        lang: Language = Language.PL,
    ) -> List[Threat]:
        """Scans PDF bytes for active content (/JavaScript, /JS) and automated actions (/OpenAction, /AA)."""
        threats: List[Threat] = []

        if not self.is_supported(file_path, mime_type):
            return threats

        try:
            content = file_path.read_bytes()
        except Exception:  # noqa: BLE001
            return threats

        # Detect embedded JavaScript elements
        if b"/JS" in content or b"/JavaScript" in content:
            threats.append(
                Threat(
                    rule_id="PDF-EMBEDDED-JS",
                    scanner_name=self.name,
                    title=get_text("PDF-JS-TITLE", lang=lang),
                    description=get_text("PDF-JS-DESC", lang=lang),
                    severity=Severity.HIGH,
                )
            )

        # Detect automatic launch actions on document open
        if b"/OpenAction" in content or b"/AA" in content:
            threats.append(
                Threat(
                    rule_id="PDF-OPEN-ACTION",
                    scanner_name=self.name,
                    title=get_text("PDF-OPENACTION-TITLE", lang=lang),
                    description=get_text("PDF-OPENACTION-DESC", lang=lang),
                    severity=Severity.HIGH,
                )
            )

        return threats

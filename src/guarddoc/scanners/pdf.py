from pathlib import Path

from guarddoc.core.i18n import Language, get_text
from guarddoc.core.models import Severity, Threat
from guarddoc.scanners.base import BaseScanner


class PdfScanner(BaseScanner):
    """Skaner analizujący strukturę obiektów plików PDF pod kątem niebezpiecznych elementów ISO."""

    @property
    def name(self) -> str:
        return "PdfScanner"

    def scan(
        self,
        file_path: Path,
        mime_type: str,
        lang: Language = Language.PL,
    ) -> list[Threat]:
        threats: list[Threat] = []

        if file_path.suffix.lower() != ".pdf" and "pdf" not in mime_type:
            return threats

        try:
            content = file_path.read_bytes()
        except Exception:  # noqa: BLE001
            return threats

        if b"/JS" in content or b"/JavaScript" in content:
            threats.append(
                Threat(
                    rule_id="PDF-EMBEDDED-JS",
                    title=get_text("PDF-JS-TITLE", lang=lang),
                    description=get_text("PDF-JS-DESC", lang=lang),
                    severity=Severity.HIGH,
                )
            )

        if b"/OpenAction" in content or b"/AA" in content:
            threats.append(
                Threat(
                    rule_id="PDF-OPEN-ACTION",
                    title=get_text("PDF-OPENACTION-TITLE", lang=lang),
                    description=get_text("PDF-OPENACTION-DESC", lang=lang),
                    severity=Severity.HIGH,
                )
            )

        return threats

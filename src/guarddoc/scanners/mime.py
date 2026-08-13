from pathlib import Path
from typing import ClassVar

from guarddoc.core.i18n import Language, get_text
from guarddoc.core.models import Severity, Threat
from guarddoc.scanners.base import BaseScanner


class MimeScanner(BaseScanner):
    """Skaner sprawdzający spójność nagłówków bajtowych z rozszerzeniem pliku."""

    DANGEROUS_MIMES: ClassVar[set[str]] = {
        "application/x-executable",
        "application/x-mach-binary",
        "application/x-dosexec",
        "text/x-shellscript",
        "application/x-sh",
    }

    @property
    def name(self) -> str:
        return "MimeScanner"

    def scan(
        self,
        file_path: Path,
        mime_type: str,
        lang: Language = Language.PL,
    ) -> list[Threat]:
        threats: list[Threat] = []
        ext = file_path.suffix.lower()

        if ext in {".pdf", ".txt", ".csv", ".json"} and mime_type in self.DANGEROUS_MIMES:
            threats.append(
                Threat(
                    rule_id="MIME-SPOOF-CRITICAL",
                    title=get_text("MIME-SPOOF-TITLE", lang=lang),
                    description=get_text("MIME-SPOOF-DESC", lang=lang, ext=ext, mime=mime_type),
                    severity=Severity.CRITICAL,
                    context={"extension": ext, "detected_mime": mime_type},
                )
            )

        return threats

from pathlib import Path

from guarddoc.core.i18n import Language, get_text
from guarddoc.core.models import Severity, Threat
from guarddoc.scanners.base import BaseScanner


class TextScanner(BaseScanner):
    """Skaner plików tekstowych i struktur Unicode."""

    @property
    def name(self) -> str:
        return "TextScanner"

    def scan(
        self,
        file_path: Path,
        mime_type: str,
        lang: Language = Language.PL,
    ) -> list[Threat]:
        threats: list[Threat] = []

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:  # noqa: BLE001
            return threats

        if "\u202e" in content or "\u202e" in file_path.name:
            threats.append(
                Threat(
                    rule_id="TXT-UNICODE-RTLO",
                    title=get_text("TEXT-RTLO-TITLE", lang=lang),
                    description=get_text("TEXT-RTLO-DESC", lang=lang),
                    severity=Severity.HIGH,
                )
            )

        if content.startswith("#!/bin/"):
            threats.append(
                Threat(
                    rule_id="TXT-SHEBANG",
                    title=get_text("TEXT-SHEBANG-TITLE", lang=lang),
                    description=get_text("TEXT-SHEBANG-DESC", lang=lang),
                    severity=Severity.MEDIUM,
                )
            )

        return threats

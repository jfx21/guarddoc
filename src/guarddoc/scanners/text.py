from __future__ import annotations

from pathlib import Path

from guarddoc.core.i18n import Language, get_text
from guarddoc.core.models import Severity, Threat
from guarddoc.scanners.base import BaseScanner


class TextScanner(BaseScanner):
    """Scanner analyzing text files and Unicode structures for spoofing and script execution indicators."""

    name: str = "TextScanner"
    description: str = "Detects Unicode RTLO spoofing and suspicious script shebang headers"

    def scan(
        self,
        file_path: Path,
        mime_type: str = "unknown",
        lang: Language = Language.PL,
    ) -> list[Threat]:
        """Scans file content and filename for RTLO characters and shebang headers."""
        threats: list[Threat] = []

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:  # noqa: BLE001
            return threats

        # Check for Right-to-Left Override (RTLO) Unicode character
        if "\u202e" in content or "\u202e" in file_path.name:
            threats.append(
                Threat(
                    rule_id="TXT-UNICODE-RTLO",
                    scanner_name=self.name,
                    title=get_text("TEXT-RTLO-TITLE", lang=lang),
                    description=get_text("TEXT-RTLO-DESC", lang=lang),
                    severity=Severity.HIGH,
                    context={"detected_char": "U+202E (RTLO)"},
                )
            )

        # Check for executable script shebang header
        if content.startswith("#!/bin/"):
            threats.append(
                Threat(
                    rule_id="TXT-SHEBANG",
                    scanner_name=self.name,
                    title=get_text("TEXT-SHEBANG-TITLE", lang=lang),
                    description=get_text("TEXT-SHEBANG-DESC", lang=lang),
                    severity=Severity.MEDIUM,
                    context={"header": content.splitlines()[0] if content else ""},
                )
            )

        return threats

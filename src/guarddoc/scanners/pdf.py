from pathlib import Path
import re
from typing import ClassVar

from guarddoc.core.i18n import Language, get_text
from guarddoc.core.models import Severity, Threat
from guarddoc.scanners.base import BaseScanner


class PdfScanner(BaseScanner):
    """Scanner for PDF files to detect suspicious structures, scripts, and embedded exploits."""

    PDF_EXTENSIONS: ClassVar[set[str]] = {".pdf"}

    MALICIOUS_PATTERNS: ClassVar[dict[str, tuple[re.Pattern[bytes], str, Severity]]] = {
        "PDF-JAVASCRIPT": (
            re.compile(rb"/JavaScript\b", re.IGNORECASE),
            "PDF-JAVASCRIPT-TITLE",
            Severity.HIGH,
        ),
        "PDF-JS-INLINE": (
            re.compile(rb"/JS\b", re.IGNORECASE),
            "PDF-JS-INLINE-TITLE",
            Severity.HIGH,
        ),
        "PDF-LAUNCH-ACTION": (
            re.compile(rb"/Launch\b", re.IGNORECASE),
            "PDF-LAUNCH-TITLE",
            Severity.CRITICAL,
        ),
        "PDF-OPEN-ACTION": (
            re.compile(rb"/OpenAction\b", re.IGNORECASE),
            "PDF-OPENACTION-TITLE",
            Severity.HIGH,
        ),
        "PDF-ADDITIONAL-ACTIONS": (
            re.compile(rb"/AA\b", re.IGNORECASE),
            "PDF-AA-TITLE",
            Severity.HIGH,
        ),
    }

    @property
    def name(self) -> str:
        return "PdfScanner"

    def is_supported(self, file_path: Path, mime_type: str | None) -> bool:
        ext = file_path.suffix.lower()
        mime = (mime_type or "").lower()
        return ext in self.PDF_EXTENSIONS or "pdf" in mime

    def scan(
        self,
        file_path: Path,
        mime_type: str | None = None,
        lang: Language = Language.PL,
    ) -> list[Threat]:
        threats: list[Threat] = []

        try:
            raw_content = file_path.read_bytes()
        except OSError:
            return threats

        has_js = bool(
            re.search(rb"/JavaScript\b", raw_content, re.IGNORECASE)
            or re.search(rb"/JS\b", raw_content, re.IGNORECASE)
        )

        for rule_id, (pattern, title_key, severity) in self.MALICIOUS_PATTERNS.items():
            if pattern.search(raw_content):
                if rule_id == "PDF-OPEN-ACTION" and b"/GoTo" in raw_content and not has_js:
                    continue

                threats.append(
                    Threat(
                        scanner_name=self.name,
                        rule_id=rule_id,
                        title=get_text(title_key, lang=lang),
                        description=get_text(f"{rule_id}-DESC", lang=lang),
                        severity=severity,
                        context={"matched_rule": rule_id},
                    )
                )

        if re.search(rb"/Type\s*/Filespec.*\.exe", raw_content, re.IGNORECASE):
            threats.append(
                Threat(
                    scanner_name=self.name,
                    rule_id="PDF-EMBEDDED-EXECUTABLE",
                    title=get_text("PDF-EMBEDDED-EXE-TITLE", lang=lang),
                    description=get_text("PDF-EMBEDDED-EXE-DESC", lang=lang),
                    severity=Severity.CRITICAL,
                )
            )

        return threats

from __future__ import annotations

from pathlib import Path
from typing import ClassVar, List, Optional, Set

from guarddoc.core.i18n import Language, get_text
from guarddoc.core.models import Severity, Threat
from guarddoc.scanners.base import BaseScanner

# Safe import of python-magic
try:
    import magic

    MAGIC_AVAILABLE = True
except (ImportError, Exception):
    MAGIC_AVAILABLE = False


class MimeScanner(BaseScanner):
    """Scanner that validates file magic bytes against file extension to detect spoofing."""

    name: str = "MimeScanner"
    description: str = "Detects file extension spoofing and MIME type mismatches"

    DANGEROUS_MIMES: ClassVar[Set[str]] = {
        "application/x-executable",
        "application/x-mach-binary",
        "application/x-dosexec",
        "application/x-sharedlib",
        "application/x-pie-executable",
        "application/x-elf",
        "application/x-msdownload",
        "application/x-ms-dos-executable",
        "text/x-shellscript",
        "application/x-sh",
    }

    DOC_EXTENSIONS: ClassVar[Set[str]] = {
        ".pdf",
        ".txt",
        ".csv",
        ".json",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".png",
        ".jpg",
        ".jpeg",
    }

    @property
    def is_available(self) -> bool:
        """Check if python-magic is functional in the current environment."""
        if not MAGIC_AVAILABLE:
            return False
        try:
            magic.from_buffer(b"\x00" * 128, mime=True)
            return True
        except Exception:
            return False

    def get_mime_type(self, file_path: Path) -> Optional[str]:
        """Safely probe MIME type from file content using magic bytes."""
        if not self.is_available:
            return None
        try:
            return magic.from_file(str(file_path), mime=True)
        except Exception:
            return None

    def scan(
        self,
        file_path: Path,
        mime_type: str = "unknown",
        lang: Language = Language.PL,
    ) -> List[Threat]:
        """Scan file for extension vs content MIME type mismatches."""
        threats: List[Threat] = []
        ext = file_path.suffix.lower()

        if ext in self.DOC_EXTENSIONS and mime_type in self.DANGEROUS_MIMES:
            threats.append(
                Threat(
                    rule_id="MIME-SPOOF-CRITICAL",
                    scanner_name=self.name,
                    title=get_text("MIME-SPOOF-TITLE", lang=lang),
                    description=get_text("MIME-SPOOF-DESC", lang=lang, ext=ext, mime=mime_type),
                    severity=Severity.CRITICAL,
                    context={"extension": ext, "detected_mime": mime_type},
                )
            )

        return threats

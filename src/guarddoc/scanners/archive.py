import re
import tarfile
import zipfile
from pathlib import Path
from typing import ClassVar

from guarddoc.core.i18n import Language, get_text
from guarddoc.core.models import Severity, Threat
from guarddoc.scanners.base import BaseScanner


class ArchiveScanner(BaseScanner):
    """Scanner for archive formats (.zip, .tar, .tar.gz, etc.) to inspect internal structures."""

    ARCHIVE_EXTENSIONS: ClassVar[set[str]] = {
        ".zip",
        ".tar",
        ".gz",
        ".tgz",
        ".bz2",
        ".tbz2",
    }

    # Scripts heavily associated with droppers/malware campaigns
    HIGH_RISK_SCRIPTS: ClassVar[set[str]] = {
        ".vbs",
        ".vbe",
        ".js",
        ".jse",
        ".wsf",
        ".hta",
        ".scr",
        ".lnk",
        ".ps1",
    }

    # Standard executables (normal for software packages -> LOW severity)
    STANDARD_EXECUTABLES: ClassVar[set[str]] = {
        ".exe",
        ".msi",
        ".dll",
        ".so",
        ".dylib",
        ".bin",
        ".elf",
        ".app",
        ".sh",
        ".bat",
        ".cmd",
    }

    MAX_ENTRIES: ClassVar[int] = 10_000
    MAX_UNCOMPRESSED_RATIO: ClassVar[float] = 100.0

    @property
    def name(self) -> str:
        return "ArchiveScanner"

    def is_supported(self, file_path: Path, mime_type: str) -> bool:
        ext = file_path.suffix.lower()
        return (
            ext in self.ARCHIVE_EXTENSIONS
            or "zip" in mime_type
            or "tar" in mime_type
            or "compressed" in mime_type
        )

    def scan(
        self,
        file_path: Path,
        mime_type: str,
        lang: Language = Language.PL,
    ) -> list[Threat]:
        threats: list[Threat] = []

        if zipfile.is_zipfile(file_path):
            threats.extend(self._scan_zip(file_path, lang=lang))
        elif tarfile.is_tarfile(file_path):
            threats.extend(self._scan_tar(file_path, lang=lang))

        return threats

    def _evaluate_entry_name(self, filename: str, lang: Language) -> Threat | None:
        ext = Path(filename).suffix.lower()

        # 1. Zip Slip / Directory traversal (CRITICAL)
        if ".." in filename or filename.startswith("/"):
            return Threat(
                scanner_name=self.name,
                rule_id="ARCHIVE-ZIP-SLIP",
                title=get_text("ARCHIVE-ZIP-SLIP-TITLE", lang=lang),
                description=get_text("ARCHIVE-ZIP-SLIP-DESC", lang=lang),
                severity=Severity.CRITICAL,
                context={"suspicious_path": filename},
            )

        # 2. Double extension masquerading e.g. "invoice.pdf.exe" (CRITICAL)
        if re.search(
            r"\.(pdf|docx?|xlsx?|txt|jpg|png)\.(exe|scr|vbs|js|bat|cmd|hta|lnk)$",
            filename,
            re.IGNORECASE,
        ):
            return Threat(
                scanner_name=self.name,
                rule_id="ARCHIVE-DOUBLE-EXTENSION-SPOOF",
                title=get_text("ARCHIVE-DOUBLE-EXTENSION-TITLE", lang=lang),
                description=get_text("ARCHIVE-DOUBLE-EXTENSION-DESC", lang=lang),
                severity=Severity.CRITICAL,
                context={"detected_file": filename},
            )

        # 3. Phishing droppers & standalone scripts (HIGH)
        if ext in self.HIGH_RISK_SCRIPTS:
            return Threat(
                scanner_name=self.name,
                rule_id="ARCHIVE-SUSPICIOUS-SCRIPT",
                title=get_text("ARCHIVE-SUSPICIOUS-SCRIPT-TITLE", lang=lang),
                description=get_text("ARCHIVE-SUSPICIOUS-SCRIPT-DESC", lang=lang),
                severity=Severity.HIGH,
                context={"detected_file": filename},
            )

        # 4. Standard installer / binary file (LOW - purely informative)
        if ext in self.STANDARD_EXECUTABLES:
            return Threat(
                scanner_name=self.name,
                rule_id="ARCHIVE-CONTAINS-BINARY",
                title=get_text("ARCHIVE-CONTAINS-BINARY-TITLE", lang=lang),
                description=get_text("ARCHIVE-CONTAINS-BINARY-DESC", lang=lang),
                severity=Severity.LOW,
                context={"detected_file": filename},
            )

        return None

    def _scan_zip(self, file_path: Path, lang: Language) -> list[Threat]:
        threats: list[Threat] = []
        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                infolist = zf.infolist()

                if len(infolist) > self.MAX_ENTRIES:
                    threats.append(
                        Threat(
                            scanner_name=self.name,
                            rule_id="ARCHIVE-ZIP-BOMB",
                            title=get_text("ARCHIVE-BOMB-TITLE", lang=lang),
                            description=get_text("ARCHIVE-BOMB-DESC", lang=lang),
                            severity=Severity.HIGH,
                            context={"entries_count": len(infolist)},
                        )
                    )

                for info in infolist:
                    threat = self._evaluate_entry_name(info.filename, lang=lang)
                    if threat:
                        threats.append(threat)

                    # Zip Bomb ratio check
                    if info.compress_size > 0:
                        ratio = info.file_size / info.compress_size
                        if (
                            ratio > self.MAX_UNCOMPRESSED_RATIO
                            and info.file_size > 10 * 1024 * 1024
                        ):
                            threats.append(
                                Threat(
                                    scanner_name=self.name,
                                    rule_id="ARCHIVE-HIGH-COMPRESSION-RATIO",
                                    title=get_text("ARCHIVE-BOMB-TITLE", lang=lang),
                                    description=get_text("ARCHIVE-BOMB-DESC", lang=lang),
                                    severity=Severity.MEDIUM,
                                    context={"file": info.filename, "ratio": f"{ratio:.1f}:1"},
                                )
                            )
        except (zipfile.BadZipFile, OSError):
            return threats

        return threats

    def _scan_tar(self, file_path: Path, lang: Language) -> list[Threat]:
        threats: list[Threat] = []
        try:
            with tarfile.open(file_path, "r:*") as tf:
                members = tf.getmembers()

                for member in members:
                    threat = self._evaluate_entry_name(member.name, lang=lang)
                    if threat:
                        threats.append(threat)
        except (tarfile.TarError, OSError):
            return threats

        return threats

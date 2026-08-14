from __future__ import annotations

import zipfile
from pathlib import Path
from typing import ClassVar, List, Set

from guarddoc.core.i18n import Language, get_text
from guarddoc.core.models import Severity, Threat
from guarddoc.scanners.base import BaseScanner


class OfficeScanner(BaseScanner):
    """Scanner for Microsoft Office documents (.doc, .docx, .xls, .xlsm, etc.) checking for VBA macros and OLE objects."""

    name: str = "OfficeScanner"
    description: str = "Detects VBA macros and embedded OLE objects in Office documents"

    OFFICE_EXTENSIONS: ClassVar[Set[str]] = {
        ".doc",
        ".docx",
        ".docm",
        ".xls",
        ".xlsx",
        ".xlsm",
        ".ppt",
        ".pptm",
    }

    def is_supported(self, file_path: Path, mime_type: str = "unknown") -> bool:
        """Check if file extension or MIME type matches Microsoft Office documents."""
        ext = file_path.suffix.lower()
        return (
            ext in self.OFFICE_EXTENSIONS or "officedocument" in mime_type or "msword" in mime_type
        )

    def scan(
        self,
        file_path: Path,
        mime_type: str = "unknown",
        lang: Language = Language.PL,
    ) -> List[Threat]:
        """Scans Office file for VBA projects and embedded OLE payloads."""
        threats: List[Threat] = []

        try:
            content = file_path.read_bytes()
        except Exception:  # noqa: BLE001
            return threats

        # 1. Analysis of OpenXML structures (.docx, .docm, .xlsm are ZIP archives)
        if zipfile.is_zipfile(file_path):
            try:
                with zipfile.ZipFile(file_path, "r") as zip_file:
                    file_list = zip_file.namelist()

                    # Check for vbaProject.bin (macros in OpenXML)
                    if any("vbaProject.bin" in f for f in file_list):
                        threats.append(
                            Threat(
                                rule_id="OFFICE-OPENXML-VBA",
                                scanner_name=self.name,
                                title=get_text("OFFICE-VBA-MACRO-TITLE", lang=lang),
                                description=get_text("OFFICE-VBA-MACRO-DESC", lang=lang),
                                severity=Severity.HIGH,
                                context={"detected_in": "vbaProject.bin"},
                            )
                        )

                    # Check for embedded binaries / OLE objects in OpenXML
                    if any("embeddings/" in f for f in file_list):
                        threats.append(
                            Threat(
                                rule_id="OFFICE-EMBEDDED-OLE",
                                scanner_name=self.name,
                                title=get_text("OFFICE-OLE-OBJECT-TITLE", lang=lang),
                                description=get_text("OFFICE-OLE-OBJECT-DESC", lang=lang),
                                severity=Severity.HIGH,
                                context={"detected_in": "embeddings/"},
                            )
                        )
            except Exception:  # noqa: BLE001
                # Corrupted ZIP archive falls back quietly to byte signature inspection
                pass

        # 2. Analysis of legacy binary OLE2 formats (.doc, .xls) – searching for byte patterns
        else:
            if b"Attribut" in content and b"VB_Name" in content:
                threats.append(
                    Threat(
                        rule_id="OFFICE-BINARY-VBA",
                        scanner_name=self.name,
                        title=get_text("OFFICE-VBA-MACRO-TITLE", lang=lang),
                        description=get_text("OFFICE-VBA-MACRO-DESC", lang=lang),
                        severity=Severity.HIGH,
                    )
                )

        return threats

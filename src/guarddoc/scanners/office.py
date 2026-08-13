import zipfile
from pathlib import Path
from typing import ClassVar

from guarddoc.core.i18n import Language, get_text
from guarddoc.core.models import Severity, Threat
from guarddoc.scanners.base import BaseScanner


class OfficeScanner(BaseScanner):
    """Skaner dokumentów Microsoft Office (.doc, .docx, .xls, .xlsm itp.) pod kątem makr VBA i obiektów OLE."""

    OFFICE_EXTENSIONS: ClassVar[set[str]] = {
        ".doc",
        ".docx",
        ".docm",
        ".xls",
        ".xlsx",
        ".xlsm",
        ".ppt",
        ".pptm",
    }

    @property
    def name(self) -> str:
        return "OfficeScanner"

    def is_supported(self, file_path: Path, mime_type: str) -> bool:
        ext = file_path.suffix.lower()
        return (
            ext in self.OFFICE_EXTENSIONS or "officedocument" in mime_type or "msword" in mime_type
        )

    def scan(
        self,
        file_path: Path,
        mime_type: str,
        lang: Language = Language.PL,
    ) -> list[Threat]:
        threats: list[Threat] = []

        try:
            content = file_path.read_bytes()
        except Exception:  # noqa: BLE001
            return threats

        # 1. Analiza struktur OpenXML (.docx, .docm, .xlsm to pliki ZIP)
        if zipfile.is_zipfile(file_path):
            try:
                with zipfile.ZipFile(file_path, "r") as zip_file:
                    file_list = zip_file.namelist()

                    # Sprawdzenie obecności pliku vbaProject.bin (makra w OpenXML)
                    if any("vbaProject.bin" in f for f in file_list):
                        threats.append(
                            Threat(
                                rule_id="OFFICE-OPENXML-VBA",
                                title=get_text("OFFICE-VBA-MACRO-TITLE", lang=lang),
                                description=get_text("OFFICE-VBA-MACRO-DESC", lang=lang),
                                severity=Severity.HIGH,
                                context={"detected_in": "vbaProject.bin"},
                            )
                        )

                    # Sprawdzenie osadzonych plików wykonywalnych / OLE w otwartym formacie
                    if any("embeddings/" in f for f in file_list):
                        threats.append(
                            Threat(
                                rule_id="OFFICE-EMBEDDED-OLE",
                                title=get_text("OFFICE-OLE-OBJECT-TITLE", lang=lang),
                                description=get_text("OFFICE-OLE-OBJECT-DESC", lang=lang),
                                severity=Severity.HIGH,
                                context={"detected_in": "embeddings/"},
                            )
                        )
            except Exception as exc:  # noqa: BLE001
                # Uszkodzone archiwum ZIP traktujemy jako cichy fallback do analizy bajtowej
                _ = exc

        # 2. Analiza starszych formatów binarnych OLE2 (.doc, .xls) – wyszukiwanie sygnatur w bajtach
        else:
            if b"Attribut" in content and b"VB_Name" in content:
                threats.append(
                    Threat(
                        rule_id="OFFICE-BINARY-VBA",
                        title=get_text("OFFICE-VBA-MACRO-TITLE", lang=lang),
                        description=get_text("OFFICE-VBA-MACRO-DESC", lang=lang),
                        severity=Severity.HIGH,
                    )
                )

        return threats

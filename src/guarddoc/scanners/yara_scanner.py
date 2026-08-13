from pathlib import Path
from typing import Any

import yara

from guarddoc.core.i18n import Language
from guarddoc.core.models import Severity, Threat
from guarddoc.scanners.base import BaseScanner


class YaraScanner(BaseScanner):
    """Skaner wykorzystujący reguły YARA z podanego katalogu do detekcji złożonych wzorców malware."""

    def __init__(self, rules_dir: Path | str = "rules") -> None:
        self.rules_dir = Path(rules_dir)
        self.compiled_rules: yara.Rules | None = None
        self._compile_rules()

    def _compile_rules(self) -> None:
        """Kompiluje wszystkie pliki .yar / .yara z katalogu reguł."""
        if not self.rules_dir.exists() or not self.rules_dir.is_dir():
            return

        rule_files: dict[str, str] = {}
        for idx, file_path in enumerate(self.rules_dir.glob("**/*")):
            if file_path.suffix.lower() in (".yar", ".yara"):
                rule_files[f"namespace_{idx}"] = str(file_path)

        if rule_files:
            try:
                self.compiled_rules = yara.compile(filepaths=rule_files)
            except yara.Error:
                # W przypadku błędu kompilacji reguł ustawiamy brak reguł
                self.compiled_rules = None

    @property
    def name(self) -> str:
        return "YaraScanner"

    def is_supported(self, file_path: Path, mime_type: str) -> bool:
        # Skaner YARA działa uniwersalnie na dowolnym pliku binarnym lub tekstowym
        return self.compiled_rules is not None

    def scan(
        self,
        file_path: Path,
        mime_type: str,
        lang: Language = Language.PL,
    ) -> list[Threat]:
        threats: list[Threat] = []

        if not self.compiled_rules:
            return threats

        try:
            matches = self.compiled_rules.match(str(file_path))

            for match in matches:
                meta: dict[str, Any] = match.meta
                rule_name = match.rule

                # Pobieranie metadanych z reguły YARA (z fallbackami)
                title = meta.get("title", f"Wykryto dopasowanie reguły YARA: {rule_name}")
                description = meta.get("description", "Plik pasuje do zdefiniowanego wzorca YARA.")
                raw_severity = str(meta.get("severity", "HIGH")).upper()

                # Mapowanie napisu na Enum Severity
                try:
                    severity = Severity[raw_severity]
                except KeyError:
                    severity = Severity.HIGH

                matched_strings = [
                    str(instance.matched_data)
                    for string_match in match.strings
                    for instance in string_match.instances
                ]

                threats.append(
                    Threat(
                        rule_id=f"YARA-{rule_name.upper()}",
                        title=title,
                        description=str(description),
                        severity=severity,
                        context={
                            "rule_name": rule_name,
                            "tags": match.tags,
                            "matches_count": len(matched_strings),
                        },
                    )
                )

        except Exception as exc:  # noqa: BLE001 - celowy fallback przy błędach I/O biblioteki yara
            err_title = (
                "Błąd silnika YARA podczas skanowania"
                if lang == Language.PL
                else "YARA engine error during scan"
            )
            err_desc = (
                "Nie udało się ukończyć skanowania regułami YARA."
                if lang == Language.PL
                else "Failed to complete scanning with YARA rules."
            )

            threats.append(
                Threat(
                    rule_id="YARA-SCAN-ERR",
                    title=err_title,
                    description=err_desc,
                    severity=Severity.LOW,
                    context={"error": str(exc)},
                )
            )

        return threats

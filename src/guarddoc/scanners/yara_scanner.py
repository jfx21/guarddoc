from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Union

try:
    import yara

    YARA_AVAILABLE = True
except (ImportError, Exception):
    yara = None  # type: ignore[assignment]
    YARA_AVAILABLE = False

from guarddoc.core.i18n import Language
from guarddoc.core.models import Severity, Threat
from guarddoc.scanners.base import BaseScanner


class YaraScanner(BaseScanner):
    """Scanner leveraging YARA rules from a directory to detect complex malware patterns."""

    name: str = "YaraScanner"
    description: str = "Matches file contents against compiled YARA rule sets"

    def __init__(self, rules_dir: Union[Path, str] = "rules") -> None:
        self.rules_dir = Path(rules_dir)
        self.compiled_rules: Optional[Any] = None
        if self.is_available:
            self._compile_rules()

    @property
    def is_available(self) -> bool:
        """Checks if yara-python dependency is available."""
        return YARA_AVAILABLE

    def _compile_rules(self) -> None:
        """Compiles all .yar and .yara files found in the rules directory."""
        if not self.rules_dir.exists() or not self.rules_dir.is_dir() or not YARA_AVAILABLE:
            return

        rule_files: Dict[str, str] = {}
        for idx, file_path in enumerate(self.rules_dir.glob("**/*")):
            if file_path.suffix.lower() in (".yar", ".yara"):
                rule_files[f"namespace_{idx}"] = str(file_path)

        if rule_files:
            try:
                self.compiled_rules = yara.compile(filepaths=rule_files)
            except Exception:
                # In case of syntax or compilation errors, disable active rules
                self.compiled_rules = None

    def is_supported(self, file_path: Path, mime_type: str = "unknown") -> bool:
        """YARA rules can scan any file format if rules are successfully compiled."""
        return self.compiled_rules is not None

    def scan(
        self,
        file_path: Path,
        mime_type: str = "unknown",
        lang: Language = Language.PL,
    ) -> List[Threat]:
        """Scans the target file against compiled YARA rules."""
        threats: List[Threat] = []

        if not self.compiled_rules:
            return threats

        try:
            matches = self.compiled_rules.match(str(file_path))

            for match in matches:
                meta: Dict[str, Any] = match.meta
                rule_name = match.rule

                # Extract metadata from YARA rule
                title = meta.get(
                    "title",
                    f"Wykryto dopasowanie reguły YARA: {rule_name}"
                    if lang == Language.PL
                    else f"YARA rule matched: {rule_name}",
                )
                description = meta.get(
                    "description",
                    "Plik pasuje do zdefiniowanego wzorca YARA."
                    if lang == Language.PL
                    else "File matches the defined YARA pattern.",
                )
                raw_severity = str(meta.get("severity", "HIGH")).upper()

                try:
                    severity = Severity.from_str(raw_severity)
                except ValueError:
                    severity = Severity.HIGH

                matched_strings = [
                    str(instance.matched_data)
                    for string_match in match.strings
                    for instance in string_match.instances
                ]

                threats.append(
                    Threat(
                        rule_id=f"YARA-{rule_name.upper()}",
                        scanner_name=self.name,
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

        except Exception as exc:  # noqa: BLE001
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
                    scanner_name=self.name,
                    title=err_title,
                    description=err_desc,
                    severity=Severity.LOW,
                    context={"error": str(exc)},
                )
            )

        return threats

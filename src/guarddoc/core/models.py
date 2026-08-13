from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Poziom istotności zagrożenia."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Threat(BaseModel):
    """Pojedyncza detekcja (wzorzec/anomalia) wykryta w pliku."""

    rule_id: str = Field(..., description="Unikalny identyfikator reguły/detekcji, np. PDF-JS-001")
    title: str = Field(..., description="Krótkie podsumowanie wykrytego elementu")
    description: str = Field(..., description="Szczegółowy opis potencjalnego zagrożenia")
    severity: Severity = Field(..., description="Poziom krytyczności")
    context: dict[str, Any] = Field(
        default_factory=dict,
        description="Dodatkowe metadane (np. numer linii, offset bajtowy, dopasowany ciąg znaków)",
    )


class ScanResult(BaseModel):
    """Ostateczny, zagregowany wynik skanowania danego pliku."""

    file_path: Path
    file_name: str
    file_size_bytes: int
    mime_type: str = "unknown"
    is_safe: bool = True
    max_severity: Severity = Severity.INFO
    threats: list[Threat] = Field(default_factory=list)
    errors: list[str] = Field(
        default_factory=list,
        description="Lista ew. błędów parsowania/skanowania, które nie przerwały pracy silnika",
    )

    def add_threat(self, threat: Threat) -> None:
        """Dodaje zagrożenie i aktualizuje ogólny stan bezpieczeństwa pliku."""
        self.threats.append(threat)
        self.is_safe = False

        # Aktualizacja najwyższego poziomu ważności
        severity_weights = {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        if severity_weights[threat.severity] > severity_weights[self.max_severity]:
            self.max_severity = threat.severity

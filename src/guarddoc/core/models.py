from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, computed_field


class Severity(str, Enum):
    """Severity levels ordered by weight for comparison and clean JSON serialization."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    def __lt__(self, other: Severity | Any) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) < order.index(other)

    def __le__(self, other: Severity | Any) -> bool:
        return self < other or self == other

    def __gt__(self, other: Severity | Any) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) > order.index(other)

    def __ge__(self, other: Severity | Any) -> bool:
        return self > other or self == other

    @classmethod
    def from_str(cls, value: str) -> Severity:
        try:
            return cls[value.upper()]
        except KeyError:
            raise ValueError(f"Invalid severity level: '{value}'")


class Threat(BaseModel):
    """A single detection or threat identified by a scanner."""

    model_config = ConfigDict(frozen=True)

    rule_id: str = Field(description="Unique rule identifier (e.g. MIME-SPOOF-CRITICAL)")
    scanner_name: str = Field(description="Name of the scanner that produced this threat")
    title: str = Field(description="Short title of the detected issue")
    description: str = Field(description="Detailed explanation of the anomaly")
    severity: Severity = Field(default=Severity.LOW, description="Severity level of the threat")
    context: Optional[Dict[str, Any]] = Field(
        default=None, description="Additional contextual metadata"
    )


class ScanResult(BaseModel):
    """Aggregated analysis result for a file across all executed scanners."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    file_path: Path = Field(description="Path to the analyzed file")
    file_name: Optional[str] = Field(default=None, description="Base name of the file")
    file_size_bytes: Optional[int] = Field(default=None, description="Size of the file in bytes")
    mime_type: Optional[str] = Field(default=None, description="Detected MIME type")
    threats: List[Threat] = Field(default_factory=list, description="List of detected threats")
    errors: List[str] = Field(default_factory=list, description="Execution errors")

    def __init__(self, **data: Any) -> None:
        super().__init__(**data)
        if self.file_name is None and self.file_path:
            self.file_name = self.file_path.name
        if self.file_size_bytes is None and self.file_path and self.file_path.exists():
            try:
                self.file_size_bytes = self.file_path.stat().st_size
            except Exception:
                pass

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_safe(self) -> bool:
        """Returns True if no threats and no fatal errors were found."""
        return len(self.threats) == 0 and len(self.errors) == 0

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_clean(self) -> bool:
        """Alias for is_safe."""
        return self.is_safe

    @computed_field  # type: ignore[prop-decorator]
    @property
    def max_severity(self) -> Optional[Severity]:
        """Returns the highest severity level found in the threats list."""
        if not self.threats:
            return None
        return max(t.severity for t in self.threats)

    def add_threat(self, threat: Threat) -> None:
        """Helper method to append a threat to the result."""
        self.threats.append(threat)

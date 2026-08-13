from abc import ABC, abstractmethod
from pathlib import Path

from guarddoc.core.i18n import Language
from guarddoc.core.models import Threat


class BaseScanner(ABC):
    """Klasa bazowa dla wszystkich skanerów w systemie GuardDoc."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Nazwa skanera."""

    def is_supported(self, file_path: Path, mime_type: str) -> bool:
        """Domyślnie skaner obsługuje każdy plik (chyba że klasa pochodna nadpisze tę metodę)."""
        return True

    @abstractmethod
    def scan(
        self,
        file_path: Path,
        mime_type: str,
        lang: Language = Language.PL,
    ) -> list[Threat]:
        """Wykonuje skanowanie pliku i zwraca listę zagrożeń."""

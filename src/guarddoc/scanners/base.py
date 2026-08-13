from abc import ABC, abstractmethod
from pathlib import Path

from guarddoc.core.models import Threat


class BaseScanner(ABC):
    """Abstrakcyjna klasa bazowa dla wszystkich modułów skanujących."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Nazwa skanera używana w logach i interfejsie."""

    @abstractmethod
    def is_supported(self, file_path: Path, mime_type: str) -> bool:
        """Określa, czy ten skaner jest w stanie przeanalizować dany plik."""

    @abstractmethod
    def scan(self, file_path: Path, mime_type: str) -> list[Threat]:
        """Główna logika skanująca plik. Zwraca listę obiektów Threat."""

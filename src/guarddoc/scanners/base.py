from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List

from guarddoc.core.i18n import Language
from guarddoc.core.models import Threat


class BaseScanner(ABC):
    """Abstract base class for all scanning modules in GuardDoc."""

    name: str = "BaseScanner"
    description: str = "Base scanner interface"

    @property
    def is_available(self) -> bool:
        """Check if required system or Python dependencies are available.

        Should be overridden by scanners requiring optional third-party libraries
        (e.g., libmagic, yara-python).
        """
        return True

    def is_supported(self, file_path: Path, mime_type: str = "unknown") -> bool:
        """Check whether this scanner supports the given file and MIME type.

        Defaults to True for general scanners. Specialized scanners (PDF, Office, etc.)
        should override this to avoid unnecessary processing.

        :param file_path: Path to the target file.
        :param mime_type: Detected or probed MIME type.
        :return: True if the scanner can analyze the file, False otherwise.
        """
        return True

    @abstractmethod
    def scan(
        self,
        file_path: Path,
        mime_type: str = "unknown",
        lang: Language = Language.PL,
    ) -> List[Threat]:
        """Scans the target file and returns a list of detected threats.

        :param file_path: Resolved path to the target file.
        :param mime_type: Probed MIME type string.
        :param lang: Output language for threat titles and descriptions.
        :return: List of Threat instances.
        """
        pass

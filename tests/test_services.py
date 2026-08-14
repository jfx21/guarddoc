from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from guarddoc.core.engine import Engine
from guarddoc.core.i18n import Language
from guarddoc.core.models import ScanResult, Threat
from guarddoc.core.services import (
    build_engine,
    get_default_scanners,
    scan_single_file,
)
from guarddoc.scanners.base import BaseScanner
from guarddoc.scanners.mime import MimeScanner
from guarddoc.scanners.office import OfficeScanner
from guarddoc.scanners.pdf import PdfScanner
from guarddoc.scanners.text import TextScanner
from guarddoc.scanners.yara_scanner import YaraScanner


class DummyCustomScanner(BaseScanner):
    name = "DummyCustomScanner"
    description = "Custom test scanner"

    def scan(self, file_path: Path) -> list[Threat]:
        return []


class TestGetDefaultScanners:
    def test_returns_all_five_standard_scanners(self, tmp_path: Path) -> None:
        scanners = get_default_scanners(rules_dir=tmp_path)
        assert len(scanners) == 5
        scanner_types = [type(s) for s in scanners]
        assert MimeScanner in scanner_types
        assert PdfScanner in scanner_types
        assert TextScanner in scanner_types
        assert OfficeScanner in scanner_types
        assert YaraScanner in scanner_types


class TestBuildEngine:
    def test_build_engine_with_defaults(self, tmp_path: Path) -> None:
        engine = build_engine(rules_dir=tmp_path)
        assert isinstance(engine, Engine)
        assert len(engine.scanners) == 5

    def test_build_engine_with_custom_scanners(self) -> None:
        custom_list = [DummyCustomScanner()]
        engine = build_engine(custom_scanners=custom_list)
        assert isinstance(engine, Engine)
        assert len(engine.scanners) == 1
        assert isinstance(engine.scanners[0], DummyCustomScanner)


class TestScanSingleFile:
    @pytest.fixture
    def sample_file(self, tmp_path: Path) -> Path:
        target = tmp_path / "sample.pdf"
        target.write_bytes(b"%PDF-1.4\n...")
        return target

    def test_scan_single_file_extracts_mime_when_available(self, sample_file: Path) -> None:
        mock_mime_scanner = MagicMock(spec=MimeScanner)
        mock_mime_scanner.is_available = True
        mock_mime_scanner.get_mime_type.return_value = "application/pdf"

        mock_engine = MagicMock(spec=Engine)
        mock_engine.scanners = [mock_mime_scanner]
        expected_result = ScanResult(file_path=sample_file.resolve(), mime_type="application/pdf")
        mock_engine.scan_file.return_value = expected_result

        result = scan_single_file(mock_engine, sample_file, lang=Language.EN)

        mock_mime_scanner.get_mime_type.assert_called_once_with(sample_file.resolve())
        mock_engine.scan_file.assert_called_once_with(
            sample_file.resolve(),
            mime_type="application/pdf",
            lang=Language.EN,
        )
        assert result == expected_result

    def test_scan_single_file_when_mime_scanner_is_unavailable(self, sample_file: Path) -> None:
        mock_mime_scanner = MagicMock(spec=MimeScanner)
        mock_mime_scanner.is_available = False

        mock_engine = MagicMock(spec=Engine)
        mock_engine.scanners = [mock_mime_scanner]

        scan_single_file(mock_engine, sample_file, lang=Language.PL)

        mock_mime_scanner.get_mime_type.assert_not_called()
        mock_engine.scan_file.assert_called_once_with(
            sample_file.resolve(),
            mime_type=None,
            lang=Language.PL,
        )

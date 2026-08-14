import zipfile
from pathlib import Path

from guarddoc.core.i18n import Language
from guarddoc.core.models import Severity
from guarddoc.scanners.office import OfficeScanner


def test_office_scanner_detects_vba_in_openxml(tmp_path: Path) -> None:
    docx_file = tmp_path / "document.docm"
    with zipfile.ZipFile(docx_file, "w") as zf:
        zf.writestr("word/vbaProject.bin", b"VBA macro binary content")
        zf.writestr("[Content_Types].xml", b"<Types></Types>")

    scanner = OfficeScanner()
    assert scanner.is_supported(docx_file, "application/vnd.ms-word")

    threats = scanner.scan(docx_file, lang=Language.EN)
    assert len(threats) == 1
    assert threats[0].rule_id == "OFFICE-OPENXML-VBA"
    assert threats[0].severity == Severity.HIGH
    assert threats[0].scanner_name == "OfficeScanner"


def test_office_scanner_detects_embedded_ole(tmp_path: Path) -> None:
    xlsx_file = tmp_path / "sheet.xlsm"
    with zipfile.ZipFile(xlsx_file, "w") as zf:
        zf.writestr("xl/embeddings/oleObject1.bin", b"Embedded OLE binary")

    scanner = OfficeScanner()
    threats = scanner.scan(xlsx_file, lang=Language.PL)

    assert len(threats) == 1
    assert threats[0].rule_id == "OFFICE-EMBEDDED-OLE"
    assert threats[0].severity == Severity.HIGH


def test_office_scanner_detects_binary_vba(tmp_path: Path) -> None:
    doc_file = tmp_path / "legacy.doc"
    # Create fake legacy binary content matching signatures
    doc_file.write_bytes(b"\xd0\xcf\x11\xe0 Attribut ... VB_Name ... payload")

    scanner = OfficeScanner()
    threats = scanner.scan(doc_file, lang=Language.EN)

    assert len(threats) == 1
    assert threats[0].rule_id == "OFFICE-BINARY-VBA"
    assert threats[0].severity == Severity.HIGH


def test_office_scanner_clean_file(tmp_path: Path) -> None:
    clean_docx = tmp_path / "clean.docx"
    with zipfile.ZipFile(clean_docx, "w") as zf:
        zf.writestr("word/document.xml", b"<xml>Clean document</xml>")

    scanner = OfficeScanner()
    threats = scanner.scan(clean_docx, lang=Language.EN)
    assert len(threats) == 0

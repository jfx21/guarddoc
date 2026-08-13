import zipfile
from pathlib import Path

from guarddoc.scanners.office import OfficeScanner


def test_office_scanner_detects_vba_in_docm(tmp_path: Path) -> None:
    docm_file = tmp_path / "invoice_with_macro.docm"

    # Tworzymy plik ZIP imitujący plik .docm z projektem VBA
    with zipfile.ZipFile(docm_file, "w") as zf:
        zf.writestr("word/vbaProject.bin", b"fake_vba_macro_stream_content")
        zf.writestr("word/document.xml", b"<xml>test</xml>")

    scanner = OfficeScanner()
    threats = scanner.scan(docm_file, mime_type="application/vnd.ms-word.document.macroEnabled.12")

    assert len(threats) == 1
    assert threats[0].rule_id == "OFFICE-OPENXML-VBA"


def test_office_scanner_clean_file(tmp_path: Path) -> None:
    clean_docx = tmp_path / "clean.docx"

    with zipfile.ZipFile(clean_docx, "w") as zf:
        zf.writestr("word/document.xml", b"<xml>clean document</xml>")

    scanner = OfficeScanner()
    threats = scanner.scan(
        clean_docx,
        mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    )

    assert len(threats) == 0

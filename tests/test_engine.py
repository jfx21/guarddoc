from pathlib import Path

from guarddoc.core.engine import Engine
from guarddoc.core.i18n import Language
from guarddoc.scanners.mime import MimeScanner


def test_engine_passes_lang_to_scanners(tmp_path: Path) -> None:
    fake_pdf = tmp_path / "invoice.pdf"
    fake_pdf.write_text("#!/bin/bash\necho 'Test'", encoding="utf-8")

    engine = Engine()
    engine.register_scanner(MimeScanner())

    result = engine.scan_file(fake_pdf, mime_type="text/x-shellscript", lang=Language.EN)

    assert result.is_safe is False
    assert len(result.threats) == 1
    assert "Executable file masquerading" in result.threats[0].title

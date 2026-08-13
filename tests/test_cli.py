import json
from pathlib import Path

from typer.testing import CliRunner

from guarddoc.cli import app

runner = CliRunner()


def test_cli_scan_recursive_directory(tmp_path: Path) -> None:
    # Tworzymy strukturę podkatalogów
    sub_dir = tmp_path / "subdir"
    sub_dir.mkdir()

    file1 = tmp_path / "clean.txt"
    file1.write_text("Czysty plik", encoding="utf-8")

    file2 = sub_dir / "bad.txt"
    file2.write_text("Dokument \u202etxt.exe", encoding="utf-8")

    # Skanowanie bez -r
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 0, f"Error output: {result.stdout}"
    assert "bad.txt" not in result.stdout

    # Skanowanie z -r
    result_rec = runner.invoke(app, ["scan", str(tmp_path), "-r"])
    assert result_rec.exit_code == 0, f"Error output: {result_rec.stdout}"
    assert "bad.txt" in result_rec.stdout


def test_cli_json_export(tmp_path: Path) -> None:
    test_file = tmp_path / "test.txt"
    test_file.write_text("#!/bin/bash\nrm -rf /", encoding="utf-8")

    output_json = tmp_path / "report.json"

    result = runner.invoke(app, ["scan", str(test_file), "--json", "-o", str(output_json)])
    assert result.exit_code == 0, f"Error output: {result.stdout}"

    assert output_json.exists()
    data = json.loads(output_json.read_text(encoding="utf-8"))

    assert len(data) == 1
    assert data[0]["is_safe"] is False

    detected_rule_ids = [threat["rule_id"] for threat in data[0]["threats"]]
    assert "MIME-SPOOF-CRITICAL" in detected_rule_ids
    assert "TXT-SHEBANG" in detected_rule_ids

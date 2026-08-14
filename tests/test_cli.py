import json
from pathlib import Path

from typer.testing import CliRunner

from guarddoc.cli import app

runner = CliRunner()


def test_cli_scan_nonexistent_file(tmp_path: Path) -> None:
    missing_file = tmp_path / "missing.txt"
    result = runner.invoke(app, ["scan", str(missing_file)])
    assert result.exit_code == 1
    normalized_stdout = " ".join(result.stdout.split())
    assert "nie istnieje" in normalized_stdout or "does not exist" in normalized_stdout


def test_cli_scan_single_file(tmp_path: Path) -> None:
    sample_file = tmp_path / "test.txt"
    sample_file.write_text("Clean test content")

    result = runner.invoke(app, ["scan", str(sample_file), "--lang", "en"])
    assert result.exit_code == 0
    assert "File Metadata" in result.stdout
    assert "No threats or suspicious characters" in result.stdout


def test_cli_scan_json_output(tmp_path: Path) -> None:
    sample_file = tmp_path / "test.txt"
    sample_file.write_text("Clean test content")

    result = runner.invoke(app, ["scan", str(sample_file), "--json"])
    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert isinstance(parsed, list)
    assert len(parsed) == 1
    assert parsed[0]["file_path"].endswith("test.txt")


def test_cli_scan_directory_recursive(tmp_path: Path) -> None:
    sub = tmp_path / "subdir"
    sub.mkdir()
    (sub / "nested.txt").write_text("Hello")
    (tmp_path / "root.txt").write_text("World")

    result = runner.invoke(app, ["scan", str(tmp_path), "--recursive", "--lang", "pl"])
    assert result.exit_code == 0
    assert "Wyniki skanowania katalogu" in result.stdout

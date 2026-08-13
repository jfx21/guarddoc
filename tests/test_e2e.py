import json
from pathlib import Path

from typer.testing import CliRunner

from guarddoc.cli import app

runner = CliRunner()
SAMPLES_DIR = Path(__file__).parent / "samples"


def test_e2e_scan_clean_file_json() -> None:
    clean_file = SAMPLES_DIR / "clean_document.txt"

    result = runner.invoke(app, ["scan", str(clean_file), "--json"])
    assert result.exit_code == 0, f"Error stdout: {result.stdout}"

    data = json.loads(result.stdout)
    assert len(data) == 1
    assert data[0]["is_safe"] is True
    assert len(data[0]["threats"]) == 0


def test_e2e_scan_spoofed_pdf_json() -> None:
    spoofed_file = SAMPLES_DIR / "spoofed_exec.pdf"

    result = runner.invoke(app, ["scan", str(spoofed_file), "--json"])
    assert result.exit_code == 0, f"Error stdout: {result.stdout}"

    data = json.loads(result.stdout)
    assert len(data) == 1
    assert data[0]["is_safe"] is False
    assert data[0]["max_severity"] == "CRITICAL"

    rule_ids = [t["rule_id"] for t in data[0]["threats"]]
    assert "MIME-SPOOF-CRITICAL" in rule_ids


def test_e2e_scan_directory_recursive_json(tmp_path: Path) -> None:
    output_report = tmp_path / "e2e_report.json"

    result = runner.invoke(
        app, ["scan", str(SAMPLES_DIR), "-r", "--json", "-o", str(output_report)]
    )
    assert result.exit_code == 0, f"Error stdout: {result.stdout}"
    assert output_report.exists()

    data = json.loads(output_report.read_text(encoding="utf-8"))
    assert len(data) >= 7

    unsafe_results = [r for r in data if not r["is_safe"]]
    assert len(unsafe_results) >= 5


def test_e2e_scan_yara_eicar_matching() -> None:
    eicar_file = SAMPLES_DIR / "eicar_sample.txt"

    result = runner.invoke(app, ["scan", str(eicar_file), "--json"])
    assert result.exit_code == 0, f"Error stdout: {result.stdout}"

    data = json.loads(result.stdout)
    assert len(data) == 1
    assert data[0]["is_safe"] is False

    rule_ids = [t["rule_id"] for t in data[0]["threats"]]
    assert "YARA-EICAR_TEST_FILE" in rule_ids

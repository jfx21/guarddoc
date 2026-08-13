from pathlib import Path

SAMPLES_DIR = Path(__file__).parent / "samples"


def generate_samples() -> None:
    SAMPLES_DIR.mkdir(exist_ok=True)

    # 1. Clean TXT
    (SAMPLES_DIR / "clean_document.txt").write_text(
        "To jest w pełni bezpieczny dokument tekstowy.", encoding="utf-8"
    )

    # 2. Clean PDF
    valid_pdf_bytes = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n"
        b"xref\n0 3\n"
        b"0000000000 65535 f \n"
        b"0000000009 00000 n \n"
        b"0000000058 00000 n \n"
        b"trailer\n<< /Size 3 /Root 1 0 R >>\n"
        b"startxref\n109\n"
        b"%%EOF\n"
    )
    (SAMPLES_DIR / "clean_sample.pdf").write_bytes(valid_pdf_bytes)

    # 3. Extension Spoofing PDF (Bash Executable)
    (SAMPLES_DIR / "spoofed_exec.pdf").write_text(
        "#!/bin/bash\necho 'Fake PDF Execution'", encoding="utf-8"
    )

    # 4. Malicious PDF (/JS & /OpenAction)
    malicious_pdf_bytes = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /OpenAction 2 0 R /JS (app.alert('XSS')) >>\nendobj\n"
        b"xref\n0 2\n0000000000 65535 f \n0000000009 00000 n \n"
        b"trailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n80\n%%EOF"
    )
    (SAMPLES_DIR / "malicious_js.pdf").write_bytes(malicious_pdf_bytes)

    # 5. Unicode RTLO Spoof TXT
    (SAMPLES_DIR / "rtlo_spoof.txt").write_text("Plik raportu \u202etxt.exe", encoding="utf-8")

    # 6. Shebang Script TXT
    (SAMPLES_DIR / "shebang_script.txt").write_text(
        "#!/bin/bash\nrm -rf /tmp/test", encoding="utf-8"
    )

    # 7. EICAR Test File
    (SAMPLES_DIR / "eicar_sample.txt").write_text(
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        encoding="utf-8",
    )


if __name__ == "__main__":
    generate_samples()

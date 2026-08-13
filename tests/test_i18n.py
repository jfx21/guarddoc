from guarddoc.core.i18n import Language, get_text


def test_i18n_translation_pl_and_en() -> None:
    title_pl = get_text("MIME-SPOOF-TITLE", lang=Language.PL)
    assert title_pl == "Wykryto plik wykonywalny podszywający się pod dokument!"

    title_en = get_text("MIME-SPOOF-TITLE", lang=Language.EN)
    assert title_en == "Executable file masquerading as a document detected!"


def test_i18n_formatting_with_kwargs() -> None:
    desc_en = get_text(
        "MIME-SPOOF-DESC",
        lang=Language.EN,
        ext=".pdf",
        mime="text/x-shellscript",
    )
    assert ".pdf" in desc_en
    assert "text/x-shellscript" in desc_en

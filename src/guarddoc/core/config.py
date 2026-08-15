import os
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from guarddoc.core.i18n import Language


def get_config_dir() -> Path:
    """Returns standard XDG config directory for guarddoc (~/.config/guarddoc)."""
    xdg_config = os.getenv("XDG_CONFIG_HOME")
    if xdg_config:
        base_dir = Path(xdg_config)
    else:
        base_dir = Path.home() / ".config"
    return base_dir / "guarddoc"


def get_config_path() -> Path:
    return get_config_dir() / "config.toml"


@dataclass
class AppConfig:
    lang: Language = Language.PL
    rules_dir: str = "rules"

    @classmethod
    def load(cls) -> "AppConfig":
        config_path = get_config_path()
        if not config_path.exists():
            return cls()

        try:
            with open(config_path, "rb") as f:
                data: dict[str, Any] = tomllib.load(f)

            raw_lang = data.get("lang", "pl").lower()
            lang = Language.EN if raw_lang == "en" else Language.PL
            rules_dir = str(data.get("rules_dir", "rules"))

            return cls(lang=lang, rules_dir=rules_dir)
        except Exception:  # noqa: BLE001
            return cls()

    def save(self) -> None:
        config_dir = get_config_dir()
        config_dir.mkdir(parents=True, exist_ok=True)
        config_path = get_config_path()

        toml_content = (
            f"# GuardDoc Configuration File\n"
            f'lang = "{self.lang.value}"\n'
            f'rules_dir = "{self.rules_dir}"\n'
        )
        config_path.write_text(toml_content, encoding="utf-8")

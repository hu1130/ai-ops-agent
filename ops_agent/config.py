from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class AppConfig:
    raw: dict[str, Any]
    base_dir: Path

    @property
    def app(self) -> dict[str, Any]:
        return self.raw.get("app", {})

    @property
    def http_checks(self) -> list[dict[str, Any]]:
        return list(self.raw.get("http_checks", []))

    @property
    def json_checks(self) -> list[dict[str, Any]]:
        return list(self.raw.get("json_checks", []))

    @property
    def server_checks(self) -> dict[str, Any]:
        return self.raw.get("server_checks", {})

    @property
    def log_checks(self) -> list[dict[str, Any]]:
        return list(self.raw.get("log_checks", []))

    @property
    def ai(self) -> dict[str, Any]:
        return self.raw.get("ai", {})

    @property
    def alerts(self) -> dict[str, Any]:
        return self.raw.get("alerts", {})

    def resolve_path(self, value: str) -> Path:
        path = Path(value)
        if path.is_absolute():
            return path
        return self.base_dir / path


def load_config(path: str | Path) -> AppConfig:
    config_path = Path(path).resolve()
    with config_path.open("r", encoding="utf-8") as handle:
        raw = json.load(handle)
    return AppConfig(raw=raw, base_dir=config_path.parent)

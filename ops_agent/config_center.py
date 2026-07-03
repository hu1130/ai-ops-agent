from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
from typing import Any

from ops_agent.config import AppConfig


SECRET_MARKERS = (
    "api_key",
    "apikey",
    "authorization",
    "auth_code",
    "password",
    "secret",
    "smtp_password",
    "token",
)


def config_snapshot(config: AppConfig) -> dict[str, Any]:
    return {
        "configured": config.config_path is not None,
        "config_path": str(config.config_path) if config.config_path else "",
        "sections": sorted(str(key) for key in config.raw.keys()),
        "config": redact_secrets(config.raw),
    }


def validate_config_candidate(config: AppConfig, candidate: dict[str, Any]) -> dict[str, Any]:
    errors = validate_updated_config(candidate, config)
    return {
        "valid": not errors,
        "errors": errors,
        "changed_sections": changed_sections(config.raw, candidate),
        "config": redact_secrets(candidate),
    }


def backup_config(config: AppConfig, reason: str = "manual") -> dict[str, Any]:
    config_path = require_config_path(config)
    backup_path = next_backup_path(config_path, safe_reason(reason))
    shutil.copy2(config_path, backup_path)
    return backup_info(backup_path)


def apply_config_update(config: AppConfig, candidate: dict[str, Any], reason: str = "apply") -> dict[str, Any]:
    config_path = require_config_path(config)
    validation = validate_config_candidate(config, candidate)
    if not validation["valid"]:
        raise ValueError("config validation failed: " + "; ".join(validation["errors"]))

    backup = backup_config(config, reason=f"before-{safe_reason(reason)}")
    temp_path = next_temp_path(config_path)
    temp_path.write_text(json.dumps(candidate, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temp_path.replace(config_path)
    config.raw.clear()
    config.raw.update(deepcopy(candidate))
    return {
        "status": "applied",
        "backup": backup,
        "validation": {"valid": True, "errors": []},
        "changed_sections": validation["changed_sections"],
        "config": redact_secrets(candidate),
    }


def restore_config_backup(config: AppConfig, backup_name: str) -> dict[str, Any]:
    config_path = require_config_path(config)
    backup_path = resolve_backup_path(config_path, backup_name)
    restored = load_json_object(backup_path)
    validation = validate_config_candidate(config, restored)
    if not validation["valid"]:
        raise ValueError("backup config validation failed: " + "; ".join(validation["errors"]))

    current_backup = backup_config(config, reason="before-restore")
    temp_path = next_temp_path(config_path)
    temp_path.write_text(json.dumps(restored, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temp_path.replace(config_path)
    config.raw.clear()
    config.raw.update(deepcopy(restored))
    return {
        "status": "restored",
        "restored_from": backup_info(backup_path),
        "backup": current_backup,
        "validation": {"valid": True, "errors": []},
        "changed_sections": validation["changed_sections"],
        "config": redact_secrets(restored),
    }


def list_config_backups(config: AppConfig) -> dict[str, Any]:
    config_path = require_config_path(config)
    backups = [backup_info(path) for path in config_path.parent.glob(f"{config_path.name}.bak*") if path.is_file()]
    backups.sort(key=lambda item: str(item.get("modified_at") or ""), reverse=True)
    return {"config_path": str(config_path), "backups": backups}


def candidate_from_body(body: dict[str, Any]) -> dict[str, Any]:
    candidate = body.get("config")
    if not isinstance(candidate, dict):
        raise ValueError("config object is required")
    return deepcopy(candidate)


def require_config_path(config: AppConfig) -> Path:
    if config.config_path is None:
        raise ValueError("config path is not configured")
    return config.config_path.resolve()


def load_json_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"config backup is not valid JSON: {path.name}") from exc
    if not isinstance(value, dict):
        raise ValueError("config file must contain a JSON object")
    return value


def validate_updated_config(raw: dict[str, Any], config: AppConfig) -> list[str]:
    from ops_agent.cli import validate_config

    return validate_config(AppConfig(raw=raw, base_dir=config.base_dir, config_path=config.config_path))


def changed_sections(current: dict[str, Any], candidate: dict[str, Any]) -> list[str]:
    keys = sorted(set(current.keys()) | set(candidate.keys()))
    return [str(key) for key in keys if current.get(key) != candidate.get(key)]


def redact_secrets(value: Any, key_name: str = "") -> Any:
    if is_secret_key(key_name):
        return "***"
    if isinstance(value, dict):
        return {str(key): redact_secrets(item, str(key)) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_secrets(item, key_name) for item in value]
    return deepcopy(value)


def is_secret_key(key_name: str) -> bool:
    text = key_name.strip().lower()
    return any(marker in text for marker in SECRET_MARKERS)


def backup_info(path: Path) -> dict[str, Any]:
    stat = path.stat()
    return {
        "name": path.name,
        "path": str(path),
        "size_bytes": stat.st_size,
        "modified_at": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
    }


def resolve_backup_path(config_path: Path, backup_name: str) -> Path:
    text = str(backup_name or "").strip()
    if not text:
        raise ValueError("backup is required")
    if Path(text).name != text:
        raise ValueError("backup must be a backup file name, not a path")
    if not text.startswith(f"{config_path.name}.bak"):
        raise ValueError("backup file name is not allowed")
    path = (config_path.parent / text).resolve()
    if path.parent != config_path.parent.resolve():
        raise ValueError("backup path is outside config directory")
    if not path.exists() or not path.is_file():
        raise ValueError(f"backup not found: {text}")
    return path


def next_backup_path(config_path: Path, reason: str) -> Path:
    for attempt in range(100):
        suffix = timestamp()
        if attempt:
            suffix = f"{suffix}-{attempt}"
        path = config_path.with_name(f"{config_path.name}.bak-{reason}-{suffix}")
        if not path.exists():
            return path
    raise ValueError("unable to allocate config backup path")


def next_temp_path(config_path: Path) -> Path:
    for attempt in range(100):
        suffix = timestamp()
        if attempt:
            suffix = f"{suffix}-{attempt}"
        path = config_path.with_name(f"{config_path.name}.tmp-config-{suffix}")
        if not path.exists():
            return path
    raise ValueError("unable to allocate config temp path")


def safe_reason(reason: str) -> str:
    cleaned = "".join(char if char.isalnum() or char in {"-", "_"} else "-" for char in str(reason or "manual"))
    cleaned = cleaned.strip("-_").lower()
    return cleaned[:48] or "manual"


def timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")

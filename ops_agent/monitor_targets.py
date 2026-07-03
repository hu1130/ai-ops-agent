from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from ops_agent.config import AppConfig


TARGET_LIST_KEYS = {
    "http": "http_checks",
    "json_api": "json_checks",
    "json": "json_checks",
    "log": "log_checks",
}
SECRET_MARKERS = ("password", "token", "secret", "api_key", "authorization")


def list_monitor_targets(raw: dict[str, Any]) -> dict[str, Any]:
    targets: list[dict[str, Any]] = []
    for target_type, key in (("http", "http_checks"), ("json_api", "json_checks"), ("log", "log_checks")):
        values = raw.get(key, [])
        if not isinstance(values, list):
            continue
        for index, target in enumerate(values):
            if not isinstance(target, dict):
                continue
            targets.append(public_target(target_type, index, target))

    server = raw.get("server_checks", {})
    server_target = public_server_target(server if isinstance(server, dict) else {})
    return {"targets": targets, "server": server_target}


def get_monitor_target(raw: dict[str, Any], target_type: str, index: int | None = None) -> dict[str, Any]:
    normalized = normalize_target_type(target_type)
    if normalized == "server":
        server = raw.get("server_checks", {})
        return public_server_target(server if isinstance(server, dict) else {})

    collection = target_collection(raw, normalized)
    if index is None or index < 0 or index >= len(collection):
        raise ValueError(f"monitor target not found: {normalized}/{index}")
    target = collection[index]
    if not isinstance(target, dict):
        raise ValueError(f"monitor target is invalid: {normalized}/{index}")
    return public_target(normalized, index, target)


def apply_monitor_target_change(
    config: AppConfig,
    target_type: str,
    index: int | None,
    action: str,
    body: dict[str, Any],
) -> dict[str, Any]:
    if config.config_path is None:
        raise ValueError("config path is not configured")

    normalized = normalize_target_type(target_type)
    resolved_action = normalize_action(normalized, index, action)
    current = deepcopy(config.raw)
    updated = deepcopy(config.raw)

    if normalized == "server":
        changed = apply_server_change(updated, resolved_action, body)
    else:
        changed = apply_list_target_change(updated, normalized, index, resolved_action, body)

    validation_errors = validate_updated_config(updated, config)
    if validation_errors:
        raise ValueError("monitor target config validation failed: " + "; ".join(validation_errors))

    write_result = write_config(config.config_path, current, updated)
    config.raw.clear()
    config.raw.update(updated)
    return {
        "action": resolved_action,
        "target": changed,
        "backup_path": write_result["backup_path"],
        "validation": {"valid": True, "errors": []},
    }


def apply_list_target_change(
    raw: dict[str, Any],
    target_type: str,
    index: int | None,
    action: str,
    body: dict[str, Any],
) -> dict[str, Any]:
    collection = target_collection(raw, target_type)
    if action == "create":
        target = body_target(body)
        if not target:
            raise ValueError("monitor target body is empty")
        collection.append(target)
        return public_target(target_type, len(collection) - 1, target)

    if index is None or index < 0 or index >= len(collection):
        raise ValueError(f"monitor target not found: {target_type}/{index}")
    existing = collection[index]
    if not isinstance(existing, dict):
        raise ValueError(f"monitor target is invalid: {target_type}/{index}")

    if action == "delete":
        removed = collection.pop(index)
        return public_target(target_type, index, removed)
    if action == "enable":
        existing["enabled"] = True
        return public_target(target_type, index, existing)
    if action == "disable":
        existing["enabled"] = False
        return public_target(target_type, index, existing)
    if action == "update":
        incoming = body_target(body)
        if not incoming:
            raise ValueError("monitor target update body is empty")
        if bool(body.get("replace", False)):
            collection[index] = incoming
        else:
            existing.update(incoming)
        return public_target(target_type, index, collection[index])
    raise ValueError(f"unsupported monitor target action: {action}")


def apply_server_change(raw: dict[str, Any], action: str, body: dict[str, Any]) -> dict[str, Any]:
    current = raw.get("server_checks", {})
    if not isinstance(current, dict):
        current = {}
        raw["server_checks"] = current

    if action == "enable":
        current["enabled"] = True
    elif action == "disable":
        current["enabled"] = False
    elif action == "update":
        incoming = body_target(body)
        if not incoming:
            raise ValueError("server check update body is empty")
        current.update(incoming)
    else:
        raise ValueError(f"unsupported server target action: {action}")
    return public_server_target(current)


def target_collection(raw: dict[str, Any], target_type: str) -> list:
    key = TARGET_LIST_KEYS.get(target_type)
    if not key:
        raise ValueError(f"unsupported monitor target type: {target_type}")
    current = raw.get(key)
    if current is None:
        current = []
        raw[key] = current
    if not isinstance(current, list):
        raise ValueError(f"{key} must be a list")
    return current


def body_target(body: dict[str, Any]) -> dict[str, Any]:
    value = body.get("target", body)
    if not isinstance(value, dict):
        return {}
    ignored = {"actor", "note", "reason", "replace"}
    return {str(key): deepcopy(item) for key, item in value.items() if key not in ignored}


def normalize_target_type(value: str) -> str:
    text = str(value or "").strip().lower().replace("-", "_")
    if text in {"server", "server_checks", "resource", "resources"}:
        return "server"
    if text in TARGET_LIST_KEYS:
        return "json_api" if text == "json" else text
    raise ValueError(f"unsupported monitor target type: {value}")


def normalize_action(target_type: str, index: int | None, action: str) -> str:
    text = str(action or "").strip().lower().replace("-", "_")
    if not text:
        return "update" if target_type == "server" or index is not None else "create"
    if text in {"create", "update", "enable", "disable", "delete"}:
        return text
    raise ValueError(f"unsupported monitor target action: {action}")


def public_target(target_type: str, index: int, target: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": f"{target_type}:{index}",
        "type": target_type,
        "index": index,
        "name": str(target.get("name") or target.get("url") or target.get("path") or target.get("container") or ""),
        "enabled": bool(target.get("enabled", True)),
        "target": redact_secrets(target),
    }


def public_server_target(target: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": "server",
        "type": "server",
        "index": None,
        "name": "Server resources",
        "enabled": bool(target.get("enabled", True)),
        "target": redact_secrets(target),
    }


def redact_secrets(value: Any, key_name: str = "") -> Any:
    if is_secret_key(key_name):
        return "***"
    if isinstance(value, dict):
        return {str(key): redact_secrets(item, str(key)) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_secrets(item, key_name) for item in value]
    return value


def is_secret_key(key_name: str) -> bool:
    text = key_name.strip().lower()
    return any(marker in text for marker in SECRET_MARKERS)


def validate_updated_config(raw: dict[str, Any], config: AppConfig) -> list[str]:
    from ops_agent.cli import validate_config

    return validate_config(AppConfig(raw=raw, base_dir=config.base_dir, config_path=config.config_path))


def write_config(config_path: Path, current: dict[str, Any], updated: dict[str, Any]) -> dict[str, str]:
    config_path = config_path.resolve()
    backup_path = config_path.with_name(f"{config_path.name}.bak-monitor-{timestamp()}")
    backup_path.write_text(json.dumps(current, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temp_path = config_path.with_name(f"{config_path.name}.tmp-monitor-{timestamp()}")
    temp_path.write_text(json.dumps(updated, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temp_path.replace(config_path)
    return {"backup_path": str(backup_path)}


def timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")

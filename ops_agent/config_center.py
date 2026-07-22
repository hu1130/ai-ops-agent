from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
from typing import Any

from ops_agent.config import AppConfig
from ops_agent.ai.repair import (
    DEEPSEEK_DEFAULT_MODEL,
    DEEPSEEK_MODEL_ENDPOINT,
    DEFAULT_TEST_COMMANDS,
    MODEL_PROVIDERS,
    ai_repair_policy_from_config,
    build_repository_context,
    is_safe_deploy_command,
    is_safe_test_command,
    normalize_ai_repair_policy,
    repair_settings,
    resolve_repair_repo_root,
)
from ops_agent.projects import list_projects


DEFAULT_AI_REPAIR_AUTO_TRIGGER_POLICY = {
    "enabled": False,
    "severities": ["critical"],
    "categories": [
        "service_unavailable",
        "dependency_failure",
        "performance_degraded",
        "probe_config_issue",
        "route_or_healthcheck_config_mismatch",
        "synthetic_quality_fail",
    ],
    "excluded_categories": ["unknown", "unclassified"],
    "sources": [],
    "excluded_sources": [],
    "environments": [],
    "run_types": [],
    "min_classification_confidence": 0.65,
    "run_dry_run": True,
    "notify": True,
    "notify_states": ["needs_dry_run", "needs_sandbox", "ready_for_approval", "blocked", "review_only"],
    "notify_limit": 20,
    "max_active_proposals": 10,
    "max_triggers_per_window": 5,
    "trigger_window_minutes": 60,
}


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


def project_config_snapshot(config: AppConfig) -> dict[str, Any]:
    return {
        "projects": list_projects(config),
        "raw_projects": redact_secrets(safe_list(config.raw.get("projects"))),
    }


def project_repair_readiness_snapshot(config: AppConfig) -> dict[str, Any]:
    repair_config = safe_dict(safe_dict(config.raw.get("ai")).get("repair"))
    settings = repair_settings({"config": {"repair": repair_config}})
    provider = str(settings.get("provider") or "rules")
    api_key_env = str(settings.get("api_key_env") or "")
    has_mock_response = bool(settings.get("mock_response"))
    needs_api_key = provider in MODEL_PROVIDERS and provider != "rules" and not has_mock_response
    api_key_configured = has_mock_response or bool(str(settings.get("api_key") or "").strip()) or bool(
        os.environ.get(api_key_env, "").strip()
    )
    rows = []
    for project in list_projects(config):
        rows.append(project_repair_readiness(config, project, repair_config, needs_api_key, api_key_configured))
    status_counts: dict[str, int] = {}
    for row in rows:
        status = str(row.get("status") or "unknown")
        status_counts[status] = status_counts.get(status, 0) + 1
    return {
        "model": {
            "provider": provider,
            "model": str(settings.get("model") or ""),
            "api_key_env": api_key_env,
            "api_key_configured": api_key_configured,
            "needs_api_key": needs_api_key,
        },
        "summary": {
            "total": len(rows),
            "by_status": status_counts,
        },
        "projects": rows,
    }


def project_repair_readiness(
    config: AppConfig,
    project: dict[str, Any],
    repair_config: dict[str, Any],
    needs_api_key: bool,
    api_key_configured: bool,
) -> dict[str, Any]:
    repo_root = resolve_repair_repo_root(config, project, {"project_id": project.get("id")}, config.base_dir)
    repo_exists = repo_root.exists() and repo_root.is_dir()
    commands = string_list(project.get("test_commands")) or DEFAULT_TEST_COMMANDS
    unsafe_commands = [command for command in commands if not is_safe_test_command(command)]
    deploy_commands = string_list(project.get("deploy_commands"))
    rollback_commands = string_list(project.get("rollback_commands"))
    unsafe_deploy_commands = [command for command in deploy_commands + rollback_commands if not is_safe_deploy_command(command)]
    git_worktree = repo_exists and is_git_worktree(repo_root)
    git_remote = str(project.get("git_remote") or "origin")
    git_remote_configured = git_worktree and has_git_remote(repo_root, git_remote)
    repair_policy = ai_repair_policy_from_config(config, project=project)
    repository_context = build_repository_context(
        config,
        repair_config,
        {},
        {},
        [],
        project,
        {"project_id": project.get("id")},
    )
    blockers: list[str] = []
    warnings: list[str] = []
    if not repo_exists:
        blockers.append("repo_root not found")
    if needs_api_key and not api_key_configured:
        blockers.append("model API key is not configured")
    if unsafe_commands:
        blockers.append("unsafe test commands are configured")
    if not repository_context.get("files"):
        warnings.append("no repository context files were loaded")
    if not string_list(project.get("test_commands")):
        warnings.append("project test_commands is empty; default tests will be used")
    if not string_list(project.get("repair_context_files")):
        warnings.append("project repair_context_files is empty; inferred files or tree preview will be used")
    status = "blocked" if blockers else ("warning" if warnings else "ready")
    closure_blockers: list[str] = []
    if not git_worktree:
        closure_blockers.append("repo_root is not a git work tree")
    if not git_remote_configured:
        closure_blockers.append(f"git remote is not configured: {git_remote}")
    if not repair_policy.get("prepare_branch"):
        closure_blockers.append("repair_policy.prepare_branch is disabled")
    if not repair_policy.get("create_pr"):
        closure_blockers.append("repair_policy.create_pr is disabled")
    if not deploy_commands:
        closure_blockers.append("project deploy_commands is empty")
    if not rollback_commands:
        closure_blockers.append("project rollback_commands is empty")
    if not string_list(project.get("health_urls")):
        closure_blockers.append("project health_urls is empty")
    if unsafe_deploy_commands:
        closure_blockers.append("unsafe deploy or rollback commands are configured")
    return {
        "id": str(project.get("id") or ""),
        "name": str(project.get("name") or project.get("id") or ""),
        "environment": str(project.get("environment") or ""),
        "run_types": string_list(project.get("run_types")),
        "status": status,
        "blockers": blockers,
        "warnings": warnings,
        "repo_root": str(repo_root),
        "repo_exists": repo_exists,
        "test_commands": commands,
        "unsafe_test_commands": unsafe_commands,
        "deploy_commands": deploy_commands,
        "rollback_commands": rollback_commands,
        "unsafe_deploy_commands": unsafe_deploy_commands,
        "health_urls": string_list(project.get("health_urls")),
        "closure": {
            "status": "blocked" if closure_blockers else "ready",
            "blockers": closure_blockers,
            "git_worktree": git_worktree,
            "git_remote": git_remote,
            "git_remote_configured": git_remote_configured,
        },
        "repair_context": {
            "enabled": bool(repository_context.get("enabled")),
            "file_count": len(safe_list(repository_context.get("files"))),
            "files": [
                str(item.get("path") or "")
                for item in safe_list(repository_context.get("files"))
                if isinstance(item, dict)
            ],
            "missing_files": string_list(repository_context.get("missing_files")),
            "skipped_files": [
                safe_dict(item)
                for item in safe_list(repository_context.get("skipped_files"))
                if isinstance(item, dict)
            ],
            "tree_preview_count": len(safe_list(repository_context.get("tree"))),
            "reason": str(repository_context.get("reason") or ""),
        },
        "repair_policy": repair_policy,
    }


def is_git_worktree(repo_root: Path) -> bool:
    if not shutil.which("git"):
        return False
    completed = subprocess.run(
        ["git", "rev-parse", "--is-inside-work-tree"],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    return completed.returncode == 0 and completed.stdout.strip().lower() == "true"


def has_git_remote(repo_root: Path, remote: str) -> bool:
    if not remote:
        return False
    completed = subprocess.run(
        ["git", "remote", "get-url", remote],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    return completed.returncode == 0 and bool(completed.stdout.strip())


def upsert_project_config(config: AppConfig, project: dict[str, Any], reason: str = "project-upsert") -> dict[str, Any]:
    candidate = deepcopy(config.raw)
    project_payload = normalize_project_payload(project)
    project_id = str(project_payload.get("id") or "").strip()
    projects = [item for item in safe_list(candidate.get("projects")) if isinstance(item, dict)]
    replaced = False
    for index, item in enumerate(projects):
        if str(item.get("id") or item.get("key") or "").strip() == project_id:
            projects[index] = {**item, **project_payload}
            replaced = True
            break
    if not replaced:
        projects.append(project_payload)
    candidate["projects"] = projects
    result = apply_config_update(config, candidate, reason=reason)
    result["project"] = next(
        (project for project in list_projects(config) if str(project.get("id")) == project_id),
        project_payload,
    )
    result["action"] = "updated" if replaced else "created"
    return result


def delete_project_config(config: AppConfig, project_id: str, reason: str = "project-delete") -> dict[str, Any]:
    target = str(project_id or "").strip()
    if not target:
        raise ValueError("project id is required")
    candidate = deepcopy(config.raw)
    projects = [item for item in safe_list(candidate.get("projects")) if isinstance(item, dict)]
    remaining = [
        item
        for item in projects
        if str(item.get("id") or item.get("key") or "").strip() != target
    ]
    if len(remaining) == len(projects):
        raise ValueError(f"project not found: {target}")
    candidate["projects"] = remaining
    result = apply_config_update(config, candidate, reason=reason)
    result["action"] = "deleted"
    result["project_id"] = target
    return result


def ai_repair_policy_snapshot(config: AppConfig) -> dict[str, Any]:
    repair = safe_dict(safe_dict(config.raw.get("ai")).get("repair"))
    return {
        "policy": normalize_ai_repair_policy(repair.get("policy")),
        "configured_policy": redact_secrets(safe_dict(repair.get("policy"))),
    }


def ai_repair_auto_trigger_snapshot(config: AppConfig) -> dict[str, Any]:
    repair = safe_dict(safe_dict(config.raw.get("ai")).get("repair"))
    return {
        "auto_trigger": normalize_ai_repair_auto_trigger_policy(repair.get("auto_trigger")),
        "configured_auto_trigger": redact_secrets(safe_dict(repair.get("auto_trigger"))),
    }


def update_ai_repair_policy(config: AppConfig, policy: dict[str, Any], reason: str = "ai-repair-policy") -> dict[str, Any]:
    candidate = deepcopy(config.raw)
    ai = safe_dict(candidate.get("ai"))
    repair = safe_dict(ai.get("repair"))
    repair["policy"] = normalize_ai_repair_policy(policy)
    ai["repair"] = repair
    candidate["ai"] = ai
    result = apply_config_update(config, candidate, reason=reason)
    result["policy"] = normalize_ai_repair_policy(safe_dict(safe_dict(config.raw.get("ai")).get("repair")).get("policy"))
    return result


def update_ai_repair_auto_trigger(
    config: AppConfig,
    policy: dict[str, Any],
    reason: str = "ai-repair-auto-trigger",
) -> dict[str, Any]:
    candidate = deepcopy(config.raw)
    ai = safe_dict(candidate.get("ai"))
    repair = safe_dict(ai.get("repair"))
    repair["auto_trigger"] = normalize_ai_repair_auto_trigger_policy(policy)
    ai["repair"] = repair
    candidate["ai"] = ai
    result = apply_config_update(config, candidate, reason=reason)
    result["auto_trigger"] = normalize_ai_repair_auto_trigger_policy(
        safe_dict(safe_dict(config.raw.get("ai")).get("repair")).get("auto_trigger")
    )
    return result


def normalize_ai_repair_auto_trigger_policy(value: Any) -> dict[str, Any]:
    raw = safe_dict(value)
    policy = deepcopy(DEFAULT_AI_REPAIR_AUTO_TRIGGER_POLICY)
    for key in ("enabled", "run_dry_run", "run_sandbox", "notify"):
        if key in raw:
            policy[key] = bool(raw.get(key))
    for key in (
        "severities",
        "categories",
        "excluded_categories",
        "sources",
        "excluded_sources",
        "environments",
        "run_types",
        "notify_states",
    ):
        if key in raw:
            policy[key] = string_list(raw.get(key))
    if "min_classification_confidence" in raw:
        policy["min_classification_confidence"] = safe_float(raw.get("min_classification_confidence"), 0.65)
    if "notify_limit" in raw:
        policy["notify_limit"] = max(1, safe_int(raw.get("notify_limit"), 20))
    if "max_active_proposals" in raw:
        policy["max_active_proposals"] = max(1, safe_int(raw.get("max_active_proposals"), 10))
    if "max_triggers_per_window" in raw:
        policy["max_triggers_per_window"] = max(1, safe_int(raw.get("max_triggers_per_window"), 5))
    if "trigger_window_minutes" in raw:
        policy["trigger_window_minutes"] = max(1, safe_int(raw.get("trigger_window_minutes"), 60))
    return policy


def configure_deepseek_repair_model(
    config: AppConfig,
    body: dict[str, Any],
    reason: str = "deepseek-repair-model",
) -> dict[str, Any]:
    candidate = deepcopy(config.raw)
    ai = safe_dict(candidate.get("ai"))
    repair = safe_dict(ai.get("repair"))
    repair["provider"] = "deepseek"
    repair["enabled"] = bool(body.get("enabled", True))
    repair["model"] = str(body.get("model") or repair.get("model") or DEEPSEEK_DEFAULT_MODEL)
    repair["endpoint_url"] = str(body.get("endpoint_url") or repair.get("endpoint_url") or DEEPSEEK_MODEL_ENDPOINT)
    repair["api_key_env"] = str(body.get("api_key_env") or repair.get("api_key_env") or "DEEPSEEK_API_KEY")
    ai["repair"] = repair
    candidate["ai"] = ai
    result = apply_config_update(config, candidate, reason=reason)
    result["repair"] = redact_secrets(safe_dict(config.raw.get("ai")).get("repair", {}))
    return result


def candidate_from_body(body: dict[str, Any]) -> dict[str, Any]:
    candidate = body.get("config")
    if not isinstance(candidate, dict):
        raise ValueError("config object is required")
    return deepcopy(candidate)


def normalize_project_payload(project: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(project, dict):
        raise ValueError("project object is required")
    project_id = str(project.get("id") or project.get("key") or project.get("name") or "").strip()
    if not project_id:
        raise ValueError("project id is required")
    payload = deepcopy(project)
    payload["id"] = project_id
    if "run_type" not in payload and "run_types" not in payload:
        payload["run_types"] = ["normal"]
    if "environment" not in payload:
        payload["environment"] = "prod"
    if "management_mode" in payload:
        from ops_agent.project_capabilities import normalize_management_mode

        payload["management_mode"] = normalize_management_mode(payload.get("management_mode"))
    if "automation_level" in payload:
        from ops_agent.project_capabilities import normalize_automation_level

        payload["automation_level"] = normalize_automation_level(payload.get("automation_level"))
    return payload


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


def safe_dict(value: Any) -> dict:
    return dict(value) if isinstance(value, dict) else {}


def safe_list(value: Any) -> list:
    return list(value) if isinstance(value, list) else []


def string_list(value: Any) -> list[str]:
    return [str(item) for item in safe_list(value) if str(item).strip()]


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


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

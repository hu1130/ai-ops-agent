from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from ops_agent.config import AppConfig


AUTOMATION_LEVELS = (
    ("monitor_only", "只读监控", "发现问题并通知，不执行任何修改。"),
    ("runtime_self_heal", "运行环境自愈", "可按审批策略重启服务或容器。"),
    ("code_suggest", "AI 修复建议", "读取已绑定仓库并生成补丁建议。"),
    ("pull_request", "PR 自动修复", "测试补丁并创建代码审核单。"),
    ("full_closure", "完整修复闭环", "合并后部署、验证，失败时回滚。"),
)
LEVEL_RANK = {level: index for index, (level, _label, _description) in enumerate(AUTOMATION_LEVELS)}
LEVEL_ALIASES = {
    "monitor": "monitor_only",
    "observe": "monitor_only",
    "runtime": "runtime_self_heal",
    "suggest": "code_suggest",
    "pr": "pull_request",
    "full": "full_closure",
}
ACTION_LEVELS = {
    "propose": "code_suggest",
    "proposal": "code_suggest",
    "drill": "code_suggest",
    "dry-run": "code_suggest",
    "sandbox-test": "code_suggest",
    "approve": "code_suggest",
    "prepare-branch": "pull_request",
    "create-pr": "pull_request",
    "deploy-merged": "full_closure",
}


def automation_level_catalog() -> list[dict[str, Any]]:
    return [
        {"id": level, "rank": index + 1, "label": label, "description": description}
        for index, (level, label, description) in enumerate(AUTOMATION_LEVELS)
    ]


def normalize_automation_level(value: Any, default: str = "monitor_only") -> str:
    text = str(value or "").strip().lower().replace("-", "_")
    text = LEVEL_ALIASES.get(text, text)
    if text not in LEVEL_RANK:
        if value not in (None, ""):
            raise ValueError(f"unsupported automation level: {value}")
        return default
    return text


def project_capability_snapshot(config: AppConfig | None, project: dict[str, Any]) -> dict[str, Any]:
    mode = normalize_management_mode(project.get("management_mode"), legacy_default="managed")
    if not bool(project.get("management_mode_configured")) and not bool(project.get("enabled", True)):
        mode = "observe_only" if project_has_enabled_monitors(config, project) else "ignored"
    enabled = bool(project.get("enabled", True)) and mode != "ignored"
    repo_root = resolve_repo_root(config, project)
    repo_exists = repo_root.exists() and repo_root.is_dir()
    git_worktree = repo_exists and is_git_worktree(repo_root)
    remote = str(project.get("git_remote") or "origin").strip()
    remote_ready = git_worktree and bool(remote) and has_git_remote(repo_root, remote)
    has_runtime_assets = bool(binding_assets(project)) or bool(project.get("health_urls"))
    deploy_ready = bool(string_list(project.get("deploy_commands")))
    rollback_ready = bool(string_list(project.get("rollback_commands")))
    health_ready = bool(string_list(project.get("health_urls")))

    available = {
        "monitor_only": enabled or mode == "observe_only",
        "runtime_self_heal": enabled and mode == "managed" and has_runtime_assets,
        "code_suggest": enabled and mode == "managed" and repo_exists,
        "pull_request": enabled and mode == "managed" and remote_ready,
        "full_closure": enabled and mode == "managed" and remote_ready and deploy_ready and rollback_ready and health_ready,
    }
    configured = bool(str(project.get("automation_level") or "").strip())
    selected = normalize_automation_level(project.get("automation_level"), inferred_level(available))
    blockers = capability_blockers(
        selected,
        enabled=enabled,
        mode=mode,
        has_runtime_assets=has_runtime_assets,
        repo_exists=repo_exists,
        git_worktree=git_worktree,
        remote_ready=remote_ready,
        deploy_ready=deploy_ready,
        rollback_ready=rollback_ready,
        health_ready=health_ready,
    )
    return {
        "project_id": str(project.get("id") or ""),
        "management_mode": mode,
        "automation_level": selected,
        "automation_level_configured": configured,
        "available": available,
        "effective_level": inferred_level(available),
        "ready": mode == "ignored" or bool(available.get(selected)),
        "blockers": [] if mode == "ignored" and selected == "monitor_only" else blockers,
        "repo_root": str(repo_root) if str(project.get("repo_root") or "").strip() else "",
        "repo_exists": repo_exists,
        "git_worktree": git_worktree,
        "git_remote_configured": remote_ready,
    }


def projects_capability_snapshot(config: AppConfig | None, projects: list[dict[str, Any]]) -> dict[str, Any]:
    rows = [project_capability_snapshot(config, project) for project in projects]
    return {
        "levels": automation_level_catalog(),
        "summary": {
            "total": len(rows),
            "ready": sum(1 for row in rows if row["ready"]),
            "blocked": sum(1 for row in rows if not row["ready"]),
        },
        "projects": rows,
    }


def ensure_project_action_allowed(project: dict[str, Any], action: str) -> None:
    if not bool(project.get("automation_level_configured")) and not str(project.get("automation_level") or "").strip():
        return
    required = ACTION_LEVELS.get(str(action or "").strip(), "monitor_only")
    selected = normalize_automation_level(project.get("automation_level"))
    if LEVEL_RANK[selected] < LEVEL_RANK[required]:
        raise ValueError(
            f"project automation level {selected} does not allow {action}; required level is {required}"
        )


def normalize_management_mode(value: Any, legacy_default: str = "observe_only") -> str:
    text = str(value or "").strip().lower().replace("-", "_")
    aliases = {"observe": "observe_only", "readonly": "observe_only", "ignore": "ignored"}
    text = aliases.get(text, text)
    if not text:
        return legacy_default
    if text not in {"managed", "observe_only", "ignored"}:
        raise ValueError(f"unsupported management mode: {value}")
    return text


def inferred_level(available: dict[str, bool]) -> str:
    for level, _label, _description in reversed(AUTOMATION_LEVELS):
        if available.get(level):
            return level
    return "monitor_only"


def capability_blockers(
    level: str,
    *,
    enabled: bool,
    mode: str,
    has_runtime_assets: bool,
    repo_exists: bool,
    git_worktree: bool,
    remote_ready: bool,
    deploy_ready: bool,
    rollback_ready: bool,
    health_ready: bool,
) -> list[str]:
    blockers: list[str] = []
    rank = LEVEL_RANK[level]
    if not enabled and mode != "observe_only":
        blockers.append("project is disabled")
    if rank >= LEVEL_RANK["runtime_self_heal"] and mode != "managed":
        blockers.append("project is not managed")
    if rank >= LEVEL_RANK["runtime_self_heal"] and not has_runtime_assets:
        blockers.append("no runtime assets are bound")
    if rank >= LEVEL_RANK["code_suggest"] and not repo_exists:
        blockers.append("repo_root is not bound or does not exist")
    if rank >= LEVEL_RANK["pull_request"] and not git_worktree:
        blockers.append("repo_root is not a git work tree")
    if rank >= LEVEL_RANK["pull_request"] and not remote_ready:
        blockers.append("git remote is not configured")
    if rank >= LEVEL_RANK["full_closure"] and not deploy_ready:
        blockers.append("deploy_commands is empty")
    if rank >= LEVEL_RANK["full_closure"] and not rollback_ready:
        blockers.append("rollback_commands is empty")
    if rank >= LEVEL_RANK["full_closure"] and not health_ready:
        blockers.append("health_urls is empty")
    return blockers


def resolve_repo_root(config: AppConfig | None, project: dict[str, Any]) -> Path:
    value = str(project.get("repo_root") or project.get("path") or "").strip()
    if not value:
        return Path("__ops_agent_unbound_repo__")
    path = Path(value)
    if path.is_absolute() or config is None:
        return path
    return config.base_dir / path


def binding_assets(project: dict[str, Any]) -> list[str]:
    bindings = project.get("discovery_bindings")
    if not isinstance(bindings, dict):
        return []
    return string_list(bindings.get("containers")) + string_list(bindings.get("compose_projects"))


def project_has_enabled_monitors(config: AppConfig | None, project: dict[str, Any]) -> bool:
    if config is None:
        return False
    project_id = str(project.get("id") or "").strip()
    bindings = project.get("discovery_bindings") if isinstance(project.get("discovery_bindings"), dict) else {}
    containers = set(string_list(bindings.get("containers")))
    compose_projects = set(string_list(bindings.get("compose_projects")))
    for key in ("docker_checks", "log_checks", "database_checks"):
        for item in config.raw.get(key, []):
            if not isinstance(item, dict) or not bool(item.get("enabled", True)):
                continue
            if project_id and str(item.get("project_id") or "") == project_id:
                return True
            if str(item.get("container") or "") in containers:
                return True
            if str(item.get("compose_project") or "") in compose_projects:
                return True
    return False


def string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def is_git_worktree(path: Path) -> bool:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=str(path),
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return completed.returncode == 0 and completed.stdout.strip().lower() == "true"


def has_git_remote(path: Path, remote: str) -> bool:
    try:
        completed = subprocess.run(
            ["git", "remote", "get-url", remote],
            cwd=str(path),
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return completed.returncode == 0 and bool(completed.stdout.strip())

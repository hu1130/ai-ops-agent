from __future__ import annotations

import re
import subprocess
from copy import deepcopy
from typing import Any, Callable

from ops_agent.config import AppConfig
from ops_agent.config_center import apply_config_update
from ops_agent.docker_identity import parse_docker_ps
from ops_agent.project_capabilities import (
    normalize_automation_level,
    normalize_management_mode,
    project_capability_snapshot,
)
from ops_agent.projects import list_projects


Runner = Callable[..., subprocess.CompletedProcess[str]]
SERVICE_SUFFIXES = {
    "api",
    "app",
    "backend",
    "chroma",
    "db",
    "frontend",
    "gateway",
    "minio",
    "mysql",
    "nginx",
    "postgres",
    "redis",
    "server",
    "service",
    "web",
    "worker",
}


def project_onboarding_snapshot(
    config: AppConfig,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    candidates = discover_project_candidates(config.raw, runner=runner)
    projects = list_projects(config)
    rows = []
    for project in projects:
        row = dict(project)
        row["capabilities"] = project_capability_snapshot(config, project)
        rows.append(row)
    return {
        "mode": "project_onboarding",
        "status": candidates["status"],
        "summary": {
            **candidates["summary"],
            "configured_projects": len(rows),
            "unbound_projects": sum(1 for item in candidates["candidates"] if item["binding_status"] == "unbound"),
        },
        "candidates": candidates["candidates"],
        "projects": rows,
        "error": candidates["error"],
    }


def discover_project_candidates(
    raw_config: dict[str, Any],
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    discovery = safe_dict(raw_config.get("asset_discovery"))
    timeout_seconds = max(1, safe_int(discovery.get("timeout_seconds"), 8))
    try:
        completed = runner(
            ["docker", "ps", "--format", "{{json .}}"],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return discovery_failure(str(exc))
    if completed.returncode != 0:
        return discovery_failure(clean_error(completed.stderr or completed.stdout))

    containers = parse_docker_ps(completed.stdout)
    groups: dict[str, dict[str, Any]] = {}
    for container in containers:
        compose_project = str(container.get("compose_project") or "").strip()
        if compose_project:
            source = "docker_compose"
            raw_name = compose_project
            confidence = 0.98
        else:
            source = "standalone_container"
            raw_name = standalone_project_name(str(container.get("name") or ""))
            confidence = 0.72
        slug = slugify(raw_name) or slugify(container.get("name")) or "unnamed"
        candidate_id = f"compose--{slug}" if source == "docker_compose" else f"container--{slug}"
        group = groups.setdefault(
            candidate_id,
            {
                "id": candidate_id,
                "suggested_project_id": slug,
                "name": raw_name or slug,
                "source": source,
                "confidence": confidence,
                "assets": [],
                "compose_projects": [],
            },
        )
        group["assets"].append(dict(container))
        if compose_project and compose_project not in group["compose_projects"]:
            group["compose_projects"].append(compose_project)

    configured = [item for item in safe_list(raw_config.get("projects")) if isinstance(item, dict)]
    candidates = []
    for candidate in groups.values():
        asset_names = [str(asset.get("name") or "") for asset in candidate["assets"]]
        project = matching_project(configured, candidate, asset_names)
        if not project:
            mode = "unbound"
        elif str(project.get("management_mode") or "").strip():
            mode = normalize_management_mode(project.get("management_mode"), legacy_default="managed")
        elif bool(project.get("enabled", True)):
            mode = "managed"
        else:
            mode = "observe_only" if candidate_has_enabled_monitors(raw_config, candidate) else "ignored"
        candidate.update(
            {
                "asset_count": len(asset_names),
                "asset_names": asset_names,
                "evidence": candidate_evidence(candidate),
                "matched_project_id": str(project.get("id") or "") if project else "",
                "binding_status": "bound" if project else "unbound",
                "management_mode": mode,
                "automation_level": (
                    normalize_automation_level(project.get("automation_level"), "monitor_only")
                    if project
                    else "monitor_only"
                ),
            }
        )
        candidates.append(candidate)
    candidates.sort(key=lambda item: (item["binding_status"] != "unbound", str(item["name"]).lower()))
    return {
        "status": "warning" if any(item["binding_status"] == "unbound" for item in candidates) else "ok",
        "summary": {
            "containers": len(containers),
            "detected_projects": len(candidates),
            "bound_projects": sum(1 for item in candidates if item["binding_status"] == "bound"),
        },
        "candidates": candidates,
        "error": "",
    }


def bind_project_candidate(
    config: AppConfig,
    candidate_id: str,
    body: dict[str, Any],
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    discovery = discover_project_candidates(config.raw, runner=runner)
    candidate = next((item for item in discovery["candidates"] if item["id"] == candidate_id), None)
    if candidate is None:
        raise ValueError(f"discovered project not found: {candidate_id}")

    mode = normalize_management_mode(body.get("management_mode"), legacy_default="observe_only")
    default_level = "runtime_self_heal" if mode == "managed" else "monitor_only"
    level = normalize_automation_level(body.get("automation_level"), default_level)
    if mode != "managed" and level != "monitor_only":
        raise ValueError("observe-only and ignored projects must use monitor_only")

    existing_id = str(candidate.get("matched_project_id") or "")
    project_id = slugify(body.get("project_id") or existing_id or candidate["suggested_project_id"])
    if not project_id:
        raise ValueError("project id is required")
    projects = [dict(item) for item in safe_list(config.raw.get("projects")) if isinstance(item, dict)]
    existing_index = next(
        (index for index, item in enumerate(projects) if str(item.get("id") or item.get("key") or "") == project_id),
        None,
    )
    existing = projects[existing_index] if existing_index is not None else {}
    bindings = {
        "source": "docker",
        "candidate_id": candidate_id,
        "compose_projects": list(candidate.get("compose_projects") or []),
        "containers": list(candidate.get("asset_names") or []),
    }
    project = {
        **existing,
        "id": project_id,
        "name": str(body.get("name") or existing.get("name") or candidate.get("name") or project_id),
        "enabled": mode != "ignored",
        "environment": str(body.get("environment") or existing.get("environment") or "prod"),
        "run_types": existing.get("run_types") or ["normal"],
        "management_mode": mode,
        "automation_level": level,
        "discovery_bindings": bindings,
    }
    if existing_index is None:
        projects.append(project)
        action = "created"
    else:
        projects[existing_index] = project
        action = "updated"

    candidate_config = deepcopy(config.raw)
    candidate_config["projects"] = projects
    candidate_config["docker_checks"] = update_docker_checks(
        safe_list(candidate_config.get("docker_checks")),
        candidate,
        project_id,
        enabled=mode != "ignored",
        observe_only=mode == "observe_only",
    )
    result = apply_config_update(config, candidate_config, reason=f"project-onboarding-{mode}")
    public = next(item for item in list_projects(config) if str(item.get("id")) == project_id)
    return {
        "status": "bound",
        "action": action,
        "candidate_id": candidate_id,
        "project": public,
        "capabilities": project_capability_snapshot(config, public),
        "changed_sections": result.get("changed_sections", []),
        "backup": result.get("backup", {}),
    }


def update_docker_checks(
    checks: list[Any],
    candidate: dict[str, Any],
    project_id: str,
    *,
    enabled: bool,
    observe_only: bool,
) -> list[dict[str, Any]]:
    rows = [dict(item) for item in checks if isinstance(item, dict)]
    assets = [safe_dict(item) for item in safe_list(candidate.get("assets"))]
    asset_names = {str(item.get("name") or "") for item in assets}
    compose_projects = {str(item) for item in safe_list(candidate.get("compose_projects")) if str(item)}
    matched: set[str] = set()
    for row in rows:
        container = str(row.get("container") or "")
        compose_project = str(row.get("compose_project") or row.get("project_id") or "")
        if container not in asset_names and compose_project not in compose_projects:
            continue
        row["enabled"] = enabled
        row["project_id"] = project_id
        if observe_only:
            row["unhealthy_status"] = "warning"
            row["not_running_status"] = "warning"
        matched.add(container)
    if enabled:
        for asset in assets:
            container = str(asset.get("name") or "")
            if not container or container in matched:
                continue
            service = str(asset.get("compose_service") or "").strip()
            row = {
                "name": f"{candidate.get('name')}/{service or container}",
                "container": container,
                "enabled": True,
                "project_id": project_id,
                "require_healthcheck": False,
                "missing_healthcheck_status": "warning",
            }
            compose_project = str(asset.get("compose_project") or "").strip()
            if compose_project:
                row["compose_project"] = compose_project
            if service:
                row["compose_service"] = service
            if observe_only:
                row["unhealthy_status"] = "warning"
                row["not_running_status"] = "warning"
            rows.append(row)
    return rows


def matching_project(
    projects: list[dict[str, Any]],
    candidate: dict[str, Any],
    asset_names: list[str],
) -> dict[str, Any] | None:
    compose_projects = set(str(item) for item in candidate.get("compose_projects") or [])
    for project in projects:
        bindings = safe_dict(project.get("discovery_bindings"))
        if compose_projects.intersection(string_set(bindings.get("compose_projects"))):
            return project
        if set(asset_names).intersection(string_set(bindings.get("containers"))):
            return project
    candidate_slug = slugify(candidate.get("suggested_project_id"))
    return next(
        (project for project in projects if slugify(project.get("id") or project.get("name")) == candidate_slug),
        None,
    )


def candidate_has_enabled_monitors(raw_config: dict[str, Any], candidate: dict[str, Any]) -> bool:
    assets = {str(item.get("name") or "") for item in safe_list(candidate.get("assets")) if isinstance(item, dict)}
    compose_projects = {str(item) for item in safe_list(candidate.get("compose_projects")) if str(item)}
    for key in ("docker_checks", "log_checks", "database_checks"):
        for item in safe_list(raw_config.get(key)):
            target = safe_dict(item)
            if not bool(target.get("enabled", True)):
                continue
            if str(target.get("container") or "") in assets:
                return True
            if str(target.get("compose_project") or "") in compose_projects:
                return True
    return False


def standalone_project_name(container_name: str) -> str:
    text = re.sub(r"[-_]\d+$", "", str(container_name or "").strip())
    parts = [part for part in re.split(r"[-_]", text) if part]
    if len(parts) > 1 and parts[-1].lower() in SERVICE_SUFFIXES:
        parts.pop()
    return "-".join(parts) or text


def candidate_evidence(candidate: dict[str, Any]) -> str:
    if candidate.get("source") == "docker_compose":
        names = ", ".join(candidate.get("compose_projects") or [])
        return f"Docker Compose 标签识别：{names}"
    return "根据容器命名和运行状态识别"


def slugify(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(value or "").strip().lower()).strip("-")


def string_set(value: Any) -> set[str]:
    return {str(item) for item in safe_list(value) if str(item)}


def discovery_failure(error: str) -> dict[str, Any]:
    return {
        "status": "warning",
        "summary": {"containers": 0, "detected_projects": 0, "bound_projects": 0},
        "candidates": [],
        "error": clean_error(error),
    }


def clean_error(value: str) -> str:
    lines = [line.strip() for line in str(value or "").splitlines() if line.strip()]
    return " | ".join(lines[-3:])[:500]


def safe_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def safe_dict(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def safe_list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, list) else []

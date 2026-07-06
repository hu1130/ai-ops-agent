from __future__ import annotations

from typing import Any

from ops_agent.config import AppConfig


def list_projects(config: AppConfig | None) -> list[dict[str, Any]]:
    if config is None:
        return [default_project({})]

    configured = config.raw.get("projects", [])
    if isinstance(configured, list) and configured:
        projects = []
        for index, item in enumerate(configured):
            if not isinstance(item, dict):
                continue
            projects.append(public_project(item, index, config.app))
        if projects:
            return projects
    return [default_project(config.app)]


def project_summary_payload(
    config: AppConfig | None,
    context_summaries: list[dict[str, Any]],
    hours: int,
) -> dict[str, Any]:
    projects = list_projects(config)
    project_rows = []
    matched_keys: set[tuple[str, str]] = set()
    for project in projects:
        contexts = [
            context
            for context in context_summaries
            if project_matches_context(project, context)
        ]
        if bool(project.get("enabled", True)):
            matched_keys.update(context_key(context) for context in contexts)
        row = dict(project)
        row["summary"] = aggregate_context_summaries(contexts, hours)
        row["contexts"] = contexts
        project_rows.append(row)

    unmapped = [
        context
        for context in context_summaries
        if context_key(context) not in matched_keys
    ]
    return {
        "hours": hours,
        "projects": project_rows,
        "contexts": context_summaries,
        "unmapped_contexts": unmapped,
    }


def public_project(item: dict[str, Any], index: int, app: dict[str, Any]) -> dict[str, Any]:
    environment = str(item.get("environment") or app.get("environment") or "prod").strip() or "prod"
    run_types = normalized_run_types(item, app)
    project_id = str(item.get("id") or item.get("key") or item.get("name") or environment).strip()
    if not project_id:
        project_id = f"project-{index + 1}"
    return {
        "id": project_id,
        "name": str(item.get("name") or project_id),
        "enabled": bool(item.get("enabled", True)),
        "environment": environment,
        "run_types": run_types,
        "description": str(item.get("description") or ""),
        "tags": [str(value) for value in item.get("tags", []) if str(value).strip()]
        if isinstance(item.get("tags"), list)
        else [],
        "repo_root": str(item.get("repo_root") or item.get("path") or ""),
        "git_remote": str(item.get("git_remote") or item.get("remote") or "origin"),
        "base_branch": str(item.get("base_branch") or item.get("branch") or "main"),
        "health_urls": string_list(item.get("health_urls") or item.get("verify_urls")),
        "test_commands": string_list(item.get("test_commands") or item.get("commands")),
        "deploy_commands": string_list(item.get("deploy_commands")),
        "rollback_commands": string_list(item.get("rollback_commands")),
        "owners": string_list(item.get("owners")),
        "repair_context_files": string_list(item.get("repair_context_files") or item.get("context_files")),
        "repair_policy": dict(item.get("repair_policy")) if isinstance(item.get("repair_policy"), dict) else {},
    }


def default_project(app: dict[str, Any]) -> dict[str, Any]:
    environment = str(app.get("environment") or "prod").strip() or "prod"
    run_type = str(app.get("run_type") or "normal").strip() or "normal"
    name = str(app.get("name") or environment).strip() or environment
    return {
        "id": environment,
        "name": name,
        "enabled": True,
        "environment": environment,
        "run_types": [run_type],
        "description": "Default project inferred from app environment.",
        "tags": [],
        "repo_root": "",
        "git_remote": "origin",
        "base_branch": "main",
        "health_urls": [],
        "test_commands": [],
        "deploy_commands": [],
        "rollback_commands": [],
        "owners": [],
        "repair_context_files": [],
        "repair_policy": {},
    }


def string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item).strip()]


def normalized_run_types(item: dict[str, Any], app: dict[str, Any]) -> list[str]:
    raw = item.get("run_types")
    if isinstance(raw, list):
        values = [str(value).strip() for value in raw if str(value).strip()]
        if values:
            return values
    single = str(item.get("run_type") or app.get("run_type") or "normal").strip()
    return [single or "normal"]


def project_matches_context(project: dict[str, Any], context: dict[str, Any]) -> bool:
    if not bool(project.get("enabled", True)):
        return False
    if str(project.get("environment") or "") != str(context.get("environment") or "prod"):
        return False
    run_types = [str(value) for value in project.get("run_types", []) if str(value)]
    return not run_types or str(context.get("run_type") or "normal") in run_types


def context_key(context: dict[str, Any]) -> tuple[str, str]:
    return str(context.get("environment") or "prod"), str(context.get("run_type") or "normal")


def aggregate_context_summaries(contexts: list[dict[str, Any]], hours: int) -> dict[str, Any]:
    counts = {"ok": 0, "warning": 0, "critical": 0}
    source_counts: dict[str, int] = {}
    latest_targets: list[dict[str, Any]] = []
    total_checks = 0
    incident_count = 0
    open_incident_count = 0
    active_problem_count = 0
    for context in contexts:
        total_checks += int(context.get("total_checks") or 0)
        incident_count += int(context.get("incident_count") or 0)
        open_incident_count += int(context.get("open_incident_count") or 0)
        active_problem_count += int(context.get("active_problem_count") or 0)
        for status in counts:
            counts[status] += int(context.get(status) or 0)
        for source, count in dict(context.get("source_counts") or {}).items():
            source_counts[str(source)] = source_counts.get(str(source), 0) + int(count or 0)
        latest_targets.extend(context.get("latest_targets") or [])

    current_status = "critical" if counts["critical"] else ("warning" if counts["warning"] else "ok")
    return {
        "hours": hours,
        "total_checks": total_checks,
        "ok": counts["ok"],
        "warning": counts["warning"],
        "critical": counts["critical"],
        "ok_rate": round((counts["ok"] / total_checks) * 100, 1) if total_checks else 100.0,
        "current_status": current_status,
        "active_problem_count": active_problem_count,
        "incident_count": incident_count,
        "open_incident_count": open_incident_count,
        "source_counts": source_counts,
        "latest_targets": latest_targets,
    }

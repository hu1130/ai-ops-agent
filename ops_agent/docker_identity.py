from __future__ import annotations

import json
import subprocess
from typing import Any, Callable


Runner = Callable[..., subprocess.CompletedProcess[str]]


def resolve_container_name(
    target: dict[str, Any],
    runner: Runner = subprocess.run,
    timeout_seconds: float = 5,
    include_stopped: bool = True,
) -> dict[str, Any]:
    configured = str(target.get("container") or "").strip()
    if not configured:
        return resolution(configured, configured, "missing", target)

    command = ["docker", "ps"]
    if include_stopped:
        command.append("-a")
    command.extend(["--format", "{{json .}}"])
    try:
        completed = runner(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        result = resolution(configured, configured, "lookup_failed", target)
        result["error"] = str(exc)
        return result
    if completed.returncode != 0:
        result = resolution(configured, configured, "lookup_failed", target)
        result["error"] = clean_error(completed.stderr or completed.stdout)
        return result

    containers = parse_docker_ps(completed.stdout)
    matched = match_container_target(target, containers)
    if matched:
        source = "exact_name" if matched["name"] == configured else "compose_identity"
        if matched["name"].endswith(f"_{configured}"):
            source = "generated_name_suffix"
        return {
            **resolution(configured, str(matched["name"]), source, target),
            "compose_project": str(matched.get("compose_project") or ""),
            "compose_service": str(matched.get("compose_service") or ""),
            "state": str(matched.get("state") or ""),
        }
    return resolution(configured, configured, "not_found", target)


def match_container_target(
    target: dict[str, Any],
    containers: list[dict[str, Any]],
) -> dict[str, Any] | None:
    configured = str(target.get("container") or "").strip()
    if not configured:
        return None
    exact = [item for item in containers if str(item.get("name") or "") == configured]
    if exact:
        return prefer_running(exact)

    suffix = [
        item
        for item in containers
        if str(item.get("name") or "").endswith(f"_{configured}")
    ]
    if len(suffix) == 1:
        return suffix[0]

    project, service = target_compose_identity(target)
    if project and service:
        compose_matches = [
            item
            for item in containers
            if str(item.get("compose_project") or "") == project
            and str(item.get("compose_service") or "") == service
        ]
        if compose_matches:
            return prefer_running(compose_matches)
    return prefer_running(suffix) if suffix else None


def container_matches_target(container: dict[str, Any], target: dict[str, Any]) -> bool:
    return match_container_target(target, [container]) is not None


def target_compose_identity(target: dict[str, Any]) -> tuple[str, str]:
    project = str(target.get("compose_project") or target.get("project_id") or "").strip()
    service = str(target.get("compose_service") or "").strip()
    if not service:
        service = infer_compose_service(str(target.get("container") or ""), project)
    return project, service


def infer_compose_service(container: str, project: str) -> str:
    name = str(container or "").strip()
    project_name = str(project or "").strip()
    if not name or not project_name:
        return ""
    prefix = f"{project_name}-"
    if not name.startswith(prefix):
        return ""
    service = name[len(prefix) :]
    if service.endswith("-1"):
        service = service[:-2]
    return service.strip("-")


def parse_docker_ps(output: str) -> list[dict[str, Any]]:
    containers: list[dict[str, Any]] = []
    for line in str(output or "").splitlines():
        text = line.strip()
        if not text:
            continue
        try:
            row = json.loads(text)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict):
            continue
        containers.append(
            {
                "name": str(row.get("Names") or row.get("Name") or ""),
                "image": str(row.get("Image") or ""),
                "state": str(row.get("State") or ""),
                "status": str(row.get("Status") or ""),
                "ports": str(row.get("Ports") or ""),
                "compose_project": label_value(str(row.get("Labels") or ""), "com.docker.compose.project"),
                "compose_service": label_value(str(row.get("Labels") or ""), "com.docker.compose.service"),
            }
        )
    return containers


def label_value(labels: str, key: str) -> str:
    for item in str(labels or "").split(","):
        name, separator, value = item.partition("=")
        if separator and name.strip() == key:
            return value.strip()
    return ""


def prefer_running(items: list[dict[str, Any]]) -> dict[str, Any]:
    return next(
        (item for item in items if str(item.get("state") or "").lower() == "running"),
        items[0],
    )


def resolution(configured: str, resolved: str, source: str, target: dict[str, Any]) -> dict[str, Any]:
    project, service = target_compose_identity(target)
    return {
        "configured_container": configured,
        "resolved_container": resolved,
        "resolution_source": source,
        "compose_project": project,
        "compose_service": service,
        "error": "",
    }


def clean_error(value: str) -> str:
    lines = [line.strip() for line in str(value or "").splitlines() if line.strip()]
    return " | ".join(lines[-3:])[:500]

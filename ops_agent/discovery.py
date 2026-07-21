from __future__ import annotations

import fnmatch
import re
import subprocess
from typing import Any, Callable

from ops_agent.docker_identity import container_matches_target, label_value, parse_docker_ps
from ops_agent.events import CheckResult


DEFAULT_INFRASTRUCTURE_PATTERNS = [
    "*mysql*",
    "*mariadb*",
    "*postgres*",
    "*redis*",
    "*minio*",
    "*chroma*",
    "*adminer*",
    "*syncthing*",
    "*prometheus*",
    "*grafana*",
]
DEFAULT_APPLICATION_TERMS = ("api", "app", "backend", "frontend", "web", "nginx", "service", "agent", "watcher")
Runner = Callable[..., subprocess.CompletedProcess[str]]


def discover_runtime_assets(
    raw_config: dict[str, Any],
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    config = safe_dict(raw_config.get("asset_discovery"))
    timeout_seconds = max(1, int(config.get("timeout_seconds", 8)))
    command = ["docker", "ps", "--format", "{{json .}}"]
    try:
        completed = runner(command, capture_output=True, text=True, timeout=timeout_seconds, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return discovery_failure(str(exc))
    if completed.returncode != 0:
        return discovery_failure(clean_error(completed.stderr or completed.stdout))

    containers = parse_docker_ps(completed.stdout)
    covered = configured_container_names(raw_config)
    configured_targets = configured_container_targets(raw_config)
    ignored_patterns = string_list(config.get("ignored_containers"))
    infrastructure_patterns = string_list(config.get("infrastructure_patterns")) or DEFAULT_INFRASTRUCTURE_PATTERNS
    candidate_patterns = string_list(config.get("candidate_patterns"))
    projects = [item for item in safe_list(raw_config.get("projects")) if isinstance(item, dict)]
    disabled_project_ids = [str(item.get("id") or "") for item in projects if not bool(item.get("enabled", True))]
    enabled_projects = [item for item in projects if bool(item.get("enabled", True))]

    candidates: list[dict[str, Any]] = []
    ignored: list[dict[str, Any]] = []
    covered_assets: list[dict[str, Any]] = []
    for container in containers:
        name = str(container.get("name") or "")
        if name in covered or any(container_matches_target(container, target) for target in configured_targets):
            covered_assets.append({**container, "coverage": "configured_monitor"})
            continue
        ignore_reason = ignored_reason(
            container,
            ignored_patterns,
            infrastructure_patterns,
            disabled_project_ids,
        )
        if ignore_reason:
            ignored.append({**container, "reason": ignore_reason})
            continue
        if not is_application_candidate(container, candidate_patterns):
            ignored.append({**container, "reason": "not_classified_as_application"})
            continue
        candidates.append(
            {
                **container,
                "reason": "running application container has no docker, log, database, or backup monitor",
                "suggested_project_id": suggested_project_id(container, enabled_projects),
            }
        )

    return {
        "mode": "runtime_asset_discovery",
        "status": "warning" if candidates else "ok",
        "summary": {
            "scanned": len(containers),
            "covered": len(covered_assets),
            "unmonitored_applications": len(candidates),
            "ignored": len(ignored),
        },
        "unmonitored_applications": candidates,
        "covered_assets": covered_assets,
        "ignored_assets": ignored,
        "configured_containers": sorted(covered),
        "error": "",
    }


def run_asset_discovery_check(
    raw_config: dict[str, Any],
    runner: Runner = subprocess.run,
) -> CheckResult:
    config = safe_dict(raw_config.get("asset_discovery"))
    name = str(config.get("name") or "Runtime asset coverage")
    discovery = discover_runtime_assets(raw_config, runner=runner)
    error = str(discovery.get("error") or "")
    candidates = safe_list(discovery.get("unmonitored_applications"))
    if error:
        status = str(config.get("failure_status") or "warning")
        summary = f"Asset discovery failed: {error}"
        classification = "asset_discovery_unavailable"
    elif candidates:
        status = str(config.get("unmonitored_status") or "warning")
        names = ", ".join(str(safe_dict(item).get("name") or "") for item in candidates[:8])
        summary = f"Found {len(candidates)} unmonitored application container(s): {names}"
        classification = "monitor_coverage_gap"
    else:
        status = "ok"
        summary = f"Runtime coverage OK; scanned {safe_dict(discovery.get('summary')).get('scanned', 0)} container(s)"
        classification = "monitor_coverage_ok"
    details = {
        **discovery,
        "classification": classification,
        **alert_policy_details(config),
    }
    return CheckResult(source="discovery", name=name, status=status, summary=summary, details=details)


def configured_container_names(raw_config: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    for key in ("docker_checks", "log_checks", "database_checks"):
        for item in safe_list(raw_config.get(key)):
            payload = safe_dict(item)
            if not bool(payload.get("enabled", True)):
                continue
            container = str(payload.get("container") or "").strip()
            if container:
                names.add(container)
    backups = safe_dict(raw_config.get("backups"))
    for item in safe_list(backups.get("targets")):
        payload = safe_dict(item)
        if not bool(payload.get("enabled", True)):
            continue
        container = str(payload.get("container") or "").strip()
        if container:
            names.add(container)
    return names


def configured_container_targets(raw_config: dict[str, Any]) -> list[dict[str, Any]]:
    targets: list[dict[str, Any]] = []
    for key in ("docker_checks", "log_checks", "database_checks"):
        for item in safe_list(raw_config.get(key)):
            payload = safe_dict(item)
            if bool(payload.get("enabled", True)) and str(payload.get("container") or "").strip():
                targets.append(payload)
    backups = safe_dict(raw_config.get("backups"))
    for item in safe_list(backups.get("targets")):
        payload = safe_dict(item)
        if bool(payload.get("enabled", True)) and str(payload.get("container") or "").strip():
            targets.append(payload)
    return targets


def ignored_reason(
    container: dict[str, Any],
    ignored_patterns: list[str],
    infrastructure_patterns: list[str],
    disabled_project_ids: list[str],
) -> str:
    name = str(container.get("name") or "")
    image = str(container.get("image") or "")
    if matches_any(name, ignored_patterns):
        return "configured_ignore"
    if matches_any(name, infrastructure_patterns) or matches_any(image, infrastructure_patterns):
        return "infrastructure_container"
    normalized_name = normalize_name(name)
    for project_id in disabled_project_ids:
        if normalize_name(project_id) and normalize_name(project_id) in normalized_name:
            return f"disabled_project:{project_id}"
    return ""


def is_application_candidate(container: dict[str, Any], candidate_patterns: list[str]) -> bool:
    name = str(container.get("name") or "")
    image = str(container.get("image") or "")
    if candidate_patterns:
        return matches_any(name, candidate_patterns) or matches_any(image, candidate_patterns)
    lowered = f"{name} {image}".lower()
    published = bool(re.search(r"(?:0\.0\.0\.0|127\.0\.0\.1|\[::\]):\d+->", str(container.get("ports") or "")))
    return published or any(term in lowered for term in DEFAULT_APPLICATION_TERMS)


def suggested_project_id(container: dict[str, Any], projects: list[dict[str, Any]]) -> str:
    values = " ".join(
        [
            str(container.get("name") or ""),
            str(container.get("compose_project") or ""),
            str(container.get("compose_service") or ""),
        ]
    )
    normalized = normalize_name(values)
    matches = [
        str(project.get("id") or "")
        for project in projects
        if normalize_name(project.get("id")) and normalize_name(project.get("id")) in normalized
    ]
    return matches[0] if matches else ""


def matches_any(value: str, patterns: list[str]) -> bool:
    lowered = str(value or "").lower()
    return any(fnmatch.fnmatch(lowered, str(pattern).lower()) for pattern in patterns if str(pattern).strip())


def normalize_name(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").lower())


def discovery_failure(error: str) -> dict[str, Any]:
    return {
        "mode": "runtime_asset_discovery",
        "status": "warning",
        "summary": {"scanned": 0, "covered": 0, "unmonitored_applications": 0, "ignored": 0},
        "unmonitored_applications": [],
        "covered_assets": [],
        "ignored_assets": [],
        "configured_containers": [],
        "error": clean_error(error),
    }


def clean_error(value: str) -> str:
    lines = [line.strip() for line in str(value or "").splitlines() if line.strip()]
    return " | ".join(lines[-3:])[:500]


def alert_policy_details(config: dict[str, Any]) -> dict[str, int]:
    details: dict[str, int] = {}
    for key in ("alert_after_failures", "consecutive_failures", "recovery_after_successes"):
        try:
            value = int(config.get(key))
        except (TypeError, ValueError):
            continue
        if value > 0:
            details[key] = value
    return details


def string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return []


def safe_dict(value: object) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def safe_list(value: object) -> list[Any]:
    return list(value) if isinstance(value, list) else []

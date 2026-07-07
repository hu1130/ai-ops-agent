from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any

from ops_agent.events import CheckResult


def run_docker_checks(checks: list[dict[str, Any]]) -> list[CheckResult]:
    if not checks:
        return []
    if shutil.which("docker") is None:
        return [docker_unavailable_result(check) for check in checks]
    return [run_docker_check(check) for check in checks]


def run_docker_check(check: dict[str, Any]) -> CheckResult:
    name = str(check.get("name") or check.get("container") or "Docker container")
    container = str(check.get("container", "")).strip()
    if not container:
        return CheckResult(
            source="docker",
            name=name,
            status="critical",
            summary="Docker container check missing container name",
            details={"error": "container is required", **alert_policy_details(check)},
        )

    timeout_seconds = float(check.get("timeout_seconds", 5))
    completed = subprocess.run(
        ["docker", "inspect", "--format", "{{json .State}}", container],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout_seconds,
    )
    if completed.returncode != 0:
        error = (completed.stderr or completed.stdout or "").strip()
        return CheckResult(
            source="docker",
            name=name,
            status=status_value(check, "missing_status", "critical"),
            summary=f"Docker inspect failed: {container}",
            details={"container": container, "error": error, **alert_policy_details(check)},
        )

    state = parse_state(completed.stdout)
    return result_from_state(name, container, state, check)


def result_from_state(name: str, container: str, state: dict[str, Any], check: dict[str, Any]) -> CheckResult:
    container_status = str(state.get("Status") or "").strip().lower()
    running = bool(state.get("Running"))
    health = state.get("Health") if isinstance(state.get("Health"), dict) else {}
    health_status = str(health.get("Status") or "").strip().lower()

    details = {
        "container": container,
        "container_status": container_status,
        "running": running,
        "health_status": health_status,
        "exit_code": state.get("ExitCode"),
        "started_at": state.get("StartedAt"),
        "finished_at": state.get("FinishedAt"),
        **alert_policy_details(check),
    }

    if not running or container_status in {"exited", "dead", "restarting", "removing", "paused"}:
        return CheckResult(
            source="docker",
            name=name,
            status=status_value(check, "not_running_status", "critical"),
            summary=f"Container {container} status {container_status or 'not running'}",
            details=details,
        )

    if health_status == "unhealthy":
        return CheckResult(
            source="docker",
            name=name,
            status=status_value(check, "unhealthy_status", "critical"),
            summary=f"Container {container} health unhealthy",
            details=details,
        )

    if health_status and health_status not in {"healthy", "starting"}:
        return CheckResult(
            source="docker",
            name=name,
            status=status_value(check, "unknown_health_status", "warning"),
            summary=f"Container {container} health {health_status}",
            details=details,
        )

    if bool(check.get("require_healthcheck", False)) and not health_status:
        return CheckResult(
            source="docker",
            name=name,
            status=status_value(check, "missing_healthcheck_status", "warning"),
            summary=f"Container {container} has no Docker healthcheck",
            details=details,
        )

    health_text = f", health {health_status}" if health_status else ", no healthcheck"
    return CheckResult(
        source="docker",
        name=name,
        status="ok",
        summary=f"Container {container} running{health_text}",
        details=details,
    )


def docker_unavailable_result(check: dict[str, Any]) -> CheckResult:
    name = str(check.get("name") or check.get("container") or "Docker container")
    return CheckResult(
        source="docker",
        name=name,
        status=status_value(check, "docker_unavailable_status", "critical"),
        summary="Docker command is not available",
        details={"container": str(check.get("container", "")).strip(), **alert_policy_details(check)},
    )


def parse_state(output: str) -> dict[str, Any]:
    text = output.strip()
    if not text:
        return {}
    try:
        parsed = json.loads(text.splitlines()[0])
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def status_value(check: dict[str, Any], key: str, default: str) -> str:
    value = str(check.get(key, default)).strip().lower()
    return value if value in {"warning", "critical"} else default


def alert_policy_details(check: dict[str, Any]) -> dict[str, Any]:
    details: dict[str, Any] = {}
    for key in ("alert_after_failures", "consecutive_failures"):
        if key in check:
            details[key] = check.get(key)
    return details

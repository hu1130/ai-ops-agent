from __future__ import annotations

import hmac
import json
import os
import platform
import re
import shutil
import socket
import time
import urllib.error
import urllib.request
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any

from ops_agent.config import AppConfig
from ops_agent.config_center import apply_config_update
from ops_agent.events import CheckResult, utc_now_iso
from ops_agent.project_capabilities import normalize_automation_level, normalize_management_mode
from ops_agent.projects import list_projects
from ops_agent.storage import Storage


NODE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
MAX_PROJECTS = 200
MAX_ASSETS = 1000


def fleet_policy(config: AppConfig | None) -> dict[str, Any]:
    raw = dict(config.raw.get("fleet") or {}) if config else {}
    thresholds = safe_dict(raw.get("resource_thresholds"))
    return {
        "enabled": bool(raw.get("enabled", False)),
        "heartbeat_interval_seconds": max(15, safe_int(raw.get("heartbeat_interval_seconds"), 60)),
        "offline_after_seconds": max(60, safe_int(raw.get("offline_after_seconds"), 180)),
        "alert_after_failures": max(1, safe_int(raw.get("alert_after_failures"), 2)),
        "recovery_after_successes": max(1, safe_int(raw.get("recovery_after_successes"), 2)),
        "enrollment_token_env": str(raw.get("enrollment_token_env") or "OPS_AGENT_FLEET_ENROLLMENT_TOKEN"),
        "resource_thresholds": {
            "cpu_warning": bounded_percent(thresholds.get("cpu_warning"), 90),
            "cpu_critical": bounded_percent(thresholds.get("cpu_critical"), 98),
            "memory_warning": bounded_percent(thresholds.get("memory_warning"), 85),
            "memory_critical": bounded_percent(thresholds.get("memory_critical"), 95),
            "disk_warning": bounded_percent(thresholds.get("disk_warning"), 85),
            "disk_critical": bounded_percent(thresholds.get("disk_critical"), 95),
        },
    }


def configured_fleet_tokens(config: AppConfig | None) -> list[tuple[str, str]]:
    if config is None:
        return []
    raw = dict(config.raw.get("fleet") or {})
    tokens: list[tuple[str, str]] = []
    default_env = str(raw.get("enrollment_token_env") or "OPS_AGENT_FLEET_ENROLLMENT_TOKEN").strip()
    if default_env:
        value = os.environ.get(default_env, "").strip()
        if value:
            tokens.append((default_env, value))
    direct = str(raw.get("enrollment_token") or "").strip()
    if direct:
        tokens.append(("config", direct))
    for index, item in enumerate(safe_list(raw.get("enrollment_tokens"))):
        if not isinstance(item, dict):
            continue
        name = bounded_text(item.get("name") or f"fleet-token-{index + 1}", 80)
        env_name = str(item.get("token_env") or "").strip()
        token = os.environ.get(env_name, "").strip() if env_name else str(item.get("token") or "").strip()
        if token:
            tokens.append((name, token))
    unique: list[tuple[str, str]] = []
    seen: set[str] = set()
    for name, token in tokens:
        if token not in seen:
            seen.add(token)
            unique.append((name, token))
    return unique


def authenticate_fleet_token(provided_token: str, config: AppConfig | None) -> str:
    if not provided_token:
        return ""
    for name, token in configured_fleet_tokens(config):
        if hmac.compare_digest(provided_token, token):
            return name
    return ""


def register_fleet_node(
    storage: Storage,
    config: AppConfig,
    payload: dict[str, Any],
    source_ip: str = "",
) -> dict[str, Any]:
    if not fleet_policy(config)["enabled"]:
        raise ValueError("fleet node enrollment is disabled")
    node = normalize_node_payload(payload, source_ip=source_ip)
    return public_node(storage.upsert_fleet_node(node), fleet_policy(config))


def fleet_snapshot(storage: Storage, config: AppConfig | None) -> dict[str, Any]:
    policy = fleet_policy(config)
    nodes = [public_node(row, policy) for row in storage.list_fleet_nodes()]
    nodes.sort(key=lambda row: (row["status"] != "offline", str(row.get("name") or row["node_id"]).lower()))
    return {
        "status": "disabled" if not policy["enabled"] else "warning" if any(row["status"] == "offline" for row in nodes) else "ok",
        "summary": {
            "total": len(nodes),
            "online": sum(1 for row in nodes if row["status"] == "online"),
            "offline": sum(1 for row in nodes if row["status"] == "offline"),
            "disabled": sum(1 for row in nodes if row["status"] == "disabled"),
            "projects": sum(len(safe_list(row.get("projects"))) for row in nodes if row["status"] != "disabled"),
        },
        "policy": {
            "enabled": policy["enabled"],
            "heartbeat_interval_seconds": policy["heartbeat_interval_seconds"],
            "offline_after_seconds": policy["offline_after_seconds"],
            "enrollment_ready": bool(configured_fleet_tokens(config)),
        },
        "nodes": nodes,
    }


def run_fleet_node_checks(storage: Storage, config: AppConfig) -> list[CheckResult]:
    policy = fleet_policy(config)
    if not policy["enabled"]:
        return []
    snapshot = fleet_snapshot(storage, config)
    nodes = {str(row["node_id"]): row for row in snapshot["nodes"] if row["status"] != "disabled"}
    results: list[CheckResult] = []
    thresholds = {
        "alert_after_failures": policy["alert_after_failures"],
        "recovery_after_successes": policy["recovery_after_successes"],
    }
    for node_id, node in nodes.items():
        age = safe_int(node.get("heartbeat_age_seconds"), 0)
        discovery = safe_dict(node.get("discovery"))
        if node["status"] == "offline":
            status = "critical"
            summary = f"服务器 {node.get('name') or node_id} 已失联 {age} 秒"
        elif discovery.get("status") not in {"", "ok"}:
            status = "warning"
            summary = f"服务器 {node.get('name') or node_id} 在线，但项目探测失败"
        else:
            status = "ok"
            summary = f"服务器 {node.get('name') or node_id} 在线，发现 {len(safe_list(node.get('projects')))} 个项目"
        results.append(
            CheckResult(
                source="fleet",
                name=f"node/{node_id}",
                status=status,
                summary=summary,
                details={
                    **thresholds,
                    "node_id": node_id,
                    "hostname": node.get("hostname"),
                    "address": node.get("address"),
                    "last_seen_at": node.get("last_seen_at"),
                    "heartbeat_age_seconds": age,
                    "projects_count": len(safe_list(node.get("projects"))),
                    "discovery": discovery,
                },
            )
        )
        if node["status"] != "online":
            continue
        metrics = safe_dict(node.get("metrics"))
        resource_thresholds = safe_dict(policy.get("resource_thresholds"))
        for key, label in (("cpu_percent", "CPU usage"), ("memory_percent", "Memory usage"), ("disk_percent", "Disk usage")):
            if key not in metrics:
                continue
            value = safe_float(metrics.get(key), 0)
            prefix = key.removesuffix("_percent")
            warning = safe_float(resource_thresholds.get(f"{prefix}_warning"), 90)
            critical = safe_float(resource_thresholds.get(f"{prefix}_critical"), 98)
            status = "critical" if value >= critical else "warning" if value >= warning else "ok"
            results.append(
                CheckResult(
                    source="fleet_resource",
                    name=f"{node_id}/{label}",
                    status=status,
                    summary=f"服务器 {node.get('name') or node_id} {label} {value:.2f}%",
                    details={
                        **thresholds,
                        "node_id": node_id,
                        "metric": key,
                        "used_percent": value,
                        "warning_threshold": warning,
                        "critical_threshold": critical,
                    },
                )
            )

    for project in list_projects(config):
        if not bool(project.get("enabled", True)):
            continue
        binding = safe_dict(project.get("discovery_bindings"))
        if binding.get("source") != "fleet":
            continue
        node_id = str(binding.get("node_id") or "")
        candidate_id = str(binding.get("candidate_id") or "")
        node = nodes.get(node_id)
        if not node or node["status"] == "offline":
            continue
        discovery = safe_dict(node.get("discovery"))
        if discovery.get("status") not in {"", "ok"}:
            continue
        present = any(str(item.get("candidate_id") or item.get("id") or "") == candidate_id for item in safe_list(node.get("projects")) if isinstance(item, dict))
        name = str(project.get("name") or project.get("id") or candidate_id)
        results.append(
            CheckResult(
                source="fleet_project",
                name=f"{node_id}/{project.get('id') or candidate_id}",
                status="ok" if present else "critical",
                summary=(
                    f"远程项目 {name} 正在服务器 {node.get('name') or node_id} 运行"
                    if present
                    else f"服务器在线，但远程项目 {name} 已不在运行列表中"
                ),
                details={
                    **thresholds,
                    "node_id": node_id,
                    "candidate_id": candidate_id,
                    "project_id": str(project.get("id") or ""),
                    "management_mode": normalize_management_mode(project.get("management_mode"), "managed"),
                },
            )
        )
    return results


def fleet_project_candidates(storage: Storage, config: AppConfig) -> list[dict[str, Any]]:
    configured = list_projects(config)
    rows: list[dict[str, Any]] = []
    for node in fleet_snapshot(storage, config)["nodes"]:
        if node["status"] == "disabled":
            continue
        for project in safe_list(node.get("projects")):
            if not isinstance(project, dict):
                continue
            remote_id = str(project.get("candidate_id") or project.get("id") or "")
            if not remote_id:
                continue
            candidate_id = fleet_candidate_id(str(node["node_id"]), remote_id)
            matched = next(
                (
                    item
                    for item in configured
                    if safe_dict(item.get("discovery_bindings")).get("source") == "fleet"
                    and str(safe_dict(item.get("discovery_bindings")).get("node_id") or "") == str(node["node_id"])
                    and str(safe_dict(item.get("discovery_bindings")).get("candidate_id") or "") == remote_id
                ),
                None,
            )
            rows.append(
                {
                    "id": candidate_id,
                    "suggested_project_id": slugify(f"{node['node_id']}-{project.get('suggested_project_id') or project.get('name') or remote_id}"),
                    "name": str(project.get("name") or remote_id),
                    "source": "fleet",
                    "confidence": float(project.get("confidence") or 0.9),
                    "asset_count": safe_int(project.get("asset_count"), len(safe_list(project.get("asset_names")))),
                    "asset_names": [bounded_text(value, 160) for value in safe_list(project.get("asset_names"))[:100]],
                    "evidence": f"服务器 {node.get('name') or node['node_id']} 自动上报",
                    "node_id": node["node_id"],
                    "remote_candidate_id": remote_id,
                    "matched_project_id": str(matched.get("id") or "") if matched else "",
                    "binding_status": "bound" if matched else "unbound",
                    "management_mode": (
                        normalize_management_mode(matched.get("management_mode"), "managed") if matched else "unbound"
                    ),
                    "automation_level": (
                        normalize_automation_level(matched.get("automation_level"), "monitor_only") if matched else "monitor_only"
                    ),
                }
            )
    return rows


def bind_fleet_project_candidate(
    storage: Storage,
    config: AppConfig,
    candidate_id: str,
    body: dict[str, Any],
) -> dict[str, Any]:
    candidate = next((row for row in fleet_project_candidates(storage, config) if row["id"] == candidate_id), None)
    if candidate is None:
        raise ValueError(f"remote project not found: {candidate_id}")
    mode = normalize_management_mode(body.get("management_mode"), "observe_only")
    default_level = "runtime_self_heal" if mode == "managed" else "monitor_only"
    level = normalize_automation_level(body.get("automation_level"), default_level)
    if mode != "managed" and level != "monitor_only":
        raise ValueError("observe-only and ignored projects must use monitor_only")
    project_id = slugify(body.get("project_id") or candidate.get("matched_project_id") or candidate["suggested_project_id"])
    if not project_id:
        raise ValueError("project id is required")
    projects = [dict(item) for item in safe_list(config.raw.get("projects")) if isinstance(item, dict)]
    index = next((i for i, item in enumerate(projects) if str(item.get("id") or "") == project_id), None)
    existing = projects[index] if index is not None else {}
    project = {
        **existing,
        "id": project_id,
        "name": bounded_text(body.get("name") or existing.get("name") or candidate.get("name") or project_id, 160),
        "enabled": mode != "ignored",
        "environment": bounded_text(body.get("environment") or existing.get("environment") or "prod", 40),
        "run_types": existing.get("run_types") or ["normal"],
        "management_mode": mode,
        "automation_level": level,
        "discovery_bindings": {
            "source": "fleet",
            "node_id": candidate["node_id"],
            "candidate_id": candidate["remote_candidate_id"],
            "containers": list(candidate.get("asset_names") or []),
        },
    }
    if index is None:
        projects.append(project)
        action = "created"
    else:
        projects[index] = project
        action = "updated"
    updated = deepcopy(config.raw)
    updated["projects"] = projects
    apply_config_update(config, updated, reason=f"fleet-project-onboarding-{mode}")
    public = next(item for item in list_projects(config) if str(item.get("id") or "") == project_id)
    return {"status": "bound", "action": action, "project": public, "candidate": candidate}


def combined_onboarding_snapshot(storage: Storage, config: AppConfig, local: dict[str, Any]) -> dict[str, Any]:
    remote = fleet_project_candidates(storage, config)
    result = deepcopy(local)
    candidates = [*safe_list(result.get("candidates")), *remote]
    candidates.sort(key=lambda item: (str(item.get("binding_status")) != "unbound", str(item.get("name") or "").lower()))
    summary = safe_dict(result.get("summary"))
    summary["detected_projects"] = len(candidates)
    summary["bound_projects"] = sum(1 for item in candidates if item.get("binding_status") == "bound")
    summary["unbound_projects"] = sum(1 for item in candidates if item.get("binding_status") == "unbound")
    summary["remote_projects"] = len(remote)
    result["summary"] = summary
    result["candidates"] = candidates
    result["status"] = "warning" if summary["unbound_projects"] else result.get("status", "ok")
    return result


def collect_local_node_payload(config: AppConfig, node_id: str, name: str = "") -> dict[str, Any]:
    validate_node_id(node_id)
    from ops_agent.project_onboarding import discover_project_candidates

    discovery = discover_project_candidates(config.raw)
    disk = shutil.disk_usage(config.base_dir)
    metrics: dict[str, Any] = {
        "disk_percent": round((disk.used / disk.total) * 100, 2) if disk.total else 0,
        "disk_free_bytes": int(disk.free),
    }
    try:
        metrics["load1"] = round(float(os.getloadavg()[0]), 2)
    except (AttributeError, OSError):
        pass
    try:
        import psutil

        metrics["cpu_percent"] = round(float(psutil.cpu_percent(interval=0.1)), 2)
        metrics["memory_percent"] = round(float(psutil.virtual_memory().percent), 2)
    except (ImportError, OSError):
        pass
    projects = []
    for item in safe_list(discovery.get("candidates"))[:MAX_PROJECTS]:
        if not isinstance(item, dict):
            continue
        projects.append(
            {
                "candidate_id": bounded_text(item.get("id"), 160),
                "suggested_project_id": bounded_text(item.get("suggested_project_id"), 100),
                "name": bounded_text(item.get("name"), 160),
                "source": bounded_text(item.get("source"), 40),
                "confidence": float(item.get("confidence") or 0),
                "asset_count": safe_int(item.get("asset_count"), len(safe_list(item.get("asset_names")))),
                "asset_names": [bounded_text(value, 160) for value in safe_list(item.get("asset_names"))[:100]],
            }
        )
    return {
        "node_id": node_id,
        "name": bounded_text(name or socket.gethostname(), 160),
        "hostname": bounded_text(socket.gethostname(), 160),
        "agent_version": agent_version(),
        "platform": bounded_text(platform.platform(), 240),
        "capabilities": ["docker_discovery", "resource_snapshot"],
        "metrics": metrics,
        "projects": projects,
        "discovery": {
            "status": str(discovery.get("status") or "warning"),
            "error": bounded_text(discovery.get("error"), 500),
            "summary": safe_dict(discovery.get("summary")),
        },
        "reported_at": utc_now_iso(),
    }


def send_fleet_heartbeat(
    server_url: str,
    token: str,
    payload: dict[str, Any],
    timeout_seconds: int = 10,
) -> dict[str, Any]:
    if not server_url.strip():
        raise ValueError("fleet server URL is required")
    if not token.strip():
        raise ValueError("fleet enrollment token is required")
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        server_url.rstrip("/") + "/api/fleet/heartbeat",
        data=data,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=max(1, timeout_seconds)) as response:
            result = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        message = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"fleet server returned HTTP {exc.code}: {message[:300]}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"fleet server is unreachable: {exc.reason}") from exc
    return result if isinstance(result, dict) else {"status": "accepted"}


def run_fleet_agent(
    config: AppConfig,
    server_url: str,
    token: str,
    node_id: str,
    name: str = "",
    once: bool = False,
    interval_seconds: int = 60,
    timeout_seconds: int = 10,
) -> int:
    while True:
        payload = collect_local_node_payload(config, node_id, name)
        result = send_fleet_heartbeat(server_url, token, payload, timeout_seconds=timeout_seconds)
        print(
            f"Fleet heartbeat accepted: node={node_id} "
            f"projects={len(payload['projects'])} status={result.get('status', 'online')}"
        )
        if once:
            return 0
        time.sleep(max(15, interval_seconds))


def normalize_node_payload(payload: dict[str, Any], source_ip: str = "") -> dict[str, Any]:
    node_id = bounded_text(payload.get("node_id"), 64)
    validate_node_id(node_id)
    projects = []
    for item in safe_list(payload.get("projects"))[:MAX_PROJECTS]:
        if not isinstance(item, dict):
            continue
        candidate_id = bounded_text(item.get("candidate_id") or item.get("id"), 160)
        if not candidate_id:
            continue
        projects.append(
            {
                "candidate_id": candidate_id,
                "suggested_project_id": bounded_text(item.get("suggested_project_id"), 100),
                "name": bounded_text(item.get("name") or candidate_id, 160),
                "source": bounded_text(item.get("source") or "agent", 40),
                "confidence": safe_float(item.get("confidence"), 0),
                "asset_count": max(0, safe_int(item.get("asset_count"), 0)),
                "asset_names": [bounded_text(value, 160) for value in safe_list(item.get("asset_names"))[:100]],
            }
        )
    capabilities = [bounded_text(value, 80) for value in safe_list(payload.get("capabilities"))[:50] if str(value).strip()]
    labels = {bounded_text(key, 80): bounded_text(value, 200) for key, value in list(safe_dict(payload.get("labels")).items())[:50]}
    metrics = normalize_metrics(safe_dict(payload.get("metrics")))
    discovery = safe_dict(payload.get("discovery"))
    return {
        "node_id": node_id,
        "name": bounded_text(payload.get("name") or node_id, 160),
        "hostname": bounded_text(payload.get("hostname") or node_id, 160),
        "address": bounded_text(source_ip, 120),
        "agent_version": bounded_text(payload.get("agent_version"), 80),
        "platform": bounded_text(payload.get("platform"), 240),
        "labels": labels,
        "capabilities": capabilities,
        "metrics": metrics,
        "projects": projects,
        "assets": [bounded_text(value, 200) for value in safe_list(payload.get("assets"))[:MAX_ASSETS]],
        "discovery": {
            "status": bounded_text(discovery.get("status") or "unknown", 20),
            "error": bounded_text(discovery.get("error"), 500),
            "summary": safe_dict(discovery.get("summary")),
        },
        "last_seen_at": utc_now_iso(),
    }


def public_node(row: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    item = dict(row)
    last_seen = parse_datetime(str(item.get("last_seen_at") or ""))
    age = max(0, int((datetime.now(timezone.utc) - last_seen).total_seconds())) if last_seen else 2**31 - 1
    enabled = bool(item.get("enabled", True))
    item["heartbeat_age_seconds"] = age
    item["status"] = "disabled" if not enabled else "offline" if age > policy["offline_after_seconds"] else "online"
    item["enabled"] = enabled
    return item


def fleet_candidate_id(node_id: str, remote_id: str) -> str:
    return f"fleet--{node_id}--{remote_id}"


def validate_node_id(node_id: str) -> None:
    if not NODE_ID_PATTERN.fullmatch(node_id):
        raise ValueError("node_id must be 1-64 characters using letters, numbers, dot, underscore, or dash")


def normalize_metrics(metrics: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        "cpu_percent",
        "memory_percent",
        "disk_percent",
        "disk_free_bytes",
        "load1",
        "load5",
        "load15",
    }
    result: dict[str, Any] = {}
    for key, value in metrics.items():
        if key not in allowed:
            continue
        number = safe_float(value, 0)
        result[key] = round(number, 2)
    return result


def parse_datetime(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def agent_version() -> str:
    try:
        from ops_agent import __version__

        return str(__version__)
    except (ImportError, AttributeError):
        return "dev"


def bounded_text(value: Any, limit: int) -> str:
    return str(value or "").strip()[:limit]


def safe_dict(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def safe_list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, list) else []


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def safe_float(value: Any, default: float = 0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def bounded_percent(value: Any, default: float) -> float:
    return min(100.0, max(0.0, safe_float(value, default)))


def slugify(value: Any) -> str:
    text = re.sub(r"[^a-z0-9]+", "-", str(value or "").strip().lower()).strip("-")
    return text[:80]

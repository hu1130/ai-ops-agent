from __future__ import annotations

import shlex
from urllib.parse import urlparse

from ops_agent.ai.classifier import classify_signal
from ops_agent.config import AppConfig
from ops_agent.events import CheckResult
from ops_agent.remediation.actions import RemediationAction
from ops_agent.remediation.playbooks import build_playbook_actions
from ops_agent.remediation.policy import apply_policy_defaults, decide_action_policy


def build_remediation_plan(results: list[CheckResult], config: AppConfig) -> list[RemediationAction]:
    remediation = dict(config.raw.get("remediation", {}))
    if not remediation.get("enabled", True):
        return []

    configured_actions = configured_auto_actions(remediation)
    classification_rules = config.classification_rules
    actions: list[RemediationAction] = []
    for result in results:
        if not result.is_problem:
            continue
        actions.extend(build_playbook_actions(result, remediation, configured_actions, classification_rules))
        actions.extend(plan_for_result(result, configured_actions, classification_rules))
    planned: list[RemediationAction] = []
    for action in dedupe_actions(actions):
        decision = decide_action_policy(action, config)
        if decision.configured and not decision.allowed:
            continue
        planned.append(apply_policy_defaults(action, config))
    return planned


def plan_for_result(
    result: CheckResult,
    configured_actions: dict[str, bool],
    classification_rules: list[dict] | None = None,
) -> list[RemediationAction]:
    actions: list[RemediationAction] = []
    category = classify_signal(result, classification_rules).category

    if result.source in {"http", "json_api", "business_flow"}:
        url = related_url(result)
        if category == "probe_config_issue":
            if url:
                actions.append(
                    RemediationAction(
                        action_type="run_diagnostic_command",
                        title="验证监控探针地址",
                        reason=(
                            f"{result.source}/{result.name} 被分类为探针或配置问题，"
                            "先复测主探针地址和响应头，而不是直接按业务宕机处理。"
                        ),
                        params={"command": f"curl -I -L --max-time 10 {shlex.quote(url)}"},
                        auto_execute=configured_actions.get("run_diagnostic_command", False),
                    )
                )
            return actions

        host, port = host_port_from_url(url)
        if host and port:
            actions.append(
                RemediationAction(
                    action_type="check_port",
                    title=f"检查端口连通性 {host}:{port}",
                    reason=f"{result.source}/{result.name} 访问异常或响应过慢，需要确认目标端口是否可连通。",
                    params={"host": host, "port": port, "timeout_seconds": 3},
                    auto_execute=configured_actions.get("check_port", False),
                )
            )
        actions.append(
            RemediationAction(
                action_type="run_diagnostic_command",
                title="查看容器状态",
                reason=f"{result.source}/{result.name} 异常时，先确认容器是否仍在运行。",
                params={"command": "docker ps --format table {{.Names}}\\t{{.Status}}\\t{{.Ports}}"},
                auto_execute=configured_actions.get("run_diagnostic_command", False),
            )
        )

    if result.source == "log":
        path = str(result.details.get("path", ""))
        actions.append(
            RemediationAction(
                action_type="run_diagnostic_command",
                title="查看最新错误日志",
                reason=f"{result.name} 出现可疑日志，需要查看最近上下文。",
                params={"command": f"tail -n 120 {shlex.quote(path)}" if path else "journalctl -n 120 --no-pager"},
                auto_execute=configured_actions.get("run_diagnostic_command", False),
            )
        )

    if result.source == "docker":
        container = str(result.details.get("container", "")).strip()
        actions.append(
            RemediationAction(
                action_type="run_diagnostic_command",
                title="查看 Docker 容器状态",
                reason=f"{result.name} 容器状态异常，先确认容器当前状态和健康检查详情。",
                params={
                    "command": (
                        f"docker inspect {shlex.quote(container)}"
                        if container
                        else "docker ps -a --format table {{.Names}}\\t{{.Status}}\\t{{.Ports}}"
                    )
                },
                auto_execute=configured_actions.get("run_diagnostic_command", False),
            )
        )
        actions.append(
            RemediationAction(
                action_type="run_diagnostic_command",
                title="查看 Docker 容器日志",
                reason=f"{result.name} 容器异常时，需要查看最近日志定位退出或 unhealthy 原因。",
                params={
                    "command": (
                        f"docker logs --tail 160 {shlex.quote(container)}"
                        if container
                        else "docker ps -a --format table {{.Names}}\\t{{.Status}}\\t{{.Ports}}"
                    )
                },
                auto_execute=configured_actions.get("run_diagnostic_command", False),
            )
        )
        if container and category == "container_unhealthy":
            actions.append(
                RemediationAction(
                    action_type="restart_docker_container",
                    title=f"重启容器 {container}",
                    reason=f"{result.name} 容器异常可考虑重启，但必须经过策略白名单和人工确认。",
                    risk="medium",
                    params={"container": container},
                    auto_execute=configured_actions.get("restart_docker_container", False),
                )
            )

    if result.source == "server" and "Disk" in result.name:
        actions.append(
            RemediationAction(
                action_type="run_diagnostic_command",
                title="查看磁盘占用",
                reason="磁盘使用率异常时，先定位大目录，再决定是否清理。",
                params={"command": "df -h"},
                auto_execute=configured_actions.get("run_diagnostic_command", False),
            )
        )
        actions.append(
            RemediationAction(
                action_type="cleanup_temp_files",
                title="清理临时文件",
                reason="磁盘异常时可以清理低风险临时目录，但默认需要人工确认。",
                risk="medium",
                params={"paths": ["/tmp"], "max_age_hours": 72},
                auto_execute=configured_actions.get("cleanup_temp_files", False),
            )
        )

    if result.source == "server" and "Memory" in result.name:
        actions.append(
            RemediationAction(
                action_type="run_diagnostic_command",
                title="查看内存占用最高进程",
                reason="内存异常时，先确认是否有进程或容器异常增长。",
                params={"command": "ps aux --sort=-%mem"},
                auto_execute=configured_actions.get("run_diagnostic_command", False),
            )
        )

    if result.source == "server" and "CPU" in result.name:
        actions.append(
            RemediationAction(
                action_type="run_diagnostic_command",
                title="查看 CPU 占用最高进程",
                reason="CPU 异常时，先确认是否有异常循环、批处理或突发流量。",
                params={"command": "ps aux --sort=-%cpu"},
                auto_execute=configured_actions.get("run_diagnostic_command", False),
            )
        )

    return actions


def configured_auto_actions(remediation: dict) -> dict[str, bool]:
    actions = remediation.get("actions", {})
    if not isinstance(actions, dict):
        return {}
    return {
        str(action_type): bool(config.get("auto_execute", False))
        for action_type, config in actions.items()
        if isinstance(config, dict)
    }


def dedupe_actions(actions: list[RemediationAction]) -> list[RemediationAction]:
    seen: set[tuple[str, str]] = set()
    unique: list[RemediationAction] = []
    for action in actions:
        key = (action.action_type, repr(sorted(public_params(action.params).items())))
        if key in seen:
            continue
        seen.add(key)
        unique.append(action)
    return unique


def public_params(params: dict) -> dict:
    return {key: value for key, value in params.items() if not str(key).startswith("_")}


def related_url(result: CheckResult) -> str:
    details = result.details or {}
    if details.get("url"):
        return str(details.get("url", ""))
    failed_step = details.get("failed_step")
    if isinstance(failed_step, dict) and failed_step.get("url"):
        return str(failed_step.get("url", ""))
    steps = details.get("steps")
    if isinstance(steps, list):
        for step in reversed(steps):
            if isinstance(step, dict) and step.get("url"):
                return str(step.get("url", ""))
    return ""


def host_port_from_url(url: str) -> tuple[str, int | None]:
    parsed = urlparse(url)
    if not parsed.hostname:
        return "", None
    if parsed.port:
        return parsed.hostname, parsed.port
    if parsed.scheme == "https":
        return parsed.hostname, 443
    if parsed.scheme == "http":
        return parsed.hostname, 80
    return parsed.hostname, None

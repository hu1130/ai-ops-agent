from __future__ import annotations

import shlex
import socket
import os
import stat
import subprocess
import time
from pathlib import Path
from typing import Any

from ops_agent.config import AppConfig
from ops_agent.remediation.actions import ActionResult, RemediationAction
from ops_agent.remediation.policy import (
    MUTATING_ACTIONS,
    apply_policy_defaults,
    decide_action_policy,
    format_policy_decision,
    policy_configured,
)


READ_ONLY_COMMANDS = {"df", "free", "ps", "docker", "journalctl", "tail", "systemctl", "pgrep"}


def execute_action(
    action: RemediationAction,
    config: AppConfig,
    dry_run: bool = True,
    approved: bool = False,
) -> ActionResult:
    decision = decide_action_policy(action, config)
    if decision.configured:
        if not decision.allowed:
            return ActionResult(action=action, status="skipped", error=format_policy_decision(decision))
        action = apply_policy_defaults(action, config)
        if not dry_run and action.action_type in MUTATING_ACTIONS and decision.requires_approval and not approved:
            return ActionResult(action=action, status="skipped", error="policy requires manual approval")
        if (
            not dry_run
            and
            action.action_type in MUTATING_ACTIONS
            and decision.verification_required
            and not action.params.get("verify_after")
        ):
            return ActionResult(action=action, status="skipped", error="policy requires verify_after")

    if dry_run:
        return ActionResult(action=action, status="dry_run", output=describe_dry_run(action))

    if not decision.configured:
        allowed_actions = set(config.raw.get("remediation", {}).get("allowed_actions", []))
        if allowed_actions and action.action_type not in allowed_actions:
            return ActionResult(action=action, status="skipped", error=f"动作未在 allowed_actions 中: {action.action_type}")

        if action.action_type in MUTATING_ACTIONS and not approved:
            return ActionResult(action=action, status="skipped", error="该动作会修改系统状态，需要先人工确认。")

    if action.action_type == "check_port":
        return check_port(action)
    if action.action_type == "check_process":
        return run_read_only_command(action, ["pgrep", "-af", str(action.params.get("pattern", ""))], config)
    if action.action_type == "run_diagnostic_command":
        return run_configured_diagnostic(action, config)
    if action.action_type == "restart_service":
        return restart_service(action, config)
    if action.action_type == "restart_docker_container":
        return restart_docker_container(action, config)
    if action.action_type == "cleanup_temp_files":
        return cleanup_temp_files(action, config)
    if action.action_type == "rotate_large_log":
        return ActionResult(action=action, status="skipped", error="日志轮转动作已建模，但执行器尚未开放。")
    return ActionResult(action=action, status="skipped", error=f"未知动作类型: {action.action_type}")


def check_port(action: RemediationAction) -> ActionResult:
    host = str(action.params.get("host", ""))
    port = int(action.params.get("port", 0))
    timeout = float(action.params.get("timeout_seconds", 3))
    if not host or port <= 0:
        return ActionResult(action=action, status="failed", error="host 或 port 参数无效。")

    try:
        with socket.create_connection((host, port), timeout=timeout):
            return ActionResult(action=action, status="executed", output=f"{host}:{port} 可连通。")
    except OSError as exc:
        return ActionResult(action=action, status="failed", error=f"{host}:{port} 不可连通: {exc}")


def run_configured_diagnostic(action: RemediationAction, config: AppConfig) -> ActionResult:
    command = str(action.params.get("command", "")).strip()
    if not command:
        return ActionResult(action=action, status="failed", error="diagnostic command 不能为空。")

    args = shlex.split(command)
    if not args:
        return ActionResult(action=action, status="failed", error="diagnostic command 不能为空。")
    if args[0] not in READ_ONLY_COMMANDS:
        return ActionResult(action=action, status="skipped", error=f"不允许执行非只读命令: {args[0]}")

    if args[0] == "docker" and len(args) > 1 and args[1] not in {"ps", "stats", "logs"}:
        return ActionResult(action=action, status="skipped", error=f"不允许执行 docker {args[1]}")
    if args[0] == "systemctl" and len(args) > 1 and args[1] not in {"status", "is-active"}:
        return ActionResult(action=action, status="skipped", error=f"不允许执行 systemctl {args[1]}")

    return run_read_only_command(action, args, config)


def restart_service(action: RemediationAction, config: AppConfig) -> ActionResult:
    service = str(action.params.get("service", "")).strip()
    allowed = set(config.raw.get("remediation", {}).get("allowed_services", []))
    if not service:
        return ActionResult(action=action, status="failed", error="service 参数不能为空。")
    if not policy_configured(config) and service not in allowed:
        return ActionResult(action=action, status="skipped", error=f"服务不在 allowed_services 白名单中: {service}")
    return run_mutating_command(action, ["systemctl", "restart", service], config)


def restart_docker_container(action: RemediationAction, config: AppConfig) -> ActionResult:
    container = str(action.params.get("container", "")).strip()
    allowed = set(config.raw.get("remediation", {}).get("allowed_containers", []))
    if not container:
        return ActionResult(action=action, status="failed", error="container 参数不能为空。")
    if not policy_configured(config) and container not in allowed:
        return ActionResult(action=action, status="skipped", error=f"容器不在 allowed_containers 白名单中: {container}")
    return run_mutating_command(action, ["docker", "restart", container], config)


def cleanup_temp_files(action: RemediationAction, config: AppConfig) -> ActionResult:
    paths = clean_path_list(action.params.get("paths"))
    if not paths:
        return ActionResult(action=action, status="failed", error="paths 参数不能为空。")

    allowed_roots = cleanup_allowed_roots(config)
    if not allowed_roots:
        return ActionResult(action=action, status="skipped", error="未配置 allowed_cleanup_paths 或清理策略 targets。")

    max_age_hours = positive_float(action.params.get("max_age_hours"), 72.0)
    max_files = positive_int(action.params.get("max_files"), 500)
    max_bytes = positive_int(action.params.get("max_bytes"), 0)
    cutoff = time.time() - max_age_hours * 3600

    deleted_files = 0
    deleted_bytes = 0
    scanned_files = 0
    skipped: list[str] = []

    for raw_path in paths:
        root = cleanup_path(raw_path, config.base_dir)
        if not path_allowed(root, allowed_roots):
            skipped.append(f"{raw_path}: not allowlisted")
            continue
        if root.is_symlink():
            skipped.append(f"{raw_path}: symlink root skipped")
            continue
        if not root.exists():
            skipped.append(f"{raw_path}: path not found")
            continue

        for file_path, size in cleanup_candidates(root, cutoff):
            scanned_files += 1
            if deleted_files >= max_files:
                skipped.append("max_files reached")
                break
            if max_bytes > 0 and deleted_bytes + size > max_bytes:
                skipped.append("max_bytes reached")
                break
            try:
                file_path.unlink()
            except OSError as exc:
                skipped.append(f"{file_path}: {exc}")
                continue
            deleted_files += 1
            deleted_bytes += size

    output = (
        f"scanned={scanned_files}, deleted_files={deleted_files}, "
        f"deleted_bytes={deleted_bytes}, max_age_hours={max_age_hours}"
    )
    if skipped:
        output += "; skipped=" + "; ".join(skipped[:8])
    return ActionResult(action=action, status="executed", output=output)


def run_read_only_command(action: RemediationAction, args: list[str], config: AppConfig) -> ActionResult:
    return run_command(action, args, config)


def run_mutating_command(action: RemediationAction, args: list[str], config: AppConfig) -> ActionResult:
    return run_command(action, args, config)


def run_command(action: RemediationAction, args: list[str], config: AppConfig) -> ActionResult:
    timeout = int(config.raw.get("remediation", {}).get("command_timeout_seconds", 8))
    max_output = int(config.raw.get("remediation", {}).get("max_command_output_chars", 4000))
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except Exception as exc:
        return ActionResult(action=action, status="failed", error=str(exc))

    output = (completed.stdout or completed.stderr or "").strip()
    if len(output) > max_output:
        output = output[:max_output] + "\n...输出已截断..."
    if completed.returncode != 0:
        return ActionResult(action=action, status="failed", output=output, error=f"exit {completed.returncode}")
    return ActionResult(action=action, status="executed", output=output)


def clean_path_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def cleanup_allowed_roots(config: AppConfig) -> list[Path]:
    remediation = config.raw.get("remediation", {})
    if not isinstance(remediation, dict):
        return []
    values: list[str] = []
    values.extend(clean_path_list(remediation.get("allowed_cleanup_paths")))
    policies = remediation.get("policies")
    if isinstance(policies, list):
        for policy in policies:
            if not isinstance(policy, dict):
                continue
            if str(policy.get("action_type") or "") != "cleanup_temp_files":
                continue
            if not bool(policy.get("enabled", True)):
                continue
            values.extend(clean_path_list(policy.get("targets")))
    roots = [cleanup_path(value, config.base_dir) for value in values if value != "*"]
    return sorted(set(roots), key=lambda item: str(item))


def cleanup_path(value: str, base_dir: Path) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = base_dir / path
    return path.resolve(strict=False)


def path_allowed(path: Path, allowed_roots: list[Path]) -> bool:
    for root in allowed_roots:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            continue
    return False


def cleanup_candidates(root: Path, cutoff: float):
    if root.is_file():
        candidate = safe_cleanup_candidate(root, cutoff)
        if candidate:
            yield candidate
        return

    if not root.is_dir():
        return

    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        base = Path(dirpath)
        dirnames[:] = [name for name in dirnames if not (base / name).is_symlink()]
        for filename in filenames:
            candidate = safe_cleanup_candidate(base / filename, cutoff)
            if candidate:
                yield candidate


def safe_cleanup_candidate(path: Path, cutoff: float) -> tuple[Path, int] | None:
    try:
        file_stat = os.stat(path, follow_symlinks=False)
    except OSError:
        return None
    if not stat.S_ISREG(file_stat.st_mode):
        return None
    if file_stat.st_mtime > cutoff:
        return None
    return path, int(file_stat.st_size)


def positive_int(value: Any, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def positive_float(value: Any, default: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def describe_dry_run(action: RemediationAction) -> str:
    params = ", ".join(
        f"{key}={value}"
        for key, value in sorted(action.params.items())
        if not str(key).startswith("_")
    )
    return f"将执行: {action.action_type} ({params})"


def format_action_plan(actions: list[RemediationAction], results: list[ActionResult] | None = None) -> str:
    if not actions:
        return ""
    lines = ["", "自动处置计划:"]
    for index, action in enumerate(actions, start=1):
        mode = "可自动执行" if action.auto_execute else "需人工确认"
        lines.append(f"{index}. [{action.risk}] {action.title} - {mode}")
        lines.append(f"   原因: {action.reason}")
        playbook = action.params.get("_playbook")
        if isinstance(playbook, dict):
            lines.append(
                "   剧本: "
                f"{playbook.get('name', '')}/{playbook.get('stage', '')}/{playbook.get('step_id', '')}"
            )
    if results:
        lines.extend(["", "处置执行结果:"])
        for result in results:
            lines.append(f"- [{result.status}] {result.action.title}")
            if result.output:
                lines.append(f"  输出: {result.output}")
            if result.error:
                lines.append(f"  错误: {result.error}")
    return "\n".join(lines)

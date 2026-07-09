from __future__ import annotations

import os
import platform
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ops_agent.config import AppConfig
from ops_agent.events import CheckResult


@dataclass
class DiagnosticSnapshot:
    resource_lines: list[str] = field(default_factory=list)
    docker_lines: list[str] = field(default_factory=list)
    log_lines: list[str] = field(default_factory=list)
    command_lines: list[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not (self.resource_lines or self.docker_lines or self.log_lines or self.command_lines)


def collect_diagnostics(results: list[CheckResult], config: AppConfig) -> DiagnosticSnapshot:
    options = dict(config.alerts.get("diagnostics", {}))
    if not options.get("enabled", True):
        return DiagnosticSnapshot()

    snapshot = DiagnosticSnapshot()
    snapshot.resource_lines = collect_resource_snapshot(config)
    if options.get("include_docker", True):
        snapshot.docker_lines = collect_docker_snapshot(
            int(options.get("command_timeout_seconds", 5)),
            disabled_diagnostic_containers(config, options),
        )
    if options.get("include_logs", True):
        snapshot.log_lines = collect_relevant_logs(results, config, options)
    snapshot.command_lines = build_command_hints(results)
    return snapshot


def collect_resource_snapshot(config: AppConfig) -> list[str]:
    lines = [
        f"主机: {platform.node() or 'unknown'}",
        f"系统: {platform.system()} {platform.release()}",
    ]

    disk_path = str(config.server_checks.get("disk_path", "."))
    try:
        disk = shutil.disk_usage(str(config.resolve_path(disk_path)))
    except OSError as exc:
        lines.append(f"磁盘: 无法读取 path={disk_path}: {exc}")
    else:
        disk_percent = (disk.used / disk.total) * 100 if disk.total else 0
        lines.append(
            f"磁盘: {format_bytes(disk.used)} / {format_bytes(disk.total)} ({disk_percent:.1f}%) path={disk_path}"
        )

    load_average = get_load_average()
    if load_average:
        lines.append(f"负载: {load_average}")

    memory = read_linux_memory()
    if memory:
        lines.append(memory)
    return lines


def collect_docker_snapshot(timeout_seconds: int, excluded_containers: set[str] | None = None) -> list[str]:
    if shutil.which("docker") is None:
        return ["未发现 docker 命令，跳过容器快照。"]

    lines: list[str] = []
    ps_output = run_command(
        ["docker", "ps", "--format", "table {{.Names}}\t{{.Status}}\t{{.Ports}}"],
        timeout_seconds,
    )
    if ps_output:
        ps_lines = filter_docker_table_lines(ps_output.splitlines(), excluded_containers or set())
        lines.extend(["docker ps:", *indent_lines(ps_lines[:12])])

    stats_output = run_command(
        ["docker", "stats", "--no-stream", "--format", "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}"],
        timeout_seconds,
    )
    if stats_output:
        stats_lines = filter_docker_table_lines(stats_output.splitlines(), excluded_containers or set())
        lines.extend(["docker stats:", *indent_lines(stats_lines[:12])])
    return lines


def collect_relevant_logs(results: list[CheckResult], config: AppConfig, options: dict[str, Any]) -> list[str]:
    max_lines = int(options.get("max_log_lines", 60))
    max_chars = int(options.get("max_log_chars", 6000))
    log_names = {result.name for result in results if result.source == "log"}
    lines: list[str] = []

    for check in config.log_checks:
        if not check.get("enabled", True):
            continue
        name = str(check.get("name", "log"))
        if log_names and name not in log_names:
            continue
        container = str(check.get("container", "")).strip()
        if container:
            output = run_command(
                ["docker", "logs", "--tail", str(max_lines), container],
                int(options.get("command_timeout_seconds", 5)),
            )
            if not output:
                lines.append(f"{name}: docker logs 为空 {container}")
                continue
            lines.append(f"{name} (container={container}) 最近 {min(max_lines, len(output.splitlines()))} 行")
            lines.extend(indent_lines(output.splitlines()[-max_lines:]))
            continue
        path_value = str(check.get("path", ""))
        if not path_value:
            continue
        path = config.resolve_path(path_value)
        if not path.exists() or not path.is_file():
            lines.append(f"{name}: 日志文件不存在 {path_value}")
            continue

        tail = tail_text_file(path, max_lines)
        if not tail:
            lines.append(f"{name}: 日志文件为空或不可读取 {path_value}")
            continue
        lines.append(f"{name} ({path_value}) 最近 {min(max_lines, len(tail))} 行:")
        lines.extend(indent_lines(tail))

    text = "\n".join(lines)
    if len(text) <= max_chars:
        return lines
    return text[:max_chars].splitlines() + ["...日志内容已截断..."]


def disabled_diagnostic_containers(config: AppConfig, options: dict[str, Any]) -> set[str]:
    containers = {
        str(check.get("container") or "").strip()
        for check in [*config.docker_checks, *config.log_checks]
        if not check.get("enabled", True)
    }
    containers.update(str(item or "").strip() for item in options.get("exclude_containers", []))
    return {container for container in containers if container}


def filter_docker_table_lines(lines: list[str], excluded_containers: set[str]) -> list[str]:
    if not excluded_containers:
        return lines

    filtered: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        first = stripped.split()[0]
        if first in {"NAMES", "NAME"} or first not in excluded_containers:
            filtered.append(line)
    return filtered


def build_command_hints(results: list[CheckResult]) -> list[str]:
    commands = ["systemctl status ops-agent --no-pager", "journalctl -u ops-agent -n 80 --no-pager"]
    if any(result.source in {"http", "json"} for result in results):
        commands.append("docker ps")
        commands.append("docker logs --tail 120 <容器名>")
    if any(result.source == "server" for result in results):
        commands.extend(["df -h", "free -h", "top -b -n 1 | head -40"])
    return commands


def format_snapshot(snapshot: DiagnosticSnapshot) -> str:
    if snapshot.is_empty():
        return ""

    sections: list[str] = ["", "诊断快照:"]
    append_section(sections, "服务器资源", snapshot.resource_lines)
    append_section(sections, "Docker 状态", snapshot.docker_lines)
    append_section(sections, "相关日志", snapshot.log_lines)
    append_section(sections, "建议排查命令", snapshot.command_lines)
    return "\n".join(sections)


def append_section(lines: list[str], title: str, body: list[str]) -> None:
    if not body:
        return
    lines.extend(["", f"{title}:"])
    lines.extend(f"- {line}" for line in body)


def run_command(command: list[str], timeout_seconds: int) -> str:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            check=False,
        )
    except Exception as exc:
        return f"命令执行失败 {' '.join(command)}: {exc}"

    output = (completed.stdout or completed.stderr or "").strip()
    if completed.returncode != 0 and output:
        return f"{output}\n(exit {completed.returncode})"
    return output


def tail_text_file(path: Path, max_lines: int) -> list[str]:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            return handle.readlines()[-max_lines:]
    except OSError:
        return []


def indent_lines(lines: list[str]) -> list[str]:
    return ["  " + line.rstrip() for line in lines if line.rstrip()]


def get_load_average() -> str:
    if not hasattr(os, "getloadavg"):
        return ""
    try:
        one, five, fifteen = os.getloadavg()
    except OSError:
        return ""
    return f"{one:.2f}, {five:.2f}, {fifteen:.2f}"


def read_linux_memory() -> str:
    meminfo = Path("/proc/meminfo")
    if not meminfo.exists():
        return ""
    values: dict[str, int] = {}
    try:
        for line in meminfo.read_text(encoding="utf-8", errors="replace").splitlines():
            key, value = line.split(":", 1)
            values[key] = int(value.strip().split()[0]) * 1024
    except (OSError, ValueError, IndexError):
        return ""

    total = values.get("MemTotal")
    available = values.get("MemAvailable")
    if not total or available is None:
        return ""
    used = total - available
    percent = (used / total) * 100
    return f"内存: {format_bytes(used)} / {format_bytes(total)} ({percent:.1f}%)"


def format_bytes(value: int) -> str:
    size = float(value)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024 or unit == "TB":
            return f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}TB"

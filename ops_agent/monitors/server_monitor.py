from __future__ import annotations

import os
import subprocess
import shutil
from pathlib import Path
from typing import Any

from ops_agent.events import CheckResult


def run_server_checks(config: dict[str, Any], base_dir: Path) -> list[CheckResult]:
    if not config.get("enabled", True):
        return []

    results = [disk_check(config, base_dir)]
    memory = memory_check(config)
    if memory:
        results.append(memory)
    cpu = cpu_check(config)
    if cpu:
        results.append(cpu)
    return results


def disk_check(config: dict[str, Any], base_dir: Path) -> CheckResult:
    disk_path = Path(str(config.get("disk_path", ".")))
    if not disk_path.is_absolute():
        disk_path = base_dir / disk_path

    usage = shutil.disk_usage(disk_path)
    used_percent = round((usage.used / usage.total) * 100, 2)
    threshold = float(config.get("disk_percent_warn", 90))
    status = "warning" if used_percent >= threshold else "ok"
    return CheckResult(
        source="server",
        name="Disk usage",
        status=status,
        summary=f"Disk usage {used_percent}%",
        details={
            "path": str(disk_path),
            "total_bytes": usage.total,
            "used_bytes": usage.used,
            "free_bytes": usage.free,
            "used_percent": used_percent,
            "threshold": threshold,
        },
    )


def memory_check(config: dict[str, Any]) -> CheckResult | None:
    try:
        import psutil  # type: ignore
    except Exception:
        return proc_memory_check(config)

    vm = psutil.virtual_memory()
    threshold = float(config.get("memory_percent_warn", 85))
    used_percent = round(float(vm.percent), 2)
    status = memory_status(used_percent, int(vm.available), config, threshold)
    details: dict[str, Any] = {
        "used_percent": used_percent,
        "available_bytes": int(vm.available),
        "threshold": threshold,
        **memory_threshold_details(config),
    }
    if should_collect_memory_evidence(config, status):
        details["top_processes"] = collect_top_processes(psutil, int(config.get("memory_top_processes", 5)))
        details["top_containers"] = collect_top_containers(
            int(config.get("memory_top_containers", 5)),
            float(config.get("memory_container_stats_timeout_seconds", 3)),
        )
    return CheckResult(
        source="server",
        name="Memory usage",
        status=status,
        summary=memory_summary(used_percent, int(vm.available), details, status),
        details=details,
    )


def cpu_check(config: dict[str, Any]) -> CheckResult | None:
    try:
        import psutil  # type: ignore
    except Exception:
        return proc_cpu_check(config) or load_average_check()

    percent = psutil.cpu_percent(interval=0.2)
    threshold = float(config.get("cpu_percent_warn", 85))
    status = "warning" if percent >= threshold else "ok"
    return CheckResult(
        source="server",
        name="CPU usage",
        status=status,
        summary=f"CPU usage {percent}%",
        details={"used_percent": percent, "threshold": threshold},
    )


def load_average_check() -> CheckResult | None:
    if not hasattr(os, "getloadavg"):
        return None
    one, five, fifteen = os.getloadavg()
    return CheckResult(
        source="server",
        name="Load average",
        status="ok",
        summary=f"Load average {one:.2f}, {five:.2f}, {fifteen:.2f}",
        details={"load_1m": one, "load_5m": five, "load_15m": fifteen},
    )


def proc_memory_check(config: dict[str, Any]) -> CheckResult | None:
    meminfo = Path("/proc/meminfo")
    if not meminfo.exists():
        return None

    values: dict[str, int] = {}
    for line in meminfo.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split()
        if len(parts) >= 2:
            values[parts[0].rstrip(":")] = int(parts[1]) * 1024

    total = values.get("MemTotal")
    available = values.get("MemAvailable")
    if not total or available is None:
        return None

    used_percent = round(((total - available) / total) * 100, 2)
    threshold = float(config.get("memory_percent_warn", 85))
    status = memory_status(used_percent, available, config, threshold)
    details: dict[str, Any] = {
        "used_percent": used_percent,
        "available_bytes": available,
        "threshold": threshold,
        **memory_threshold_details(config),
    }
    if should_collect_memory_evidence(config, status):
        details["top_processes"] = collect_top_processes_from_ps(
            int(config.get("memory_top_processes", 5)),
            float(config.get("memory_process_stats_timeout_seconds", 3)),
        )
        details["top_containers"] = collect_top_containers(
            int(config.get("memory_top_containers", 5)),
            float(config.get("memory_container_stats_timeout_seconds", 3)),
        )
    return CheckResult(
        source="server",
        name="Memory usage",
        status=status,
        summary=memory_summary(used_percent, available, details, status),
        details=details,
    )


def proc_cpu_check(config: dict[str, Any]) -> CheckResult | None:
    first = read_proc_cpu()
    if not first:
        return None

    import time

    time.sleep(0.2)
    second = read_proc_cpu()
    if not second:
        return None

    idle_delta = second["idle"] - first["idle"]
    total_delta = second["total"] - first["total"]
    if total_delta <= 0:
        return None

    used_percent = round((1 - idle_delta / total_delta) * 100, 2)
    threshold = float(config.get("cpu_percent_warn", 85))
    status = "warning" if used_percent >= threshold else "ok"
    return CheckResult(
        source="server",
        name="CPU usage",
        status=status,
        summary=f"CPU usage {used_percent}%",
        details={"used_percent": used_percent, "threshold": threshold},
    )


def read_proc_cpu() -> dict[str, int] | None:
    stat = Path("/proc/stat")
    if not stat.exists():
        return None
    fields = stat.read_text(encoding="utf-8", errors="replace").splitlines()[0].split()
    if not fields or fields[0] != "cpu":
        return None
    values = [int(value) for value in fields[1:]]
    idle = values[3] + (values[4] if len(values) > 4 else 0)
    return {"idle": idle, "total": sum(values)}


def should_collect_memory_evidence(config: dict[str, Any], status: str) -> bool:
    if not bool(config.get("memory_collect_evidence", True)):
        return False
    return status != "ok" or bool(config.get("memory_collect_evidence_when_ok", False))


def memory_status(used_percent: float, available_bytes: int, config: dict[str, Any], percent_threshold: float) -> str:
    if used_percent < percent_threshold:
        return "ok"
    available_threshold_mb = float(config.get("memory_available_mb_warn") or 0)
    if available_threshold_mb <= 0:
        return "warning"
    return "warning" if available_bytes <= available_threshold_mb * 1024 * 1024 else "ok"


def memory_threshold_details(config: dict[str, Any]) -> dict[str, Any]:
    available_threshold_mb = float(config.get("memory_available_mb_warn") or 0)
    if available_threshold_mb <= 0:
        return {}
    return {"available_threshold_bytes": int(available_threshold_mb * 1024 * 1024)}


def collect_top_processes(psutil_module: Any, limit: int) -> list[dict[str, Any]]:
    if limit <= 0:
        return []
    rows: list[dict[str, Any]] = []
    for process in psutil_module.process_iter(["pid", "name", "memory_info", "memory_percent"]):
        try:
            info = process.info
            memory_info = info.get("memory_info")
            rss_bytes = int(getattr(memory_info, "rss", 0) or 0)
            if rss_bytes <= 0:
                continue
            rows.append(
                {
                    "pid": int(info.get("pid") or 0),
                    "name": str(info.get("name") or "process"),
                    "rss_bytes": rss_bytes,
                    "rss_mib": round(rss_bytes / 1024 / 1024, 1),
                    "memory_percent": round(float(info.get("memory_percent") or 0), 2),
                }
            )
        except Exception:
            continue
    rows.sort(key=lambda item: int(item["rss_bytes"]), reverse=True)
    return rows[:limit]


def collect_top_processes_from_ps(limit: int, timeout_seconds: float) -> list[dict[str, Any]]:
    if limit <= 0:
        return []
    try:
        completed = subprocess.run(
            ["ps", "-eo", "pid=,comm=,rss=,%mem=", "--sort=-rss"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=max(1.0, timeout_seconds),
            check=False,
        )
    except Exception:
        return []
    if completed.returncode != 0:
        return []
    return parse_ps_top_processes(completed.stdout, limit)


def parse_ps_top_processes(output: str, limit: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in output.splitlines():
        parts = line.split(None, 3)
        if len(parts) != 4:
            continue
        try:
            pid = int(parts[0])
            rss_kib = int(parts[2])
            memory_percent = float(parts[3])
        except ValueError:
            continue
        rows.append(
            {
                "pid": pid,
                "name": parts[1],
                "rss_bytes": rss_kib * 1024,
                "rss_mib": round(rss_kib / 1024, 1),
                "memory_percent": round(memory_percent, 2),
            }
        )
    rows.sort(key=lambda item: int(item["rss_bytes"]), reverse=True)
    return rows[:limit]


def collect_top_containers(limit: int, timeout_seconds: float) -> list[dict[str, Any]]:
    if limit <= 0:
        return []
    try:
        completed = subprocess.run(
            [
                "docker",
                "stats",
                "--no-stream",
                "--format",
                "{{.Name}}\t{{.MemUsage}}\t{{.MemPerc}}",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=max(1.0, timeout_seconds),
            check=False,
        )
    except Exception:
        return []
    if completed.returncode != 0:
        return []
    rows: list[dict[str, Any]] = []
    for line in completed.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        rows.append(
            {
                "name": parts[0].strip(),
                "memory_usage": parts[1].split("/", 1)[0].strip(),
                "memory_percent": parts[2].strip(),
                "_sort_percent": parse_percent(parts[2]),
            }
        )
    rows.sort(key=lambda item: float(item["_sort_percent"]), reverse=True)
    for row in rows:
        row.pop("_sort_percent", None)
    return rows[:limit]


def parse_percent(value: str) -> float:
    try:
        return float(value.strip().rstrip("%"))
    except ValueError:
        return 0.0


def memory_summary(used_percent: float, available_bytes: int, details: dict[str, Any], status: str) -> str:
    text = f"Memory usage {used_percent}% (available {format_mib(available_bytes)})"
    if status == "ok":
        return text
    top_processes = details.get("top_processes")
    if not isinstance(top_processes, list) or not top_processes:
        return text
    process_text = ", ".join(
        f"{item.get('name', 'process')} {item.get('rss_mib', 0)}MiB"
        for item in top_processes[:3]
        if isinstance(item, dict)
    )
    return f"{text}; top processes: {process_text}" if process_text else text


def format_mib(value: int) -> str:
    return f"{value / 1024 / 1024:.1f}MiB"

from __future__ import annotations

import os
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
        return None

    vm = psutil.virtual_memory()
    threshold = float(config.get("memory_percent_warn", 85))
    status = "warning" if vm.percent >= threshold else "ok"
    return CheckResult(
        source="server",
        name="Memory usage",
        status=status,
        summary=f"Memory usage {vm.percent}%",
        details={"used_percent": vm.percent, "available_bytes": vm.available, "threshold": threshold},
    )


def cpu_check(config: dict[str, Any]) -> CheckResult | None:
    try:
        import psutil  # type: ignore
    except Exception:
        return load_average_check()

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

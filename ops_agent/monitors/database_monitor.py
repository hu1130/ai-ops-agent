from __future__ import annotations

import json
import os
import subprocess
import time
from typing import Any, Callable

from ops_agent.events import CheckResult


MYSQL_METRICS_QUERY = """
SELECT JSON_OBJECT(
  'database', DATABASE(),
  'version', VERSION(),
  'max_connections', @@GLOBAL.max_connections,
  'read_only', @@GLOBAL.read_only,
  'threads_connected', (
    SELECT VARIABLE_VALUE FROM performance_schema.global_status
    WHERE VARIABLE_NAME = 'Threads_connected'
  ),
  'threads_running', (
    SELECT VARIABLE_VALUE FROM performance_schema.global_status
    WHERE VARIABLE_NAME = 'Threads_running'
  ),
  'slow_queries', (
    SELECT VARIABLE_VALUE FROM performance_schema.global_status
    WHERE VARIABLE_NAME = 'Slow_queries'
  ),
  'uptime_seconds', (
    SELECT VARIABLE_VALUE FROM performance_schema.global_status
    WHERE VARIABLE_NAME = 'Uptime'
  ),
  'database_bytes', (
    SELECT COALESCE(SUM(DATA_LENGTH + INDEX_LENGTH), 0)
    FROM information_schema.TABLES
    WHERE TABLE_SCHEMA = DATABASE()
  )
);
""".strip()

MYSQL_DOCKER_SCRIPT = """
set -eu
if [ -n "${MYSQL_ROOT_PASSWORD:-}" ]; then
  user="root"
  password="$MYSQL_ROOT_PASSWORD"
else
  user="${MYSQL_USER:-root}"
  password="${MYSQL_PASSWORD:-}"
fi
database="${MYSQL_DATABASE:-mysql}"
if [ -z "$password" ]; then
  echo "MySQL password environment variable is missing" >&2
  exit 3
fi
MYSQL_PWD="$password" mysql --protocol=TCP -h 127.0.0.1 -u "$user" -D "$database" \
  --connect-timeout=5 --batch --skip-column-names -e "$OPS_AGENT_MYSQL_QUERY"
""".strip()

Runner = Callable[..., subprocess.CompletedProcess[str]]


def run_database_checks(checks: list[dict[str, Any]]) -> list[CheckResult]:
    return [run_database_check(check) for check in checks if check.get("enabled", True)]


def run_database_check(check: dict[str, Any], runner: Runner = subprocess.run) -> CheckResult:
    engine = str(check.get("engine") or "mysql_docker").strip().lower()
    name = str(check.get("name") or check.get("container") or check.get("host") or "Database")
    timeout_seconds = max(1, int(check.get("timeout_seconds", 10)))
    started = time.perf_counter()
    try:
        if engine == "mysql_docker":
            completed = run_mysql_docker(check, runner, timeout_seconds)
        elif engine == "mysql":
            completed = run_mysql_tcp(check, runner, timeout_seconds)
        else:
            return failure_result(check, name, f"Unsupported database engine: {engine}", engine)
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        return failure_result(check, name, f"Database check failed: {exc}", engine)

    latency_ms = int((time.perf_counter() - started) * 1000)
    if completed.returncode != 0:
        error = sanitize_error(completed.stderr or completed.stdout)
        return failure_result(
            check,
            name,
            f"Database query failed: {error or f'exit {completed.returncode}'}",
            engine,
            latency_ms=latency_ms,
        )

    try:
        metrics = parse_metrics(completed.stdout)
    except ValueError as exc:
        return failure_result(check, name, f"Database metrics invalid: {exc}", engine, latency_ms=latency_ms)
    return metrics_result(check, name, engine, metrics, latency_ms)


def run_mysql_docker(check: dict[str, Any], runner: Runner, timeout_seconds: int) -> subprocess.CompletedProcess[str]:
    container = str(check.get("container") or "").strip()
    if not container:
        raise ValueError("mysql_docker check requires container")
    command = [
        "docker",
        "exec",
        "-e",
        f"OPS_AGENT_MYSQL_QUERY={MYSQL_METRICS_QUERY}",
        container,
        "sh",
        "-lc",
        MYSQL_DOCKER_SCRIPT,
    ]
    return runner(command, capture_output=True, text=True, timeout=timeout_seconds, check=False)


def run_mysql_tcp(check: dict[str, Any], runner: Runner, timeout_seconds: int) -> subprocess.CompletedProcess[str]:
    host = str(check.get("host") or "127.0.0.1").strip()
    port = int(check.get("port", 3306))
    user = str(check.get("username") or check.get("user") or "").strip()
    database = str(check.get("database") or "mysql").strip()
    password = str(check.get("password") or "")
    password_env = str(check.get("password_env") or "").strip()
    if password_env:
        password = str(os.environ.get(password_env) or password)
    if not user or not password:
        raise ValueError("mysql check requires username and password/password_env")
    command = [
        "mysql",
        "--protocol=TCP",
        "-h",
        host,
        "-P",
        str(port),
        "-u",
        user,
        "-D",
        database,
        f"--connect-timeout={min(timeout_seconds, 30)}",
        "--batch",
        "--skip-column-names",
        "-e",
        MYSQL_METRICS_QUERY,
    ]
    env = os.environ.copy()
    env["MYSQL_PWD"] = password
    return runner(command, capture_output=True, text=True, timeout=timeout_seconds, check=False, env=env)


def parse_metrics(output: str) -> dict[str, Any]:
    lines = [line.strip() for line in str(output or "").splitlines() if line.strip()]
    if not lines:
        raise ValueError("empty MySQL output")
    try:
        payload = json.loads(lines[-1])
    except json.JSONDecodeError as exc:
        raise ValueError("last MySQL output line is not JSON") from exc
    if not isinstance(payload, dict) or int_value(payload.get("max_connections")) <= 0:
        raise ValueError("required MySQL metrics are missing")
    return {
        "database": str(payload.get("database") or ""),
        "version": str(payload.get("version") or ""),
        "max_connections": int_value(payload.get("max_connections")),
        "threads_connected": int_value(payload.get("threads_connected")),
        "threads_running": int_value(payload.get("threads_running")),
        "slow_queries": int_value(payload.get("slow_queries")),
        "uptime_seconds": int_value(payload.get("uptime_seconds")),
        "database_bytes": int_value(payload.get("database_bytes")),
        "read_only": bool(int_value(payload.get("read_only"))),
    }


def metrics_result(
    check: dict[str, Any],
    name: str,
    engine: str,
    metrics: dict[str, Any],
    latency_ms: int,
) -> CheckResult:
    max_connections = max(1, int(metrics["max_connections"]))
    connection_usage = round(int(metrics["threads_connected"]) * 100 / max_connections, 2)
    max_connection_usage = float(check.get("max_connection_usage_percent", 80))
    max_running_threads = int(check.get("max_running_threads", 20))
    max_query_latency_ms = int(check.get("max_query_latency_ms", 3000))
    max_database_bytes = int(check.get("max_database_bytes", 0) or 0)
    warnings: list[str] = []
    if connection_usage >= max_connection_usage:
        warnings.append(f"connection usage {connection_usage}% >= {max_connection_usage}%")
    if int(metrics["threads_running"]) >= max_running_threads:
        warnings.append(f"running threads {metrics['threads_running']} >= {max_running_threads}")
    if latency_ms >= max_query_latency_ms:
        warnings.append(f"query latency {latency_ms} ms >= {max_query_latency_ms} ms")
    if max_database_bytes > 0 and int(metrics["database_bytes"]) >= max_database_bytes:
        warnings.append(f"database size {metrics['database_bytes']} bytes >= {max_database_bytes} bytes")
    if bool(check.get("expect_writable", True)) and metrics["read_only"]:
        warnings.append("database is read-only")

    status = "warning" if warnings else "ok"
    summary = (
        f"MySQL warning: {'; '.join(warnings)}"
        if warnings
        else f"MySQL OK in {latency_ms} ms; connections {metrics['threads_connected']}/{max_connections}"
    )
    details = {
        "engine": engine,
        "container": str(check.get("container") or ""),
        "host": str(check.get("host") or ""),
        "port": int(check.get("port", 3306)),
        "database": metrics["database"],
        "version": metrics["version"],
        "latency_ms": latency_ms,
        "connection_usage_percent": connection_usage,
        **metrics,
        "thresholds": {
            "max_connection_usage_percent": max_connection_usage,
            "max_running_threads": max_running_threads,
            "max_query_latency_ms": max_query_latency_ms,
            "max_database_bytes": max_database_bytes,
        },
        "classification": "database_pressure" if warnings else "database_healthy",
        **alert_policy_details(check),
    }
    return CheckResult(source="database", name=name, status=status, summary=summary, details=details)


def failure_result(
    check: dict[str, Any],
    name: str,
    summary: str,
    engine: str,
    latency_ms: int = 0,
) -> CheckResult:
    return CheckResult(
        source="database",
        name=name,
        status=str(check.get("failure_status") or "critical"),
        summary=summary,
        details={
            "engine": engine,
            "container": str(check.get("container") or ""),
            "host": str(check.get("host") or ""),
            "port": int(check.get("port", 3306)),
            "latency_ms": latency_ms,
            "classification": "database_unavailable",
            **alert_policy_details(check),
        },
    )


def alert_policy_details(check: dict[str, Any]) -> dict[str, int]:
    details: dict[str, int] = {}
    for key in ("alert_after_failures", "consecutive_failures", "recovery_after_successes"):
        try:
            value = int(check.get(key))
        except (TypeError, ValueError):
            continue
        if value > 0:
            details[key] = value
    return details


def sanitize_error(value: str) -> str:
    lines = [line.strip() for line in str(value or "").splitlines() if line.strip()]
    return " | ".join(lines[-3:])[:500]


def int_value(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0

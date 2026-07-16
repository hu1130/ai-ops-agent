from __future__ import annotations

from datetime import datetime, timedelta, timezone
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
from typing import Any, Callable

from ops_agent.config import AppConfig
from ops_agent.events import CheckResult
from ops_agent.storage import Storage


MYSQL_BACKUP_SCRIPT = """
set -eu
database="${MYSQL_DATABASE:-}"
if [ -z "$database" ]; then
  echo "MYSQL_DATABASE is missing" >&2
  exit 3
fi
if [ -n "${MYSQL_ROOT_PASSWORD:-}" ]; then
  user="root"
  password="$MYSQL_ROOT_PASSWORD"
else
  user="${MYSQL_USER:-root}"
  password="${MYSQL_PASSWORD:-}"
fi
if [ -z "$password" ]; then
  echo "MySQL backup password environment variable is missing" >&2
  exit 3
fi
MYSQL_PWD="$password" mysqldump -h 127.0.0.1 -u "$user" \
  --single-transaction --quick --routines --events --triggers --no-tablespaces "$database"
""".strip()

MYSQL_DRILL_ADMIN_SCRIPT = """
set -eu
case "$OPS_DRILL_DATABASE" in
  ops_restore_drill_*) ;;
  *) echo "invalid restore drill database name" >&2; exit 4 ;;
esac
if [ -n "${MYSQL_ROOT_PASSWORD:-}" ]; then
  user="root"
  password="$MYSQL_ROOT_PASSWORD"
else
  user="${MYSQL_USER:-root}"
  password="${MYSQL_PASSWORD:-}"
fi
if [ -z "$password" ]; then
  echo "MySQL restore password environment variable is missing" >&2
  exit 3
fi
case "$OPS_DRILL_ACTION" in
  create)
    query="DROP DATABASE IF EXISTS \`$OPS_DRILL_DATABASE\`; CREATE DATABASE \`$OPS_DRILL_DATABASE\`"
    ;;
  verify)
    query="SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='$OPS_DRILL_DATABASE'"
    ;;
  drop)
    query="DROP DATABASE IF EXISTS \`$OPS_DRILL_DATABASE\`"
    ;;
  *) echo "invalid restore drill action" >&2; exit 4 ;;
esac
MYSQL_PWD="$password" mysql -h 127.0.0.1 -u "$user" --batch --skip-column-names -e "$query"
""".strip()

MYSQL_RESTORE_SCRIPT = """
set -eu
case "$OPS_DRILL_DATABASE" in
  ops_restore_drill_*) ;;
  *) echo "invalid restore drill database name" >&2; exit 4 ;;
esac
if [ -n "${MYSQL_ROOT_PASSWORD:-}" ]; then
  user="root"
  password="$MYSQL_ROOT_PASSWORD"
else
  user="${MYSQL_USER:-root}"
  password="${MYSQL_PASSWORD:-}"
fi
MYSQL_PWD="$password" mysql -h 127.0.0.1 -u "$user" "$OPS_DRILL_DATABASE"
""".strip()

Runner = Callable[..., subprocess.CompletedProcess]


def run_due_backups(
    storage: Storage,
    config: AppConfig,
    runner: Runner = subprocess.run,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    backup_config = safe_dict(config.raw.get("backups"))
    if not backup_config.get("enabled", False):
        return []
    current = now or datetime.now(timezone.utc)
    results: list[dict[str, Any]] = []
    for target in configured_targets(config):
        target_id = str(target["id"])
        latest_backup = storage.latest_successful_backup_run(target_id, "backup")
        if run_due(latest_backup, float(target.get("interval_hours", 24)), current):
            results.append(run_backup_target(storage, config, target, runner=runner))
            latest_backup = storage.latest_successful_backup_run(target_id, "backup")
        drill = safe_dict(target.get("restore_drill"))
        latest_drill = storage.latest_successful_backup_run(target_id, "restore_drill")
        if drill.get("enabled", False) and latest_backup and run_due(
            latest_drill,
            float(drill.get("interval_days", 7)) * 24,
            current,
        ):
            results.append(run_restore_drill(storage, config, target, latest_backup, runner=runner))
        cleanup_old_backup_files(config, target, current)
    return results


def run_backup_now(
    storage: Storage,
    config: AppConfig,
    target_id: str = "",
    runner: Runner = subprocess.run,
) -> list[dict[str, Any]]:
    targets = selected_targets(config, target_id)
    return [run_backup_target(storage, config, target, runner=runner) for target in targets]


def run_restore_drill_now(
    storage: Storage,
    config: AppConfig,
    target_id: str,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    targets = selected_targets(config, target_id)
    if len(targets) != 1:
        raise ValueError("restore drill requires exactly one target_id")
    target = targets[0]
    latest = storage.latest_successful_backup_run(str(target["id"]), "backup")
    if not latest:
        raise ValueError(f"no successful backup available for {target['id']}")
    return run_restore_drill(storage, config, target, latest, runner=runner)


def run_backup_target(
    storage: Storage,
    config: AppConfig,
    target: dict[str, Any],
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    target_id = str(target["id"])
    engine = str(target.get("engine") or "sqlite")
    run_id = storage.start_backup_run(target_id, engine, "backup", {"name": target.get("name") or target_id})
    try:
        if engine == "sqlite":
            result = backup_sqlite(config, target)
        elif engine == "mysql_docker":
            result = backup_mysql_docker(config, target, runner)
        else:
            raise ValueError(f"unsupported backup engine: {engine}")
        return storage.finish_backup_run(
            run_id,
            "success",
            path=str(result["path"]),
            size_bytes=int(result["size_bytes"]),
            checksum=str(result["checksum"]),
            metadata=safe_dict(result.get("metadata")),
        )
    except Exception as exc:
        return storage.finish_backup_run(run_id, "failed", error=clean_error(str(exc)))


def run_restore_drill(
    storage: Storage,
    config: AppConfig,
    target: dict[str, Any],
    backup_run: dict[str, Any],
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    target_id = str(target["id"])
    engine = str(target.get("engine") or "sqlite")
    run_id = storage.start_backup_run(
        target_id,
        engine,
        "restore_drill",
        {"backup_run_id": backup_run.get("id")},
    )
    try:
        backup_path = Path(str(backup_run.get("path") or ""))
        if not backup_path.is_file():
            raise ValueError("backup file is missing")
        if engine == "sqlite":
            result = restore_drill_sqlite(backup_path)
        elif engine == "mysql_docker":
            result = restore_drill_mysql_docker(target, backup_path, runner)
        else:
            raise ValueError(f"unsupported restore drill engine: {engine}")
        return storage.finish_backup_run(
            run_id,
            "success",
            path=str(backup_path),
            size_bytes=int(backup_run.get("size_bytes") or backup_path.stat().st_size),
            checksum=str(backup_run.get("checksum") or ""),
            metadata={"backup_run_id": backup_run.get("id"), **result},
        )
    except Exception as exc:
        return storage.finish_backup_run(
            run_id,
            "failed",
            path=str(backup_run.get("path") or ""),
            error=clean_error(str(exc)),
            metadata={"backup_run_id": backup_run.get("id")},
        )


def backup_sqlite(config: AppConfig, target: dict[str, Any]) -> dict[str, Any]:
    source = config.resolve_path(str(target.get("path") or config.app.get("database_path") or "data/ops_agent.db"))
    if not source.is_file():
        raise ValueError(f"SQLite source does not exist: {source}")
    destination = target_backup_dir(config, target) / f"{file_timestamp()}.sqlite"
    source_connection = sqlite3.connect(source)
    destination_connection = sqlite3.connect(destination)
    try:
        source_connection.backup(destination_connection)
        destination_connection.commit()
        integrity = str(destination_connection.execute("pragma integrity_check").fetchone()[0])
        table_count = int(
            destination_connection.execute(
                "select count(*) from sqlite_master where type = 'table' and name not like 'sqlite_%'"
            ).fetchone()[0]
        )
    finally:
        destination_connection.close()
        source_connection.close()
    if integrity.lower() != "ok":
        destination.unlink(missing_ok=True)
        raise ValueError(f"SQLite backup integrity check failed: {integrity}")
    return file_result(destination, {"integrity_check": integrity, "table_count": table_count})


def backup_mysql_docker(
    config: AppConfig,
    target: dict[str, Any],
    runner: Runner,
) -> dict[str, Any]:
    container = str(target.get("container") or "").strip()
    if not container:
        raise ValueError("mysql_docker backup requires container")
    timeout_seconds = max(30, int(target.get("timeout_seconds", 900)))
    raw_path = target_backup_dir(config, target) / f"{file_timestamp()}.sql"
    command = ["docker", "exec", container, "sh", "-lc", MYSQL_BACKUP_SCRIPT]
    with raw_path.open("wb") as output:
        completed = runner(command, stdout=output, stderr=subprocess.PIPE, timeout=timeout_seconds, check=False)
        fallback_stdout = completed.stdout
        if raw_path.stat().st_size == 0 and fallback_stdout:
            output.write(bytes_value(fallback_stdout))
    if completed.returncode != 0:
        raw_path.unlink(missing_ok=True)
        raise ValueError(f"mysqldump failed: {clean_error(text_value(completed.stderr))}")
    if raw_path.stat().st_size < int(target.get("minimum_backup_bytes", 100)):
        raw_path.unlink(missing_ok=True)
        raise ValueError("mysqldump output is unexpectedly small")
    gzip_path = raw_path.with_suffix(".sql.gz")
    with raw_path.open("rb") as source, gzip.open(gzip_path, "wb", compresslevel=6) as destination:
        shutil.copyfileobj(source, destination)
    raw_path.unlink(missing_ok=True)
    return file_result(gzip_path, {"container": container, "compressed": True})


def restore_drill_sqlite(backup_path: Path) -> dict[str, Any]:
    restored_path = backup_path.with_name(f".{backup_path.stem}-restore-drill.sqlite")
    source = sqlite3.connect(backup_path)
    restored = sqlite3.connect(restored_path)
    try:
        source.backup(restored)
        restored.commit()
        integrity = str(restored.execute("pragma integrity_check").fetchone()[0])
        table_count = int(
            restored.execute(
                "select count(*) from sqlite_master where type = 'table' and name not like 'sqlite_%'"
            ).fetchone()[0]
        )
    finally:
        restored.close()
        source.close()
        restored_path.unlink(missing_ok=True)
    if integrity.lower() != "ok":
        raise ValueError(f"restored SQLite integrity check failed: {integrity}")
    return {"integrity_check": integrity, "table_count": table_count, "isolated_restore": True}


def restore_drill_mysql_docker(
    target: dict[str, Any],
    backup_path: Path,
    runner: Runner,
) -> dict[str, Any]:
    container = str(target.get("container") or "").strip()
    if not container:
        raise ValueError("mysql_docker restore drill requires container")
    timeout_seconds = max(60, int(safe_dict(target.get("restore_drill")).get("timeout_seconds", 1200)))
    drill_database = f"ops_restore_drill_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}"
    create = mysql_drill_admin_command(container, drill_database, "create")
    verify = mysql_drill_admin_command(container, drill_database, "verify")
    drop = mysql_drill_admin_command(container, drill_database, "drop")
    restore = [
        "docker",
        "exec",
        "-i",
        "-e",
        f"OPS_DRILL_DATABASE={drill_database}",
        container,
        "sh",
        "-lc",
        MYSQL_RESTORE_SCRIPT,
    ]
    create_result = runner(create, capture_output=True, text=True, timeout=timeout_seconds, check=False)
    if create_result.returncode != 0:
        raise ValueError(f"restore drill database create failed: {clean_error(text_value(create_result.stderr))}")
    restore_error = ""
    table_count = 0
    try:
        restored_sql = backup_path.with_name(f".{backup_path.stem}-restore-drill.sql")
        try:
            with gzip.open(backup_path, "rb") as source, restored_sql.open("wb") as destination:
                shutil.copyfileobj(source, destination)
            with restored_sql.open("rb") as source:
                restore_result = runner(
                    restore,
                    stdin=source,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=timeout_seconds,
                    check=False,
                )
            if restore_result.returncode != 0:
                restore_error = clean_error(text_value(restore_result.stderr))
                raise ValueError(f"restore drill import failed: {restore_error}")
        finally:
            restored_sql.unlink(missing_ok=True)
        verify_result = runner(verify, capture_output=True, text=True, timeout=timeout_seconds, check=False)
        if verify_result.returncode != 0:
            raise ValueError(f"restore drill verification failed: {clean_error(text_value(verify_result.stderr))}")
        table_count = last_int(text_value(verify_result.stdout))
        minimum_tables = int(safe_dict(target.get("restore_drill")).get("minimum_tables", 1))
        if table_count < minimum_tables:
            raise ValueError(f"restored table count {table_count} is below required {minimum_tables}")
    finally:
        drop_result = runner(drop, capture_output=True, text=True, timeout=timeout_seconds, check=False)
        if drop_result.returncode != 0 and not restore_error:
            raise ValueError(f"restore drill cleanup failed: {clean_error(text_value(drop_result.stderr))}")
    return {"table_count": table_count, "isolated_restore": True, "temporary_database_removed": True}


def run_backup_health_checks(storage: Storage, config: AppConfig) -> list[CheckResult]:
    backup_config = safe_dict(config.raw.get("backups"))
    if not backup_config.get("enabled", False):
        return []
    return [backup_health_result(storage, target) for target in configured_targets(config)]


def backup_health_result(storage: Storage, target: dict[str, Any]) -> CheckResult:
    target_id = str(target["id"])
    name = str(target.get("name") or target_id)
    latest_backup = storage.latest_successful_backup_run(target_id, "backup")
    latest_attempts = storage.latest_backup_runs(1, target_id=target_id, kind="backup")
    latest_attempt = latest_attempts[0] if latest_attempts else None
    max_age_hours = float(target.get("max_age_hours", float(target.get("interval_hours", 24)) * 2))
    problems: list[str] = []
    severity = "ok"
    if latest_attempt and latest_attempt.get("status") == "failed":
        problems.append(f"latest backup failed: {latest_attempt.get('error') or 'unknown error'}")
        severity = "critical"
    if not latest_backup:
        problems.append("no successful backup exists")
        severity = max_severity(severity, str(target.get("missing_status") or "warning"))
    else:
        age_hours = run_age_hours(latest_backup)
        if age_hours > max_age_hours:
            problems.append(f"last successful backup is {age_hours:.1f} hours old")
            severity = max_severity(severity, str(target.get("stale_status") or "critical"))

    drill = safe_dict(target.get("restore_drill"))
    latest_drill = storage.latest_successful_backup_run(target_id, "restore_drill")
    if drill.get("enabled", False):
        max_drill_age = float(drill.get("max_age_days", float(drill.get("interval_days", 7)) * 2)) * 24
        latest_drill_attempts = storage.latest_backup_runs(1, target_id=target_id, kind="restore_drill")
        latest_drill_attempt = latest_drill_attempts[0] if latest_drill_attempts else None
        if latest_drill_attempt and latest_drill_attempt.get("status") == "failed":
            problems.append(f"latest restore drill failed: {latest_drill_attempt.get('error') or 'unknown error'}")
            severity = max_severity(severity, "critical")
        elif not latest_drill:
            problems.append("no successful restore drill exists")
            severity = max_severity(severity, "warning")
        elif run_age_hours(latest_drill) > max_drill_age:
            problems.append("restore drill is stale")
            severity = max_severity(severity, "warning")

    summary = f"Backup healthy for {name}" if not problems else f"Backup warning for {name}: {'; '.join(problems)}"
    return CheckResult(
        source="backup",
        name=name,
        status=severity,
        summary=summary,
        details={
            "target_id": target_id,
            "engine": str(target.get("engine") or "sqlite"),
            "classification": "backup_failure" if problems else "backup_healthy",
            "latest_backup": public_backup_run(latest_backup),
            "latest_restore_drill": public_backup_run(latest_drill),
            "max_age_hours": max_age_hours,
            **alert_policy_details(target),
        },
    )


def backup_status_payload(storage: Storage, config: AppConfig, limit: int = 100) -> dict[str, Any]:
    targets = configured_targets(config)
    health = run_backup_health_checks(storage, config)
    return {
        "mode": "backup_status",
        "enabled": bool(safe_dict(config.raw.get("backups")).get("enabled", False)),
        "target_count": len(targets),
        "targets": [public_target(target) for target in targets],
        "health": [result.__dict__ for result in health],
        "runs": [public_backup_run(row) for row in storage.latest_backup_runs(limit)],
    }


def configured_targets(config: AppConfig) -> list[dict[str, Any]]:
    backups = safe_dict(config.raw.get("backups"))
    targets: list[dict[str, Any]] = []
    for item in safe_list(backups.get("targets")):
        target = safe_dict(item)
        if not target.get("enabled", True):
            continue
        target_id = str(target.get("id") or "").strip()
        if not target_id:
            continue
        targets.append(target)
    return targets


def selected_targets(config: AppConfig, target_id: str) -> list[dict[str, Any]]:
    targets = configured_targets(config)
    if target_id:
        targets = [target for target in targets if str(target.get("id")) == target_id]
        if not targets:
            raise ValueError(f"backup target not found: {target_id}")
    if not targets:
        raise ValueError("no enabled backup targets")
    return targets


def target_backup_dir(config: AppConfig, target: dict[str, Any]) -> Path:
    backups = safe_dict(config.raw.get("backups"))
    base = config.resolve_path(str(backups.get("base_dir") or "data/backups"))
    target_id = str(target.get("id") or "backup")
    path = (base / target_id).resolve()
    base_resolved = base.resolve()
    if base_resolved not in path.parents:
        raise ValueError("backup target path is outside backup base directory")
    path.mkdir(parents=True, exist_ok=True)
    return path


def cleanup_old_backup_files(config: AppConfig, target: dict[str, Any], now: datetime) -> int:
    directory = target_backup_dir(config, target)
    retention_days = max(1, int(target.get("retention_days", 14)))
    minimum_backups = max(1, int(target.get("minimum_backups", 3)))
    cutoff = now.timestamp() - retention_days * 86400
    files = sorted(
        [path for path in directory.iterdir() if path.is_file() and not path.name.startswith(".")],
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    deleted = 0
    for path in files[minimum_backups:]:
        if path.stat().st_mtime < cutoff:
            path.unlink(missing_ok=True)
            deleted += 1
    return deleted


def mysql_drill_admin_command(container: str, database: str, action: str) -> list[str]:
    return [
        "docker",
        "exec",
        "-e",
        f"OPS_DRILL_DATABASE={database}",
        "-e",
        f"OPS_DRILL_ACTION={action}",
        container,
        "sh",
        "-lc",
        MYSQL_DRILL_ADMIN_SCRIPT,
    ]


def file_result(path: Path, metadata: dict[str, Any]) -> dict[str, Any]:
    return {
        "path": path,
        "size_bytes": path.stat().st_size,
        "checksum": sha256_file(path),
        "metadata": metadata,
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_due(run: dict | None, interval_hours: float, now: datetime) -> bool:
    if not run:
        return True
    completed = parse_datetime(str(run.get("completed_at") or run.get("started_at") or ""))
    return completed is None or now - completed >= timedelta(hours=max(0.01, interval_hours))


def run_age_hours(run: dict) -> float:
    completed = parse_datetime(str(run.get("completed_at") or run.get("started_at") or ""))
    if not completed:
        return float("inf")
    return max(0.0, (datetime.now(timezone.utc) - completed).total_seconds() / 3600)


def parse_datetime(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def public_backup_run(run: dict | None) -> dict[str, Any] | None:
    if not run:
        return None
    path = Path(str(run.get("path") or ""))
    return {
        "id": run.get("id"),
        "target_id": run.get("target_id"),
        "engine": run.get("engine"),
        "kind": run.get("kind"),
        "status": run.get("status"),
        "started_at": run.get("started_at"),
        "completed_at": run.get("completed_at"),
        "file_name": path.name if path.name else "",
        "size_bytes": int(run.get("size_bytes") or 0),
        "checksum": str(run.get("checksum") or ""),
        "error": str(run.get("error") or ""),
        "metadata": safe_dict(run.get("metadata")),
    }


def public_target(target: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(target.get("id") or ""),
        "name": str(target.get("name") or target.get("id") or ""),
        "engine": str(target.get("engine") or "sqlite"),
        "container": str(target.get("container") or ""),
        "interval_hours": float(target.get("interval_hours", 24)),
        "retention_days": int(target.get("retention_days", 14)),
        "restore_drill": safe_dict(target.get("restore_drill")),
    }


def alert_policy_details(target: dict[str, Any]) -> dict[str, int]:
    details: dict[str, int] = {}
    for key in ("alert_after_failures", "consecutive_failures", "recovery_after_successes"):
        try:
            value = int(target.get(key))
        except (TypeError, ValueError):
            continue
        if value > 0:
            details[key] = value
    return details


def max_severity(left: str, right: str) -> str:
    rank = {"ok": 0, "warning": 1, "critical": 2}
    return right if rank.get(right, 1) > rank.get(left, 0) else left


def file_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def last_int(output: str) -> int:
    lines = [line.strip() for line in str(output or "").splitlines() if line.strip()]
    if not lines:
        raise ValueError("restore drill verification returned no table count")
    try:
        return int(lines[-1])
    except ValueError as exc:
        raise ValueError("restore drill verification table count is invalid") from exc


def clean_error(value: str) -> str:
    lines = [line.strip() for line in str(value or "").splitlines() if line.strip()]
    return " | ".join(lines[-3:])[:1000]


def text_value(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value or "")


def bytes_value(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    return str(value or "").encode("utf-8")


def safe_dict(value: object) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def safe_list(value: object) -> list[Any]:
    return list(value) if isinstance(value, list) else []

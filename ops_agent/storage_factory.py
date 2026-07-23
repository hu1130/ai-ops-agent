from __future__ import annotations

import os
from pathlib import Path
from threading import RLock
from typing import Any, Iterable

from ops_agent.config import AppConfig
from ops_agent.storage import Storage


REQUIRED_MYSQL_TABLES = {
    "action_logs",
    "ai_repair_proposals",
    "api_audit_logs",
    "backup_runs",
    "check_results",
    "incidents",
    "notification_logs",
    "fleet_nodes",
    "organizations",
    "users",
    "auth_sessions",
    "api_credentials",
    "fleet_enrollment_tokens",
}


def open_configured_storage(config: AppConfig) -> Storage:
    backend = str(config.app.get("storage_backend") or "sqlite").strip().lower()
    if backend == "sqlite":
        path = config.resolve_path(str(config.app.get("database_path", "data/ops_agent.db")))
        return Storage(path)
    if backend == "mysql":
        return MySQLStorage(mysql_settings(config))
    raise ValueError(f"unsupported storage backend: {backend}")


def mysql_settings(config: AppConfig) -> dict[str, Any]:
    raw = config.raw.get("mysql") if isinstance(config.raw.get("mysql"), dict) else {}
    password_env = str(raw.get("password_env") or "OPS_AGENT_MYSQL_PASSWORD").strip()
    password = str(raw.get("password") or os.environ.get(password_env, ""))
    if not password:
        raise ValueError(f"MySQL password is not configured; set {password_env}")
    database = str(raw.get("database") or "ops_agent").strip()
    user = str(raw.get("user") or "ops_agent").strip()
    if not database or not user:
        raise ValueError("MySQL database and user are required")
    return {
        "host": str(raw.get("host") or "127.0.0.1"),
        "port": int(raw.get("port") or 3306),
        "database": database,
        "user": user,
        "password": password,
        "charset": "utf8mb4",
        "connect_timeout": int(raw.get("connect_timeout_seconds") or 5),
        "read_timeout": int(raw.get("read_timeout_seconds") or 30),
        "write_timeout": int(raw.get("write_timeout_seconds") or 30),
    }


class MySQLStorage(Storage):
    def __init__(self, settings: dict[str, Any]):
        try:
            import pymysql
            from pymysql.cursors import DictCursor
        except ImportError as exc:
            raise RuntimeError("PyMySQL is required for the MySQL storage backend") from exc

        self.database_path = Path(f"mysql-{settings['database']}")
        raw_connection = pymysql.connect(
            host=settings["host"],
            port=int(settings["port"]),
            user=settings["user"],
            password=settings["password"],
            database=settings["database"],
            charset=settings.get("charset", "utf8mb4"),
            connect_timeout=int(settings.get("connect_timeout", 5)),
            read_timeout=int(settings.get("read_timeout", 30)),
            write_timeout=int(settings.get("write_timeout", 30)),
            autocommit=False,
            cursorclass=DictCursor,
        )
        self.connection = MySQLConnectionAdapter(raw_connection)
        self.lock = RLock()
        self.ensure_fleet_schema()
        self.ensure_scope_columns()
        self.ensure_identity_schema()
        self.verify_schema()

    def migrate(self) -> None:
        self.verify_schema()

    def verify_schema(self) -> None:
        rows = self.connection.execute(
            "select table_name from information_schema.tables where table_schema = database()"
        ).fetchall()
        tables = {str(row.get("table_name") or row.get("TABLE_NAME") or "") for row in rows}
        missing = sorted(REQUIRED_MYSQL_TABLES - tables)
        if missing:
            self.connection.close()
            raise RuntimeError("MySQL schema is incomplete; missing tables: " + ", ".join(missing))

    def ensure_fleet_schema(self) -> None:
        self.connection.execute(
            """
            create table if not exists fleet_nodes (
                node_id varchar(64) not null,
                created_at varchar(255) not null,
                updated_at varchar(255) not null,
                last_seen_at varchar(255) not null,
                name varchar(255) not null,
                hostname varchar(255) not null,
                address varchar(255) not null,
                agent_version varchar(80) not null,
                platform varchar(255) not null,
                enabled tinyint not null default 1,
                labels_json longtext not null,
                capabilities_json longtext not null,
                metrics_json longtext not null,
                projects_json longtext not null,
                assets_json longtext not null,
                discovery_json longtext not null,
                primary key (node_id)
            ) engine=InnoDB default charset=utf8mb4 collate=utf8mb4_unicode_ci
            """
        )
        self.connection.commit()

    def vacuum(self) -> None:
        return None


class MySQLConnectionAdapter:
    backend = "mysql"

    def __init__(self, connection: Any):
        self._connection = connection
        self._dirty = False
        self._lock = RLock()

    def execute(self, sql: str, params: Iterable[Any] | None = None) -> "BufferedCursor":
        with self._lock:
            self._ping_if_idle()
            cursor = self._connection.cursor()
            try:
                cursor.execute(mysql_placeholders(sql), tuple(params or ()))
                result = BufferedCursor.from_cursor(cursor)
                if cursor.description:
                    if not self._dirty:
                        self._connection.rollback()
                else:
                    self._dirty = True
                return result
            except Exception:
                self._discard_failed_transaction()
                raise
            finally:
                cursor.close()

    def executemany(self, sql: str, params: Iterable[Iterable[Any]]) -> "BufferedCursor":
        with self._lock:
            self._ping_if_idle()
            cursor = self._connection.cursor()
            try:
                cursor.executemany(mysql_placeholders(sql), [tuple(row) for row in params])
                result = BufferedCursor.from_cursor(cursor)
                self._dirty = True
                return result
            except Exception:
                self._discard_failed_transaction()
                raise
            finally:
                cursor.close()

    def commit(self) -> None:
        with self._lock:
            try:
                self._connection.commit()
            finally:
                self._dirty = False

    def rollback(self) -> None:
        with self._lock:
            try:
                self._connection.rollback()
            finally:
                self._dirty = False

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def _ping_if_idle(self) -> None:
        if self._dirty:
            return
        ping = getattr(self._connection, "ping", None)
        if callable(ping):
            ping(reconnect=True)

    def _discard_failed_transaction(self) -> None:
        try:
            self._connection.rollback()
        except Exception:
            pass
        self._dirty = False


class BufferedCursor:
    def __init__(self, rows: list[dict[str, Any]], lastrowid: int, rowcount: int):
        self._rows = rows
        self._position = 0
        self.lastrowid = lastrowid
        self.rowcount = rowcount

    @classmethod
    def from_cursor(cls, cursor: Any) -> "BufferedCursor":
        rows = [dict(row) for row in cursor.fetchall()] if cursor.description else []
        return cls(rows, int(cursor.lastrowid or 0), int(cursor.rowcount or 0))

    def fetchone(self) -> dict[str, Any] | None:
        if self._position >= len(self._rows):
            return None
        row = self._rows[self._position]
        self._position += 1
        return row

    def fetchall(self) -> list[dict[str, Any]]:
        rows = self._rows[self._position :]
        self._position = len(self._rows)
        return rows

    def __iter__(self):
        return iter(self.fetchall())


def mysql_placeholders(sql: str) -> str:
    return str(sql).replace("?", "%s")

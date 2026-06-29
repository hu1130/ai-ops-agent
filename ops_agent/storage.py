from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import RLock

from ops_agent.events import CheckResult, utc_now_iso


class Storage:
    def __init__(self, database_path: Path):
        self.database_path = database_path
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.database_path, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.lock = RLock()
        self.migrate()

    def migrate(self) -> None:
        with self.lock:
            self.connection.executescript(
                """
                create table if not exists check_results (
                    id integer primary key autoincrement,
                    created_at text not null,
                    source text not null,
                    name text not null,
                    status text not null,
                    summary text not null,
                    details_json text not null
                );

                create table if not exists incidents (
                    id integer primary key autoincrement,
                    created_at text not null,
                    severity text not null,
                    title text not null,
                    analysis text not null,
                    results_json text not null
                );

                create table if not exists action_logs (
                    id integer primary key autoincrement,
                    created_at text not null,
                    updated_at text,
                    action_type text not null,
                    title text not null,
                    risk text not null,
                    status text not null,
                    reason text not null,
                    params_json text not null,
                    output text not null,
                    error text not null,
                    approved_by text,
                    approved_at text
                );
                """
            )
            self.ensure_action_log_columns()
            self.connection.commit()

    def ensure_action_log_columns(self) -> None:
        columns = {
            row["name"]
            for row in self.connection.execute("pragma table_info(action_logs)").fetchall()
        }
        additions = {
            "updated_at": "alter table action_logs add column updated_at text",
            "approved_by": "alter table action_logs add column approved_by text",
            "approved_at": "alter table action_logs add column approved_at text",
        }
        for column, statement in additions.items():
            if column not in columns:
                self.connection.execute(statement)

    def save_results(self, results: list[CheckResult]) -> None:
        with self.lock:
            self.connection.executemany(
                """
                insert into check_results (created_at, source, name, status, summary, details_json)
                values (?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        result.created_at,
                        result.source,
                        result.name,
                        result.status,
                        result.summary,
                        json.dumps(result.details, ensure_ascii=False),
                    )
                    for result in results
                ],
            )
            self.connection.commit()

    def save_incident(self, severity: str, title: str, analysis: str, results: list[CheckResult]) -> int:
        with self.lock:
            cursor = self.connection.execute(
                """
                insert into incidents (created_at, severity, title, analysis, results_json)
                values (?, ?, ?, ?, ?)
                """,
                (
                    utc_now_iso(),
                    severity,
                    title,
                    analysis,
                    json.dumps([result.__dict__ for result in results], ensure_ascii=False),
                ),
            )
            self.connection.commit()
            return int(cursor.lastrowid)

    def latest_results(self, limit: int = 50) -> list[dict]:
        with self.lock:
            rows = self.connection.execute(
                """
                select * from check_results
                order by id desc
                limit ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def latest_incidents(self, limit: int = 20) -> list[dict]:
        with self.lock:
            rows = self.connection.execute(
                """
                select * from incidents
                order by id desc
                limit ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def save_action_log(
        self,
        action_type: str,
        title: str,
        risk: str,
        status: str,
        reason: str,
        params: dict,
        output: str = "",
        error: str = "",
    ) -> int:
        with self.lock:
            cursor = self.connection.execute(
                """
                insert into action_logs (created_at, action_type, title, risk, status, reason, params_json, output, error)
                values (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    utc_now_iso(),
                    action_type,
                    title,
                    risk,
                    status,
                    reason,
                    json.dumps(params, ensure_ascii=False),
                    output,
                    error,
                ),
            )
            self.connection.commit()
            return int(cursor.lastrowid)

    def get_action_log(self, action_id: int) -> dict | None:
        with self.lock:
            row = self.connection.execute(
                """
                select * from action_logs
                where id = ?
                """,
                (action_id,),
            ).fetchone()
        return dict(row) if row else None

    def update_action_log(
        self,
        action_id: int,
        status: str,
        output: str = "",
        error: str = "",
        approved_by: str = "",
    ) -> None:
        approved_at = utc_now_iso() if approved_by else None
        with self.lock:
            self.connection.execute(
                """
                update action_logs
                set updated_at = ?,
                    status = ?,
                    output = ?,
                    error = ?,
                    approved_by = coalesce(nullif(?, ''), approved_by),
                    approved_at = coalesce(?, approved_at)
                where id = ?
                """,
                (utc_now_iso(), status, output, error, approved_by, approved_at, action_id),
            )
            self.connection.commit()

    def latest_action_logs(self, limit: int = 50) -> list[dict]:
        with self.lock:
            rows = self.connection.execute(
                """
                select * from action_logs
                order by id desc
                limit ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def recent_results(self, since_iso: str) -> list[dict]:
        with self.lock:
            rows = self.connection.execute(
                """
                select * from check_results
                where created_at >= ?
                order by id asc
                """,
                (since_iso,),
            ).fetchall()
        return [dict(row) for row in rows]

    def recent_incidents(self, since_iso: str, limit: int = 100) -> list[dict]:
        with self.lock:
            rows = self.connection.execute(
                """
                select * from incidents
                where created_at >= ?
                order by id desc
                limit ?
                """,
                (since_iso, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def dashboard_summary(self, hours: int = 24) -> dict:
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        rows = self.recent_results(since.isoformat())
        incidents = self.recent_incidents(since.isoformat())
        latest: dict[str, dict] = {}
        counts = {"ok": 0, "warning": 0, "critical": 0}
        source_counts: dict[str, int] = {}

        for row in rows:
            status = str(row.get("status", ""))
            if status in counts:
                counts[status] += 1
            source = str(row.get("source", "unknown"))
            source_counts[source] = source_counts.get(source, 0) + 1
            latest[f"{row.get('source')}/{row.get('name')}"] = row

        problem_targets = [
            row for row in latest.values() if row.get("status") in {"warning", "critical"}
        ]
        total = len(rows)
        ok_rate = round((counts["ok"] / total) * 100, 1) if total else 100.0
        current_status = "critical" if any(row.get("status") == "critical" for row in latest.values()) else (
            "warning" if problem_targets else "ok"
        )

        return {
            "hours": hours,
            "total_checks": total,
            "ok": counts["ok"],
            "warning": counts["warning"],
            "critical": counts["critical"],
            "ok_rate": ok_rate,
            "current_status": current_status,
            "active_problem_count": len(problem_targets),
            "incident_count": len(incidents),
            "source_counts": source_counts,
            "latest_targets": list(latest.values()),
        }

    def close(self) -> None:
        with self.lock:
            self.connection.close()

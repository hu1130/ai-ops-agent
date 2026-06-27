from __future__ import annotations

import json
import sqlite3
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
                """
            )
            self.connection.commit()

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

    def close(self) -> None:
        with self.lock:
            self.connection.close()

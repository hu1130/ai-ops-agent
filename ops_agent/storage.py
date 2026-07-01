from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import RLock
from typing import Sequence

from ops_agent.events import CheckResult, utc_now_iso
from ops_agent.incident_lifecycle import (
    initial_incident_status,
    lifecycle_payload,
    validate_incident_status,
    validate_transition,
)


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
                    environment text not null default 'prod',
                    run_type text not null default 'normal',
                    trace_id text not null default '',
                    source text not null,
                    name text not null,
                    status text not null,
                    summary text not null,
                    details_json text not null
                );

                create table if not exists incidents (
                    id integer primary key autoincrement,
                    created_at text not null,
                    updated_at text,
                    environment text not null default 'prod',
                    run_type text not null default 'normal',
                    trace_id text not null default '',
                    fingerprint text not null default '',
                    occurrence_count integer not null default 1,
                    first_seen_at text,
                    last_seen_at text,
                    last_summary text not null default '',
                    status text not null default 'open',
                    severity text not null,
                    title text not null,
                    analysis text not null,
                    results_json text not null,
                    acknowledged_at text,
                    acknowledged_by text,
                    resolved_at text,
                    closed_at text,
                    closed_reason text
                );

                create table if not exists incident_events (
                    id integer primary key autoincrement,
                    incident_id integer not null,
                    created_at text not null,
                    from_status text not null,
                    to_status text not null,
                    actor text not null,
                    note text not null,
                    metadata_json text not null
                );

                create table if not exists action_logs (
                    id integer primary key autoincrement,
                    incident_id integer,
                    created_at text not null,
                    updated_at text,
                    environment text not null default 'prod',
                    run_type text not null default 'normal',
                    trace_id text not null default '',
                    action_type text not null,
                    title text not null,
                    risk text not null,
                    status text not null,
                    reason text not null,
                    params_json text not null,
                    output text not null,
                    error text not null,
                    approved_by text,
                    approved_at text,
                    verify_status text,
                    verify_output text,
                    verified_at text
                );

                create table if not exists api_audit_logs (
                    id integer primary key autoincrement,
                    created_at text not null,
                    environment text not null default 'prod',
                    run_type text not null default 'api',
                    actor text not null,
                    source_ip text not null,
                    method text not null,
                    path text not null,
                    operation text not null,
                    target_type text not null,
                    target_id integer,
                    status_code integer not null,
                    outcome text not null,
                    message text not null,
                    metadata_json text not null
                );
                """
            )
            self.ensure_context_columns()
            self.ensure_incident_lifecycle_columns()
            self.ensure_action_log_columns()
            self.connection.commit()

    def ensure_context_columns(self) -> None:
        defaults = {
            "environment": "text not null default 'prod'",
            "run_type": "text not null default 'normal'",
            "trace_id": "text not null default ''",
        }
        for table in ("check_results", "incidents", "action_logs"):
            columns = {
                row["name"]
                for row in self.connection.execute(f"pragma table_info({table})").fetchall()
            }
            for column, definition in defaults.items():
                if column not in columns:
                    self.connection.execute(f"alter table {table} add column {column} {definition}")

        audit_columns = {
            row["name"]
            for row in self.connection.execute("pragma table_info(api_audit_logs)").fetchall()
        }
        audit_defaults = {
            "environment": "text not null default 'prod'",
            "run_type": "text not null default 'api'",
        }
        for column, definition in audit_defaults.items():
            if column not in audit_columns:
                self.connection.execute(f"alter table api_audit_logs add column {column} {definition}")

    def ensure_incident_lifecycle_columns(self) -> None:
        columns = {
            row["name"]
            for row in self.connection.execute("pragma table_info(incidents)").fetchall()
        }
        additions = {
            "updated_at": "alter table incidents add column updated_at text",
            "fingerprint": "alter table incidents add column fingerprint text not null default ''",
            "occurrence_count": "alter table incidents add column occurrence_count integer not null default 1",
            "first_seen_at": "alter table incidents add column first_seen_at text",
            "last_seen_at": "alter table incidents add column last_seen_at text",
            "last_summary": "alter table incidents add column last_summary text not null default ''",
            "status": "alter table incidents add column status text not null default 'open'",
            "acknowledged_at": "alter table incidents add column acknowledged_at text",
            "acknowledged_by": "alter table incidents add column acknowledged_by text",
            "resolved_at": "alter table incidents add column resolved_at text",
            "closed_at": "alter table incidents add column closed_at text",
            "closed_reason": "alter table incidents add column closed_reason text",
        }
        for column, statement in additions.items():
            if column not in columns:
                self.connection.execute(statement)
        self.connection.execute(
            """
            update incidents
            set status = 'resolved',
                updated_at = coalesce(updated_at, created_at),
                resolved_at = coalesce(resolved_at, created_at)
            where severity = 'ok' and status = 'open'
            """
        )
        self.connection.execute(
            """
            update incidents
            set updated_at = coalesce(updated_at, created_at)
            where updated_at is null
            """
        )
        self.connection.execute(
            """
            update incidents
            set first_seen_at = coalesce(first_seen_at, created_at),
                last_seen_at = coalesce(last_seen_at, updated_at, created_at),
                last_summary = coalesce(nullif(last_summary, ''), title)
            """
        )

    def ensure_action_log_columns(self) -> None:
        columns = {
            row["name"]
            for row in self.connection.execute("pragma table_info(action_logs)").fetchall()
        }
        additions = {
            "incident_id": "alter table action_logs add column incident_id integer",
            "updated_at": "alter table action_logs add column updated_at text",
            "approved_by": "alter table action_logs add column approved_by text",
            "approved_at": "alter table action_logs add column approved_at text",
            "verify_status": "alter table action_logs add column verify_status text",
            "verify_output": "alter table action_logs add column verify_output text",
            "verified_at": "alter table action_logs add column verified_at text",
            "decision": "alter table action_logs add column decision text",
            "decision_by": "alter table action_logs add column decision_by text",
            "decision_at": "alter table action_logs add column decision_at text",
            "decision_note": "alter table action_logs add column decision_note text",
        }
        for column, statement in additions.items():
            if column not in columns:
                self.connection.execute(statement)

    def save_results(self, results: list[CheckResult]) -> None:
        with self.lock:
            self.connection.executemany(
                """
                insert into check_results (
                    created_at, environment, run_type, trace_id, source, name, status, summary, details_json
                )
                values (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        result.created_at,
                        result.environment or "prod",
                        result.run_type or "normal",
                        result.trace_id or "",
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

    def update_action_verification(
        self,
        action_id: int,
        verify_status: str,
        verify_output: str = "",
    ) -> None:
        with self.lock:
            self.connection.execute(
                """
                update action_logs
                set updated_at = ?,
                    status = ?,
                    verify_status = ?,
                    verify_output = ?,
                    verified_at = ?
                where id = ?
                """,
                (utc_now_iso(), verify_status, verify_status, verify_output, utc_now_iso(), action_id),
            )
            self.connection.commit()

    def save_incident(
        self,
        severity: str,
        title: str,
        analysis: str,
        results: list[CheckResult],
        status: str | None = None,
        fingerprint: str = "",
        occurrence_count: int = 0,
    ) -> int:
        incident_status = validate_incident_status(status or initial_incident_status(severity))
        created_at = utc_now_iso()
        occurrences = occurrence_count if occurrence_count > 0 else max(1, len(results))
        last_summary = summarize_results(results) or title
        with self.lock:
            cursor = self.connection.execute(
                """
                insert into incidents (
                    created_at, updated_at, environment, run_type, trace_id,
                    fingerprint, occurrence_count, first_seen_at, last_seen_at, last_summary, status,
                    severity, title, analysis, results_json, resolved_at
                )
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    created_at,
                    created_at,
                    common_value([result.environment for result in results], "prod"),
                    common_value([result.run_type for result in results], "normal"),
                    common_value([result.trace_id for result in results], ""),
                    fingerprint,
                    occurrences,
                    created_at,
                    created_at,
                    last_summary,
                    incident_status,
                    severity,
                    title,
                    analysis,
                    json.dumps([result.__dict__ for result in results], ensure_ascii=False),
                    created_at if incident_status == "resolved" else None,
                ),
            )
            incident_id = int(cursor.lastrowid)
            self.record_incident_event(
                incident_id,
                "",
                incident_status,
                "system",
                "incident created",
                {"severity": severity},
                commit=False,
            )
            self.connection.commit()
            return incident_id

    def find_active_incident_by_fingerprint(self, fingerprint: str) -> dict | None:
        if not fingerprint:
            return None
        with self.lock:
            row = self.connection.execute(
                """
                select * from incidents
                where fingerprint = ?
                  and status not in ('resolved', 'closed')
                order by id desc
                limit 1
                """,
                (fingerprint,),
            ).fetchone()
        return dict(row) if row else None

    def find_active_incidents_for_check(self, environment: str, run_type: str, target_key: str) -> list[dict]:
        if not target_key:
            return []
        return [
            row
            for row in self.active_fingerprint_incidents(environment, run_type)
            if target_key in fingerprint_target_keys(str(row.get("fingerprint", "")))
        ]

    def find_recoverable_active_incidents(
        self,
        environment: str,
        run_type: str,
        recovered_target_keys: Sequence[str],
    ) -> list[dict]:
        recovered_keys = {key for key in recovered_target_keys if key}
        if not recovered_keys:
            return []

        recoverable: list[dict] = []
        for row in self.active_fingerprint_incidents(environment, run_type):
            targets = fingerprint_target_keys(str(row.get("fingerprint", "")))
            if targets and targets.issubset(recovered_keys):
                recoverable.append(row)
        return recoverable

    def active_fingerprint_incidents(self, environment: str, run_type: str) -> list[dict]:
        with self.lock:
            rows = self.connection.execute(
                """
                select * from incidents
                where environment = ?
                  and run_type = ?
                  and fingerprint <> ''
                  and status not in ('resolved', 'closed')
                order by id desc
                """,
                (environment or "prod", run_type or "normal"),
            ).fetchall()
        return [dict(row) for row in rows]

    def update_incident_occurrence(
        self,
        incident_id: int,
        severity: str,
        title: str,
        results: list[CheckResult],
        increment: int = 1,
    ) -> dict:
        now = utc_now_iso()
        last_summary = summarize_results(results) or title
        with self.lock:
            row = self.connection.execute(
                "select * from incidents where id = ?",
                (incident_id,),
            ).fetchone()
            if not row:
                raise ValueError(f"incident not found: {incident_id}")
            next_count = int(row["occurrence_count"] or 1) + max(1, increment)
            next_severity = max_severity(str(row["severity"]), severity)
            self.connection.execute(
                """
                update incidents
                set updated_at = ?,
                    last_seen_at = ?,
                    last_summary = ?,
                    occurrence_count = ?,
                    severity = ?,
                    title = ?,
                    results_json = ?
                where id = ?
                """,
                (
                    now,
                    now,
                    last_summary,
                    next_count,
                    next_severity,
                    title,
                    json.dumps([result.__dict__ for result in results], ensure_ascii=False),
                    incident_id,
                ),
            )
            self.connection.commit()
            updated = self.connection.execute(
                "select * from incidents where id = ?",
                (incident_id,),
            ).fetchone()
        return dict(updated)

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

    def get_incident(self, incident_id: int) -> dict | None:
        with self.lock:
            row = self.connection.execute(
                """
                select * from incidents
                where id = ?
                """,
                (incident_id,),
            ).fetchone()
        return dict(row) if row else None

    def latest_incident_events(self, incident_id: int, limit: int = 100) -> list[dict]:
        with self.lock:
            rows = self.connection.execute(
                """
                select * from incident_events
                where incident_id = ?
                order by id asc
                limit ?
                """,
                (incident_id, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def transition_incident(
        self,
        incident_id: int,
        to_status: str,
        actor: str = "system",
        note: str = "",
        metadata: dict | None = None,
    ) -> dict:
        with self.lock:
            row = self.connection.execute(
                "select * from incidents where id = ?",
                (incident_id,),
            ).fetchone()
            if not row:
                raise ValueError(f"incident not found: {incident_id}")

            current = str(row["status"])
            from_status, target = validate_transition(current, to_status)
            if from_status == target:
                return dict(row)

            payload = lifecycle_payload(actor, note, metadata)
            now = utc_now_iso()
            acknowledged_at = row["acknowledged_at"]
            acknowledged_by = row["acknowledged_by"]
            resolved_at = row["resolved_at"]
            closed_at = row["closed_at"]
            closed_reason = row["closed_reason"]

            if target == "acknowledged":
                acknowledged_at = acknowledged_at or now
                acknowledged_by = acknowledged_by or payload["actor"]
            if target == "resolved":
                resolved_at = resolved_at or now
            if target == "closed":
                closed_at = closed_at or now
                closed_reason = payload["note"] or closed_reason

            self.connection.execute(
                """
                update incidents
                set status = ?,
                    updated_at = ?,
                    acknowledged_at = ?,
                    acknowledged_by = ?,
                    resolved_at = ?,
                    closed_at = ?,
                    closed_reason = ?
                where id = ?
                """,
                (
                    target,
                    now,
                    acknowledged_at,
                    acknowledged_by,
                    resolved_at,
                    closed_at,
                    closed_reason,
                    incident_id,
                ),
            )
            self.record_incident_event(
                incident_id,
                from_status,
                target,
                payload["actor"],
                payload["note"],
                payload["metadata"],
                commit=False,
            )
            self.connection.commit()
            updated = self.connection.execute(
                "select * from incidents where id = ?",
                (incident_id,),
            ).fetchone()
        return dict(updated)

    def record_incident_event(
        self,
        incident_id: int,
        from_status: str,
        to_status: str,
        actor: str,
        note: str = "",
        metadata: dict | None = None,
        commit: bool = True,
    ) -> int:
        with self.lock:
            cursor = self.connection.execute(
                """
                insert into incident_events (
                    incident_id, created_at, from_status, to_status, actor, note, metadata_json
                )
                values (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident_id,
                    utc_now_iso(),
                    from_status,
                    to_status,
                    actor,
                    note,
                    json.dumps(metadata or {}, ensure_ascii=False),
                ),
            )
            if commit:
                self.connection.commit()
            return int(cursor.lastrowid)

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
        environment: str = "prod",
        run_type: str = "normal",
        trace_id: str = "",
        incident_id: int | None = None,
    ) -> int:
        with self.lock:
            cursor = self.connection.execute(
                """
                insert into action_logs (
                    incident_id, created_at, environment, run_type, trace_id,
                    action_type, title, risk, status, reason, params_json, output, error
                )
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident_id,
                    utc_now_iso(),
                    environment or "prod",
                    run_type or "normal",
                    trace_id or "",
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
        decision = "approved" if approved_by else ""
        with self.lock:
            self.connection.execute(
                """
                update action_logs
                set updated_at = ?,
                    status = ?,
                    output = ?,
                    error = ?,
                    approved_by = coalesce(nullif(?, ''), approved_by),
                    approved_at = coalesce(?, approved_at),
                    decision = coalesce(nullif(?, ''), decision),
                    decision_by = coalesce(nullif(?, ''), decision_by),
                    decision_at = coalesce(?, decision_at)
                where id = ?
                """,
                (
                    utc_now_iso(),
                    status,
                    output,
                    error,
                    approved_by,
                    approved_at,
                    decision,
                    approved_by,
                    approved_at,
                    action_id,
                ),
            )
            self.connection.commit()

    def reject_action_log(self, action_id: int, rejected_by: str, note: str = "") -> dict:
        now = utc_now_iso()
        actor = rejected_by.strip() or "operator"
        message = f"rejected by {actor}"
        if note.strip():
            message += f": {note.strip()}"
        with self.lock:
            self.connection.execute(
                """
                update action_logs
                set updated_at = ?,
                    status = 'rejected',
                    error = ?,
                    decision = 'rejected',
                    decision_by = ?,
                    decision_at = ?,
                    decision_note = ?
                where id = ?
                """,
                (now, message, actor, now, note.strip(), action_id),
            )
            self.connection.commit()
            row = self.connection.execute(
                "select * from action_logs where id = ?",
                (action_id,),
            ).fetchone()
        return dict(row) if row else {}

    def latest_action_logs(
        self,
        limit: int = 50,
        incident_id: int | None = None,
        status: str | None = None,
    ) -> list[dict]:
        with self.lock:
            where: list[str] = []
            params: list[object] = []
            if incident_id is not None:
                where.append("incident_id = ?")
                params.append(incident_id)
            if status:
                where.append("status = ?")
                params.append(status)
            where_sql = f"where {' and '.join(where)}" if where else ""
            rows = self.connection.execute(
                f"""
                select * from action_logs
                {where_sql}
                order by id desc
                limit ?
                """,
                (*params, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def record_api_audit(
        self,
        actor: str = "",
        source_ip: str = "",
        method: str = "",
        path: str = "",
        operation: str = "",
        target_type: str = "",
        target_id: int | None = None,
        status_code: int = 0,
        outcome: str = "",
        message: str = "",
        metadata: dict | None = None,
        environment: str = "prod",
        run_type: str = "api",
    ) -> int:
        with self.lock:
            cursor = self.connection.execute(
                """
                insert into api_audit_logs (
                    created_at, environment, run_type, actor, source_ip, method, path,
                    operation, target_type, target_id, status_code, outcome, message, metadata_json
                )
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    utc_now_iso(),
                    environment or "prod",
                    run_type or "api",
                    actor or "",
                    source_ip or "",
                    method or "",
                    path or "",
                    operation or "",
                    target_type or "",
                    target_id,
                    int(status_code),
                    outcome or "",
                    message or "",
                    json.dumps(metadata or {}, ensure_ascii=False),
                ),
            )
            self.connection.commit()
            return int(cursor.lastrowid)

    def latest_api_audit_logs(self, limit: int = 50) -> list[dict]:
        with self.lock:
            rows = self.connection.execute(
                """
                select * from api_audit_logs
                order by id desc
                limit ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def update_incident_analysis(self, incident_id: int, analysis: str) -> None:
        with self.lock:
            self.connection.execute(
                """
                update incidents
                set analysis = ?,
                    updated_at = ?
                where id = ?
                """,
                (analysis, utc_now_iso(), incident_id),
            )
            self.connection.commit()

    def count_resolved_incidents_to_auto_close(
        self,
        resolved_cutoff: str,
        incident_retention_cutoff: str,
        test_resolved_cutoff: str = "",
        test_incident_retention_cutoff: str = "",
        test_environments: Sequence[str] | None = None,
        test_run_types: Sequence[str] | None = None,
    ) -> int:
        where, params = build_auto_close_where(
            resolved_cutoff,
            incident_retention_cutoff,
            test_resolved_cutoff,
            test_incident_retention_cutoff,
            test_environments or [],
            test_run_types or [],
        )
        with self.lock:
            count = self.connection.execute(
                f"select count(*) from incidents where {where}",
                params,
            ).fetchone()[0]
        return int(count)

    def close_resolved_incidents(
        self,
        resolved_cutoff: str,
        incident_retention_cutoff: str,
        test_resolved_cutoff: str = "",
        test_incident_retention_cutoff: str = "",
        test_environments: Sequence[str] | None = None,
        test_run_types: Sequence[str] | None = None,
    ) -> int:
        where, params = build_auto_close_where(
            resolved_cutoff,
            incident_retention_cutoff,
            test_resolved_cutoff,
            test_incident_retention_cutoff,
            test_environments or [],
            test_run_types or [],
        )
        with self.lock:
            rows = self.connection.execute(
                f"select id from incidents where {where} order by id asc",
                params,
            ).fetchall()

        closed = 0
        for row in rows:
            try:
                self.transition_incident(
                    int(row["id"]),
                    "closed",
                    actor="retention",
                    note="auto-close resolved incident",
                    metadata={
                        "resolved_cutoff": resolved_cutoff,
                        "test_resolved_cutoff": test_resolved_cutoff,
                    },
                )
            except ValueError:
                continue
            closed += 1
        return closed

    def count_retention_candidates(
        self,
        check_cutoff: str,
        problem_cutoff: str,
        incident_cutoff: str,
        action_cutoff: str,
        test_check_cutoff: str = "",
        test_incident_cutoff: str = "",
        test_action_cutoff: str = "",
        test_environments: Sequence[str] | None = None,
        test_run_types: Sequence[str] | None = None,
        api_audit_cutoff: str = "",
        test_api_audit_cutoff: str = "",
    ) -> dict[str, int]:
        test_environments = test_environments or []
        test_run_types = test_run_types or []
        check_where, check_params = build_retention_where(
            "(created_at < ? and status = 'ok') or (created_at < ? and status in ('warning', 'critical'))",
            [check_cutoff, problem_cutoff],
            test_check_cutoff,
            test_environments,
            test_run_types,
        )
        incident_where, incident_params = build_retention_where(
            "created_at < ?",
            [incident_cutoff],
            test_incident_cutoff,
            test_environments,
            test_run_types,
        )
        action_where, action_params = build_retention_where(
            "created_at < ?",
            [action_cutoff],
            test_action_cutoff,
            test_environments,
            test_run_types,
        )
        api_audit_where, api_audit_params = build_retention_where(
            "created_at < ?",
            [api_audit_cutoff or action_cutoff],
            test_api_audit_cutoff,
            test_environments,
            test_run_types,
        )
        with self.lock:
            check_results = self.connection.execute(
                f"select count(*) from check_results where {check_where}",
                check_params,
            ).fetchone()[0]
            incidents = self.connection.execute(
                f"select count(*) from incidents where {incident_where}",
                incident_params,
            ).fetchone()[0]
            action_logs = self.connection.execute(
                f"select count(*) from action_logs where {action_where}",
                action_params,
            ).fetchone()[0]
            api_audit_logs = self.connection.execute(
                f"select count(*) from api_audit_logs where {api_audit_where}",
                api_audit_params,
            ).fetchone()[0]
        return {
            "check_results": int(check_results),
            "incidents": int(incidents),
            "action_logs": int(action_logs),
            "api_audit_logs": int(api_audit_logs),
        }

    def delete_retention_candidates(
        self,
        check_cutoff: str,
        problem_cutoff: str,
        incident_cutoff: str,
        action_cutoff: str,
        test_check_cutoff: str = "",
        test_incident_cutoff: str = "",
        test_action_cutoff: str = "",
        test_environments: Sequence[str] | None = None,
        test_run_types: Sequence[str] | None = None,
        api_audit_cutoff: str = "",
        test_api_audit_cutoff: str = "",
    ) -> dict[str, int]:
        test_environments = test_environments or []
        test_run_types = test_run_types or []
        check_where, check_params = build_retention_where(
            "(created_at < ? and status = 'ok') or (created_at < ? and status in ('warning', 'critical'))",
            [check_cutoff, problem_cutoff],
            test_check_cutoff,
            test_environments,
            test_run_types,
        )
        incident_where, incident_params = build_retention_where(
            "created_at < ?",
            [incident_cutoff],
            test_incident_cutoff,
            test_environments,
            test_run_types,
        )
        action_where, action_params = build_retention_where(
            "created_at < ?",
            [action_cutoff],
            test_action_cutoff,
            test_environments,
            test_run_types,
        )
        api_audit_where, api_audit_params = build_retention_where(
            "created_at < ?",
            [api_audit_cutoff or action_cutoff],
            test_api_audit_cutoff,
            test_environments,
            test_run_types,
        )
        with self.lock:
            before = self.count_retention_candidates(
                check_cutoff,
                problem_cutoff,
                incident_cutoff,
                action_cutoff,
                test_check_cutoff,
                test_incident_cutoff,
                test_action_cutoff,
                test_environments,
                test_run_types,
                api_audit_cutoff=api_audit_cutoff,
                test_api_audit_cutoff=test_api_audit_cutoff,
            )
            self.connection.execute(
                f"delete from check_results where {check_where}",
                check_params,
            )
            self.connection.execute(
                f"""
                delete from incident_events
                where incident_id in (
                    select id from incidents where {incident_where}
                )
                """,
                incident_params,
            )
            self.connection.execute(f"delete from incidents where {incident_where}", incident_params)
            self.connection.execute(f"delete from action_logs where {action_where}", action_params)
            self.connection.execute(f"delete from api_audit_logs where {api_audit_where}", api_audit_params)
            self.connection.commit()
        return before

    def vacuum(self) -> None:
        with self.lock:
            self.connection.execute("vacuum")

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
            "open_incident_count": sum(
                1 for row in incidents if row.get("status", "open") not in {"resolved", "closed"}
            ),
            "source_counts": source_counts,
            "latest_targets": list(latest.values()),
        }

    def close(self) -> None:
        with self.lock:
            self.connection.close()


def common_value(values: list[str], default: str) -> str:
    cleaned = [value for value in values if value]
    if not cleaned:
        return default
    first = cleaned[0]
    if all(value == first for value in cleaned):
        return first
    return "mixed"


def summarize_results(results: list[CheckResult]) -> str:
    return "; ".join(
        f"{result.source}/{result.name}: {result.summary}"
        for result in results
    )


def fingerprint_target_keys(fingerprint: str) -> set[str]:
    parts = (fingerprint or "").split(":", 2)
    if len(parts) < 3:
        return set()
    return {target for target in parts[2].split("|") if target}


def max_severity(current: str, incoming: str) -> str:
    rank = {"ok": 0, "warning": 1, "critical": 2}
    return incoming if rank.get(incoming, 0) > rank.get(current, 0) else current


def build_auto_close_where(
    resolved_cutoff: str,
    incident_retention_cutoff: str,
    test_resolved_cutoff: str,
    test_incident_retention_cutoff: str,
    test_environments: Sequence[str],
    test_run_types: Sequence[str],
) -> tuple[str, list[str]]:
    timestamp = "coalesce(resolved_at, updated_at, created_at)"
    normal_where = f"status = 'resolved' and {timestamp} < ? and created_at >= ?"
    test_clause, test_params = build_test_clause(test_environments, test_run_types)
    if not test_clause or not test_resolved_cutoff or not test_incident_retention_cutoff:
        return f"({normal_where})", [resolved_cutoff, incident_retention_cutoff]

    test_where = f"status = 'resolved' and {timestamp} < ? and created_at >= ?"
    return (
        f"(({test_clause}) and {test_where}) or (not ({test_clause}) and {normal_where})",
        [
            *test_params,
            test_resolved_cutoff,
            test_incident_retention_cutoff,
            *test_params,
            resolved_cutoff,
            incident_retention_cutoff,
        ],
    )


def build_retention_where(
    normal_where: str,
    normal_params: list[str],
    test_cutoff: str,
    test_environments: Sequence[str],
    test_run_types: Sequence[str],
) -> tuple[str, list[str]]:
    test_clause, test_params = build_test_clause(test_environments, test_run_types)
    if not test_clause or not test_cutoff:
        return f"({normal_where})", normal_params
    return (
        f"(({test_clause}) and created_at < ?) or (not ({test_clause}) and ({normal_where}))",
        [*test_params, test_cutoff, *test_params, *normal_params],
    )


def build_test_clause(test_environments: Sequence[str], test_run_types: Sequence[str]) -> tuple[str, list[str]]:
    clauses: list[str] = []
    params: list[str] = []
    environments = [value for value in test_environments if value]
    run_types = [value for value in test_run_types if value]
    if environments:
        clauses.append(f"environment in ({','.join('?' for _ in environments)})")
        params.extend(environments)
    if run_types:
        clauses.append(f"run_type in ({','.join('?' for _ in run_types)})")
        params.extend(run_types)
    return " or ".join(clauses), params

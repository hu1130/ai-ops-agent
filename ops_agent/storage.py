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
                    last_notification_at text,
                    last_notification_kind text not null default '',
                    escalated_at text,
                    escalation_level integer not null default 0,
                    escalation_reason text not null default '',
                    status text not null default 'open',
                    severity text not null,
                    title text not null,
                    analysis text not null,
                    results_json text not null,
                    classification_category text not null default '',
                    classification_confidence real not null default 0,
                    classification_summary text not null default '',
                    classification_evidence_json text not null default '[]',
                    classification_next_steps_json text not null default '[]',
                    acknowledged_at text,
                    acknowledged_by text,
                    resolved_at text,
                    closed_at text,
                    closed_reason text,
                    assignee text not null default '',
                    priority text not null default 'medium',
                    false_positive integer not null default 0,
                    false_positive_at text,
                    false_positive_by text,
                    false_positive_reason text not null default ''
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

                create table if not exists incident_comments (
                    id integer primary key autoincrement,
                    incident_id integer not null,
                    created_at text not null,
                    actor text not null,
                    comment text not null,
                    metadata_json text not null default '{}'
                );

                create table if not exists incident_recommendations (
                    id integer primary key autoincrement,
                    incident_id integer not null,
                    created_at text not null,
                    updated_at text,
                    environment text not null default 'prod',
                    run_type text not null default 'normal',
                    trace_id text not null default '',
                    position integer not null default 0,
                    category text not null default 'diagnose',
                    action_type text not null default '',
                    title text not null,
                    reason text not null,
                    risk text not null default 'low',
                    approval_required integer not null default 0,
                    auto_execute integer not null default 0,
                    verification_required integer not null default 0,
                    status text not null default 'suggested',
                    params_json text not null default '{}',
                    action_log_id integer,
                    decision_by text,
                    decision_at text,
                    decision_note text,
                    executed_at text,
                    source text not null default 'planner',
                    metadata_json text not null default '{}'
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

                create table if not exists notification_logs (
                    id integer primary key autoincrement,
                    created_at text not null,
                    environment text not null default 'prod',
                    run_type text not null default 'normal',
                    trace_id text not null default '',
                    incident_id integer,
                    severity text not null default '',
                    title text not null,
                    dedupe_key text not null,
                    status text not null,
                    route_names_json text not null default '[]',
                    channels_json text not null default '[]',
                    suppressed_reason text not null default '',
                    error text not null default '',
                    metadata_json text not null default '{}'
                );

                create table if not exists learning_recommendations (
                    id integer primary key autoincrement,
                    created_at text not null,
                    updated_at text,
                    last_seen_at text,
                    status text not null default 'open',
                    priority text not null default 'medium',
                    category text not null default '',
                    trigger_type text not null default '',
                    dedupe_key text not null default '',
                    title text not null,
                    reason text not null,
                    recommended_action text not null,
                    evidence_json text not null default '[]',
                    incident_ids_json text not null default '[]',
                    metrics_json text not null default '{}',
                    source text not null default 'classification_learning',
                    seen_count integer not null default 1,
                    decision_by text,
                    decision_at text,
                    decision_note text,
                    applied_at text,
                    draft_json text not null default '{}'
                );

                create table if not exists learning_config_patches (
                    id integer primary key autoincrement,
                    created_at text not null,
                    updated_at text,
                    recommendation_id integer not null,
                    status text not null default 'proposed',
                    patch_type text not null default '',
                    title text not null,
                    reason text not null,
                    patch_json text not null default '{}',
                    decision_by text,
                    decision_at text,
                    decision_note text,
                    applied_at text,
                    apply_result_json text not null default '{}'
                );

                create index if not exists idx_incident_recommendations_incident
                    on incident_recommendations (incident_id, position, id);
                create index if not exists idx_incident_comments_incident
                    on incident_comments (incident_id, id);
                create unique index if not exists idx_learning_recommendations_dedupe
                    on learning_recommendations (dedupe_key);
                create index if not exists idx_learning_config_patches_status
                    on learning_config_patches (status, updated_at, id);
                create index if not exists idx_learning_config_patches_recommendation
                    on learning_config_patches (recommendation_id, id);
                create index if not exists idx_notification_logs_created
                    on notification_logs (created_at, id);
                create index if not exists idx_notification_logs_status
                    on notification_logs (status, id);
                """
            )
            self.ensure_context_columns()
            self.ensure_incident_lifecycle_columns()
            self.ensure_incident_classification_columns()
            self.ensure_action_log_columns()
            self.ensure_recommendation_columns()
            self.ensure_learning_recommendation_columns()
            self.ensure_learning_config_patch_columns()
            self.ensure_notification_log_columns()
            self.connection.commit()

    def ensure_context_columns(self) -> None:
        defaults = {
            "environment": "text not null default 'prod'",
            "run_type": "text not null default 'normal'",
            "trace_id": "text not null default ''",
        }
        for table in ("check_results", "incidents", "action_logs", "notification_logs"):
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
            "last_notification_at": "alter table incidents add column last_notification_at text",
            "last_notification_kind": "alter table incidents add column last_notification_kind text not null default ''",
            "escalated_at": "alter table incidents add column escalated_at text",
            "escalation_level": "alter table incidents add column escalation_level integer not null default 0",
            "escalation_reason": "alter table incidents add column escalation_reason text not null default ''",
            "status": "alter table incidents add column status text not null default 'open'",
            "acknowledged_at": "alter table incidents add column acknowledged_at text",
            "acknowledged_by": "alter table incidents add column acknowledged_by text",
            "resolved_at": "alter table incidents add column resolved_at text",
            "closed_at": "alter table incidents add column closed_at text",
            "closed_reason": "alter table incidents add column closed_reason text",
            "assignee": "alter table incidents add column assignee text not null default ''",
            "priority": "alter table incidents add column priority text not null default 'medium'",
            "false_positive": "alter table incidents add column false_positive integer not null default 0",
            "false_positive_at": "alter table incidents add column false_positive_at text",
            "false_positive_by": "alter table incidents add column false_positive_by text",
            "false_positive_reason": "alter table incidents add column false_positive_reason text not null default ''",
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
                last_summary = coalesce(nullif(last_summary, ''), title),
                last_notification_at = coalesce(last_notification_at, created_at)
            """
        )

    def ensure_incident_classification_columns(self) -> None:
        columns = {
            row["name"]
            for row in self.connection.execute("pragma table_info(incidents)").fetchall()
        }
        additions = {
            "classification_category": "alter table incidents add column classification_category text not null default ''",
            "classification_confidence": "alter table incidents add column classification_confidence real not null default 0",
            "classification_summary": "alter table incidents add column classification_summary text not null default ''",
            "classification_evidence_json": "alter table incidents add column classification_evidence_json text not null default '[]'",
            "classification_next_steps_json": "alter table incidents add column classification_next_steps_json text not null default '[]'",
        }
        for column, statement in additions.items():
            if column not in columns:
                self.connection.execute(statement)

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

    def ensure_notification_log_columns(self) -> None:
        columns = {
            row["name"]
            for row in self.connection.execute("pragma table_info(notification_logs)").fetchall()
        }
        additions = {
            "environment": "alter table notification_logs add column environment text not null default 'prod'",
            "run_type": "alter table notification_logs add column run_type text not null default 'normal'",
            "trace_id": "alter table notification_logs add column trace_id text not null default ''",
            "incident_id": "alter table notification_logs add column incident_id integer",
            "severity": "alter table notification_logs add column severity text not null default ''",
            "route_names_json": "alter table notification_logs add column route_names_json text not null default '[]'",
            "channels_json": "alter table notification_logs add column channels_json text not null default '[]'",
            "suppressed_reason": "alter table notification_logs add column suppressed_reason text not null default ''",
            "error": "alter table notification_logs add column error text not null default ''",
            "metadata_json": "alter table notification_logs add column metadata_json text not null default '{}'",
        }
        for column, statement in additions.items():
            if column not in columns:
                self.connection.execute(statement)

    def ensure_recommendation_columns(self) -> None:
        columns = {
            row["name"]
            for row in self.connection.execute("pragma table_info(incident_recommendations)").fetchall()
        }
        additions = {
            "updated_at": "alter table incident_recommendations add column updated_at text",
            "environment": "alter table incident_recommendations add column environment text not null default 'prod'",
            "run_type": "alter table incident_recommendations add column run_type text not null default 'normal'",
            "trace_id": "alter table incident_recommendations add column trace_id text not null default ''",
            "position": "alter table incident_recommendations add column position integer not null default 0",
            "category": "alter table incident_recommendations add column category text not null default 'diagnose'",
            "action_type": "alter table incident_recommendations add column action_type text not null default ''",
            "risk": "alter table incident_recommendations add column risk text not null default 'low'",
            "approval_required": "alter table incident_recommendations add column approval_required integer not null default 0",
            "auto_execute": "alter table incident_recommendations add column auto_execute integer not null default 0",
            "verification_required": "alter table incident_recommendations add column verification_required integer not null default 0",
            "status": "alter table incident_recommendations add column status text not null default 'suggested'",
            "params_json": "alter table incident_recommendations add column params_json text not null default '{}'",
            "action_log_id": "alter table incident_recommendations add column action_log_id integer",
            "decision_by": "alter table incident_recommendations add column decision_by text",
            "decision_at": "alter table incident_recommendations add column decision_at text",
            "decision_note": "alter table incident_recommendations add column decision_note text",
            "executed_at": "alter table incident_recommendations add column executed_at text",
            "source": "alter table incident_recommendations add column source text not null default 'planner'",
            "metadata_json": "alter table incident_recommendations add column metadata_json text not null default '{}'",
        }
        for column, statement in additions.items():
            if column not in columns:
                self.connection.execute(statement)

    def ensure_learning_recommendation_columns(self) -> None:
        columns = {
            row["name"]
            for row in self.connection.execute("pragma table_info(learning_recommendations)").fetchall()
        }
        additions = {
            "decision_by": "alter table learning_recommendations add column decision_by text",
            "decision_at": "alter table learning_recommendations add column decision_at text",
            "decision_note": "alter table learning_recommendations add column decision_note text",
            "applied_at": "alter table learning_recommendations add column applied_at text",
            "draft_json": "alter table learning_recommendations add column draft_json text not null default '{}'",
        }
        for column, statement in additions.items():
            if column not in columns:
                self.connection.execute(statement)

    def ensure_learning_config_patch_columns(self) -> None:
        columns = {
            row["name"]
            for row in self.connection.execute("pragma table_info(learning_config_patches)").fetchall()
        }
        additions = {
            "updated_at": "alter table learning_config_patches add column updated_at text",
            "recommendation_id": "alter table learning_config_patches add column recommendation_id integer not null default 0",
            "status": "alter table learning_config_patches add column status text not null default 'proposed'",
            "patch_type": "alter table learning_config_patches add column patch_type text not null default ''",
            "title": "alter table learning_config_patches add column title text not null default ''",
            "reason": "alter table learning_config_patches add column reason text not null default ''",
            "patch_json": "alter table learning_config_patches add column patch_json text not null default '{}'",
            "decision_by": "alter table learning_config_patches add column decision_by text",
            "decision_at": "alter table learning_config_patches add column decision_at text",
            "decision_note": "alter table learning_config_patches add column decision_note text",
            "applied_at": "alter table learning_config_patches add column applied_at text",
            "apply_result_json": "alter table learning_config_patches add column apply_result_json text not null default '{}'",
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
        classification: dict | None = None,
    ) -> int:
        incident_status = validate_incident_status(status or initial_incident_status(severity))
        created_at = utc_now_iso()
        occurrences = occurrence_count if occurrence_count > 0 else max(1, len(results))
        last_summary = summarize_results(results) or title
        classification_payload = normalize_classification(classification)
        with self.lock:
            cursor = self.connection.execute(
                """
                insert into incidents (
                    created_at, updated_at, environment, run_type, trace_id,
                    fingerprint, occurrence_count, first_seen_at, last_seen_at, last_summary,
                    last_notification_at, last_notification_kind, status,
                    severity, title, analysis, results_json,
                    classification_category, classification_confidence, classification_summary,
                    classification_evidence_json, classification_next_steps_json,
                    resolved_at
                )
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    created_at,
                    "initial",
                    incident_status,
                    severity,
                    title,
                    analysis,
                    json.dumps([result.__dict__ for result in results], ensure_ascii=False),
                    classification_payload["category"],
                    classification_payload["confidence"],
                    classification_payload["summary"],
                    json.dumps(classification_payload["evidence"], ensure_ascii=False),
                    json.dumps(classification_payload["next_steps"], ensure_ascii=False),
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
                {"severity": severity, "classification": classification_payload},
                commit=False,
            )
            self.connection.commit()
            return incident_id

    def save_incident_recommendations(self, incident_id: int, recommendations: list[dict]) -> None:
        now = utc_now_iso()
        with self.lock:
            self.connection.execute(
                "delete from incident_recommendations where incident_id = ?",
                (incident_id,),
            )
            self.connection.executemany(
                """
                insert into incident_recommendations (
                    incident_id, created_at, updated_at, environment, run_type, trace_id,
                    position, category, action_type, title, reason, risk,
                    approval_required, auto_execute, verification_required, status,
                    params_json, action_log_id, decision_by, decision_at, decision_note,
                    executed_at, source, metadata_json
                )
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        incident_id,
                        now,
                        now,
                        str(item.get("environment") or "prod"),
                        str(item.get("run_type") or "normal"),
                        str(item.get("trace_id") or ""),
                        int(item.get("position") or index),
                        str(item.get("category") or "diagnose"),
                        str(item.get("action_type") or ""),
                        str(item.get("title") or ""),
                        str(item.get("reason") or ""),
                        str(item.get("risk") or "low"),
                        1 if item.get("approval_required") else 0,
                        1 if item.get("auto_execute") else 0,
                        1 if item.get("verification_required") else 0,
                        str(item.get("status") or "suggested"),
                        json.dumps(safe_dict(item.get("params")), ensure_ascii=False),
                        item.get("action_log_id"),
                        str(item.get("decision_by") or "") or None,
                        str(item.get("decision_at") or "") or None,
                        str(item.get("decision_note") or "") or None,
                        str(item.get("executed_at") or "") or None,
                        str(item.get("source") or "planner"),
                        json.dumps(safe_dict(item.get("metadata")), ensure_ascii=False),
                    )
                    for index, item in enumerate(recommendations, start=1)
                ],
            )
            self.connection.commit()

    def add_incident_recommendations(
        self,
        incident_id: int,
        recommendations: list[dict],
        source: str = "playbook_center",
    ) -> list[dict]:
        if not recommendations:
            return []
        now = utc_now_iso()
        saved: list[dict] = []
        with self.lock:
            incident = self.connection.execute("select id from incidents where id = ?", (incident_id,)).fetchone()
            if not incident:
                raise ValueError(f"incident not found: {incident_id}")
            existing_rows = self.connection.execute(
                """
                select * from incident_recommendations
                where incident_id = ?
                order by position asc, id asc
                """,
                (incident_id,),
            ).fetchall()
            existing_by_key = {
                recommendation_dedupe_key(recommendation_payload(row), str(row["source"] or source)): row
                for row in existing_rows
            }
            next_position = max([int(row["position"] or 0) for row in existing_rows] or [0]) + 1

            for item in recommendations:
                item_source = str(item.get("source") or source)
                key = recommendation_dedupe_key(item, item_source)
                if key in existing_by_key:
                    saved.append(recommendation_payload(existing_by_key[key]))
                    continue
                cursor = self.connection.execute(
                    """
                    insert into incident_recommendations (
                        incident_id, created_at, updated_at, environment, run_type, trace_id,
                        position, category, action_type, title, reason, risk,
                        approval_required, auto_execute, verification_required, status,
                        params_json, action_log_id, decision_by, decision_at, decision_note,
                        executed_at, source, metadata_json
                    )
                    values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        incident_id,
                        now,
                        now,
                        str(item.get("environment") or "prod"),
                        str(item.get("run_type") or "normal"),
                        str(item.get("trace_id") or ""),
                        int(item.get("position") or next_position),
                        str(item.get("category") or "diagnose"),
                        str(item.get("action_type") or ""),
                        str(item.get("title") or ""),
                        str(item.get("reason") or ""),
                        str(item.get("risk") or "low"),
                        1 if item.get("approval_required") else 0,
                        1 if item.get("auto_execute") else 0,
                        1 if item.get("verification_required") else 0,
                        str(item.get("status") or "suggested"),
                        json.dumps(safe_dict(item.get("params")), ensure_ascii=False),
                        item.get("action_log_id"),
                        str(item.get("decision_by") or "") or None,
                        str(item.get("decision_at") or "") or None,
                        str(item.get("decision_note") or "") or None,
                        str(item.get("executed_at") or "") or None,
                        item_source,
                        json.dumps(safe_dict(item.get("metadata")), ensure_ascii=False),
                    ),
                )
                next_position += 1
                row = self.connection.execute(
                    "select * from incident_recommendations where id = ?",
                    (int(cursor.lastrowid),),
                ).fetchone()
                if row:
                    existing_by_key[key] = row
                    saved.append(recommendation_payload(row))
            self.connection.commit()
        return saved

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
        classification: dict | None = None,
    ) -> dict:
        now = utc_now_iso()
        last_summary = summarize_results(results) or title
        classification_payload = normalize_classification(classification)
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
                    results_json = ?,
                    classification_category = ?,
                    classification_confidence = ?,
                    classification_summary = ?,
                    classification_evidence_json = ?,
                    classification_next_steps_json = ?
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
                    classification_payload["category"],
                    classification_payload["confidence"],
                    classification_payload["summary"],
                    json.dumps(classification_payload["evidence"], ensure_ascii=False),
                    json.dumps(classification_payload["next_steps"], ensure_ascii=False),
                    incident_id,
                ),
            )
            self.connection.commit()
            updated = self.connection.execute(
                "select * from incidents where id = ?",
                (incident_id,),
            ).fetchone()
        return dict(updated)

    def update_incident_notification(self, incident_id: int, kind: str = "repeat") -> dict:
        now = utc_now_iso()
        with self.lock:
            self.connection.execute(
                """
                update incidents
                set updated_at = ?,
                    last_notification_at = ?,
                    last_notification_kind = ?
                where id = ?
                """,
                (now, now, kind, incident_id),
            )
            self.connection.commit()
            row = self.connection.execute(
                "select * from incidents where id = ?",
                (incident_id,),
            ).fetchone()
        if not row:
            raise ValueError(f"incident not found: {incident_id}")
        return dict(row)

    def escalate_incident(
        self,
        incident_id: int,
        level: int,
        reason: str,
        metadata: dict | None = None,
    ) -> dict:
        now = utc_now_iso()
        with self.lock:
            row = self.connection.execute(
                "select * from incidents where id = ?",
                (incident_id,),
            ).fetchone()
            if not row:
                raise ValueError(f"incident not found: {incident_id}")
            current_level = int(row["escalation_level"] or 0)
            if current_level >= level:
                return dict(row)
            current_status = str(row["status"])
            self.connection.execute(
                """
                update incidents
                set updated_at = ?,
                    escalated_at = ?,
                    escalation_level = ?,
                    escalation_reason = ?,
                    last_notification_at = ?,
                    last_notification_kind = 'escalation'
                where id = ?
                """,
                (now, now, level, reason, now, incident_id),
            )
            self.record_incident_event(
                incident_id,
                current_status,
                current_status,
                "scheduler",
                "incident escalated",
                {"level": level, "reason": reason, **(metadata or {})},
                commit=False,
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

    def latest_incidents(
        self,
        limit: int = 20,
        status: str = "",
        assignee: str = "",
        priority: str = "",
        severity: str = "",
        false_positive: bool | None = None,
    ) -> list[dict]:
        with self.lock:
            where: list[str] = []
            params: list[object] = []
            if status:
                where.append("status = ?")
                params.append(status)
            if assignee:
                where.append("assignee = ?")
                params.append(assignee)
            if priority:
                where.append("priority = ?")
                params.append(priority)
            if severity:
                where.append("severity = ?")
                params.append(severity)
            if false_positive is not None:
                where.append("false_positive = ?")
                params.append(1 if false_positive else 0)
            where_sql = f"where {' and '.join(where)}" if where else ""
            rows = self.connection.execute(
                f"""
                select * from incidents
                {where_sql}
                order by id desc
                limit ?
                """,
                (*params, limit),
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

    def incident_detail(self, incident_id: int) -> dict | None:
        incident = self.get_incident(incident_id)
        if not incident:
            return None
        events = self.latest_incident_events(incident_id)
        comments = self.latest_incident_comments(incident_id)
        recommendations = self.latest_incident_recommendations(incident_id)
        actions = self.latest_action_logs(100, incident_id=incident_id)
        failed_actions = self.latest_failed_action_logs(100, incident_id=incident_id)
        notifications = self.latest_notification_logs(100, incident_id=incident_id)
        return {
            "incident": incident,
            "events": events,
            "comments": comments,
            "recommendations": recommendations,
            "actions": actions,
            "failed_actions": failed_actions,
            "notifications": notifications,
            "summary": {
                "is_escalated": int(incident.get("escalation_level") or 0) > 0,
                "escalation_level": int(incident.get("escalation_level") or 0),
                "event_count": len(events),
                "comment_count": len(comments),
                "recommendation_count": len(recommendations),
                "action_count": len(actions),
                "failed_action_count": len(failed_actions),
                "notification_count": len(notifications),
                "status": incident.get("status", ""),
                "severity": incident.get("severity", ""),
            },
        }

    def latest_escalated_incidents(self, limit: int = 20) -> list[dict]:
        with self.lock:
            rows = self.connection.execute(
                """
                select * from incidents
                where escalation_level > 0
                order by coalesce(escalated_at, updated_at, created_at) desc, id desc
                limit ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def latest_incident_recommendations(self, incident_id: int, limit: int = 100) -> list[dict]:
        with self.lock:
            rows = self.connection.execute(
                """
                select * from incident_recommendations
                where incident_id = ?
                order by position asc, id asc
                limit ?
                """,
                (incident_id, limit),
            ).fetchall()
        return [recommendation_payload(row) for row in rows]

    def latest_recommendations(
        self,
        limit: int = 50,
        incident_id: int | None = None,
        statuses: Sequence[str] | None = None,
        category: str = "",
        risk: str = "",
        action_type: str = "",
        source: str = "",
    ) -> list[dict]:
        with self.lock:
            where: list[str] = []
            params: list[object] = []
            if incident_id is not None:
                where.append("incident_id = ?")
                params.append(incident_id)
            cleaned_statuses = [status for status in (statuses or []) if status]
            if cleaned_statuses:
                where.append(f"status in ({','.join('?' for _ in cleaned_statuses)})")
                params.extend(cleaned_statuses)
            for column, value in (
                ("category", category),
                ("risk", risk),
                ("action_type", action_type),
                ("source", source),
            ):
                if value:
                    where.append(f"{column} = ?")
                    params.append(value)
            where_sql = f"where {' and '.join(where)}" if where else ""
            rows = self.connection.execute(
                f"""
                select * from incident_recommendations
                {where_sql}
                order by updated_at desc, created_at desc, id desc
                limit ?
                """,
                (*params, limit),
            ).fetchall()
        return [recommendation_payload(row) for row in rows]

    def save_learning_recommendations(self, recommendations: list[dict]) -> list[dict]:
        if not recommendations:
            return []
        now = utc_now_iso()
        saved: list[dict] = []
        preserved_statuses = {"accepted", "applied", "dismissed"}
        with self.lock:
            for item in recommendations:
                payload = normalize_learning_recommendation(item)
                if not payload["dedupe_key"]:
                    continue
                existing = self.connection.execute(
                    "select * from learning_recommendations where dedupe_key = ?",
                    (payload["dedupe_key"],),
                ).fetchone()
                if existing:
                    status = str(existing["status"] or "open")
                    next_status = status if status in preserved_statuses else "open"
                    seen_count = int(existing["seen_count"] or 1) + 1
                    self.connection.execute(
                        """
                        update learning_recommendations
                        set updated_at = ?,
                            last_seen_at = ?,
                            status = ?,
                            priority = ?,
                            category = ?,
                            trigger_type = ?,
                            title = ?,
                            reason = ?,
                            recommended_action = ?,
                            evidence_json = ?,
                            incident_ids_json = ?,
                            metrics_json = ?,
                            source = ?,
                            seen_count = ?
                        where id = ?
                        """,
                        (
                            now,
                            now,
                            next_status,
                            payload["priority"],
                            payload["category"],
                            payload["trigger_type"],
                            payload["title"],
                            payload["reason"],
                            payload["recommended_action"],
                            json.dumps(payload["evidence"], ensure_ascii=False),
                            json.dumps(payload["incident_ids"], ensure_ascii=False),
                            json.dumps(payload["metrics"], ensure_ascii=False),
                            payload["source"],
                            seen_count,
                            existing["id"],
                        ),
                    )
                    row_id = int(existing["id"])
                else:
                    cursor = self.connection.execute(
                        """
                        insert into learning_recommendations (
                            created_at, updated_at, last_seen_at, status, priority, category,
                            trigger_type, dedupe_key, title, reason, recommended_action,
                            evidence_json, incident_ids_json, metrics_json, source, seen_count
                        )
                        values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            now,
                            now,
                            now,
                            "open",
                            payload["priority"],
                            payload["category"],
                            payload["trigger_type"],
                            payload["dedupe_key"],
                            payload["title"],
                            payload["reason"],
                            payload["recommended_action"],
                            json.dumps(payload["evidence"], ensure_ascii=False),
                            json.dumps(payload["incident_ids"], ensure_ascii=False),
                            json.dumps(payload["metrics"], ensure_ascii=False),
                            payload["source"],
                            1,
                        ),
                    )
                    row_id = int(cursor.lastrowid)
                row = self.connection.execute(
                    "select * from learning_recommendations where id = ?",
                    (row_id,),
                ).fetchone()
                saved.append(learning_recommendation_payload(row))
            self.connection.commit()
        return saved

    def latest_learning_recommendations(
        self,
        limit: int = 50,
        statuses: Sequence[str] | None = None,
        category: str = "",
        priority: str = "",
        trigger_type: str = "",
    ) -> list[dict]:
        with self.lock:
            where: list[str] = []
            params: list[object] = []
            cleaned_statuses = [status for status in (statuses or []) if status]
            if cleaned_statuses:
                where.append(f"status in ({','.join('?' for _ in cleaned_statuses)})")
                params.extend(cleaned_statuses)
            for column, value in (
                ("category", category),
                ("priority", priority),
                ("trigger_type", trigger_type),
            ):
                if value:
                    where.append(f"{column} = ?")
                    params.append(value)
            where_sql = f"where {' and '.join(where)}" if where else ""
            rows = self.connection.execute(
                f"""
                select * from learning_recommendations
                {where_sql}
                order by
                    case priority when 'high' then 0 when 'medium' then 1 when 'low' then 2 else 3 end,
                    last_seen_at desc,
                    id desc
                limit ?
                """,
                (*params, limit),
            ).fetchall()
        return [learning_recommendation_payload(row) for row in rows]

    def get_learning_recommendation(self, recommendation_id: int) -> dict | None:
        with self.lock:
            row = self.connection.execute(
                """
                select * from learning_recommendations
                where id = ?
                """,
                (recommendation_id,),
            ).fetchone()
        return learning_recommendation_payload(row) if row else None

    def update_learning_recommendation_status(
        self,
        recommendation_id: int,
        status: str,
        actor: str = "",
        note: str = "",
        draft: dict | None = None,
    ) -> dict:
        allowed_statuses = {"open", "accepted", "dismissed", "applied"}
        normalized_status = (status or "").strip().lower()
        if normalized_status not in allowed_statuses:
            raise ValueError(f"unsupported learning recommendation status: {status}")

        now = utc_now_iso()
        actor_value = actor.strip()
        note_value = note.strip()
        draft_payload = safe_dict(draft)
        with self.lock:
            row = self.connection.execute(
                "select * from learning_recommendations where id = ?",
                (recommendation_id,),
            ).fetchone()
            if not row:
                raise ValueError(f"learning recommendation not found: #{recommendation_id}")

            current_status = str(row["status"] or "open")
            if current_status in {"dismissed", "applied"} and current_status != normalized_status:
                raise ValueError(
                    f"learning recommendation already {current_status}: #{recommendation_id}"
                )
            if normalized_status == "accepted" and current_status not in {"open", "accepted"}:
                raise ValueError(
                    f"learning recommendation cannot be accepted from {current_status}: #{recommendation_id}"
                )
            if normalized_status == "dismissed" and current_status not in {"open", "accepted", "dismissed"}:
                raise ValueError(
                    f"learning recommendation cannot be dismissed from {current_status}: #{recommendation_id}"
                )

            existing_draft = parse_json_object(str(row["draft_json"] or "{}"))
            next_draft = draft_payload or existing_draft
            self.connection.execute(
                """
                update learning_recommendations
                set updated_at = ?,
                    status = ?,
                    decision_by = coalesce(nullif(?, ''), decision_by),
                    decision_at = coalesce(?, decision_at),
                    decision_note = coalesce(nullif(?, ''), decision_note),
                    applied_at = coalesce(?, applied_at),
                    draft_json = ?
                where id = ?
                """,
                (
                    now,
                    normalized_status,
                    actor_value,
                    now if actor_value or note_value or normalized_status in {"accepted", "dismissed", "applied"} else None,
                    note_value,
                    now if normalized_status == "applied" else None,
                    json.dumps(next_draft, ensure_ascii=False),
                    recommendation_id,
                ),
            )
            self.connection.commit()
            updated = self.connection.execute(
                "select * from learning_recommendations where id = ?",
                (recommendation_id,),
            ).fetchone()
        return learning_recommendation_payload(updated)

    def save_learning_config_patch(self, recommendation_id: int, patch: dict) -> dict:
        payload = normalize_learning_config_patch(patch)
        if recommendation_id <= 0:
            raise ValueError("recommendation_id must be positive")
        if not payload["patch_type"]:
            raise ValueError("learning config patch type is required")
        now = utc_now_iso()
        with self.lock:
            existing = self.connection.execute(
                """
                select * from learning_config_patches
                where recommendation_id = ?
                  and patch_type = ?
                  and status in ('proposed', 'approved')
                order by id desc
                limit 1
                """,
                (recommendation_id, payload["patch_type"]),
            ).fetchone()
            if existing:
                self.connection.execute(
                    """
                    update learning_config_patches
                    set updated_at = ?,
                        title = ?,
                        reason = ?,
                        patch_json = ?
                    where id = ?
                    """,
                    (
                        now,
                        payload["title"],
                        payload["reason"],
                        json.dumps(payload["patch"], ensure_ascii=False),
                        existing["id"],
                    ),
                )
                row_id = int(existing["id"])
            else:
                cursor = self.connection.execute(
                    """
                    insert into learning_config_patches (
                        created_at, updated_at, recommendation_id, status, patch_type,
                        title, reason, patch_json, apply_result_json
                    )
                    values (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        now,
                        now,
                        recommendation_id,
                        "proposed",
                        payload["patch_type"],
                        payload["title"],
                        payload["reason"],
                        json.dumps(payload["patch"], ensure_ascii=False),
                        "{}",
                    ),
                )
                row_id = int(cursor.lastrowid)
            self.connection.commit()
            row = self.connection.execute(
                "select * from learning_config_patches where id = ?",
                (row_id,),
            ).fetchone()
        return learning_config_patch_payload(row)

    def latest_learning_config_patches(
        self,
        limit: int = 50,
        statuses: Sequence[str] | None = None,
        recommendation_id: int | None = None,
        patch_type: str = "",
    ) -> list[dict]:
        with self.lock:
            where: list[str] = []
            params: list[object] = []
            cleaned_statuses = [status for status in (statuses or []) if status]
            if cleaned_statuses:
                where.append(f"status in ({','.join('?' for _ in cleaned_statuses)})")
                params.extend(cleaned_statuses)
            if recommendation_id:
                where.append("recommendation_id = ?")
                params.append(recommendation_id)
            if patch_type:
                where.append("patch_type = ?")
                params.append(patch_type)
            where_sql = f"where {' and '.join(where)}" if where else ""
            rows = self.connection.execute(
                f"""
                select * from learning_config_patches
                {where_sql}
                order by
                    case status when 'proposed' then 0 when 'approved' then 1 when 'applied' then 2 else 3 end,
                    updated_at desc,
                    id desc
                limit ?
                """,
                (*params, limit),
            ).fetchall()
        return [learning_config_patch_payload(row) for row in rows]

    def get_learning_config_patch(self, patch_id: int) -> dict | None:
        with self.lock:
            row = self.connection.execute(
                """
                select * from learning_config_patches
                where id = ?
                """,
                (patch_id,),
            ).fetchone()
        return learning_config_patch_payload(row) if row else None

    def update_learning_config_patch_status(
        self,
        patch_id: int,
        status: str,
        actor: str = "",
        note: str = "",
        apply_result: dict | None = None,
    ) -> dict:
        allowed_statuses = {"proposed", "approved", "rejected", "applied"}
        normalized_status = (status or "").strip().lower()
        if normalized_status not in allowed_statuses:
            raise ValueError(f"unsupported learning config patch status: {status}")
        now = utc_now_iso()
        actor_value = actor.strip()
        note_value = note.strip()
        with self.lock:
            row = self.connection.execute(
                "select * from learning_config_patches where id = ?",
                (patch_id,),
            ).fetchone()
            if not row:
                raise ValueError(f"learning config patch not found: #{patch_id}")
            current_status = str(row["status"] or "proposed")
            if current_status in {"rejected", "applied"} and current_status != normalized_status:
                raise ValueError(f"learning config patch already {current_status}: #{patch_id}")
            if normalized_status == "approved" and current_status not in {"proposed", "approved"}:
                raise ValueError(f"learning config patch cannot be approved from {current_status}: #{patch_id}")
            if normalized_status == "applied" and current_status not in {"approved", "applied"}:
                raise ValueError(f"learning config patch cannot be applied from {current_status}: #{patch_id}")
            existing_result = parse_json_object(str(row["apply_result_json"] or "{}"))
            result_payload = safe_dict(apply_result) or existing_result
            self.connection.execute(
                """
                update learning_config_patches
                set updated_at = ?,
                    status = ?,
                    decision_by = coalesce(nullif(?, ''), decision_by),
                    decision_at = coalesce(?, decision_at),
                    decision_note = coalesce(nullif(?, ''), decision_note),
                    applied_at = coalesce(?, applied_at),
                    apply_result_json = ?
                where id = ?
                """,
                (
                    now,
                    normalized_status,
                    actor_value,
                    now if actor_value or note_value or normalized_status in {"approved", "rejected", "applied"} else None,
                    note_value,
                    now if normalized_status == "applied" else None,
                    json.dumps(result_payload, ensure_ascii=False),
                    patch_id,
                ),
            )
            self.connection.commit()
            updated = self.connection.execute(
                "select * from learning_config_patches where id = ?",
                (patch_id,),
            ).fetchone()
        return learning_config_patch_payload(updated)

    def learning_summary(self, limit: int = 500) -> dict:
        rows = self.latest_learning_recommendations(limit=limit)
        by_status: dict[str, int] = {}
        by_priority: dict[str, int] = {}
        by_trigger_type: dict[str, int] = {}
        open_count = 0
        for row in rows:
            status = str(row.get("status") or "open")
            priority = str(row.get("priority") or "medium")
            trigger_type = str(row.get("trigger_type") or "")
            by_status[status] = by_status.get(status, 0) + 1
            by_priority[priority] = by_priority.get(priority, 0) + 1
            by_trigger_type[trigger_type] = by_trigger_type.get(trigger_type, 0) + 1
            if status == "open":
                open_count += 1
        return {
            "total": len(rows),
            "open_count": open_count,
            "by_status": by_status,
            "by_priority": by_priority,
            "by_trigger_type": by_trigger_type,
            "latest": rows[:20],
        }

    def get_incident_recommendation(self, recommendation_id: int) -> dict | None:
        with self.lock:
            row = self.connection.execute(
                """
                select * from incident_recommendations
                where id = ?
                """,
                (recommendation_id,),
            ).fetchone()
        return recommendation_payload(row) if row else None

    def update_incident_recommendation_status(
        self,
        recommendation_id: int,
        status: str,
        actor: str = "",
        note: str = "",
        action_log_id: int | None = None,
        metadata: dict | None = None,
    ) -> dict:
        terminal_statuses = {"executed", "failed", "verified_ok", "verified_failed", "skipped", "rejected"}
        now = utc_now_iso()
        actor_value = actor.strip()
        note_value = note.strip()
        with self.lock:
            row = self.connection.execute(
                "select * from incident_recommendations where id = ?",
                (recommendation_id,),
            ).fetchone()
            if not row:
                raise ValueError(f"recommendation not found: #{recommendation_id}")
            merged_metadata = parse_json_object(str(row["metadata_json"] or "{}"))
            if metadata:
                merged_metadata.update(metadata)
            self.connection.execute(
                """
                update incident_recommendations
                set updated_at = ?,
                    status = ?,
                    action_log_id = coalesce(?, action_log_id),
                    decision_by = coalesce(nullif(?, ''), decision_by),
                    decision_at = coalesce(?, decision_at),
                    decision_note = coalesce(nullif(?, ''), decision_note),
                    executed_at = coalesce(?, executed_at),
                    metadata_json = ?
                where id = ?
                """,
                (
                    now,
                    status,
                    action_log_id,
                    actor_value,
                    now if actor_value or note_value else None,
                    note_value,
                    now if status in terminal_statuses else None,
                    json.dumps(merged_metadata, ensure_ascii=False),
                    recommendation_id,
                ),
            )
            self.connection.commit()
            updated = self.connection.execute(
                "select * from incident_recommendations where id = ?",
                (recommendation_id,),
            ).fetchone()
        return recommendation_payload(updated)

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

    def latest_incident_comments(self, incident_id: int, limit: int = 100) -> list[dict]:
        with self.lock:
            rows = self.connection.execute(
                """
                select * from incident_comments
                where incident_id = ?
                order by id asc
                limit ?
                """,
                (incident_id, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def add_incident_comment(
        self,
        incident_id: int,
        actor: str,
        comment: str,
        metadata: dict | None = None,
    ) -> dict:
        text = comment.strip()
        if not text:
            raise ValueError("comment cannot be empty")
        payload = lifecycle_payload(actor, text, metadata)
        now = utc_now_iso()
        with self.lock:
            row = self.connection.execute("select * from incidents where id = ?", (incident_id,)).fetchone()
            if not row:
                raise ValueError(f"incident not found: {incident_id}")
            cursor = self.connection.execute(
                """
                insert into incident_comments (incident_id, created_at, actor, comment, metadata_json)
                values (?, ?, ?, ?, ?)
                """,
                (
                    incident_id,
                    now,
                    payload["actor"],
                    text,
                    json.dumps(payload["metadata"], ensure_ascii=False),
                ),
            )
            self.connection.execute(
                "update incidents set updated_at = ? where id = ?",
                (now, incident_id),
            )
            self.record_incident_event(
                incident_id,
                str(row["status"]),
                str(row["status"]),
                payload["actor"],
                "comment added",
                {"comment_id": int(cursor.lastrowid), **payload["metadata"]},
                commit=False,
            )
            self.connection.commit()
            created = self.connection.execute(
                "select * from incident_comments where id = ?",
                (int(cursor.lastrowid),),
            ).fetchone()
        return dict(created)

    def assign_incident(self, incident_id: int, assignee: str, actor: str = "system", note: str = "") -> dict:
        assignee = assignee.strip()
        payload = lifecycle_payload(actor, note, {"assignee": assignee})
        now = utc_now_iso()
        with self.lock:
            row = self.connection.execute("select * from incidents where id = ?", (incident_id,)).fetchone()
            if not row:
                raise ValueError(f"incident not found: {incident_id}")
            self.connection.execute(
                "update incidents set assignee = ?, updated_at = ? where id = ?",
                (assignee, now, incident_id),
            )
            self.record_incident_event(
                incident_id,
                str(row["status"]),
                str(row["status"]),
                payload["actor"],
                payload["note"] or ("incident unassigned" if not assignee else f"incident assigned to {assignee}"),
                payload["metadata"],
                commit=False,
            )
            self.connection.commit()
            updated = self.connection.execute("select * from incidents where id = ?", (incident_id,)).fetchone()
        return dict(updated)

    def set_incident_priority(self, incident_id: int, priority: str, actor: str = "system", note: str = "") -> dict:
        normalized = validate_incident_priority(priority)
        payload = lifecycle_payload(actor, note, {"priority": normalized})
        now = utc_now_iso()
        with self.lock:
            row = self.connection.execute("select * from incidents where id = ?", (incident_id,)).fetchone()
            if not row:
                raise ValueError(f"incident not found: {incident_id}")
            self.connection.execute(
                "update incidents set priority = ?, updated_at = ? where id = ?",
                (normalized, now, incident_id),
            )
            self.record_incident_event(
                incident_id,
                str(row["status"]),
                str(row["status"]),
                payload["actor"],
                payload["note"] or f"incident priority set to {normalized}",
                payload["metadata"],
                commit=False,
            )
            self.connection.commit()
            updated = self.connection.execute("select * from incidents where id = ?", (incident_id,)).fetchone()
        return dict(updated)

    def mark_incident_false_positive(
        self,
        incident_id: int,
        actor: str = "system",
        reason: str = "",
    ) -> dict:
        payload = lifecycle_payload(actor, reason, {"false_positive": True})
        now = utc_now_iso()
        with self.lock:
            row = self.connection.execute("select * from incidents where id = ?", (incident_id,)).fetchone()
            if not row:
                raise ValueError(f"incident not found: {incident_id}")
            current = str(row["status"])
            target = "closed" if current != "closed" else current
            if current != target:
                validate_transition(current, target)
            closed_at = row["closed_at"] or (now if target == "closed" else None)
            closed_reason = payload["note"] or row["closed_reason"] or "false positive"
            self.connection.execute(
                """
                update incidents
                set false_positive = 1,
                    false_positive_at = ?,
                    false_positive_by = ?,
                    false_positive_reason = ?,
                    status = ?,
                    updated_at = ?,
                    closed_at = ?,
                    closed_reason = ?
                where id = ?
                """,
                (
                    now,
                    payload["actor"],
                    payload["note"],
                    target,
                    now,
                    closed_at,
                    closed_reason,
                    incident_id,
                ),
            )
            self.record_incident_event(
                incident_id,
                current,
                target,
                payload["actor"],
                payload["note"] or "marked false positive",
                payload["metadata"],
                commit=False,
            )
            self.connection.commit()
            updated = self.connection.execute("select * from incidents where id = ?", (incident_id,)).fetchone()
        return dict(updated)

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

    def latest_failed_action_logs(
        self,
        limit: int = 50,
        incident_id: int | None = None,
    ) -> list[dict]:
        with self.lock:
            where = ["status in ('failed', 'verified_failed')"]
            params: list[object] = []
            if incident_id is not None:
                where.append("incident_id = ?")
                params.append(incident_id)
            rows = self.connection.execute(
                f"""
                select * from action_logs
                where {' and '.join(where)}
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

    def save_notification_log(
        self,
        title: str,
        dedupe_key: str,
        status: str,
        severity: str = "",
        route_names: Sequence[str] | None = None,
        channels: Sequence[str] | None = None,
        suppressed_reason: str = "",
        error: str = "",
        environment: str = "prod",
        run_type: str = "normal",
        trace_id: str = "",
        incident_id: int | None = None,
        metadata: dict | None = None,
    ) -> int:
        with self.lock:
            cursor = self.connection.execute(
                """
                insert into notification_logs (
                    created_at, environment, run_type, trace_id, incident_id,
                    severity, title, dedupe_key, status, route_names_json,
                    channels_json, suppressed_reason, error, metadata_json
                )
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    utc_now_iso(),
                    environment or "prod",
                    run_type or "normal",
                    trace_id or "",
                    incident_id,
                    severity or "",
                    title,
                    dedupe_key,
                    status,
                    json.dumps(list(route_names or []), ensure_ascii=False),
                    json.dumps(list(channels or []), ensure_ascii=False),
                    suppressed_reason,
                    error,
                    json.dumps(metadata or {}, ensure_ascii=False),
                ),
            )
            self.connection.commit()
            return int(cursor.lastrowid)

    def latest_notification_logs(
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
                select * from notification_logs
                {where_sql}
                order by id desc
                limit ?
                """,
                (*params, limit),
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
        notification_cutoff: str = "",
        test_notification_cutoff: str = "",
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
        notification_where, notification_params = build_retention_where(
            "created_at < ?",
            [notification_cutoff or api_audit_cutoff or action_cutoff],
            test_notification_cutoff,
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
            notification_logs = self.connection.execute(
                f"select count(*) from notification_logs where {notification_where}",
                notification_params,
            ).fetchone()[0]
        return {
            "check_results": int(check_results),
            "incidents": int(incidents),
            "action_logs": int(action_logs),
            "api_audit_logs": int(api_audit_logs),
            "notification_logs": int(notification_logs),
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
        notification_cutoff: str = "",
        test_notification_cutoff: str = "",
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
        notification_where, notification_params = build_retention_where(
            "created_at < ?",
            [notification_cutoff or api_audit_cutoff or action_cutoff],
            test_notification_cutoff,
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
                notification_cutoff=notification_cutoff,
                test_notification_cutoff=test_notification_cutoff,
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
            self.connection.execute(
                f"""
                delete from incident_recommendations
                where incident_id in (
                    select id from incidents where {incident_where}
                )
                """,
                incident_params,
            )
            self.connection.execute(
                f"""
                delete from incident_comments
                where incident_id in (
                    select id from incidents where {incident_where}
                )
                """,
                incident_params,
            )
            self.connection.execute(f"delete from incidents where {incident_where}", incident_params)
            self.connection.execute(f"delete from action_logs where {action_where}", action_params)
            self.connection.execute(f"delete from api_audit_logs where {api_audit_where}", api_audit_params)
            self.connection.execute(f"delete from notification_logs where {notification_where}", notification_params)
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

    def classification_summary(self, hours: int = 24) -> dict:
        bounded_hours = min(max(int(hours), 1), 24 * 365)
        since = datetime.now(timezone.utc) - timedelta(hours=bounded_hours)
        incidents = self.recent_incidents(since.isoformat(), limit=1000)

        by_category: dict[str, dict] = {}
        by_status: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        classified_count = 0

        for row in incidents:
            category = str(row.get("classification_category") or "unclassified")
            status = str(row.get("status") or "open")
            severity = str(row.get("severity") or "")
            confidence = safe_float(row.get("classification_confidence"))
            occurrence_count = safe_int(row.get("occurrence_count"), default=1)
            latest_at = str(row.get("last_seen_at") or row.get("updated_at") or row.get("created_at") or "")

            if category != "unclassified":
                classified_count += 1
            by_status[status] = by_status.get(status, 0) + 1
            by_severity[severity] = by_severity.get(severity, 0) + 1

            bucket = by_category.setdefault(
                category,
                {
                    "category": category,
                    "count": 0,
                    "occurrence_count": 0,
                    "open_count": 0,
                    "critical_count": 0,
                    "warning_count": 0,
                    "resolved_count": 0,
                    "confidence_sum": 0.0,
                    "latest_at": "",
                    "examples": [],
                },
            )
            bucket["count"] += 1
            bucket["occurrence_count"] += occurrence_count
            bucket["confidence_sum"] += confidence
            if status not in {"resolved", "closed"}:
                bucket["open_count"] += 1
            if severity == "critical":
                bucket["critical_count"] += 1
            if severity == "warning":
                bucket["warning_count"] += 1
            if status == "resolved":
                bucket["resolved_count"] += 1
            if latest_at > str(bucket.get("latest_at") or ""):
                bucket["latest_at"] = latest_at
            examples = bucket["examples"]
            if len(examples) < 3:
                examples.append(
                    {
                        "id": row.get("id"),
                        "title": row.get("title"),
                        "status": status,
                        "severity": severity,
                        "summary": row.get("classification_summary") or row.get("last_summary") or "",
                        "latest_at": latest_at,
                    }
                )

        category_rows = []
        for bucket in by_category.values():
            count = int(bucket["count"])
            confidence_sum = float(bucket.pop("confidence_sum"))
            bucket["avg_confidence"] = round(confidence_sum / count, 3) if count else 0.0
            category_rows.append(bucket)
        category_rows.sort(key=lambda item: (-int(item["count"]), str(item["category"])))

        optimization_candidates = []
        for item in category_rows:
            reason = learning_candidate_reason(item)
            if reason:
                optimization_candidates.append(
                    {
                        "category": item["category"],
                        "reason": reason,
                        "count": item["count"],
                        "avg_confidence": item["avg_confidence"],
                        "open_count": item["open_count"],
                    }
                )

        return {
            "hours": bounded_hours,
            "total_incidents": len(incidents),
            "classified_count": classified_count,
            "unclassified_count": len(incidents) - classified_count,
            "by_category": category_rows,
            "by_status": by_status,
            "by_severity": by_severity,
            "optimization_candidates": optimization_candidates,
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


def recommendation_payload(row: sqlite3.Row) -> dict:
    payload = dict(row)
    payload["approval_required"] = bool(payload.get("approval_required"))
    payload["auto_execute"] = bool(payload.get("auto_execute"))
    payload["verification_required"] = bool(payload.get("verification_required"))
    payload["params"] = parse_json_object(str(payload.get("params_json") or "{}"))
    payload["metadata"] = parse_json_object(str(payload.get("metadata_json") or "{}"))
    return payload


def recommendation_dedupe_key(item: dict, source: str) -> str:
    payload = {
        "source": source,
        "action_type": str(item.get("action_type") or ""),
        "title": str(item.get("title") or ""),
        "params": safe_dict(item.get("params")),
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True)


def learning_recommendation_payload(row: sqlite3.Row) -> dict:
    payload = dict(row)
    payload["evidence"] = parse_json_list(str(payload.get("evidence_json") or "[]"))
    payload["incident_ids"] = [
        safe_int(value)
        for value in parse_json_list(str(payload.get("incident_ids_json") or "[]"))
        if safe_int(value) > 0
    ]
    payload["metrics"] = parse_json_object(str(payload.get("metrics_json") or "{}"))
    payload["draft"] = parse_json_object(str(payload.get("draft_json") or "{}"))
    return payload


def learning_config_patch_payload(row: sqlite3.Row) -> dict:
    payload = dict(row)
    payload["patch"] = parse_json_object(str(payload.get("patch_json") or "{}"))
    payload["apply_result"] = parse_json_object(str(payload.get("apply_result_json") or "{}"))
    return payload


def parse_json_object(value: str) -> dict:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def parse_json_list(value: str) -> list:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return []
    return parsed if isinstance(parsed, list) else []


def normalize_classification(value: dict | None) -> dict:
    payload = safe_dict(value)
    return {
        "category": str(payload.get("category") or ""),
        "confidence": safe_float(payload.get("confidence")),
        "summary": str(payload.get("summary") or ""),
        "evidence": safe_list(payload.get("evidence")),
        "next_steps": safe_list(payload.get("next_steps")),
    }


def validate_incident_priority(value: str) -> str:
    priority = str(value or "").strip().lower()
    if priority not in {"low", "medium", "high", "critical"}:
        raise ValueError(f"invalid incident priority: {value}")
    return priority


def normalize_learning_recommendation(value: dict | None) -> dict:
    payload = safe_dict(value)
    return {
        "dedupe_key": str(payload.get("dedupe_key") or ""),
        "priority": str(payload.get("priority") or "medium"),
        "category": str(payload.get("category") or ""),
        "trigger_type": str(payload.get("trigger_type") or ""),
        "title": str(payload.get("title") or ""),
        "reason": str(payload.get("reason") or ""),
        "recommended_action": str(payload.get("recommended_action") or ""),
        "evidence": safe_list(payload.get("evidence")),
        "incident_ids": [safe_int(value) for value in safe_list(payload.get("incident_ids")) if safe_int(value) > 0],
        "metrics": safe_dict(payload.get("metrics")),
        "source": str(payload.get("source") or "classification_learning"),
    }


def normalize_learning_config_patch(value: dict | None) -> dict:
    payload = safe_dict(value)
    return {
        "patch_type": str(payload.get("patch_type") or ""),
        "title": str(payload.get("title") or ""),
        "reason": str(payload.get("reason") or ""),
        "patch": payload,
    }


def safe_dict(value: object) -> dict:
    return dict(value) if isinstance(value, dict) else {}


def safe_list(value: object) -> list:
    return list(value) if isinstance(value, list) else []


def safe_int(value: object, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def safe_float(value: object, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def learning_candidate_reason(item: dict) -> str:
    category = str(item.get("category") or "")
    avg_confidence = safe_float(item.get("avg_confidence"))
    if category in {"unknown", "unclassified"}:
        return "needs_more_rules"
    if avg_confidence and avg_confidence < 0.65:
        return "low_confidence"
    if safe_int(item.get("open_count")) > 0 and safe_int(item.get("count")) >= 3:
        return "frequent_open_incidents"
    return ""


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

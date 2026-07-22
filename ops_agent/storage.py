from __future__ import annotations

import hashlib
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

                create table if not exists incident_diagnoses (
                    id integer primary key autoincrement,
                    incident_id integer not null,
                    created_at text not null,
                    environment text not null default 'prod',
                    run_type text not null default 'normal',
                    trace_id text not null default '',
                    top_category text not null default '',
                    top_confidence real not null default 0,
                    next_decision text not null default '',
                    evidence_json text not null default '{}',
                    payload_json text not null default '{}'
                );

                create table if not exists incident_reviews (
                    id integer primary key autoincrement,
                    incident_id integer not null,
                    created_at text not null,
                    generated_by text not null default 'ops-agent',
                    status text not null default '',
                    severity text not null default '',
                    title text not null default '',
                    summary text not null default '',
                    root_causes_json text not null default '[]',
                    actions_json text not null default '[]',
                    related_changes_json text not null default '[]',
                    prevention_items_json text not null default '[]',
                    timeline_summary_json text not null default '{}',
                    payload_json text not null default '{}'
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
                    approval_expires_at text,
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

                create table if not exists backup_runs (
                    id integer primary key autoincrement,
                    target_id text not null,
                    engine text not null,
                    kind text not null default 'backup',
                    status text not null default 'running',
                    started_at text not null,
                    completed_at text,
                    path text not null default '',
                    size_bytes integer not null default 0,
                    checksum text not null default '',
                    error text not null default '',
                    metadata_json text not null default '{}'
                );

                create table if not exists fleet_nodes (
                    node_id text primary key,
                    created_at text not null,
                    updated_at text not null,
                    last_seen_at text not null,
                    name text not null default '',
                    hostname text not null default '',
                    address text not null default '',
                    agent_version text not null default '',
                    platform text not null default '',
                    enabled integer not null default 1,
                    labels_json text not null default '{}',
                    capabilities_json text not null default '[]',
                    metrics_json text not null default '{}',
                    projects_json text not null default '[]',
                    assets_json text not null default '[]',
                    discovery_json text not null default '{}'
                );

                create table if not exists change_events (
                    id integer primary key autoincrement,
                    created_at text not null,
                    updated_at text,
                    environment text not null default 'prod',
                    run_type text not null default 'normal',
                    project_id text not null default '',
                    source text not null default '',
                    change_type text not null default '',
                    title text not null,
                    summary text not null default '',
                    actor text not null default '',
                    status text not null default 'completed',
                    risk text not null default 'medium',
                    commit_sha text not null default '',
                    branch text not null default '',
                    version text not null default '',
                    related_incident_id integer,
                    related_ai_repair_id integer,
                    links_json text not null default '[]',
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

                create table if not exists ai_repair_proposals (
                    id integer primary key autoincrement,
                    incident_id integer not null,
                    created_at text not null,
                    updated_at text,
                    status text not null default 'proposed',
                    title text not null default '',
                    summary text not null default '',
                    risk text not null default 'medium',
                    root_cause text not null default '',
                    model_provider text not null default 'rules',
                    model_name text not null default '',
                    prompt_json text not null default '{}',
                    proposal_json text not null default '{}',
                    patch_json text not null default '{}',
                    test_plan_json text not null default '{}',
                    dry_run_json text not null default '{}',
                    test_result_json text not null default '{}',
                    decision_by text,
                    decision_at text,
                    decision_note text
                );

                create index if not exists idx_check_results_created
                    on check_results (created_at, id);
                create index if not exists idx_incidents_created
                    on incidents (created_at, id);
                create index if not exists idx_incident_recommendations_incident
                    on incident_recommendations (incident_id, position, id);
                create index if not exists idx_incident_comments_incident
                    on incident_comments (incident_id, id);
                create index if not exists idx_incident_diagnoses_incident
                    on incident_diagnoses (incident_id, id);
                create index if not exists idx_incident_reviews_incident
                    on incident_reviews (incident_id, id);
                create unique index if not exists idx_learning_recommendations_dedupe
                    on learning_recommendations (dedupe_key);
                create index if not exists idx_learning_config_patches_status
                    on learning_config_patches (status, updated_at, id);
                create index if not exists idx_learning_config_patches_recommendation
                    on learning_config_patches (recommendation_id, id);
                create index if not exists idx_ai_repair_proposals_incident
                    on ai_repair_proposals (incident_id, id);
                create index if not exists idx_ai_repair_proposals_status
                    on ai_repair_proposals (status, updated_at, id);
                create index if not exists idx_notification_logs_created
                    on notification_logs (created_at, id);
                create index if not exists idx_notification_logs_status
                    on notification_logs (status, id);
                create index if not exists idx_change_events_created
                    on change_events (created_at, id);
                create index if not exists idx_change_events_context
                    on change_events (environment, run_type, created_at, id);
                create index if not exists idx_change_events_project
                    on change_events (project_id, created_at, id);
                create index if not exists idx_change_events_related
                    on change_events (related_incident_id, related_ai_repair_id, id);
                """
            )
            self.ensure_context_columns()
            self.connection.executescript(
                """
                create index if not exists idx_check_results_context
                    on check_results (environment, run_type, created_at, id);
                create index if not exists idx_incidents_context
                    on incidents (environment, run_type, created_at, id);
                """
            )
            self.ensure_incident_lifecycle_columns()
            self.ensure_incident_classification_columns()
            self.ensure_action_log_columns()
            self.ensure_recommendation_columns()
            self.ensure_learning_recommendation_columns()
            self.ensure_learning_config_patch_columns()
            self.ensure_ai_repair_proposal_columns()
            self.ensure_notification_log_columns()
            self.ensure_change_event_columns()
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
            "approval_expires_at": "alter table action_logs add column approval_expires_at text",
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

    def ensure_change_event_columns(self) -> None:
        columns = {
            row["name"]
            for row in self.connection.execute("pragma table_info(change_events)").fetchall()
        }
        additions = {
            "updated_at": "alter table change_events add column updated_at text",
            "environment": "alter table change_events add column environment text not null default 'prod'",
            "run_type": "alter table change_events add column run_type text not null default 'normal'",
            "project_id": "alter table change_events add column project_id text not null default ''",
            "source": "alter table change_events add column source text not null default ''",
            "change_type": "alter table change_events add column change_type text not null default ''",
            "summary": "alter table change_events add column summary text not null default ''",
            "actor": "alter table change_events add column actor text not null default ''",
            "status": "alter table change_events add column status text not null default 'completed'",
            "risk": "alter table change_events add column risk text not null default 'medium'",
            "commit_sha": "alter table change_events add column commit_sha text not null default ''",
            "branch": "alter table change_events add column branch text not null default ''",
            "version": "alter table change_events add column version text not null default ''",
            "related_incident_id": "alter table change_events add column related_incident_id integer",
            "related_ai_repair_id": "alter table change_events add column related_ai_repair_id integer",
            "links_json": "alter table change_events add column links_json text not null default '[]'",
            "metadata_json": "alter table change_events add column metadata_json text not null default '{}'",
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

    def ensure_ai_repair_proposal_columns(self) -> None:
        columns = {
            row["name"]
            for row in self.connection.execute("pragma table_info(ai_repair_proposals)").fetchall()
        }
        additions = {
            "updated_at": "alter table ai_repair_proposals add column updated_at text",
            "status": "alter table ai_repair_proposals add column status text not null default 'proposed'",
            "title": "alter table ai_repair_proposals add column title text not null default ''",
            "summary": "alter table ai_repair_proposals add column summary text not null default ''",
            "risk": "alter table ai_repair_proposals add column risk text not null default 'medium'",
            "root_cause": "alter table ai_repair_proposals add column root_cause text not null default ''",
            "model_provider": "alter table ai_repair_proposals add column model_provider text not null default 'rules'",
            "model_name": "alter table ai_repair_proposals add column model_name text not null default ''",
            "prompt_json": "alter table ai_repair_proposals add column prompt_json text not null default '{}'",
            "proposal_json": "alter table ai_repair_proposals add column proposal_json text not null default '{}'",
            "patch_json": "alter table ai_repair_proposals add column patch_json text not null default '{}'",
            "test_plan_json": "alter table ai_repair_proposals add column test_plan_json text not null default '{}'",
            "dry_run_json": "alter table ai_repair_proposals add column dry_run_json text not null default '{}'",
            "test_result_json": "alter table ai_repair_proposals add column test_result_json text not null default '{}'",
            "decision_by": "alter table ai_repair_proposals add column decision_by text",
            "decision_at": "alter table ai_repair_proposals add column decision_at text",
            "decision_note": "alter table ai_repair_proposals add column decision_note text",
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

    def latest_results(self, limit: int = 50, environment: str = "", run_type: str = "") -> list[dict]:
        with self.lock:
            where, params = context_where(environment, run_type)
            where_sql = f"where {' and '.join(where)}" if where else ""
            rows = self.connection.execute(
                f"""
                select * from check_results
                {where_sql}
                order by id desc
                limit ?
                """,
                (*params, limit),
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
        environment: str = "",
        run_type: str = "",
    ) -> list[dict]:
        with self.lock:
            where, params = context_where(environment, run_type)
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
        diagnoses = self.latest_incident_diagnoses(incident_id)
        recommendations = self.latest_incident_recommendations(incident_id)
        actions = self.latest_action_logs(100, incident_id=incident_id)
        failed_actions = self.latest_failed_action_logs(100, incident_id=incident_id)
        notifications = self.latest_notification_logs(100, incident_id=incident_id)
        timeline = self.incident_timeline(incident_id)
        return {
            "incident": incident,
            "events": events,
            "comments": comments,
            "diagnosis": diagnoses[0] if diagnoses else None,
            "diagnoses": diagnoses,
            "recommendations": recommendations,
            "actions": actions,
            "failed_actions": failed_actions,
            "notifications": notifications,
            "timeline": timeline,
            "summary": {
                "is_escalated": int(incident.get("escalation_level") or 0) > 0,
                "escalation_level": int(incident.get("escalation_level") or 0),
                "event_count": len(events),
                "comment_count": len(comments),
                "diagnosis_count": len(diagnoses),
                "recommendation_count": len(recommendations),
                "action_count": len(actions),
                "failed_action_count": len(failed_actions),
                "notification_count": len(notifications),
                "timeline_count": len(timeline.get("entries", [])) if timeline else 0,
                "status": incident.get("status", ""),
                "severity": incident.get("severity", ""),
            },
        }

    def incident_timeline(self, incident_id: int, hours: int = 24, limit: int = 200) -> dict | None:
        incident = self.get_incident(incident_id)
        if not incident:
            return None
        bounded_hours = max(1, int(hours or 24))
        bounded_limit = min(max(int(limit or 200), 1), 1000)
        occurred_at = (
            parse_iso_datetime(incident.get("last_seen_at"))
            or parse_iso_datetime(incident.get("updated_at"))
            or parse_iso_datetime(incident.get("created_at"))
            or datetime.now(timezone.utc)
        )
        since = occurred_at - timedelta(hours=bounded_hours)
        since_iso = since.isoformat()
        environment = str(incident.get("environment") or "prod")
        run_type = str(incident.get("run_type") or "normal")
        targets = incident_result_targets(incident)
        entries: list[dict] = [
            timeline_entry(
                "incident",
                incident.get("created_at"),
                str(incident.get("title") or f"Incident #{incident_id}"),
                str(incident.get("last_summary") or incident.get("analysis") or ""),
                status=str(incident.get("status") or ""),
                severity=str(incident.get("severity") or ""),
                source_id=f"incident:{incident_id}",
                payload={
                    "id": incident_id,
                    "classification_category": incident.get("classification_category") or "",
                    "classification_confidence": incident.get("classification_confidence") or 0,
                    "occurrence_count": incident.get("occurrence_count") or 1,
                },
            )
        ]

        for row in self.recent_results_for_targets(since_iso, environment, run_type, targets, limit=bounded_limit):
            entries.append(
                timeline_entry(
                    "check_result",
                    row.get("created_at"),
                    f"{row.get('source')}/{row.get('name')}",
                    str(row.get("summary") or ""),
                    status=str(row.get("status") or ""),
                    severity=str(row.get("status") or ""),
                    source=str(row.get("source") or ""),
                    source_id=f"check_result:{row.get('id')}",
                    payload={
                        "id": row.get("id"),
                        "name": row.get("name"),
                        "trace_id": row.get("trace_id"),
                        "details": parse_json_object(str(row.get("details_json") or "{}")),
                    },
                )
            )

        for row in self.latest_incident_events(incident_id, limit=bounded_limit):
            entries.append(
                timeline_entry(
                    "incident_event",
                    row.get("created_at"),
                    f"{row.get('from_status')} -> {row.get('to_status')}",
                    str(row.get("note") or ""),
                    status=str(row.get("to_status") or ""),
                    source_id=f"incident_event:{row.get('id')}",
                    payload={
                        **row,
                        "metadata": parse_json_object(str(row.get("metadata_json") or "{}")),
                    },
                )
            )

        for row in self.latest_incident_comments(incident_id, limit=bounded_limit):
            entries.append(
                timeline_entry(
                    "comment",
                    row.get("created_at"),
                    f"Comment by {row.get('actor') or 'operator'}",
                    str(row.get("comment") or ""),
                    source_id=f"comment:{row.get('id')}",
                    payload={
                        **row,
                        "metadata": parse_json_object(str(row.get("metadata_json") or "{}")),
                    },
                )
            )

        for row in self.latest_incident_diagnoses(incident_id, limit=bounded_limit):
            entries.append(
                timeline_entry(
                    "diagnosis",
                    row.get("created_at"),
                    f"Diagnosis: {row.get('top_category') or 'unknown'}",
                    f"confidence={row.get('top_confidence')}; next={row.get('next_decision')}",
                    status=str(row.get("next_decision") or ""),
                    source_id=f"diagnosis:{row.get('id')}",
                    payload=row,
                )
            )

        for row in self.latest_incident_recommendations(incident_id, limit=bounded_limit):
            entries.append(
                timeline_entry(
                    "recommendation",
                    row.get("created_at"),
                    str(row.get("title") or row.get("action_type") or "Recommendation"),
                    str(row.get("reason") or ""),
                    status=str(row.get("status") or ""),
                    severity=str(row.get("risk") or ""),
                    source=str(row.get("source") or ""),
                    source_id=f"recommendation:{row.get('id')}",
                    payload=row,
                )
            )

        for row in self.latest_action_logs(bounded_limit, incident_id=incident_id):
            entries.append(
                timeline_entry(
                    "action",
                    row.get("created_at"),
                    str(row.get("title") or row.get("action_type") or "Action"),
                    str(row.get("error") or row.get("output") or row.get("reason") or ""),
                    status=str(row.get("status") or ""),
                    severity=str(row.get("risk") or ""),
                    source=str(row.get("action_type") or ""),
                    source_id=f"action:{row.get('id')}",
                    payload={
                        **row,
                        "params": parse_json_object(str(row.get("params_json") or "{}")),
                    },
                )
            )

        for row in self.latest_notification_logs(bounded_limit, incident_id=incident_id):
            entries.append(
                timeline_entry(
                    "notification",
                    row.get("created_at"),
                    str(row.get("title") or "Notification"),
                    str(row.get("error") or row.get("suppressed_reason") or row.get("dedupe_key") or ""),
                    status=str(row.get("status") or ""),
                    severity=str(row.get("severity") or ""),
                    source_id=f"notification:{row.get('id')}",
                    payload={
                        **row,
                        "route_names": parse_json_list(str(row.get("route_names_json") or "[]")),
                        "channels": parse_json_list(str(row.get("channels_json") or "[]")),
                        "metadata": parse_json_object(str(row.get("metadata_json") or "{}")),
                    },
                )
            )

        change_correlation = self.correlate_incident_changes(incident, hours=bounded_hours, limit=20)
        for row in change_correlation.get("related_changes", []):
            entries.append(
                timeline_entry(
                    "change_event",
                    row.get("created_at"),
                    str(row.get("title") or "Change event"),
                    str(row.get("summary") or row.get("change_type") or ""),
                    status=str(row.get("status") or ""),
                    severity=str(row.get("risk") or ""),
                    source=str(row.get("source") or ""),
                    source_id=f"change_event:{row.get('id')}",
                    payload=row,
                    extra={
                        "correlation_score": row.get("correlation_score"),
                        "correlation_reasons": row.get("correlation_reasons") or [],
                    },
                )
            )

        entries = [entry for entry in entries if entry.get("occurred_at")]
        entries.sort(key=lambda entry: (str(entry.get("occurred_at") or ""), timeline_kind_rank(str(entry.get("kind") or "")), str(entry.get("source_id") or "")))
        limited_entries = entries[:bounded_limit]
        return {
            "incident_id": incident_id,
            "window": {
                "hours": bounded_hours,
                "since": since_iso,
                "anchor": occurred_at.isoformat(),
            },
            "targets": [{"source": source, "name": name} for source, name in sorted(targets)],
            "summary": timeline_summary(limited_entries),
            "change_correlation": change_correlation,
            "entries": limited_entries,
        }

    def generate_incident_review(
        self,
        incident_id: int,
        generated_by: str = "ops-agent",
        hours: int = 24,
    ) -> dict | None:
        incident = self.get_incident(incident_id)
        if not incident:
            return None
        timeline = self.incident_timeline(incident_id, hours=hours, limit=500) or {}
        review = build_incident_review_payload(
            incident=incident,
            timeline=timeline,
            diagnoses=self.latest_incident_diagnoses(incident_id, limit=20),
            recommendations=self.latest_incident_recommendations(incident_id, limit=100),
            actions=self.latest_action_logs(100, incident_id=incident_id),
            notifications=self.latest_notification_logs(100, incident_id=incident_id),
        )
        return self.save_incident_review(incident_id, generated_by, review)

    def save_incident_review(self, incident_id: int, generated_by: str, review: dict) -> dict:
        now = utc_now_iso()
        payload = safe_dict(review)
        with self.lock:
            cursor = self.connection.execute(
                """
                insert into incident_reviews (
                    incident_id, created_at, generated_by, status, severity, title, summary,
                    root_causes_json, actions_json, related_changes_json, prevention_items_json,
                    timeline_summary_json, payload_json
                )
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident_id,
                    now,
                    str(generated_by or "ops-agent"),
                    str(payload.get("status") or ""),
                    str(payload.get("severity") or ""),
                    str(payload.get("title") or ""),
                    str(payload.get("summary") or ""),
                    json.dumps(safe_list(payload.get("root_causes")), ensure_ascii=False),
                    json.dumps(safe_list(payload.get("actions")), ensure_ascii=False),
                    json.dumps(safe_list(payload.get("related_changes")), ensure_ascii=False),
                    json.dumps(safe_list(payload.get("prevention_items")), ensure_ascii=False),
                    json.dumps(safe_dict(payload.get("timeline_summary")), ensure_ascii=False),
                    json.dumps(payload, ensure_ascii=False),
                ),
            )
            self.connection.commit()
            row = self.connection.execute(
                "select * from incident_reviews where id = ?",
                (int(cursor.lastrowid),),
            ).fetchone()
        return incident_review_payload(row)

    def latest_incident_reviews(self, incident_id: int, limit: int = 10) -> list[dict]:
        with self.lock:
            rows = self.connection.execute(
                """
                select * from incident_reviews
                where incident_id = ?
                order by id desc
                limit ?
                """,
                (incident_id, min(max(int(limit or 10), 1), 100)),
            ).fetchall()
        return [incident_review_payload(row) for row in rows]

    def save_change_event(self, event: dict) -> dict:
        payload = normalize_change_event(event)
        now = utc_now_iso()
        created_at = payload["created_at"] or now
        with self.lock:
            cursor = self.connection.execute(
                """
                insert into change_events (
                    created_at, updated_at, environment, run_type, project_id, source,
                    change_type, title, summary, actor, status, risk, commit_sha, branch,
                    version, related_incident_id, related_ai_repair_id, links_json, metadata_json
                )
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    created_at,
                    now,
                    payload["environment"],
                    payload["run_type"],
                    payload["project_id"],
                    payload["source"],
                    payload["change_type"],
                    payload["title"],
                    payload["summary"],
                    payload["actor"],
                    payload["status"],
                    payload["risk"],
                    payload["commit_sha"],
                    payload["branch"],
                    payload["version"],
                    payload["related_incident_id"],
                    payload["related_ai_repair_id"],
                    json.dumps(payload["links"], ensure_ascii=False),
                    json.dumps(payload["metadata"], ensure_ascii=False),
                ),
            )
            self.connection.commit()
            row = self.connection.execute(
                "select * from change_events where id = ?",
                (int(cursor.lastrowid),),
            ).fetchone()
        return change_event_payload(row)

    def latest_change_events(
        self,
        limit: int = 50,
        environment: str = "",
        run_type: str = "",
        project_id: str = "",
        change_type: str = "",
        source: str = "",
        status: str = "",
        risk: str = "",
        related_incident_id: int | None = None,
        related_ai_repair_id: int | None = None,
    ) -> list[dict]:
        with self.lock:
            where, params = context_where(environment, run_type)
            if project_id:
                where.append("project_id = ?")
                params.append(project_id)
            if change_type:
                where.append("change_type = ?")
                params.append(change_type)
            if source:
                where.append("source = ?")
                params.append(source)
            if status:
                where.append("status = ?")
                params.append(status)
            if risk:
                where.append("risk = ?")
                params.append(risk)
            if related_incident_id is not None:
                where.append("related_incident_id = ?")
                params.append(related_incident_id)
            if related_ai_repair_id is not None:
                where.append("related_ai_repair_id = ?")
                params.append(related_ai_repair_id)
            where_sql = f"where {' and '.join(where)}" if where else ""
            rows = self.connection.execute(
                f"""
                select * from change_events
                {where_sql}
                order by created_at desc, id desc
                limit ?
                """,
                (*params, limit),
            ).fetchall()
        return [change_event_payload(row) for row in rows]

    def recent_change_events_for_context(
        self,
        since_iso: str,
        environment: str = "",
        run_type: str = "",
        project_id: str = "",
        limit: int = 20,
    ) -> list[dict]:
        with self.lock:
            where, params = context_where(environment, run_type)
            if since_iso:
                where.append("created_at >= ?")
                params.append(since_iso)
            if project_id:
                where.append("(project_id = ? or project_id = '')")
                params.append(project_id)
            where_sql = f"where {' and '.join(where)}" if where else ""
            rows = self.connection.execute(
                f"""
                select * from change_events
                {where_sql}
                order by created_at desc, id desc
                limit ?
                """,
                (*params, limit),
            ).fetchall()
        return [change_event_payload(row) for row in rows]

    def correlate_incident_changes(self, incident: dict, hours: int = 24, limit: int = 10) -> dict:
        incident_id = safe_int(incident.get("id"))
        environment = str(incident.get("environment") or "prod")
        run_type = str(incident.get("run_type") or "normal")
        occurred_at = (
            parse_iso_datetime(incident.get("last_seen_at"))
            or parse_iso_datetime(incident.get("updated_at"))
            or parse_iso_datetime(incident.get("created_at"))
            or datetime.now(timezone.utc)
        )
        since = occurred_at - timedelta(hours=max(1, int(hours or 24)))
        incident_text = incident_correlation_text(incident)
        rows = self.recent_change_events_for_context(
            since.isoformat(),
            environment=environment,
            run_type=run_type,
            limit=max(limit * 4, 20),
        )
        scored = []
        for row in rows:
            score, reasons = score_change_event_for_incident(row, incident, incident_text, occurred_at)
            correlated = score >= 0.45 or safe_int(row.get("related_incident_id")) == incident_id
            enriched = dict(row)
            enriched["correlation_score"] = round(score, 3)
            enriched["correlation_reasons"] = reasons
            enriched["correlated"] = correlated
            if correlated:
                scored.append(enriched)
        scored.sort(
            key=lambda item: (safe_float(item.get("correlation_score")), str(item.get("created_at") or "")),
            reverse=True,
        )
        return {
            "incident_id": incident_id,
            "window_hours": max(1, int(hours or 24)),
            "since": since.isoformat(),
            "environment": environment,
            "run_type": run_type,
            "related_count": len(scored),
            "related_changes": scored[:limit],
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

    def save_ai_repair_proposal(self, incident_id: int, proposal: dict) -> dict:
        if not self.get_incident(incident_id):
            raise ValueError(f"incident not found: #{incident_id}")
        payload = normalize_ai_repair_proposal(proposal)
        now = utc_now_iso()
        with self.lock:
            cursor = self.connection.execute(
                """
                insert into ai_repair_proposals (
                    incident_id, created_at, updated_at, status, title, summary, risk,
                    root_cause, model_provider, model_name, prompt_json, proposal_json,
                    patch_json, test_plan_json, dry_run_json, test_result_json
                )
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident_id,
                    now,
                    now,
                    "proposed",
                    payload["title"],
                    payload["summary"],
                    payload["risk"],
                    payload["root_cause"],
                    payload["model_provider"],
                    payload["model_name"],
                    json.dumps(payload["prompt"], ensure_ascii=False),
                    json.dumps(payload["proposal"], ensure_ascii=False),
                    json.dumps(payload["patch"], ensure_ascii=False),
                    json.dumps(payload["test_plan"], ensure_ascii=False),
                    "{}",
                    "{}",
                ),
            )
            self.connection.commit()
            row = self.connection.execute(
                "select * from ai_repair_proposals where id = ?",
                (int(cursor.lastrowid),),
            ).fetchone()
        return ai_repair_proposal_payload(row)

    def latest_ai_repair_proposals(
        self,
        limit: int = 50,
        statuses: Sequence[str] | None = None,
        incident_id: int | None = None,
        risk: str = "",
        model_provider: str = "",
    ) -> list[dict]:
        with self.lock:
            where: list[str] = []
            params: list[object] = []
            cleaned_statuses = [status for status in (statuses or []) if status]
            if cleaned_statuses:
                where.append(f"status in ({','.join('?' for _ in cleaned_statuses)})")
                params.extend(cleaned_statuses)
            if incident_id:
                where.append("incident_id = ?")
                params.append(incident_id)
            if risk:
                where.append("risk = ?")
                params.append(risk)
            if model_provider:
                where.append("model_provider = ?")
                params.append(model_provider)
            where_sql = f"where {' and '.join(where)}" if where else ""
            rows = self.connection.execute(
                f"""
                select * from ai_repair_proposals
                {where_sql}
                order by
                    case status
                        when 'proposed' then 0
                        when 'dry_run_failed' then 1
                        when 'dry_run_passed' then 2
                        when 'test_failed' then 3
                        when 'test_not_run' then 4
                        when 'test_passed' then 5
                        when 'approved' then 6
                        when 'branch_failed' then 7
                        when 'branch_prepared' then 8
                        when 'pr_failed' then 9
                        when 'pr_created' then 10
                        when 'merge_pending' then 11
                        when 'deploy_failed' then 12
                        when 'rollback_failed' then 13
                        when 'rollback_succeeded' then 14
                        when 'deployed' then 15
                        when 'rejected' then 16
                        else 17
                    end,
                    updated_at desc,
                    id desc
                limit ?
                """,
                (*params, limit),
            ).fetchall()
        return [ai_repair_proposal_payload(row) for row in rows]

    def get_ai_repair_proposal(self, repair_id: int) -> dict | None:
        with self.lock:
            row = self.connection.execute(
                """
                select * from ai_repair_proposals
                where id = ?
                """,
                (repair_id,),
            ).fetchone()
        return ai_repair_proposal_payload(row) if row else None

    def update_ai_repair_proposal_status(
        self,
        repair_id: int,
        status: str,
        actor: str = "",
        note: str = "",
        dry_run: dict | None = None,
        test_result: dict | None = None,
    ) -> dict:
        allowed_statuses = {
            "proposed",
            "dry_run_passed",
            "dry_run_failed",
            "test_passed",
            "test_failed",
            "test_not_run",
            "approved",
            "branch_failed",
            "branch_prepared",
            "pr_failed",
            "pr_created",
            "merge_pending",
            "deploy_failed",
            "rollback_failed",
            "rollback_succeeded",
            "deployed",
            "rejected",
        }
        normalized_status = (status or "").strip().lower()
        if normalized_status not in allowed_statuses:
            raise ValueError(f"unsupported AI repair proposal status: {status}")
        now = utc_now_iso()
        actor_value = actor.strip()
        note_value = note.strip()
        with self.lock:
            row = self.connection.execute(
                "select * from ai_repair_proposals where id = ?",
                (repair_id,),
            ).fetchone()
            if not row:
                raise ValueError(f"AI repair proposal not found: #{repair_id}")
            current_status = str(row["status"] or "proposed")
            if current_status == "rejected" and normalized_status != "rejected":
                raise ValueError(f"AI repair proposal already rejected: #{repair_id}")
            dry_run_payload = safe_dict(dry_run) or parse_json_object(str(row["dry_run_json"] or "{}"))
            test_payload = safe_dict(test_result) or parse_json_object(str(row["test_result_json"] or "{}"))
            self.connection.execute(
                """
                update ai_repair_proposals
                set updated_at = ?,
                    status = ?,
                    dry_run_json = ?,
                    test_result_json = ?,
                    decision_by = coalesce(nullif(?, ''), decision_by),
                    decision_at = coalesce(?, decision_at),
                    decision_note = coalesce(nullif(?, ''), decision_note)
                where id = ?
                """,
                (
                    now,
                    normalized_status,
                    json.dumps(dry_run_payload, ensure_ascii=False),
                    json.dumps(test_payload, ensure_ascii=False),
                    actor_value,
                    now if actor_value or note_value or normalized_status in {"approved", "rejected"} else None,
                    note_value,
                    repair_id,
                ),
            )
            self.connection.commit()
            updated = self.connection.execute(
                "select * from ai_repair_proposals where id = ?",
                (repair_id,),
            ).fetchone()
        return ai_repair_proposal_payload(updated)

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

    def save_incident_diagnosis(self, incident_id: int, diagnosis: dict) -> int:
        context = safe_dict(diagnosis.get("context"))
        causes = safe_list(diagnosis.get("probable_causes"))
        top = safe_dict(causes[0]) if causes else {}
        next_decision = safe_dict(diagnosis.get("next_decision"))
        evidence = safe_dict(diagnosis.get("evidence"))
        created_at = utc_now_iso()
        with self.lock:
            cursor = self.connection.execute(
                """
                insert into incident_diagnoses (
                    incident_id, created_at, environment, run_type, trace_id,
                    top_category, top_confidence, next_decision, evidence_json, payload_json
                )
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident_id,
                    created_at,
                    str(context.get("environment") or "prod"),
                    str(context.get("run_type") or "normal"),
                    str(context.get("trace_id") or ""),
                    str(top.get("category") or ""),
                    safe_float(top.get("confidence")),
                    str(next_decision.get("action") or ""),
                    json.dumps(evidence, ensure_ascii=False),
                    json.dumps(diagnosis, ensure_ascii=False),
                ),
            )
            self.connection.commit()
            return int(cursor.lastrowid)

    def latest_incident_diagnoses(self, incident_id: int, limit: int = 10) -> list[dict]:
        with self.lock:
            rows = self.connection.execute(
                """
                select * from incident_diagnoses
                where incident_id = ?
                order by id desc
                limit ?
                """,
                (incident_id, limit),
            ).fetchall()
        return [diagnosis_record_payload(row) for row in rows]

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
        approval_expires_at: str = "",
    ) -> int:
        with self.lock:
            cursor = self.connection.execute(
                """
                insert into action_logs (
                    incident_id, created_at, environment, run_type, trace_id,
                    action_type, title, risk, status, reason, params_json, output, error,
                    approval_expires_at
                )
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    approval_expires_at or None,
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

    def expire_action_log(self, action_id: int, actor: str = "operator", note: str = "") -> dict:
        now = utc_now_iso()
        actor_value = actor.strip() or "operator"
        note_value = note.strip() or "approval expired"
        with self.lock:
            self.connection.execute(
                """
                update action_logs
                set updated_at = ?,
                    status = 'skipped',
                    error = ?,
                    decision = 'expired',
                    decision_by = ?,
                    decision_at = ?,
                    decision_note = ?
                where id = ?
                """,
                (now, note_value, actor_value, now, note_value, action_id),
            )
            self.connection.commit()
            row = self.connection.execute(
                "select * from action_logs where id = ?",
                (action_id,),
            ).fetchone()
        return dict(row) if row else {}

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
        stored_dedupe_key = bounded_dedupe_key(dedupe_key)
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
                    stored_dedupe_key,
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

    def recent_results(self, since_iso: str, environment: str = "", run_type: str = "") -> list[dict]:
        with self.lock:
            where, params = context_where(environment, run_type)
            where.append("created_at >= ?")
            params.append(since_iso)
            rows = self.connection.execute(
                f"""
                select * from check_results
                where {' and '.join(where)}
                order by id asc
                """,
                params,
            ).fetchall()
        return [dict(row) for row in rows]

    def start_backup_run(
        self,
        target_id: str,
        engine: str,
        kind: str = "backup",
        metadata: dict | None = None,
    ) -> int:
        with self.lock:
            cursor = self.connection.execute(
                """
                insert into backup_runs (
                    target_id, engine, kind, status, started_at, metadata_json
                )
                values (?, ?, ?, 'running', ?, ?)
                """,
                (
                    target_id,
                    engine,
                    kind,
                    utc_now_iso(),
                    json.dumps(metadata or {}, ensure_ascii=False),
                ),
            )
            self.connection.commit()
            return int(cursor.lastrowid)

    def upsert_fleet_node(self, node: dict) -> dict:
        node_id = str(node.get("node_id") or "").strip()
        if not node_id:
            raise ValueError("node_id is required")
        now = utc_now_iso()
        with self.lock:
            existing = self.connection.execute(
                "select node_id, created_at, enabled from fleet_nodes where node_id = ?",
                (node_id,),
            ).fetchone()
            values = (
                str(node.get("last_seen_at") or now),
                str(node.get("name") or node_id),
                str(node.get("hostname") or node_id),
                str(node.get("address") or ""),
                str(node.get("agent_version") or ""),
                str(node.get("platform") or ""),
                json.dumps(node.get("labels") or {}, ensure_ascii=False),
                json.dumps(node.get("capabilities") or [], ensure_ascii=False),
                json.dumps(node.get("metrics") or {}, ensure_ascii=False),
                json.dumps(node.get("projects") or [], ensure_ascii=False),
                json.dumps(node.get("assets") or [], ensure_ascii=False),
                json.dumps(node.get("discovery") or {}, ensure_ascii=False),
            )
            if existing:
                self.connection.execute(
                    """
                    update fleet_nodes
                    set updated_at = ?, last_seen_at = ?, name = ?, hostname = ?, address = ?,
                        agent_version = ?, platform = ?, labels_json = ?, capabilities_json = ?,
                        metrics_json = ?, projects_json = ?, assets_json = ?, discovery_json = ?
                    where node_id = ?
                    """,
                    (now, *values, node_id),
                )
            else:
                self.connection.execute(
                    """
                    insert into fleet_nodes (
                        node_id, created_at, updated_at, last_seen_at, name, hostname, address,
                        agent_version, platform, enabled, labels_json, capabilities_json,
                        metrics_json, projects_json, assets_json, discovery_json
                    ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (node_id, now, now, *values[:6], 1, *values[6:]),
                )
            self.connection.commit()
        return self.get_fleet_node(node_id) or {}

    def get_fleet_node(self, node_id: str) -> dict | None:
        with self.lock:
            row = self.connection.execute(
                "select * from fleet_nodes where node_id = ?",
                (node_id,),
            ).fetchone()
        return decode_fleet_node(row) if row else None

    def list_fleet_nodes(self) -> list[dict]:
        with self.lock:
            rows = self.connection.execute(
                "select * from fleet_nodes order by name, node_id"
            ).fetchall()
        return [decode_fleet_node(row) for row in rows]

    def set_fleet_node_enabled(self, node_id: str, enabled: bool) -> dict:
        with self.lock:
            cursor = self.connection.execute(
                "update fleet_nodes set enabled = ?, updated_at = ? where node_id = ?",
                (1 if enabled else 0, utc_now_iso(), node_id),
            )
            if int(cursor.rowcount or 0) <= 0:
                self.connection.rollback()
                raise ValueError(f"fleet node not found: {node_id}")
            self.connection.commit()
        return self.get_fleet_node(node_id) or {}

    def finish_backup_run(
        self,
        run_id: int,
        status: str,
        path: str = "",
        size_bytes: int = 0,
        checksum: str = "",
        error: str = "",
        metadata: dict | None = None,
    ) -> dict:
        with self.lock:
            self.connection.execute(
                """
                update backup_runs
                set status = ?, completed_at = ?, path = ?, size_bytes = ?,
                    checksum = ?, error = ?, metadata_json = ?
                where id = ?
                """,
                (
                    status,
                    utc_now_iso(),
                    path,
                    max(0, int(size_bytes or 0)),
                    checksum,
                    error,
                    json.dumps(metadata or {}, ensure_ascii=False),
                    run_id,
                ),
            )
            self.connection.commit()
            row = self.connection.execute("select * from backup_runs where id = ?", (run_id,)).fetchone()
        if not row:
            raise ValueError(f"backup run not found: {run_id}")
        return backup_run_payload(row)

    def latest_backup_runs(
        self,
        limit: int = 50,
        target_id: str = "",
        kind: str = "",
        status: str = "",
    ) -> list[dict]:
        with self.lock:
            where: list[str] = []
            params: list[object] = []
            for column, value in (("target_id", target_id), ("kind", kind), ("status", status)):
                if value:
                    where.append(f"{column} = ?")
                    params.append(value)
            where_sql = f"where {' and '.join(where)}" if where else ""
            rows = self.connection.execute(
                f"""
                select * from backup_runs
                {where_sql}
                order by id desc
                limit ?
                """,
                (*params, max(1, min(int(limit or 50), 500))),
            ).fetchall()
        return [backup_run_payload(row) for row in rows]

    def latest_successful_backup_run(self, target_id: str, kind: str = "backup") -> dict | None:
        rows = self.latest_backup_runs(1, target_id=target_id, kind=kind, status="success")
        return rows[0] if rows else None

    def recent_results_for_targets(
        self,
        since_iso: str,
        environment: str,
        run_type: str,
        targets: set[tuple[str, str]],
        limit: int = 200,
    ) -> list[dict]:
        if not targets:
            return []
        with self.lock:
            where, params = context_where(environment, run_type)
            where.append("created_at >= ?")
            params.append(since_iso)
            target_clauses = []
            for source, name in sorted(targets):
                target_clauses.append("(source = ? and name = ?)")
                params.extend([source, name])
            where.append(f"({' or '.join(target_clauses)})")
            rows = self.connection.execute(
                f"""
                select * from check_results
                where {' and '.join(where)}
                order by created_at asc, id asc
                limit ?
                """,
                (*params, min(max(int(limit or 200), 1), 1000)),
            ).fetchall()
        return [dict(row) for row in rows]

    def recent_incidents(
        self,
        since_iso: str,
        limit: int = 100,
        environment: str = "",
        run_type: str = "",
    ) -> list[dict]:
        with self.lock:
            where, params = context_where(environment, run_type)
            where.append("created_at >= ?")
            params.append(since_iso)
            rows = self.connection.execute(
                f"""
                select * from incidents
                where {' and '.join(where)}
                order by id desc
                limit ?
                """,
                (*params, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def dashboard_summary(self, hours: int = 24, environment: str = "", run_type: str = "") -> dict:
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        with self.lock:
            where, params = context_where(environment, run_type)
            where.append("created_at >= ?")
            params.append(since.isoformat())
            result_where = " and ".join(where)
            status_rows = self.connection.execute(
                f"select status, count(*) as total from check_results where {result_where} group by status",
                params,
            ).fetchall()
            source_rows = self.connection.execute(
                f"select source, count(*) as total from check_results where {result_where} group by source",
                params,
            ).fetchall()
            latest_rows = self.connection.execute(
                f"""
                select current.* from check_results current
                inner join (
                    select max(id) as id from check_results
                    where {result_where}
                    group by environment, run_type, source, name
                ) latest on latest.id = current.id
                order by current.id asc
                """,
                params,
            ).fetchall()

            incident_where, incident_params = context_where(environment, run_type)
            incident_where.append("created_at >= ?")
            incident_params.append(since.isoformat())
            incident_counts = self.connection.execute(
                f"""
                select count(*) as total,
                    sum(case when status not in ('resolved', 'closed') then 1 else 0 end) as open_total
                from incidents
                where {' and '.join(incident_where)}
                """,
                incident_params,
            ).fetchone() or {}

        counts = {"ok": 0, "warning": 0, "critical": 0}
        for raw_row in status_rows:
            row = dict(raw_row)
            status = str(row.get("status") or "")
            if status in counts:
                counts[status] = int(row.get("total") or 0)
        latest = [dict(row) for row in latest_rows]
        incident_count_values = dict(incident_counts)
        problem_targets = [row for row in latest if row.get("status") in {"warning", "critical"}]
        total = sum(counts.values())
        return {
            "hours": hours,
            "total_checks": total,
            "ok": counts["ok"],
            "warning": counts["warning"],
            "critical": counts["critical"],
            "ok_rate": round((counts["ok"] / total) * 100, 1) if total else 100.0,
            "current_status": "critical" if any(row.get("status") == "critical" for row in latest) else (
                "warning" if problem_targets else "ok"
            ),
            "active_problem_count": len(problem_targets),
            "incident_count": int(incident_count_values.get("total") or 0),
            "open_incident_count": int(incident_count_values.get("open_total") or 0),
            "source_counts": {
                str(dict(row).get("source") or "unknown"): int(dict(row).get("total") or 0)
                for row in source_rows
            },
            "latest_targets": latest,
        }

    def context_summaries(self, hours: int = 24) -> list[dict]:
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        rows = self.recent_results(since.isoformat())
        incidents = self.recent_incidents(since.isoformat(), limit=5000)
        keys = sorted(
            {
                (str(row.get("environment") or "prod"), str(row.get("run_type") or "normal"))
                for row in [*rows, *incidents]
            }
        )
        summaries: list[dict] = []
        for environment, run_type in keys:
            context_rows = [
                row
                for row in rows
                if str(row.get("environment") or "prod") == environment
                and str(row.get("run_type") or "normal") == run_type
            ]
            context_incidents = [
                row
                for row in incidents
                if str(row.get("environment") or "prod") == environment
                and str(row.get("run_type") or "normal") == run_type
            ]
            summary = dashboard_summary_from_rows(hours, context_rows, context_incidents)
            summary["environment"] = environment
            summary["run_type"] = run_type
            summaries.append(summary)
        return summaries


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

    def ops_metrics(self, hours: int = 24) -> dict:
        bounded_hours = min(max(int(hours), 1), 24 * 365)
        generated_at = datetime.now(timezone.utc)
        since = generated_at - timedelta(hours=bounded_hours)
        since_iso = since.isoformat()
        results = self.recent_results(since_iso)
        incidents = self.recent_incidents(since_iso, limit=5000)
        with self.lock:
            action_rows = self.connection.execute(
                """
                select * from action_logs
                where created_at >= ?
                order by id desc
                limit 5000
                """,
                (since_iso,),
            ).fetchall()
            notification_rows = self.connection.execute(
                """
                select * from notification_logs
                where created_at >= ?
                order by id desc
                limit 5000
                """,
                (since_iso,),
            ).fetchall()

        actions = [dict(row) for row in action_rows]
        notifications = [dict(row) for row in notification_rows]
        readiness_blockers = readiness_blocker_counts(actions, [])
        check_status_counts = count_by_key(results, "status")
        incident_status_counts = count_by_key(incidents, "status")
        action_status_counts = count_by_key(actions, "status")
        notification_status_counts = count_by_key(notifications, "status")
        mttr_samples = [
            seconds_between(row.get("created_at"), row.get("resolved_at") or row.get("closed_at"))
            for row in incidents
            if row.get("resolved_at") or row.get("closed_at")
        ]
        mttr_samples = [value for value in mttr_samples if value >= 0]
        total_checks = len(results)
        ok_checks = int(check_status_counts.get("ok", 0))
        problem_checks = int(check_status_counts.get("warning", 0)) + int(check_status_counts.get("critical", 0))
        total_actions = len(actions)
        successful_actions = sum(
            int(action_status_counts.get(status, 0))
            for status in ("executed", "verified_ok", "dry_run")
        )
        return {
            "generated_at": generated_at.isoformat(),
            "window": {
                "hours": bounded_hours,
                "since": since_iso,
                "until": generated_at.isoformat(),
            },
            "availability": {
                "total_checks": total_checks,
                "ok_checks": ok_checks,
                "warning_checks": int(check_status_counts.get("warning", 0)),
                "critical_checks": int(check_status_counts.get("critical", 0)),
                "problem_checks": problem_checks,
                "ok_rate": round((ok_checks / total_checks) * 100, 2) if total_checks else 100.0,
                "by_status": check_status_counts,
                "by_source": count_by_key(results, "source"),
            },
            "incidents": {
                "total": len(incidents),
                "open": sum(1 for row in incidents if row.get("status") not in {"resolved", "closed"}),
                "resolved": int(incident_status_counts.get("resolved", 0)),
                "closed": int(incident_status_counts.get("closed", 0)),
                "critical": sum(1 for row in incidents if row.get("severity") == "critical"),
                "warning": sum(1 for row in incidents if row.get("severity") == "warning"),
                "false_positive": sum(1 for row in incidents if int(row.get("false_positive") or 0) == 1),
                "by_status": incident_status_counts,
                "by_severity": count_by_key(incidents, "severity"),
                "by_category": count_by_key(incidents, "classification_category", default="unclassified"),
                "mttr_seconds": {
                    "avg": round(sum(mttr_samples) / len(mttr_samples), 2) if mttr_samples else 0.0,
                    "samples": len(mttr_samples),
                },
            },
            "actions": {
                "total": total_actions,
                "success_rate": round((successful_actions / total_actions) * 100, 2) if total_actions else 100.0,
                "pending_approval": int(action_status_counts.get("pending_approval", 0)),
                "expired": sum(1 for row in actions if row.get("decision") == "expired"),
                "by_status": action_status_counts,
                "by_type": count_by_key(actions, "action_type"),
                "by_risk": count_by_key(actions, "risk"),
                "verification": count_by_key(actions, "verify_status", default="not_verified"),
                "readiness_blocked": sum(1 for row in actions if action_was_readiness_blocked(row)),
                "readiness_blockers": readiness_blockers,
            },
            "notifications": {
                "total": len(notifications),
                "suppressed": sum(1 for row in notifications if row.get("suppressed_reason")),
                "failed": sum(1 for row in notifications if row.get("error")),
                "by_status": notification_status_counts,
                "by_severity": count_by_key(notifications, "severity"),
            },
            "latest": {
                "incidents": incidents[:10],
                "actions": actions[:10],
                "notifications": notifications[:10],
            },
        }

    def remediation_audit(self, hours: int = 24, limit: int = 50) -> dict:
        bounded_hours = min(max(int(hours), 1), 24 * 365)
        bounded_limit = min(max(int(limit), 1), 500)
        generated_at = datetime.now(timezone.utc)
        since = generated_at - timedelta(hours=bounded_hours)
        since_iso = since.isoformat()
        with self.lock:
            action_rows = self.connection.execute(
                """
                select * from action_logs
                where created_at >= ?
                order by id desc
                limit 5000
                """,
                (since_iso,),
            ).fetchall()
            recommendation_rows = self.connection.execute(
                """
                select * from incident_recommendations
                where coalesce(updated_at, created_at) >= ?
                order by coalesce(updated_at, created_at) desc, id desc
                limit 5000
                """,
                (since_iso,),
            ).fetchall()

        actions = [action_log_payload(row) for row in action_rows]
        recommendations = [recommendation_payload(row) for row in recommendation_rows]
        action_status_counts = count_by_key(actions, "status")
        recommendation_status_counts = count_by_key(recommendations, "status")
        readiness_blocked_actions = [row for row in actions if action_was_readiness_blocked(row)]
        readiness_blocked_recommendations = [
            row for row in recommendations if recommendation_was_readiness_blocked(row)
        ]
        readiness_blockers = readiness_blocker_counts(actions, recommendations)
        mutating_actions = [row for row in actions if is_mutating_action(str(row.get("action_type") or ""))]
        verified_actions = [row for row in actions if row.get("verify_status")]
        failed_or_blocked_actions = [
            row
            for row in actions
            if row.get("status") in {"failed", "verified_failed"}
            or action_was_readiness_blocked(row)
        ]

        return {
            "generated_at": generated_at.isoformat(),
            "window": {
                "hours": bounded_hours,
                "since": since_iso,
                "until": generated_at.isoformat(),
            },
            "actions": {
                "total": len(actions),
                "mutating": len(mutating_actions),
                "read_only": len(actions) - len(mutating_actions),
                "pending_approval": int(action_status_counts.get("pending_approval", 0)),
                "approved": sum(1 for row in actions if row.get("decision") == "approved"),
                "rejected": sum(1 for row in actions if row.get("decision") == "rejected"),
                "expired": sum(1 for row in actions if row.get("decision") == "expired"),
                "executed": int(action_status_counts.get("executed", 0)),
                "failed": int(action_status_counts.get("failed", 0)),
                "verified_ok": int(action_status_counts.get("verified_ok", 0)),
                "verified_failed": int(action_status_counts.get("verified_failed", 0)),
                "skipped": int(action_status_counts.get("skipped", 0)),
                "readiness_blocked": len(readiness_blocked_actions),
                "by_status": action_status_counts,
                "by_type": count_by_key(actions, "action_type"),
                "by_risk": count_by_key(actions, "risk"),
                "verification": count_by_key(actions, "verify_status", default="not_verified"),
            },
            "recommendations": {
                "total": len(recommendations),
                "approval_required": sum(1 for row in recommendations if row.get("approval_required")),
                "auto_execute": sum(1 for row in recommendations if row.get("auto_execute")),
                "verification_required": sum(1 for row in recommendations if row.get("verification_required")),
                "readiness_blocked": len(readiness_blocked_recommendations),
                "by_status": recommendation_status_counts,
                "by_risk": count_by_key(recommendations, "risk"),
                "by_type": count_by_key(recommendations, "action_type"),
                "by_source": count_by_key(recommendations, "source"),
            },
            "readiness": {
                "blocked_actions": len(readiness_blocked_actions),
                "blocked_recommendations": len(readiness_blocked_recommendations),
                "by_blocker": readiness_blockers,
                "recent_blocks": [
                    *[
                        readiness_action_block_payload(row)
                        for row in readiness_blocked_actions[:bounded_limit]
                    ],
                    *[
                        readiness_recommendation_block_payload(row)
                        for row in readiness_blocked_recommendations[:bounded_limit]
                    ],
                ][:bounded_limit],
            },
            "latest": {
                "actions": actions[:bounded_limit],
                "recommendations": recommendations[:bounded_limit],
                "failed_or_blocked_actions": failed_or_blocked_actions[:bounded_limit],
                "verified_actions": verified_actions[:bounded_limit],
            },
        }

    def close(self) -> None:
        with self.lock:
            self.connection.close()


def dashboard_summary_from_rows(hours: int, rows: list[dict], incidents: list[dict]) -> dict:
    latest: dict[str, dict] = {}
    counts = {"ok": 0, "warning": 0, "critical": 0}
    source_counts: dict[str, int] = {}

    for row in rows:
        status = str(row.get("status", ""))
        if status in counts:
            counts[status] += 1
        source = str(row.get("source", "unknown"))
        source_counts[source] = source_counts.get(source, 0) + 1
        latest[f"{row.get('environment')}/{row.get('run_type')}/{row.get('source')}/{row.get('name')}"] = row

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


def context_where(environment: str = "", run_type: str = "") -> tuple[list[str], list[object]]:
    where: list[str] = []
    params: list[object] = []
    if environment:
        where.append("environment = ?")
        params.append(environment)
    if run_type:
        where.append("run_type = ?")
        params.append(run_type)
    return where, params


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


def action_log_payload(row: sqlite3.Row) -> dict:
    payload = dict(row)
    payload["params"] = parse_json_object(str(payload.get("params_json") or "{}"))
    return payload


def diagnosis_record_payload(row: sqlite3.Row) -> dict:
    payload = dict(row)
    payload["evidence"] = parse_json_object(str(payload.get("evidence_json") or "{}"))
    payload["payload"] = parse_json_object(str(payload.get("payload_json") or "{}"))
    return payload


def incident_review_payload(row: sqlite3.Row) -> dict:
    payload = dict(row)
    payload["root_causes"] = parse_json_list(str(payload.get("root_causes_json") or "[]"))
    payload["actions"] = parse_json_list(str(payload.get("actions_json") or "[]"))
    payload["related_changes"] = parse_json_list(str(payload.get("related_changes_json") or "[]"))
    payload["prevention_items"] = parse_json_list(str(payload.get("prevention_items_json") or "[]"))
    payload["timeline_summary"] = parse_json_object(str(payload.get("timeline_summary_json") or "{}"))
    payload["payload"] = parse_json_object(str(payload.get("payload_json") or "{}"))
    return payload


def bounded_dedupe_key(value: object, max_length: int = 255) -> str:
    key = str(value or "default")
    if len(key) <= max_length:
        return key
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    suffix = f"|sha256:{digest}"
    return key[: max_length - len(suffix)] + suffix


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


def ai_repair_proposal_payload(row: sqlite3.Row) -> dict:
    payload = dict(row)
    payload["prompt"] = parse_json_object(str(payload.get("prompt_json") or "{}"))
    payload["proposal"] = parse_json_object(str(payload.get("proposal_json") or "{}"))
    payload["patch"] = parse_json_object(str(payload.get("patch_json") or "{}"))
    payload["test_plan"] = parse_json_object(str(payload.get("test_plan_json") or "{}"))
    payload["dry_run"] = parse_json_object(str(payload.get("dry_run_json") or "{}"))
    payload["test_result"] = parse_json_object(str(payload.get("test_result_json") or "{}"))
    return payload


def change_event_payload(row: sqlite3.Row) -> dict:
    payload = dict(row)
    payload["links"] = parse_json_list(str(payload.get("links_json") or "[]"))
    payload["metadata"] = parse_json_object(str(payload.get("metadata_json") or "{}"))
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
        "dedupe_key": bounded_dedupe_key(payload.get("dedupe_key") or ""),
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


def normalize_ai_repair_proposal(value: dict | None) -> dict:
    payload = safe_dict(value)
    risk = str(payload.get("risk") or "medium").strip().lower()
    if risk not in {"low", "medium", "high", "critical"}:
        risk = "medium"
    return {
        "title": str(payload.get("title") or "AI repair proposal"),
        "summary": str(payload.get("summary") or ""),
        "risk": risk,
        "root_cause": str(payload.get("root_cause") or ""),
        "model_provider": str(payload.get("model_provider") or "rules"),
        "model_name": str(payload.get("model_name") or ""),
        "prompt": safe_dict(payload.get("prompt")),
        "proposal": safe_dict(payload.get("proposal")),
        "patch": safe_dict(payload.get("patch")),
        "test_plan": safe_dict(payload.get("test_plan")),
    }


def normalize_change_event(value: dict | None) -> dict:
    payload = safe_dict(value)
    title = str(payload.get("title") or "").strip()
    if not title:
        raise ValueError("change event title is required")
    risk = str(payload.get("risk") or "medium").strip().lower()
    if risk not in {"low", "medium", "high", "critical"}:
        risk = "medium"
    status = str(payload.get("status") or "completed").strip().lower()
    if not status:
        status = "completed"
    return {
        "created_at": str(payload.get("created_at") or "").strip(),
        "environment": str(payload.get("environment") or "prod").strip() or "prod",
        "run_type": str(payload.get("run_type") or "normal").strip() or "normal",
        "project_id": str(payload.get("project_id") or "").strip(),
        "source": str(payload.get("source") or "").strip(),
        "change_type": str(payload.get("change_type") or "").strip(),
        "title": title,
        "summary": str(payload.get("summary") or "").strip(),
        "actor": str(payload.get("actor") or "").strip(),
        "status": status,
        "risk": risk,
        "commit_sha": str(payload.get("commit_sha") or payload.get("commit") or "").strip(),
        "branch": str(payload.get("branch") or "").strip(),
        "version": str(payload.get("version") or "").strip(),
        "related_incident_id": positive_optional_int(payload.get("related_incident_id")),
        "related_ai_repair_id": positive_optional_int(payload.get("related_ai_repair_id")),
        "links": safe_list(payload.get("links")),
        "metadata": safe_dict(payload.get("metadata")),
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


def positive_optional_int(value: object) -> int | None:
    parsed = safe_int(value)
    return parsed if parsed > 0 else None


def incident_correlation_text(incident: dict) -> str:
    parts = [
        str(incident.get("title") or ""),
        str(incident.get("analysis") or ""),
        str(incident.get("last_summary") or ""),
        str(incident.get("classification_category") or ""),
        str(incident.get("classification_summary") or ""),
    ]
    for result in parse_json_list(str(incident.get("results_json") or "[]")):
        if isinstance(result, dict):
            parts.extend(
                [
                    str(result.get("source") or ""),
                    str(result.get("name") or ""),
                    str(result.get("summary") or ""),
                ]
            )
    return " ".join(parts).lower()


def score_change_event_for_incident(
    event: dict,
    incident: dict,
    incident_text: str,
    occurred_at: datetime,
) -> tuple[float, list[str]]:
    score = 0.0
    reasons: list[str] = []
    if safe_int(event.get("related_incident_id")) == safe_int(incident.get("id")) and safe_int(incident.get("id")) > 0:
        score += 1.0
        reasons.append("direct_incident_link")
    if str(event.get("environment") or "") == str(incident.get("environment") or "prod"):
        score += 0.2
        reasons.append("same_environment")
    if str(event.get("run_type") or "") == str(incident.get("run_type") or "normal"):
        score += 0.15
        reasons.append("same_run_type")
    project_id = str(event.get("project_id") or "").strip().lower()
    if project_id and project_id in incident_text:
        score += 0.25
        reasons.append("project_matches_incident_signal")
    change_type = str(event.get("change_type") or "").lower()
    source = str(event.get("source") or "").lower()
    if change_type in {"deployment", "release", "rollback", "config", "configuration", "ai_repair"}:
        score += 0.15
        reasons.append("high_signal_change_type")
    if source in {"ai_repair", "config_center", "deploy", "release", "operator"}:
        score += 0.1
        reasons.append("known_change_source")
    created_at = parse_iso_datetime(event.get("created_at"))
    if created_at:
        age_seconds = abs((occurred_at - created_at).total_seconds())
        if age_seconds <= 6 * 3600:
            score += 0.15
            reasons.append("within_6_hours")
        elif age_seconds <= 24 * 3600:
            score += 0.08
            reasons.append("within_24_hours")
    if str(event.get("status") or "") in {"failed", "partial", "rolled_back", "rollback_failed"}:
        score += 0.12
        reasons.append("change_status_not_clean")
    return min(score, 1.0), reasons


TIMELINE_KIND_ORDER = {
    "change_event": 0,
    "check_result": 1,
    "incident": 2,
    "incident_event": 3,
    "diagnosis": 4,
    "recommendation": 5,
    "action": 6,
    "notification": 7,
    "comment": 8,
}


def timeline_kind_rank(kind: str) -> int:
    return TIMELINE_KIND_ORDER.get(kind, 100)


def timeline_entry(
    kind: str,
    occurred_at: object,
    title: str,
    summary: str = "",
    status: str = "",
    severity: str = "",
    source: str = "",
    source_id: str = "",
    payload: dict | None = None,
    extra: dict | None = None,
) -> dict:
    entry = {
        "kind": kind,
        "occurred_at": str(occurred_at or ""),
        "title": title,
        "summary": summary,
        "status": status,
        "severity": severity,
        "source": source,
        "source_id": source_id,
        "payload": safe_dict(payload),
    }
    entry.update(safe_dict(extra))
    return entry


def timeline_summary(entries: list[dict]) -> dict:
    return {
        "total": len(entries),
        "by_kind": count_by_key(entries, "kind"),
        "by_status": count_by_key([entry for entry in entries if entry.get("status")], "status", ""),
        "first_at": str(entries[0].get("occurred_at") or "") if entries else "",
        "last_at": str(entries[-1].get("occurred_at") or "") if entries else "",
    }


def incident_result_targets(incident: dict) -> set[tuple[str, str]]:
    targets: set[tuple[str, str]] = set()
    for result in parse_json_list(str(incident.get("results_json") or "[]")):
        if not isinstance(result, dict):
            continue
        source = str(result.get("source") or "").strip()
        name = str(result.get("name") or "").strip()
        if source and name:
            targets.add((source, name))
    fingerprint = str(incident.get("fingerprint") or "")
    for target_key in fingerprint_target_keys(fingerprint):
        if "/" not in target_key:
            continue
        source, name = target_key.split("/", 1)
        source = source.strip()
        name = name.strip()
        if source and name:
            targets.add((source, name))
    return targets


def build_incident_review_payload(
    incident: dict,
    timeline: dict,
    diagnoses: list[dict],
    recommendations: list[dict],
    actions: list[dict],
    notifications: list[dict],
) -> dict:
    incident_id = safe_int(incident.get("id"))
    severity = str(incident.get("severity") or "")
    status = str(incident.get("status") or "")
    title = str(incident.get("title") or f"Incident #{incident_id}")
    timeline_summary = safe_dict(timeline.get("summary"))
    change_correlation = safe_dict(timeline.get("change_correlation"))
    related_changes = [
        {
            "id": row.get("id"),
            "created_at": row.get("created_at"),
            "title": row.get("title"),
            "source": row.get("source"),
            "change_type": row.get("change_type"),
            "risk": row.get("risk"),
            "status": row.get("status"),
            "correlation_score": row.get("correlation_score"),
            "correlation_reasons": row.get("correlation_reasons") or [],
        }
        for row in safe_list(change_correlation.get("related_changes"))
        if isinstance(row, dict)
    ]
    root_causes = incident_review_root_causes(incident, diagnoses, related_changes)
    action_items = incident_review_actions(actions)
    notification_items = [
        {
            "id": row.get("id"),
            "created_at": row.get("created_at"),
            "title": row.get("title"),
            "status": row.get("status"),
            "severity": row.get("severity"),
            "channels": parse_json_list(str(row.get("channels_json") or "[]")),
        }
        for row in notifications
    ]
    prevention_items = incident_review_prevention_items(incident, recommendations, related_changes, root_causes)
    summary = (
        f"{severity or 'unknown'} incident is {status or 'unknown'}; "
        f"{safe_int(incident.get('occurrence_count'), 1)} occurrence(s); "
        f"{len(action_items)} action record(s); {len(related_changes)} related change(s)."
    )
    return {
        "incident_id": incident_id,
        "title": f"Incident #{incident_id} review: {title}",
        "status": status,
        "severity": severity,
        "summary": summary,
        "impact": {
            "occurrence_count": safe_int(incident.get("occurrence_count"), 1),
            "first_seen_at": incident.get("first_seen_at") or incident.get("created_at") or "",
            "last_seen_at": incident.get("last_seen_at") or incident.get("updated_at") or "",
            "notification_count": len(notification_items),
            "timeline_entry_count": safe_int(timeline_summary.get("total")),
        },
        "root_causes": root_causes,
        "actions": action_items,
        "notifications": notification_items,
        "related_changes": related_changes,
        "prevention_items": prevention_items,
        "timeline_summary": timeline_summary,
        "generated_mode": "rules",
    }


def incident_review_root_causes(incident: dict, diagnoses: list[dict], related_changes: list[dict]) -> list[dict]:
    root_causes: list[dict] = []
    for row in diagnoses[:3]:
        category = str(row.get("top_category") or "").strip()
        if not category:
            continue
        root_causes.append(
            {
                "category": category,
                "confidence": safe_float(row.get("top_confidence")),
                "source": "diagnosis",
                "summary": f"Diagnosis selected {category}.",
                "evidence": safe_dict(row.get("evidence")),
            }
        )
    classification = str(incident.get("classification_category") or "").strip()
    if classification and not root_causes:
        root_causes.append(
            {
                "category": classification,
                "confidence": safe_float(incident.get("classification_confidence")),
                "source": "classification",
                "summary": str(incident.get("classification_summary") or ""),
                "evidence": parse_json_list(str(incident.get("classification_evidence_json") or "[]")),
            }
        )
    if related_changes:
        best_change = max(related_changes, key=lambda row: safe_float(row.get("correlation_score")))
        root_causes.append(
            {
                "category": "recent_change_correlation",
                "confidence": safe_float(best_change.get("correlation_score")),
                "source": "change_events",
                "summary": f"{len(related_changes)} related change event(s) found near the incident.",
                "evidence": [best_change.get("title") or best_change.get("change_type") or "change_event"],
            }
        )
    if safe_int(incident.get("false_positive")):
        root_causes.append(
            {
                "category": "false_positive",
                "confidence": 1.0,
                "source": "incident_lifecycle",
                "summary": str(incident.get("false_positive_reason") or "Incident marked false positive."),
                "evidence": [],
            }
        )
    if not root_causes:
        root_causes.append(
            {
                "category": "unknown",
                "confidence": 0.0,
                "source": "rules",
                "summary": "No diagnosis or related change has enough evidence yet.",
                "evidence": [],
            }
        )
    return root_causes


def incident_review_actions(actions: list[dict]) -> list[dict]:
    return [
        {
            "id": row.get("id"),
            "created_at": row.get("created_at"),
            "action_type": row.get("action_type"),
            "title": row.get("title"),
            "risk": row.get("risk"),
            "status": row.get("status"),
            "verify_status": row.get("verify_status"),
            "summary": bounded_text(row.get("error") or row.get("output") or row.get("reason"), 500),
        }
        for row in actions
    ]


def incident_review_prevention_items(
    incident: dict,
    recommendations: list[dict],
    related_changes: list[dict],
    root_causes: list[dict],
) -> list[dict]:
    items: list[dict] = []
    for step in parse_json_list(str(incident.get("classification_next_steps_json") or "[]"))[:5]:
        text = str(step or "").strip()
        if text:
            items.append({"source": "classification", "title": text, "priority": "medium"})
    for row in recommendations[:10]:
        title = str(row.get("title") or row.get("action_type") or "").strip()
        if title:
            items.append(
                {
                    "source": "recommendation",
                    "title": title,
                    "priority": str(row.get("risk") or "medium"),
                    "status": str(row.get("status") or ""),
                }
            )
    categories = {str(row.get("category") or "") for row in root_causes}
    if "recent_change_correlation" in categories:
        items.append(
            {
                "source": "change_events",
                "title": "Review release, rollback, and config-change gates for this project.",
                "priority": "high",
            }
        )
    if not related_changes:
        items.append(
            {
                "source": "change_events",
                "title": "Keep deployment and config changes recorded so future incidents can be correlated.",
                "priority": "medium",
            }
        )
    if not items:
        items.append(
            {
                "source": "rules",
                "title": "Collect more evidence and add a specific classifier or playbook if this repeats.",
                "priority": "medium",
            }
        )
    return dedupe_review_items(items)


def dedupe_review_items(items: list[dict]) -> list[dict]:
    seen: set[str] = set()
    deduped: list[dict] = []
    for item in items:
        key = f"{item.get('source')}:{item.get('title')}"
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def bounded_text(value: object, max_length: int = 500) -> str:
    text = str(value or "")
    if len(text) <= max_length:
        return text
    return text[: max(0, max_length - 3)] + "..."


def count_by_key(rows: list[dict], key: str, default: str = "unknown") -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        value = str(row.get(key) or default)
        counts[value] = counts.get(value, 0) + 1
    return counts


MUTATING_ACTION_TYPES = {"restart_service", "restart_docker_container", "cleanup_temp_files", "rotate_large_log"}
READINESS_BLOCK_PREFIX = "readiness blocked:"


def is_mutating_action(action_type: str) -> bool:
    return action_type in MUTATING_ACTION_TYPES


def backup_run_payload(row: sqlite3.Row | dict) -> dict:
    payload = dict(row)
    try:
        payload["metadata"] = json.loads(payload.get("metadata_json") or "{}")
    except (json.JSONDecodeError, TypeError):
        payload["metadata"] = {}
    return payload


def action_was_readiness_blocked(row: dict) -> bool:
    return str(row.get("status") or "") == "skipped" and str(row.get("error") or "").startswith(READINESS_BLOCK_PREFIX)


def recommendation_was_readiness_blocked(row: dict) -> bool:
    readiness = safe_dict(safe_dict(row.get("metadata")).get("readiness"))
    return str(readiness.get("status") or "") == "blocked"


def readiness_blocker_counts(actions: list[dict], recommendations: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in actions:
        for blocker in readiness_blockers_from_action(row):
            counts[blocker] = counts.get(blocker, 0) + 1
    for row in recommendations:
        for blocker in readiness_blockers_from_recommendation(row):
            counts[blocker] = counts.get(blocker, 0) + 1
    return counts


def readiness_blockers_from_action(row: dict) -> list[str]:
    error = str(row.get("error") or "")
    if not error.startswith(READINESS_BLOCK_PREFIX):
        return []
    raw = error[len(READINESS_BLOCK_PREFIX):].strip()
    return [item.strip() for item in raw.split(";") if item.strip()]


def readiness_blockers_from_recommendation(row: dict) -> list[str]:
    readiness = safe_dict(safe_dict(row.get("metadata")).get("readiness"))
    blockers = readiness.get("blockers")
    if not isinstance(blockers, list):
        return []
    return [str(item).strip() for item in blockers if str(item).strip()]


def readiness_action_block_payload(row: dict) -> dict:
    return {
        "kind": "action",
        "id": row.get("id"),
        "incident_id": row.get("incident_id"),
        "created_at": row.get("created_at"),
        "action_type": row.get("action_type"),
        "title": row.get("title"),
        "risk": row.get("risk"),
        "status": row.get("status"),
        "blockers": readiness_blockers_from_action(row),
    }


def readiness_recommendation_block_payload(row: dict) -> dict:
    return {
        "kind": "recommendation",
        "id": row.get("id"),
        "incident_id": row.get("incident_id"),
        "updated_at": row.get("updated_at"),
        "action_type": row.get("action_type"),
        "title": row.get("title"),
        "risk": row.get("risk"),
        "status": row.get("status"),
        "source": row.get("source"),
        "blockers": readiness_blockers_from_recommendation(row),
    }


def seconds_between(start: object, end: object) -> float:
    start_dt = parse_iso_datetime(start)
    end_dt = parse_iso_datetime(end)
    if not start_dt or not end_dt:
        return -1.0
    return max(0.0, (end_dt - start_dt).total_seconds())


def parse_iso_datetime(value: object) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


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


def decode_fleet_node(row: object) -> dict:
    item = dict(row)  # type: ignore[arg-type]
    for column, output, fallback in (
        ("labels_json", "labels", {}),
        ("capabilities_json", "capabilities", []),
        ("metrics_json", "metrics", {}),
        ("projects_json", "projects", []),
        ("assets_json", "assets", []),
        ("discovery_json", "discovery", {}),
    ):
        try:
            item[output] = json.loads(str(item.get(column) or ""))
        except (TypeError, ValueError, json.JSONDecodeError):
            item[output] = fallback
        item.pop(column, None)
    item["enabled"] = bool(item.get("enabled", 1))
    return item

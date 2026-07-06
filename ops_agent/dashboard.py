from __future__ import annotations

import html
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import parse_qs, urlsplit

from ops_agent.alerts.notifier import Notifier
from ops_agent.auth import AuthResult, authenticate_token, configured_api_tokens, has_role
from ops_agent.config import AppConfig
from ops_agent.config_center import (
    ai_repair_auto_trigger_snapshot,
    ai_repair_policy_snapshot,
    apply_config_update,
    backup_config,
    candidate_from_body,
    configure_deepseek_repair_model,
    config_snapshot,
    delete_project_config,
    list_config_backups,
    project_config_snapshot,
    project_repair_readiness_snapshot,
    restore_config_backup,
    update_ai_repair_auto_trigger,
    update_ai_repair_policy,
    upsert_project_config,
    validate_config_candidate,
)
from ops_agent.diagnosis import persist_incident_diagnosis
from ops_agent.ai.config_patches import (
    apply_config_patch,
    build_config_patch_from_recommendation,
    preview_config_patch,
)
from ops_agent.ai.learning_review import build_learning_optimization_draft
from ops_agent.ai.repair import (
    ai_repair_approval_queue,
    ai_repair_policy_from_config,
    build_ai_repair_proposal,
    deploy_ai_repair_after_merge,
    dry_run_ai_repair_proposal,
    notify_ai_repair_approval_queue,
    prepare_ai_repair_branch,
    publish_ai_repair_pull_request,
    record_ai_repair_test_result,
    run_ai_repair_pipeline,
    run_ai_repair_pipeline_for_incident,
    run_ai_repair_queue_next_action,
    run_project_ai_repair_drill,
    sandbox_test_ai_repair_proposal,
)
from ops_agent.monitor_targets import (
    apply_monitor_target_change,
    get_monitor_target,
    list_monitor_targets,
)
from ops_agent.projects import list_projects, project_summary_payload
from ops_agent.remediation.approval import approval_expiry_from_config, approve_action_log, reject_action_log
from ops_agent.remediation.playbook_center import (
    create_incident_playbook_recommendations,
    get_playbook,
    list_playbooks,
    preview_incident_playbooks,
)
from ops_agent.remediation.readiness import incident_self_heal_readiness
from ops_agent.remediation.recommendations import (
    approve_recommendation,
    reject_recommendation,
    request_recommendation_approval,
)
from ops_agent.storage import Storage


ACTIONABLE_RECOMMENDATION_STATUSES = ["suggested", "pending_approval", "failed", "verified_failed", "skipped"]


def start_dashboard(
    storage: Storage,
    host: str,
    port: int,
    config: AppConfig | None = None,
    notifier: Notifier | None = None,
) -> ThreadingHTTPServer:
    api_tokens = configured_api_tokens(config)
    protect_reads = bool(config.app.get("api_auth_required_for_reads", False)) if config else False
    app_context = dict(config.app) if config else {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            path, query = split_request_path(self.path)
            if path.startswith("/api/") and protect_reads:
                auth = self.require_role(path, "viewer")
                if auth is None:
                    return
            if path == "/api/summary":
                self.send_json(storage.dashboard_summary(**summary_filters_from_query(query)))
                return
            if path == "/api/ops/metrics":
                self.send_json(storage.ops_metrics(query_hours(query)))
                return
            if path == "/api/ops/report":
                metrics = storage.ops_metrics(query_hours(query))
                self.send_json(ops_report_payload(metrics))
                return
            if path == "/api/remediation/audit":
                self.send_json(
                    storage.remediation_audit(
                        query_hours(query),
                        query_limit(query, default=50, maximum=500),
                    )
                )
                return
            if path == "/api/classifications/summary":
                self.send_json(storage.classification_summary(query_hours(query)))
                return
            if path == "/api/learning/recommendations":
                self.send_json(storage.latest_learning_recommendations(**learning_filters_from_query(query)))
                return
            if path == "/api/learning/summary":
                self.send_json(storage.learning_summary(query_limit(query, default=500, maximum=1000)))
                return
            if path == "/api/learning/config-patches":
                self.send_json(storage.latest_learning_config_patches(**learning_config_patch_filters_from_query(query)))
                return
            if path == "/api/ai-repairs":
                self.send_json(storage.latest_ai_repair_proposals(**ai_repair_filters_from_query(query)))
                return
            if path == "/api/ai-repairs/approval-queue":
                self.send_json(ai_repair_approval_queue(storage, **ai_repair_queue_filters_from_query(query)))
                return
            if path == "/api/change-events":
                self.send_json(storage.latest_change_events(**change_event_filters_from_query(query)))
                return
            if path == "/api/config":
                if config is None:
                    self.send_json({"error": "config is not configured"}, status=503)
                    return
                self.send_json(config_snapshot(config))
                return
            if path == "/api/config/projects":
                if config is None:
                    self.send_json({"error": "config is not configured"}, status=503)
                    return
                self.send_json(project_config_snapshot(config))
                return
            if path == "/api/config/ai-repair-policy":
                if config is None:
                    self.send_json({"error": "config is not configured"}, status=503)
                    return
                self.send_json(ai_repair_policy_snapshot(config))
                return
            if path == "/api/config/ai-repair-auto-trigger":
                if config is None:
                    self.send_json({"error": "config is not configured"}, status=503)
                    return
                self.send_json(ai_repair_auto_trigger_snapshot(config))
                return
            if path == "/api/config/backups":
                if config is None:
                    self.send_json({"error": "config is not configured"}, status=503)
                    return
                try:
                    self.send_json(list_config_backups(config))
                except ValueError as exc:
                    self.send_json({"error": str(exc)}, status=503)
                return
            config_patch_request = parse_learning_config_patch_api_path(path)
            if config_patch_request:
                patch_id, action = config_patch_request
                if action == "":
                    row = storage.get_learning_config_patch(patch_id)
                    if not row:
                        self.send_json({"error": "learning config patch not found"}, status=404)
                        return
                    self.send_json(row)
                    return
            ai_repair_request = parse_ai_repair_api_path(path)
            if ai_repair_request:
                repair_id, action = ai_repair_request
                if action == "":
                    row = storage.get_ai_repair_proposal(repair_id)
                    if not row:
                        self.send_json({"error": "AI repair proposal not found"}, status=404)
                        return
                    self.send_json(row)
                    return
            learning_request = parse_learning_recommendation_api_path(path)
            if learning_request:
                recommendation_id, action = learning_request
                if action == "":
                    row = storage.get_learning_recommendation(recommendation_id)
                    if not row:
                        self.send_json({"error": "learning recommendation not found"}, status=404)
                        return
                    self.send_json(row)
                    return
            if path == "/api/results":
                self.send_json(storage.latest_results(**result_filters_from_query(query)))
                return
            if path == "/api/projects":
                self.send_json({"projects": list_projects(config)})
                return
            if path == "/api/projects/summary":
                hours = query_hours(query)
                self.send_json(project_summary_payload(config, storage.context_summaries(hours), hours))
                return
            if path == "/api/projects/repair-readiness":
                if config is None:
                    self.send_json({"error": "config is not configured"}, status=503)
                    return
                self.send_json(project_repair_readiness_snapshot(config))
                return
            if path == "/api/monitor-targets":
                self.send_json(list_monitor_targets(config.raw if config else {}))
                return
            if path == "/api/playbooks":
                self.send_json(list_playbooks(config))
                return
            if path == "/api/playbooks/detail":
                name = query_text(query, "name")
                if not name:
                    self.send_json({"error": "name is required"}, status=400)
                    return
                row = get_playbook(config, name)
                if not row:
                    self.send_json({"error": "playbook not found"}, status=404)
                    return
                self.send_json(row)
                return
            monitor_target_request = parse_monitor_target_api_path(path)
            if monitor_target_request:
                if config is None:
                    self.send_json({"error": "config is not configured"}, status=503)
                    return
                target_type, index, _action = monitor_target_request
                try:
                    self.send_json(get_monitor_target(config.raw, target_type, index))
                except ValueError as exc:
                    self.send_json({"error": str(exc)}, status=404)
                return
            if path == "/api/incidents":
                self.send_json(storage.latest_incidents(**incident_filters_from_query(query)))
                return
            if path == "/api/incidents/escalated":
                self.send_json(storage.latest_escalated_incidents())
                return
            incident_request = parse_incident_api_path(path)
            if incident_request:
                incident_id, action = incident_request
                if action == "":
                    incident = storage.get_incident(incident_id)
                    if not incident:
                        self.send_json({"error": "incident not found"}, status=404)
                        return
                    self.send_json(incident)
                    return
                if action == "detail":
                    detail = storage.incident_detail(incident_id)
                    if not detail:
                        self.send_json({"error": "incident not found"}, status=404)
                        return
                    self.send_json(detail)
                    return
                if action == "events":
                    self.send_json(storage.latest_incident_events(incident_id))
                    return
                if action == "recommendations":
                    self.send_json(storage.latest_incident_recommendations(incident_id))
                    return
                if action == "actions":
                    self.send_json(storage.latest_action_logs(100, incident_id=incident_id))
                    return
                if action == "failed-actions":
                    self.send_json(storage.latest_failed_action_logs(100, incident_id=incident_id))
                    return
                if action == "diagnoses":
                    self.send_json(storage.latest_incident_diagnoses(incident_id))
                    return
                if action == "diagnosis":
                    try:
                        self.send_json(persist_incident_diagnosis(storage, config, incident_id))
                    except ValueError as exc:
                        self.send_json({"error": str(exc)}, status=404)
                    return
                if action == "changes":
                    incident = storage.get_incident(incident_id)
                    if not incident:
                        self.send_json({"error": "incident not found"}, status=404)
                        return
                    self.send_json(storage.correlate_incident_changes(incident))
                    return
                if action == "playbook-matches":
                    if config is None:
                        self.send_json({"error": "config is not configured"}, status=503)
                        return
                    try:
                        self.send_json(preview_incident_playbooks(storage, config, incident_id))
                    except ValueError as exc:
                        self.send_json({"error": str(exc)}, status=404)
                    return
                if action in {"self-heal-readiness", "readiness"}:
                    if config is None:
                        self.send_json({"error": "config is not configured"}, status=503)
                        return
                    try:
                        self.send_json(incident_self_heal_readiness(storage, config, incident_id))
                    except ValueError as exc:
                        self.send_json({"error": str(exc)}, status=404)
                    return
            if path == "/api/action-logs":
                self.send_json(storage.latest_action_logs())
                return
            if path == "/api/notification-logs":
                self.send_json(storage.latest_notification_logs())
                return
            if path == "/api/audit-logs":
                self.send_json(storage.latest_api_audit_logs())
                return
            if path == "/api/actions/pending":
                self.send_json(storage.latest_action_logs(100, status="pending_approval"))
                return
            if path == "/api/actions/failed":
                self.send_json(storage.latest_failed_action_logs())
                return
            if path == "/api/recommendations":
                self.send_json(storage.latest_recommendations(**recommendation_filters_from_query(query)))
                return
            if path == "/api/recommendations/pending":
                self.send_json(storage.latest_recommendations(statuses=["pending_approval"]))
                return
            if path == "/api/recommendations/actionable":
                self.send_json(storage.latest_recommendations(statuses=ACTIONABLE_RECOMMENDATION_STATUSES))
                return
            recommendation_request = parse_recommendation_api_path(path)
            if recommendation_request:
                recommendation_id, action = recommendation_request
                if action == "":
                    row = storage.get_incident_recommendation(recommendation_id)
                    if not row:
                        self.send_json({"error": "recommendation not found"}, status=404)
                        return
                    self.send_json(row)
                    return
            action_request = parse_action_api_path(path)
            if action_request:
                action_id, action = action_request
                if action == "":
                    row = storage.get_action_log(action_id)
                    if not row:
                        self.send_json({"error": "action not found"}, status=404)
                        return
                    self.send_json(row)
                    return
            self.send_html(render_page(storage))

        def do_POST(self) -> None:  # noqa: N802
            path = self.path.split("?", 1)[0]
            auth = self.require_role(path, "operator")
            if auth is None:
                return

            config_patch_request = parse_learning_config_patch_api_path(path)
            if config_patch_request:
                self.handle_learning_config_patch_post(config_patch_request, auth)
                return

            if path.startswith("/api/config"):
                self.handle_config_center_post(path, auth)
                return

            learning_request = parse_learning_recommendation_api_path(path)
            if learning_request:
                self.handle_learning_recommendation_post(learning_request, auth)
                return

            if path == "/api/ai-repairs/approval-queue/notify":
                self.handle_ai_repair_queue_notify_post(auth)
                return

            if path == "/api/change-events":
                self.handle_change_event_post(auth)
                return

            ai_repair_request = parse_ai_repair_api_path(path)
            if ai_repair_request:
                self.handle_ai_repair_post(ai_repair_request, auth)
                return

            incident_ai_repair_request = parse_incident_ai_repair_api_path(path)
            if incident_ai_repair_request:
                self.handle_incident_ai_repair_post(incident_ai_repair_request, auth)
                return

            project_ai_repair_request = parse_project_ai_repair_api_path(path)
            if project_ai_repair_request:
                self.handle_project_ai_repair_post(project_ai_repair_request, auth)
                return

            monitor_target_request = parse_monitor_target_api_path(path)
            if monitor_target_request:
                self.handle_monitor_target_post(monitor_target_request, auth)
                return

            recommendation_request = parse_recommendation_api_path(path)
            if recommendation_request:
                self.handle_recommendation_post(recommendation_request, auth)
                return

            action_request = parse_action_api_path(path)
            if action_request:
                self.handle_action_post(action_request, auth)
                return

            incident_request = parse_incident_api_path(path)
            if not incident_request:
                self.record_audit(path, 404, "not_found", "unsupported api path", auth=auth)
                self.send_json({"error": "not found"}, status=404)
                return
            self.handle_incident_post(incident_request, auth)

        def handle_incident_post(self, incident_request: tuple[int, str], auth: AuthResult) -> None:
            incident_id, action = incident_request
            path = self.path.split("?", 1)[0]
            actor = "api"
            try:
                body = self.read_json_body()
                actor = self.actor_from_body(body, auth)
                note = str(body.get("note") or body.get("reason") or "")

                if action == "assign":
                    updated = storage.assign_incident(
                        incident_id,
                        str(body.get("assignee") or body.get("owner") or ""),
                        actor=actor,
                        note=note,
                    )
                    self.record_audit(path, 200, "success", "incident assigned", actor=actor, auth=auth)
                    self.send_json(updated)
                    return

                if action == "unassign":
                    updated = storage.assign_incident(incident_id, "", actor=actor, note=note)
                    self.record_audit(path, 200, "success", "incident unassigned", actor=actor, auth=auth)
                    self.send_json(updated)
                    return

                if action == "priority":
                    updated = storage.set_incident_priority(
                        incident_id,
                        str(body.get("priority") or ""),
                        actor=actor,
                        note=note,
                    )
                    self.record_audit(path, 200, "success", "incident priority updated", actor=actor, auth=auth)
                    self.send_json(updated)
                    return

                if action == "comment":
                    comment = str(body.get("comment") or body.get("note") or "")
                    created = storage.add_incident_comment(
                        incident_id,
                        actor=actor,
                        comment=comment,
                        metadata={"api_action": action},
                    )
                    self.record_audit(path, 200, "success", "incident comment added", actor=actor, auth=auth)
                    self.send_json(created)
                    return

                if action in {"false-positive", "false_positive"}:
                    updated = storage.mark_incident_false_positive(incident_id, actor=actor, reason=note)
                    self.record_audit(path, 200, "success", "incident marked false positive", actor=actor, auth=auth)
                    self.send_json(updated)
                    return

                if action == "playbook-recommendations":
                    if config is None:
                        self.record_audit(path, 503, "error", "config is not configured", actor=actor, auth=auth)
                        self.send_json({"error": "config is not configured"}, status=503)
                        return
                    result = create_incident_playbook_recommendations(storage, config, incident_id)
                    self.record_audit(
                        path,
                        200,
                        "success",
                        f"playbook recommendations saved={result.get('saved_count')}",
                        actor=actor,
                        auth=auth,
                    )
                    self.send_json(result)
                    return

                to_status = status_from_incident_action(action, body)
                updated = storage.transition_incident(
                    incident_id,
                    to_status,
                    actor=actor,
                    note=str(body.get("note") or body.get("reason") or ""),
                    metadata={"api_action": action},
                )
            except ValueError as exc:
                self.record_audit(path, 400, "error", str(exc), actor=actor, auth=auth)
                self.send_json({"error": str(exc)}, status=400)
                return
            except Exception as exc:
                self.record_audit(path, 500, "error", str(exc), actor=actor, auth=auth)
                self.send_json({"error": str(exc)}, status=500)
                return
            self.record_audit(path, 200, "success", f"incident status={updated.get('status')}", actor=actor, auth=auth)
            self.send_json(updated)

        def handle_change_event_post(self, auth: AuthResult) -> None:
            path = self.path.split("?", 1)[0]
            actor = "api"
            try:
                body = self.read_json_body()
                actor = self.actor_from_body(body, auth)
                payload = dict(body)
                payload["actor"] = str(payload.get("actor") or actor)
                created = storage.save_change_event(payload)
            except ValueError as exc:
                self.record_audit(path, 400, "error", str(exc), actor=actor, auth=auth)
                self.send_json({"error": str(exc)}, status=400)
                return
            except Exception as exc:
                self.record_audit(path, 500, "error", str(exc), actor=actor, auth=auth)
                self.send_json({"error": str(exc)}, status=500)
                return
            self.record_audit(path, 200, "success", f"change event created #{created.get('id')}", actor=actor, auth=auth)
            self.send_json(created)

        def handle_incident_ai_repair_post(
            self,
            repair_request: tuple[int, str],
            auth: AuthResult,
        ) -> None:
            incident_id, action = repair_request
            path = self.path.split("?", 1)[0]
            actor = "api"
            try:
                body = self.read_json_body()
                actor = self.actor_from_body(body, auth)
                if action in {"run-pipeline", "pipeline", "autopilot"}:
                    if config is None:
                        self.record_audit(path, 503, "error", "config is not configured", actor=actor, auth=auth)
                        self.send_json({"error": "config is not configured"}, status=503)
                        return
                    commands = body.get("commands")
                    auto_approve_risks = body.get("auto_approve_risks")
                    updated = run_ai_repair_pipeline_for_incident(
                        storage,
                        config,
                        incident_id,
                        config.base_dir,
                        actor=actor,
                        note=str(body.get("note") or body.get("reason") or ""),
                        commands=commands if isinstance(commands, list) else None,
                        auto_approve=bool(body.get("auto_approve", False)),
                        auto_approve_risks=auto_approve_risks if isinstance(auto_approve_risks, list) else None,
                        prepare_branch=bool(body.get("prepare_branch", False)),
                        create_pr=bool(body.get("create_pr", False)),
                        remote=str(body.get("remote") or "origin"),
                        base=str(body.get("base") or "main"),
                        draft=bool(body.get("draft", True)),
                        request=body,
                    )
                    pipeline = safe_body_dict(safe_body_dict(updated.get("test_result")).get("pipeline"))
                    outcome = "error" if pipeline.get("status") == "failed" else "success"
                    self.record_audit(path, 200, outcome, "AI repair pipeline completed", actor=actor, auth=auth)
                    self.send_json(updated)
                    return
                if action not in {"propose", "proposal"}:
                    self.record_audit(
                        path,
                        404,
                        "not_found",
                        f"unsupported incident AI repair operation: {action}",
                        actor=actor,
                        auth=auth,
                    )
                    self.send_json({"error": f"unsupported incident AI repair operation: {action}"}, status=404)
                    return
                proposal = build_ai_repair_proposal(
                    storage,
                    config,
                    incident_id,
                    request={**body, "actor": actor},
                )
                self.record_audit(path, 200, "success", "AI repair proposal created", actor=actor, auth=auth)
                self.send_json(proposal)
            except ValueError as exc:
                self.record_audit(path, 400, "error", str(exc), actor=actor, auth=auth)
                self.send_json({"error": str(exc)}, status=400)
            except Exception as exc:
                self.record_audit(path, 500, "error", str(exc), actor=actor, auth=auth)
                self.send_json({"error": str(exc)}, status=500)

        def handle_project_ai_repair_post(
            self,
            repair_request: tuple[str, str],
            auth: AuthResult,
        ) -> None:
            project_id, action = repair_request
            path = self.path.split("?", 1)[0]
            actor = "api"
            try:
                body = self.read_json_body()
                actor = self.actor_from_body(body, auth)
                if action not in {"drill", "proposal-drill", "repair-drill"}:
                    self.record_audit(
                        path,
                        404,
                        "not_found",
                        f"unsupported project AI repair operation: {action}",
                        actor=actor,
                        auth=auth,
                    )
                    self.send_json({"error": f"unsupported project AI repair operation: {action}"}, status=404)
                    return
                if config is None:
                    self.record_audit(path, 503, "error", "config is not configured", actor=actor, auth=auth)
                    self.send_json({"error": "config is not configured"}, status=503)
                    return
                readiness = project_repair_readiness_snapshot(config)
                project_ready = next(
                    (
                        row
                        for row in readiness.get("projects", [])
                        if project_id in {str(row.get("id") or ""), str(row.get("name") or "")}
                    ),
                    None,
                )
                if not project_ready:
                    self.record_audit(path, 404, "not_found", f"project not found: {project_id}", actor=actor, auth=auth)
                    self.send_json({"error": f"project not found: {project_id}"}, status=404)
                    return
                if project_ready.get("status") == "blocked" and not bool(body.get("force")):
                    self.record_audit(
                        path,
                        409,
                        "blocked",
                        f"project repair readiness blocked: {project_id}",
                        actor=actor,
                        auth=auth,
                    )
                    self.send_json(
                        {
                            "error": "project repair readiness is blocked",
                            "readiness": project_ready,
                        },
                        status=409,
                    )
                    return
                result = run_project_ai_repair_drill(
                    storage,
                    config,
                    project_id,
                    actor=actor,
                    request=body,
                )
                result["readiness"] = project_ready
                self.record_audit(path, 200, "success", "project AI repair drill completed", actor=actor, auth=auth)
                self.send_json(result)
            except ValueError as exc:
                self.record_audit(path, 400, "error", str(exc), actor=actor, auth=auth)
                self.send_json({"error": str(exc)}, status=400)
            except Exception as exc:
                self.record_audit(path, 500, "error", str(exc), actor=actor, auth=auth)
                self.send_json({"error": str(exc)}, status=500)

        def handle_ai_repair_queue_notify_post(self, auth: AuthResult) -> None:
            path = self.path.split("?", 1)[0]
            actor = "api"
            try:
                body = self.read_json_body()
                actor = self.actor_from_body(body, auth)
                result = notify_ai_repair_approval_queue(
                    storage,
                    config,
                    notifier=notifier,
                    limit=int(body.get("limit") or 50),
                    states=body.get("states") if isinstance(body.get("states"), list) else None,
                    repair_ids=body.get("repair_ids") if isinstance(body.get("repair_ids"), list) else None,
                    include_done=bool(body.get("include_done", False)),
                    actor=actor,
                )
                outcome = "success" if result.get("status") in {"sent", "skipped", "suppressed"} else "error"
                self.record_audit(path, 200, outcome, "AI repair approval queue notification processed", actor=actor, auth=auth)
                self.send_json(result)
            except ValueError as exc:
                self.record_audit(path, 400, "error", str(exc), actor=actor, auth=auth)
                self.send_json({"error": str(exc)}, status=400)
            except Exception as exc:
                self.record_audit(path, 500, "error", str(exc), actor=actor, auth=auth)
                self.send_json({"error": str(exc)}, status=500)

        def handle_ai_repair_post(
            self,
            repair_request: tuple[int, str],
            auth: AuthResult,
        ) -> None:
            repair_id, action = repair_request
            path = self.path.split("?", 1)[0]
            actor = "api"
            try:
                body = self.read_json_body()
                actor = self.actor_from_body(body, auth)
                note = str(body.get("note") or body.get("reason") or "")
                if action in {"advance", "run-next", "next-action"}:
                    updated = run_ai_repair_queue_next_action(
                        storage,
                        config,
                        repair_id,
                        actor=actor,
                        request=body,
                    )
                    self.record_audit(path, 200, "success", "AI repair queue next action executed", actor=actor, auth=auth)
                    self.send_json(updated)
                    return
                if action in {"run-pipeline", "pipeline", "autopilot"}:
                    if config is None:
                        self.record_audit(path, 503, "error", "config is not configured", actor=actor, auth=auth)
                        self.send_json({"error": "config is not configured"}, status=503)
                        return
                    commands = body.get("commands")
                    auto_approve_risks = body.get("auto_approve_risks")
                    updated = run_ai_repair_pipeline(
                        storage,
                        repair_id,
                        config.base_dir,
                        actor=actor,
                        note=note,
                        commands=commands if isinstance(commands, list) else None,
                        auto_approve=bool(body.get("auto_approve", False)),
                        auto_approve_risks=auto_approve_risks if isinstance(auto_approve_risks, list) else None,
                        prepare_branch=bool(body.get("prepare_branch", False)),
                        create_pr=bool(body.get("create_pr", False)),
                        remote=str(body.get("remote") or "origin"),
                        base=str(body.get("base") or "main"),
                        draft=bool(body.get("draft", True)),
                    )
                    pipeline = safe_body_dict(safe_body_dict(updated.get("test_result")).get("pipeline"))
                    outcome = "error" if pipeline.get("status") == "failed" else "success"
                    self.record_audit(path, 200, outcome, "AI repair pipeline completed", actor=actor, auth=auth)
                    self.send_json(updated)
                    return
                if action in {"dry-run", "apply-dry-run", "validate"}:
                    updated = dry_run_ai_repair_proposal(storage, repair_id, actor=actor, note=note)
                    outcome = "success" if updated.get("status") == "dry_run_passed" else "error"
                    self.record_audit(path, 200, outcome, "AI repair dry run completed", actor=actor, auth=auth)
                    self.send_json(updated)
                    return
                if action in {"test", "record-test"}:
                    result = safe_body_dict(body.get("result")) or body
                    updated = record_ai_repair_test_result(storage, repair_id, result=result, actor=actor, note=note)
                    outcome = "success" if updated.get("status") == "test_passed" else "error"
                    self.record_audit(path, 200, outcome, "AI repair test result recorded", actor=actor, auth=auth)
                    self.send_json(updated)
                    return
                if action in {"sandbox-test", "sandbox", "test-sandbox"}:
                    if config is None:
                        self.record_audit(path, 503, "error", "config is not configured", actor=actor, auth=auth)
                        self.send_json({"error": "config is not configured"}, status=503)
                        return
                    commands = body.get("commands")
                    updated = sandbox_test_ai_repair_proposal(
                        storage,
                        repair_id,
                        config.base_dir,
                        actor=actor,
                        note=note,
                        commands=commands if isinstance(commands, list) else None,
                        policy=ai_repair_policy_from_config(config),
                    )
                    outcome = "success" if updated.get("status") == "test_passed" else "error"
                    self.record_audit(path, 200, outcome, "AI repair sandbox test completed", actor=actor, auth=auth)
                    self.send_json(updated)
                    return
                if action in {"prepare-branch", "apply-approved", "prepare-pr"}:
                    if config is None:
                        self.record_audit(path, 503, "error", "config is not configured", actor=actor, auth=auth)
                        self.send_json({"error": "config is not configured"}, status=503)
                        return
                    commands = body.get("commands")
                    updated = prepare_ai_repair_branch(
                        storage,
                        repair_id,
                        config.base_dir,
                        actor=actor,
                        note=note,
                        commands=commands if isinstance(commands, list) else None,
                    )
                    outcome = "success" if updated.get("status") == "branch_prepared" else "error"
                    self.record_audit(path, 200, outcome, "AI repair controlled branch prepared", actor=actor, auth=auth)
                    self.send_json(updated)
                    return
                if action in {"create-pr", "publish-pr", "open-pr"}:
                    if config is None:
                        self.record_audit(path, 503, "error", "config is not configured", actor=actor, auth=auth)
                        self.send_json({"error": "config is not configured"}, status=503)
                        return
                    updated = publish_ai_repair_pull_request(
                        storage,
                        repair_id,
                        config.base_dir,
                        actor=actor,
                        note=note,
                        remote=str(body.get("remote") or "origin"),
                        base=str(body.get("base") or "main"),
                        draft=bool(body.get("draft", True)),
                    )
                    outcome = "success" if updated.get("status") == "pr_created" else "error"
                    self.record_audit(path, 200, outcome, "AI repair pull request published", actor=actor, auth=auth)
                    self.send_json(updated)
                    return
                if action in {"deploy-merged", "deploy", "verify-deploy"}:
                    if config is None:
                        self.record_audit(path, 503, "error", "config is not configured", actor=actor, auth=auth)
                        self.send_json({"error": "config is not configured"}, status=503)
                        return
                    commands = body.get("commands")
                    verify_urls = body.get("verify_urls") or body.get("verification_urls")
                    rollback_commands = body.get("rollback_commands")
                    rollback_verify_urls = body.get("rollback_verify_urls") or body.get("rollback_verification_urls")
                    updated = deploy_ai_repair_after_merge(
                        storage,
                        repair_id,
                        config.base_dir,
                        actor=actor,
                        note=note,
                        remote=str(body.get("remote") or "origin"),
                        base=str(body.get("base") or "main"),
                        commands=commands if isinstance(commands, list) else None,
                        verify_urls=verify_urls if isinstance(verify_urls, list) else None,
                        rollback_commands=rollback_commands if isinstance(rollback_commands, list) else None,
                        rollback_verify_urls=rollback_verify_urls if isinstance(rollback_verify_urls, list) else None,
                    )
                    outcome = "success" if updated.get("status") in {"deployed", "rollback_succeeded"} else "error"
                    self.record_audit(path, 200, outcome, "AI repair merged PR deployment checked", actor=actor, auth=auth)
                    self.send_json(updated)
                    return
                if action == "approve":
                    updated = storage.update_ai_repair_proposal_status(
                        repair_id,
                        "approved",
                        actor=actor,
                        note=note,
                    )
                    self.record_audit(path, 200, "success", "AI repair proposal approved", actor=actor, auth=auth)
                    self.send_json(updated)
                    return
                if action == "reject":
                    updated = storage.update_ai_repair_proposal_status(
                        repair_id,
                        "rejected",
                        actor=actor,
                        note=note,
                    )
                    self.record_audit(path, 200, "success", "AI repair proposal rejected", actor=actor, auth=auth)
                    self.send_json(updated)
                    return
            except ValueError as exc:
                self.record_audit(path, 400, "error", str(exc), actor=actor, auth=auth)
                self.send_json({"error": str(exc)}, status=400)
                return
            except Exception as exc:
                self.record_audit(path, 500, "error", str(exc), actor=actor, auth=auth)
                self.send_json({"error": str(exc)}, status=500)
                return
            self.record_audit(
                path,
                404,
                "not_found",
                f"unsupported AI repair operation: {action}",
                actor=actor,
                auth=auth,
            )
            self.send_json({"error": f"unsupported AI repair operation: {action}"}, status=404)

        def handle_config_center_post(self, path: str, auth: AuthResult) -> None:
            actor = "api"
            try:
                body = self.read_json_body()
                actor = self.actor_from_body(body, auth)
                if config is None or config.config_path is None:
                    self.record_audit(path, 503, "error", "config path is not configured", actor=actor, auth=auth)
                    self.send_json({"error": "config path is not configured"}, status=503)
                    return

                if path == "/api/config/validate":
                    candidate = candidate_from_body(body)
                    result = validate_config_candidate(config, candidate)
                    self.record_audit(
                        path,
                        200,
                        "success" if result.get("valid") else "validation_failed",
                        "config validation passed" if result.get("valid") else "config validation failed",
                        actor=actor,
                        auth=auth,
                    )
                    self.send_json(result)
                    return

                if path == "/api/config/backup":
                    result = backup_config(config, reason=str(body.get("reason") or "manual"))
                    self.record_audit(path, 200, "success", f"config backup {result.get('name')}", actor=actor, auth=auth)
                    self.send_json({"status": "backed_up", "backup": result})
                    return

                if path == "/api/config/deepseek":
                    result = configure_deepseek_repair_model(
                        config,
                        body,
                        reason=str(body.get("reason") or "deepseek-repair-model"),
                    )
                    self.record_audit(path, 200, "success", "DeepSeek repair model configured", actor=actor, auth=auth)
                    self.send_json(result)
                    return

                if path == "/api/config/projects/upsert":
                    result = upsert_project_config(
                        config,
                        safe_body_dict(body.get("project")) or body,
                        reason=str(body.get("reason") or "project-upsert"),
                    )
                    self.record_audit(
                        path,
                        200,
                        "success",
                        f"project {result.get('action')} {safe_body_dict(result.get('project')).get('id')}",
                        actor=actor,
                        auth=auth,
                    )
                    self.send_json(result)
                    return

                if path == "/api/config/projects/delete":
                    result = delete_project_config(
                        config,
                        str(body.get("id") or body.get("project_id") or ""),
                        reason=str(body.get("reason") or "project-delete"),
                    )
                    self.record_audit(path, 200, "success", f"project deleted {result.get('project_id')}", actor=actor, auth=auth)
                    self.send_json(result)
                    return

                if path == "/api/config/ai-repair-policy":
                    result = update_ai_repair_policy(
                        config,
                        safe_body_dict(body.get("policy")) or body,
                        reason=str(body.get("reason") or "ai-repair-policy"),
                    )
                    self.record_audit(path, 200, "success", "AI repair policy updated", actor=actor, auth=auth)
                    self.send_json(result)
                    return

                if path == "/api/config/ai-repair-auto-trigger":
                    result = update_ai_repair_auto_trigger(
                        config,
                        safe_body_dict(body.get("auto_trigger")) or body,
                        reason=str(body.get("reason") or "ai-repair-auto-trigger"),
                    )
                    self.record_audit(path, 200, "success", "AI repair auto-trigger policy updated", actor=actor, auth=auth)
                    self.send_json(result)
                    return

                if path == "/api/config/apply":
                    candidate = candidate_from_body(body)
                    result = apply_config_update(config, candidate, reason=str(body.get("reason") or "api-apply"))
                    self.record_audit(
                        path,
                        200,
                        "success",
                        f"config applied sections={','.join(result.get('changed_sections') or [])}",
                        actor=actor,
                        auth=auth,
                    )
                    self.send_json(result)
                    return

                if path == "/api/config/restore":
                    result = restore_config_backup(config, str(body.get("backup") or body.get("name") or ""))
                    self.record_audit(
                        path,
                        200,
                        "success",
                        f"config restored from {result.get('restored_from', {}).get('name')}",
                        actor=actor,
                        auth=auth,
                    )
                    self.send_json(result)
                    return

                self.record_audit(path, 404, "not_found", "unsupported config api path", actor=actor, auth=auth)
                self.send_json({"error": "not found"}, status=404)
                return
            except ValueError as exc:
                self.record_audit(path, 400, "error", str(exc), actor=actor, auth=auth)
                self.send_json({"error": str(exc)}, status=400)
                return
            except Exception as exc:
                self.record_audit(path, 500, "error", str(exc), actor=actor, auth=auth)
                self.send_json({"error": str(exc)}, status=500)
                return

        def handle_monitor_target_post(
            self,
            target_request: tuple[str, int | None, str],
            auth: AuthResult,
        ) -> None:
            target_type, index, action = target_request
            path = self.path.split("?", 1)[0]
            actor = "api"
            try:
                if config is None or config.config_path is None:
                    self.record_audit(path, 503, "error", "config path is not configured", actor=actor, auth=auth)
                    self.send_json({"error": "config path is not configured"}, status=503)
                    return
                body = self.read_json_body()
                actor = self.actor_from_body(body, auth)
                result = apply_monitor_target_change(config, target_type, index, action, body)
                self.record_audit(
                    path,
                    200,
                    "success",
                    f"monitor target {result.get('action')} {result.get('target', {}).get('id')}",
                    actor=actor,
                    auth=auth,
                )
                self.send_json(result)
                return
            except ValueError as exc:
                self.record_audit(path, 400, "error", str(exc), actor=actor, auth=auth)
                self.send_json({"error": str(exc)}, status=400)
                return
            except Exception as exc:
                self.record_audit(path, 500, "error", str(exc), actor=actor, auth=auth)
                self.send_json({"error": str(exc)}, status=500)
                return

        def handle_action_post(self, action_request: tuple[int, str], auth: AuthResult) -> None:
            action_id, action = action_request
            path = self.path.split("?", 1)[0]
            actor = "api"
            try:
                body = self.read_json_body()
                actor = self.actor_from_body(body, auth)
                note = str(body.get("note") or body.get("reason") or "")
                if action == "approve":
                    if config is None:
                        self.record_audit(
                            path,
                            503,
                            "error",
                            "approval execution is not configured",
                            actor=actor,
                            auth=auth,
                        )
                        self.send_json({"error": "approval execution is not configured"}, status=503)
                        return
                    result = approve_action_log(storage, config, action_id, actor=actor, notifier=notifier)
                    self.record_audit(
                        path,
                        200,
                        "success",
                        f"action status={result.result.status}",
                        actor=actor,
                        auth=auth,
                    )
                    self.send_json(result.to_dict())
                    return
                if action == "reject":
                    rejected = reject_action_log(storage, action_id, actor=actor, note=note)
                    self.record_audit(path, 200, "success", "action rejected", actor=actor, auth=auth)
                    self.send_json(rejected)
                    return
            except ValueError as exc:
                self.record_audit(path, 400, "error", str(exc), actor=actor, auth=auth)
                self.send_json({"error": str(exc)}, status=400)
                return
            except Exception as exc:
                self.record_audit(path, 500, "error", str(exc), actor=actor, auth=auth)
                self.send_json({"error": str(exc)}, status=500)
                return
            self.record_audit(
                path,
                404,
                "not_found",
                f"unsupported action operation: {action}",
                actor=actor,
                auth=auth,
            )
            self.send_json({"error": f"unsupported action operation: {action}"}, status=404)

        def handle_recommendation_post(self, recommendation_request: tuple[int, str], auth: AuthResult) -> None:
            recommendation_id, action = recommendation_request
            path = self.path.split("?", 1)[0]
            actor = "api"
            try:
                body = self.read_json_body()
                actor = self.actor_from_body(body, auth)
                note = str(body.get("note") or body.get("reason") or "")
                if action == "request-approval":
                    result = request_recommendation_approval(
                        storage,
                        recommendation_id,
                        actor=actor,
                        note=note,
                        approval_expires_at=approval_expiry_from_config(config),
                    )
                    self.record_audit(path, 200, "success", "recommendation pending approval", actor=actor, auth=auth)
                    self.send_json(result)
                    return
                if action == "approve":
                    if config is None:
                        self.record_audit(
                            path,
                            503,
                            "error",
                            "recommendation approval is not configured",
                            actor=actor,
                            auth=auth,
                        )
                        self.send_json({"error": "recommendation approval is not configured"}, status=503)
                        return
                    result = approve_recommendation(
                        storage,
                        config,
                        recommendation_id,
                        actor=actor,
                        note=note,
                        notifier=notifier,
                    )
                    self.record_audit(
                        path,
                        200,
                        "success",
                        f"recommendation status={result['recommendation'].get('status')}",
                        actor=actor,
                        auth=auth,
                    )
                    self.send_json(result)
                    return
                if action == "reject":
                    result = reject_recommendation(storage, recommendation_id, actor=actor, note=note)
                    self.record_audit(path, 200, "success", "recommendation rejected", actor=actor, auth=auth)
                    self.send_json(result)
                    return
            except ValueError as exc:
                self.record_audit(path, 400, "error", str(exc), actor=actor, auth=auth)
                self.send_json({"error": str(exc)}, status=400)
                return
            except Exception as exc:
                self.record_audit(path, 500, "error", str(exc), actor=actor, auth=auth)
                self.send_json({"error": str(exc)}, status=500)
                return
            self.record_audit(
                path,
                404,
                "not_found",
                f"unsupported recommendation operation: {action}",
                actor=actor,
                auth=auth,
            )
            self.send_json({"error": f"unsupported recommendation operation: {action}"}, status=404)

        def handle_learning_recommendation_post(
            self,
            recommendation_request: tuple[int, str],
            auth: AuthResult,
        ) -> None:
            recommendation_id, action = recommendation_request
            path = self.path.split("?", 1)[0]
            actor = "api"
            try:
                body = self.read_json_body()
                actor = self.actor_from_body(body, auth)
                note = str(body.get("note") or body.get("reason") or "")
                current = storage.get_learning_recommendation(recommendation_id)
                if not current:
                    raise ValueError(f"learning recommendation not found: #{recommendation_id}")

                if action == "accept":
                    draft = build_learning_optimization_draft(current)
                    updated = storage.update_learning_recommendation_status(
                        recommendation_id,
                        "accepted",
                        actor=actor,
                        note=note,
                        draft=draft,
                    )
                    self.record_audit(path, 200, "success", "learning recommendation accepted", actor=actor, auth=auth)
                    self.send_json({"recommendation": updated, "draft": updated.get("draft")})
                    return
                if action == "dismiss":
                    updated = storage.update_learning_recommendation_status(
                        recommendation_id,
                        "dismissed",
                        actor=actor,
                        note=note,
                    )
                    self.record_audit(path, 200, "success", "learning recommendation dismissed", actor=actor, auth=auth)
                    self.send_json({"recommendation": updated})
                    return
                if action == "apply":
                    draft = safe_body_dict(body.get("draft")) or current.get("draft") or build_learning_optimization_draft(current)
                    updated = storage.update_learning_recommendation_status(
                        recommendation_id,
                        "applied",
                        actor=actor,
                        note=note,
                        draft=draft,
                    )
                    self.record_audit(path, 200, "success", "learning recommendation marked applied", actor=actor, auth=auth)
                    self.send_json({"recommendation": updated, "draft": updated.get("draft")})
                    return
                if action == "propose-config":
                    if str(current.get("status") or "") != "accepted":
                        raise ValueError("learning recommendation must be accepted before proposing config")
                    draft = safe_body_dict(body.get("draft")) or current.get("draft") or build_learning_optimization_draft(current)
                    if not current.get("draft"):
                        current = storage.update_learning_recommendation_status(
                            recommendation_id,
                            "accepted",
                            actor=actor,
                            note=note,
                            draft=draft,
                        )
                    patch = safe_body_dict(body.get("patch")) or build_config_patch_from_recommendation(
                        {**current, "draft": draft}
                    )
                    config_patch = storage.save_learning_config_patch(recommendation_id, patch)
                    self.record_audit(path, 200, "success", "learning config patch proposed", actor=actor, auth=auth)
                    self.send_json({"recommendation": current, "config_patch": config_patch})
                    return
            except ValueError as exc:
                self.record_audit(path, 400, "error", str(exc), actor=actor, auth=auth)
                self.send_json({"error": str(exc)}, status=400)
                return
            except Exception as exc:
                self.record_audit(path, 500, "error", str(exc), actor=actor, auth=auth)
                self.send_json({"error": str(exc)}, status=500)
                return
            self.record_audit(
                path,
                404,
                "not_found",
                f"unsupported learning recommendation operation: {action}",
                actor=actor,
                auth=auth,
            )
            self.send_json({"error": f"unsupported learning recommendation operation: {action}"}, status=404)

        def handle_learning_config_patch_post(
            self,
            patch_request: tuple[int, str],
            auth: AuthResult,
        ) -> None:
            patch_id, action = patch_request
            path = self.path.split("?", 1)[0]
            actor = "api"
            try:
                body = self.read_json_body()
                actor = self.actor_from_body(body, auth)
                note = str(body.get("note") or body.get("reason") or "")
                current = storage.get_learning_config_patch(patch_id)
                if not current:
                    raise ValueError(f"learning config patch not found: #{patch_id}")
                if action == "approve":
                    updated = storage.update_learning_config_patch_status(
                        patch_id,
                        "approved",
                        actor=actor,
                        note=note,
                    )
                    self.record_audit(path, 200, "success", "learning config patch approved", actor=actor, auth=auth)
                    self.send_json(updated)
                    return
                if action == "reject":
                    updated = storage.update_learning_config_patch_status(
                        patch_id,
                        "rejected",
                        actor=actor,
                        note=note,
                    )
                    self.record_audit(path, 200, "success", "learning config patch rejected", actor=actor, auth=auth)
                    self.send_json(updated)
                    return
                if action == "validate":
                    if config is None or config.config_path is None:
                        self.record_audit(path, 503, "error", "config path is not configured", actor=actor, auth=auth)
                        self.send_json({"error": "config path is not configured"}, status=503)
                        return
                    preview = public_config_patch_preview(
                        preview_config_patch(config.config_path, current.get("patch") or {})
                    )
                    outcome = "success" if preview["valid"] else "error"
                    self.record_audit(path, 200, outcome, "learning config patch validated", actor=actor, auth=auth)
                    self.send_json({"config_patch": current, "validation": preview})
                    return
                if action == "apply":
                    if str(current.get("status") or "") != "approved":
                        raise ValueError(f"learning config patch cannot be applied from {current.get('status')}")
                    if config is None or config.config_path is None:
                        self.record_audit(path, 503, "error", "config path is not configured", actor=actor, auth=auth)
                        self.send_json({"error": "config path is not configured"}, status=503)
                        return
                    apply_result = apply_config_patch(config.config_path, current.get("patch") or {})
                    next_config = apply_result.pop("config", None)
                    apply_result.pop("current", None)
                    if isinstance(next_config, dict):
                        config.raw.clear()
                        config.raw.update(next_config)
                    updated = storage.update_learning_config_patch_status(
                        patch_id,
                        "applied",
                        actor=actor,
                        note=note,
                        apply_result=apply_result,
                    )
                    try:
                        storage.update_learning_recommendation_status(
                            int(current.get("recommendation_id") or 0),
                            "applied",
                            actor=actor,
                            note=note,
                        )
                    except ValueError:
                        pass
                    self.record_audit(path, 200, "success", "learning config patch applied", actor=actor, auth=auth)
                    self.send_json(updated)
                    return
            except ValueError as exc:
                self.record_audit(path, 400, "error", str(exc), actor=actor, auth=auth)
                self.send_json({"error": str(exc)}, status=400)
                return
            except Exception as exc:
                self.record_audit(path, 500, "error", str(exc), actor=actor, auth=auth)
                self.send_json({"error": str(exc)}, status=500)
                return
            self.record_audit(
                path,
                404,
                "not_found",
                f"unsupported learning config patch operation: {action}",
                actor=actor,
                auth=auth,
            )
            self.send_json({"error": f"unsupported learning config patch operation: {action}"}, status=404)

        def read_json_body(self) -> dict:
            length = int(self.headers.get("Content-Length", "0") or "0")
            if length <= 0:
                return {}
            raw = self.rfile.read(length).decode("utf-8", errors="replace")
            if not raw.strip():
                return {}
            payload = json.loads(raw)
            return payload if isinstance(payload, dict) else {}

        def require_role(self, path: str, required_role: str) -> AuthResult | None:
            auth = self.authenticate()
            if not auth.authenticated:
                message = auth.reason or "missing or invalid token"
                self.record_audit(path, 401, "unauthorized", message, auth=auth)
                self.send_auth_error(401, "unauthorized")
                return None
            if not has_role(auth.role, required_role):
                message = f"requires {required_role} role"
                self.record_audit(path, 403, "forbidden", message, auth=auth)
                self.send_auth_error(403, "forbidden")
                return None
            return auth

        def authenticate(self) -> AuthResult:
            return authenticate_token(self.provided_token(), api_tokens)

        def provided_token(self) -> str:
            provided = self.headers.get("X-Ops-Agent-Token", "").strip()
            authorization = self.headers.get("Authorization", "").strip()
            if authorization.lower().startswith("bearer "):
                provided = authorization[7:].strip()
            return provided

        def actor_from_body(self, body: dict, auth: AuthResult) -> str:
            return str(
                body.get("actor")
                or self.headers.get("X-Ops-Agent-Actor")
                or auth.token_name
                or "api"
            )

        def send_auth_error(self, status: int, message: str) -> None:
            payload = {"error": message}
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            if status == 401:
                self.send_header("WWW-Authenticate", 'Bearer realm="ops-agent"')
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def record_audit(
            self,
            path: str,
            status_code: int,
            outcome: str,
            message: str,
            actor: str = "",
            auth: AuthResult | None = None,
        ) -> None:
            operation, target_type, target_id = audit_target_from_path(path)
            audit_actor = actor or self.headers.get("X-Ops-Agent-Actor", "")
            if not audit_actor and auth and auth.authenticated:
                audit_actor = auth.token_name
            try:
                storage.record_api_audit(
                    actor=audit_actor,
                    source_ip=self.client_ip(),
                    method=self.command,
                    path=path,
                    operation=operation,
                    target_type=target_type,
                    target_id=target_id,
                    status_code=status_code,
                    outcome=outcome,
                    message=message,
                    metadata={
                        "user_agent": self.headers.get("User-Agent", ""),
                        "auth_role": auth.role if auth else "anonymous",
                        "token_name": auth.token_name if auth else "",
                        "auth_reason": auth.reason if auth else "",
                    },
                    environment=str(app_context.get("environment") or "prod"),
                    run_type="api",
                )
            except Exception:
                return

        def client_ip(self) -> str:
            forwarded_for = self.headers.get("X-Forwarded-For", "")
            if forwarded_for.strip():
                return forwarded_for.split(",", 1)[0].strip()
            return str(self.client_address[0]) if self.client_address else ""

        def send_json(self, payload: object, status: int = 200) -> None:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def send_html(self, body: str) -> None:
            data = body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, format: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer((host, port), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    actual_host, actual_port = server.server_address
    print(f"Dashboard: http://{actual_host}:{actual_port}")
    return server


def split_request_path(raw_path: str) -> tuple[str, dict[str, list[str]]]:
    parsed = urlsplit(raw_path)
    return parsed.path, parse_qs(parsed.query, keep_blank_values=False)


def recommendation_filters_from_query(query: dict[str, list[str]]) -> dict:
    return {
        "limit": query_limit(query, default=50, maximum=200),
        "incident_id": query_optional_int(query, "incident_id"),
        "statuses": query_statuses(query),
        "category": query_text(query, "category"),
        "risk": query_text(query, "risk"),
        "action_type": query_text(query, "action_type"),
        "source": query_text(query, "source"),
    }


def incident_filters_from_query(query: dict[str, list[str]]) -> dict:
    return {
        "limit": query_limit(query, default=20, maximum=200),
        "status": query_text(query, "status"),
        "assignee": query_text(query, "assignee"),
        "priority": query_text(query, "priority"),
        "severity": query_text(query, "severity"),
        "false_positive": query_optional_bool(query, "false_positive"),
        "environment": query_text(query, "environment"),
        "run_type": query_text(query, "run_type"),
    }


def result_filters_from_query(query: dict[str, list[str]]) -> dict:
    return {
        "limit": query_limit(query, default=50, maximum=500),
        "environment": query_text(query, "environment"),
        "run_type": query_text(query, "run_type"),
    }


def summary_filters_from_query(query: dict[str, list[str]]) -> dict:
    return {
        "hours": query_hours(query),
        "environment": query_text(query, "environment"),
        "run_type": query_text(query, "run_type"),
    }


def learning_filters_from_query(query: dict[str, list[str]]) -> dict:
    return {
        "limit": query_limit(query, default=50, maximum=200),
        "statuses": query_statuses(query),
        "category": query_text(query, "category"),
        "priority": query_text(query, "priority"),
        "trigger_type": query_text(query, "trigger_type"),
    }


def learning_config_patch_filters_from_query(query: dict[str, list[str]]) -> dict:
    return {
        "limit": query_limit(query, default=50, maximum=200),
        "statuses": query_statuses(query),
        "recommendation_id": query_optional_int(query, "recommendation_id"),
        "patch_type": query_text(query, "patch_type"),
    }


def ai_repair_filters_from_query(query: dict[str, list[str]]) -> dict:
    return {
        "limit": query_limit(query, default=50, maximum=200),
        "statuses": query_statuses(query),
        "incident_id": query_optional_int(query, "incident_id"),
        "risk": query_text(query, "risk"),
        "model_provider": query_text(query, "model_provider"),
    }


def ai_repair_queue_filters_from_query(query: dict[str, list[str]]) -> dict:
    return {
        "limit": query_limit(query, default=50, maximum=200),
        "statuses": query_statuses(query),
        "include_done": bool(query_optional_bool(query, "include_done")),
        "risk": query_text(query, "risk"),
        "model_provider": query_text(query, "model_provider"),
    }


def change_event_filters_from_query(query: dict[str, list[str]]) -> dict:
    return {
        "limit": query_limit(query, default=50, maximum=500),
        "environment": query_text(query, "environment"),
        "run_type": query_text(query, "run_type"),
        "project_id": query_text(query, "project_id"),
        "change_type": query_text(query, "change_type"),
        "source": query_text(query, "source"),
        "status": query_text(query, "status"),
        "risk": query_text(query, "risk"),
        "related_incident_id": query_optional_int(query, "related_incident_id"),
        "related_ai_repair_id": query_optional_int(query, "related_ai_repair_id"),
    }


def query_text(query: dict[str, list[str]], key: str) -> str:
    values = query.get(key, [])
    return str(values[0]).strip() if values else ""


def query_optional_int(query: dict[str, list[str]], key: str) -> int | None:
    text = query_text(query, key)
    if not text:
        return None
    try:
        value = int(text)
    except ValueError:
        return None
    return value if value > 0 else None


def ops_report_payload(metrics: dict) -> dict:
    availability = metrics.get("availability", {})
    incidents = metrics.get("incidents", {})
    actions = metrics.get("actions", {})
    notifications = metrics.get("notifications", {})
    return {
        "generated_at": metrics.get("generated_at"),
        "window": metrics.get("window"),
        "executive_summary": [
            f"OK rate {availability.get('ok_rate', 100.0)}% across {availability.get('total_checks', 0)} checks.",
            f"{incidents.get('total', 0)} incident(s), {incidents.get('open', 0)} still open.",
            f"{actions.get('total', 0)} remediation action(s), success rate {actions.get('success_rate', 100.0)}%.",
            f"{notifications.get('total', 0)} notification record(s), {notifications.get('failed', 0)} failed.",
        ],
        "scorecard": {
            "ok_rate": availability.get("ok_rate", 100.0),
            "open_incidents": incidents.get("open", 0),
            "critical_incidents": incidents.get("critical", 0),
            "action_success_rate": actions.get("success_rate", 100.0),
            "expired_approvals": actions.get("expired", 0),
            "readiness_blocked_actions": actions.get("readiness_blocked", 0),
            "notification_failures": notifications.get("failed", 0),
            "mttr_seconds_avg": safe_nested_number(incidents, ["mttr_seconds", "avg"]),
        },
        "metrics": metrics,
    }


def safe_nested_number(payload: dict, keys: list[str]) -> float:
    current: object = payload
    for key in keys:
        if not isinstance(current, dict):
            return 0.0
        current = current.get(key)
    try:
        return float(current or 0)
    except (TypeError, ValueError):
        return 0.0


def query_optional_bool(query: dict[str, list[str]], key: str) -> bool | None:
    text = query_text(query, key).lower()
    if not text:
        return None
    if text in {"1", "true", "yes", "y", "on"}:
        return True
    if text in {"0", "false", "no", "n", "off"}:
        return False
    return None


def query_limit(query: dict[str, list[str]], default: int, maximum: int) -> int:
    text = query_text(query, "limit")
    if not text:
        return default
    try:
        value = int(text)
    except ValueError:
        return default
    return min(max(value, 1), maximum)


def query_hours(query: dict[str, list[str]], default: int = 24, maximum: int = 24 * 365) -> int:
    text = query_text(query, "hours")
    if not text:
        return default
    try:
        value = int(text)
    except ValueError:
        return default
    return min(max(value, 1), maximum)


def query_statuses(query: dict[str, list[str]]) -> list[str]:
    raw_values = query.get("status", []) + query.get("statuses", [])
    statuses: list[str] = []
    for value in raw_values:
        statuses.extend(part.strip() for part in str(value).split(",") if part.strip())
    return statuses


def render_page(storage: Storage) -> str:
    summary = storage.dashboard_summary()
    incidents = storage.latest_incidents(12)
    results = storage.latest_results(60)
    latest_targets = sorted(
        summary["latest_targets"],
        key=lambda row: (status_rank(str(row.get("status"))), str(row.get("source")), str(row.get("name"))),
    )

    incident_rows = "\n".join(render_incident_row(row) for row in incidents)
    result_rows = "\n".join(render_result_row(row) for row in results)
    target_rows = "\n".join(render_target_row(row) for row in latest_targets)
    source_badges = "\n".join(
        f"<span class='badge'>{safe(source)} <strong>{count}</strong></span>"
        for source, count in sorted(summary["source_counts"].items())
    )
    status_text = {"ok": "运行正常", "warning": "存在告警", "critical": "严重异常"}.get(
        summary["current_status"], "未知"
    )

    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AI Ops Agent</title>
  <style>
    :root {{
      --ink: #17212b;
      --muted: #687385;
      --paper: #f7f8fa;
      --panel: #ffffff;
      --line: #d9e0e8;
      --ok: #157f5b;
      --warn: #a76300;
      --bad: #b42318;
      --accent: #2454d6;
      --code: #263445;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--paper);
      color: var(--ink);
      font-family: "Segoe UI", "Microsoft YaHei", Arial, sans-serif;
      font-size: 14px;
      letter-spacing: 0;
    }}
    header {{
      background: #182230;
      color: #f8fafc;
      border-bottom: 4px solid #52b788;
    }}
    .header-inner {{
      max-width: 1320px;
      margin: 0 auto;
      padding: 22px 28px;
      display: flex;
      align-items: end;
      justify-content: space-between;
      gap: 20px;
    }}
    h1, h2, h3, p {{ margin: 0; }}
    h1 {{ font-size: 24px; font-weight: 750; }}
    .subtitle {{ color: #cbd5e1; margin-top: 6px; }}
    .status-pill {{
      border: 1px solid rgba(255,255,255,.25);
      padding: 8px 12px;
      min-width: 112px;
      text-align: center;
      font-weight: 700;
      background: rgba(255,255,255,.08);
    }}
    main {{ max-width: 1320px; margin: 0 auto; padding: 24px 28px 36px; }}
    .metrics {{
      display: grid;
      grid-template-columns: repeat(5, minmax(0, 1fr));
      gap: 12px;
      margin-bottom: 18px;
    }}
    .metric {{
      background: var(--panel);
      border: 1px solid var(--line);
      padding: 14px 16px;
      min-height: 92px;
    }}
    .metric-label {{ color: var(--muted); font-size: 12px; }}
    .metric-value {{ display: block; margin-top: 10px; font-size: 28px; font-weight: 760; }}
    .metric-note {{ color: var(--muted); margin-top: 4px; font-size: 12px; }}
    .workbench {{
      display: grid;
      grid-template-columns: minmax(0, 1.15fr) minmax(360px, .85fr);
      gap: 16px;
      align-items: start;
    }}
    section {{
      background: var(--panel);
      border: 1px solid var(--line);
      margin-bottom: 16px;
    }}
    .section-head {{
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: center;
      padding: 14px 16px;
      border-bottom: 1px solid var(--line);
    }}
    h2 {{ font-size: 16px; }}
    .badges {{ display: flex; flex-wrap: wrap; gap: 8px; }}
    .badge {{
      display: inline-flex;
      gap: 6px;
      align-items: center;
      border: 1px solid var(--line);
      padding: 4px 8px;
      color: var(--muted);
      background: #fbfcfe;
      font-size: 12px;
    }}
    table {{ width: 100%; border-collapse: collapse; table-layout: fixed; }}
    th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--line); vertical-align: top; }}
    th {{ color: var(--muted); font-size: 12px; font-weight: 700; background: #f2f5f8; }}
    tr:last-child td {{ border-bottom: 0; }}
    .time {{ width: 176px; color: var(--muted); font-variant-numeric: tabular-nums; }}
    .source {{ width: 86px; }}
    .status {{ width: 88px; font-weight: 760; }}
    .summary {{ overflow-wrap: anywhere; }}
    .ok {{ color: var(--ok); }}
    .warning {{ color: var(--warn); }}
    .critical {{ color: var(--bad); }}
    .empty {{ color: var(--muted); padding: 18px 16px; }}
    details {{ border-bottom: 1px solid var(--line); }}
    details:last-child {{ border-bottom: 0; }}
    summary {{
      cursor: pointer;
      padding: 12px 16px;
      display: grid;
      grid-template-columns: 126px 156px minmax(0, 1fr);
      gap: 10px;
      align-items: center;
      list-style: none;
    }}
    summary::-webkit-details-marker {{ display: none; }}
    pre {{
      margin: 0;
      padding: 0 16px 14px;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      color: var(--code);
      font-family: Consolas, "Cascadia Mono", monospace;
      font-size: 12px;
      line-height: 1.55;
    }}
    .mobile-label {{ display: none; }}
    @media (max-width: 980px) {{
      .header-inner {{ align-items: start; flex-direction: column; }}
      .metrics {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
      .workbench {{ grid-template-columns: 1fr; }}
    }}
    @media (max-width: 640px) {{
      main, .header-inner {{ padding-left: 14px; padding-right: 14px; }}
      .metrics {{ grid-template-columns: 1fr; }}
      table, thead, tbody, tr, th, td {{ display: block; }}
      thead {{ display: none; }}
      tr {{ border-bottom: 1px solid var(--line); padding: 8px 0; }}
      td {{ border: 0; padding: 5px 12px; }}
      .time, .source, .status {{ width: auto; }}
      .mobile-label {{ display: inline; color: var(--muted); margin-right: 6px; }}
      summary {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <header>
    <div class="header-inner">
      <div>
        <h1>AI Ops Agent</h1>
        <p class="subtitle">内部运维监控工作台 · 最近 {summary["hours"]} 小时</p>
      </div>
      <div class="status-pill {safe(summary["current_status"])}">{safe(status_text)}</div>
    </div>
  </header>
  <main>
    <div class="metrics">
      {metric("总巡检", summary["total_checks"], "最近 24 小时记录")}
      {metric("正常率", f'{summary["ok_rate"]}%', "按巡检记录计算")}
      {metric("当前异常", summary["active_problem_count"], "最新状态仍异常")}
      {metric("告警事件", summary["incident_count"], "最近 24 小时")}
      {metric("严重异常", summary["critical"], "critical 记录数")}
    </div>
    <div class="workbench">
      <div>
        <section>
          <div class="section-head">
            <h2>当前监控目标</h2>
            <div class="badges">{source_badges}</div>
          </div>
          <table>
            <thead><tr><th class="status">状态</th><th class="source">来源</th><th>名称</th><th>摘要</th><th class="time">更新时间</th></tr></thead>
            <tbody>{target_rows or "<tr><td colspan='5' class='empty'>暂无巡检记录</td></tr>"}</tbody>
          </table>
        </section>
        <section>
          <div class="section-head"><h2>最近巡检</h2></div>
          <table>
            <thead><tr><th class="time">时间</th><th class="source">来源</th><th>名称</th><th class="status">状态</th><th>摘要</th></tr></thead>
            <tbody>{result_rows or "<tr><td colspan='5' class='empty'>暂无巡检记录</td></tr>"}</tbody>
          </table>
        </section>
      </div>
      <section>
        <div class="section-head"><h2>事件中心</h2></div>
        {incident_rows or "<div class='empty'>暂无告警事件</div>"}
      </section>
    </div>
  </main>
</body>
</html>"""


def metric(label: str, value: object, note: str) -> str:
    return (
        "<div class='metric'>"
        f"<div class='metric-label'>{safe(label)}</div>"
        f"<span class='metric-value'>{safe(value)}</span>"
        f"<div class='metric-note'>{safe(note)}</div>"
        "</div>"
    )


def render_target_row(row: dict) -> str:
    status = safe(row.get("status", ""))
    return (
        "<tr>"
        f"<td class='status {status}'><span class='mobile-label'>状态</span>{status}</td>"
        f"<td class='source'><span class='mobile-label'>来源</span>{safe(row.get('source', ''))}</td>"
        f"<td><span class='mobile-label'>名称</span>{safe(row.get('name', ''))}</td>"
        f"<td class='summary'><span class='mobile-label'>摘要</span>{safe(row.get('summary', ''))}</td>"
        f"<td class='time'><span class='mobile-label'>更新时间</span>{safe(row.get('created_at', ''))}</td>"
        "</tr>"
    )


def render_result_row(row: dict) -> str:
    status = safe(row.get("status", ""))
    return (
        "<tr>"
        f"<td class='time'><span class='mobile-label'>时间</span>{safe(row.get('created_at', ''))}</td>"
        f"<td class='source'><span class='mobile-label'>来源</span>{safe(row.get('source', ''))}</td>"
        f"<td><span class='mobile-label'>名称</span>{safe(row.get('name', ''))}</td>"
        f"<td class='status {status}'><span class='mobile-label'>状态</span>{status}</td>"
        f"<td class='summary'><span class='mobile-label'>摘要</span>{safe(row.get('summary', ''))}</td>"
        "</tr>"
    )


def render_incident_row(row: dict) -> str:
    severity = safe(row.get("severity", ""))
    lifecycle_status = safe(row.get("status", "open"))
    occurrence_count = int(row.get("occurrence_count") or 1)
    occurrence_label = f" x{occurrence_count}" if occurrence_count > 1 else ""
    last_seen = row.get("last_seen_at") or row.get("updated_at") or row.get("created_at", "")
    return (
        "<details>"
        "<summary>"
        f"<span class='time'>{safe(last_seen)}</span>"
        f"<span class='status {severity}'>{severity}/{lifecycle_status}{safe(occurrence_label)}</span>"
        f"<strong>{safe(row.get('title', ''))}</strong>"
        "</summary>"
        f"<pre>{safe(row.get('analysis', ''))}</pre>"
        "</details>"
    )


def status_rank(value: str) -> int:
    return {"critical": 0, "warning": 1, "ok": 2}.get(value, 3)


def parse_incident_api_path(path: str) -> tuple[int, str] | None:
    parts = [part for part in path.strip("/").split("/") if part]
    if len(parts) < 3 or parts[0] != "api" or parts[1] != "incidents":
        return None
    try:
        incident_id = int(parts[2])
    except ValueError:
        return None
    action = parts[3] if len(parts) >= 4 else ""
    return incident_id, action


def parse_incident_ai_repair_api_path(path: str) -> tuple[int, str] | None:
    parts = [part for part in path.strip("/").split("/") if part]
    if len(parts) < 5 or parts[0] != "api" or parts[1] != "incidents" or parts[3] != "ai-repair":
        return None
    try:
        incident_id = int(parts[2])
    except ValueError:
        return None
    action = parts[4] if len(parts) >= 5 else ""
    return incident_id, action


def parse_project_ai_repair_api_path(path: str) -> tuple[str, str] | None:
    parts = [part for part in path.strip("/").split("/") if part]
    if len(parts) < 5 or parts[0] != "api" or parts[1] != "projects" or parts[3] != "ai-repair":
        return None
    return parts[2], parts[4]


def parse_action_api_path(path: str) -> tuple[int, str] | None:
    parts = [part for part in path.strip("/").split("/") if part]
    if len(parts) < 3 or parts[0] != "api" or parts[1] != "actions":
        return None
    try:
        action_id = int(parts[2])
    except ValueError:
        return None
    action = parts[3] if len(parts) >= 4 else ""
    return action_id, action


def parse_recommendation_api_path(path: str) -> tuple[int, str] | None:
    parts = [part for part in path.strip("/").split("/") if part]
    if len(parts) < 3 or parts[0] != "api" or parts[1] != "recommendations":
        return None
    try:
        recommendation_id = int(parts[2])
    except ValueError:
        return None
    action = parts[3] if len(parts) >= 4 else ""
    return recommendation_id, action


def parse_learning_recommendation_api_path(path: str) -> tuple[int, str] | None:
    parts = [part for part in path.strip("/").split("/") if part]
    if len(parts) < 4 or parts[0] != "api" or parts[1] != "learning" or parts[2] != "recommendations":
        return None
    try:
        recommendation_id = int(parts[3])
    except ValueError:
        return None
    action = parts[4] if len(parts) >= 5 else ""
    return recommendation_id, action


def parse_learning_config_patch_api_path(path: str) -> tuple[int, str] | None:
    parts = [part for part in path.strip("/").split("/") if part]
    if len(parts) < 4 or parts[0] != "api" or parts[1] != "learning" or parts[2] != "config-patches":
        return None
    try:
        patch_id = int(parts[3])
    except ValueError:
        return None
    action = parts[4] if len(parts) >= 5 else ""
    return patch_id, action


def parse_ai_repair_api_path(path: str) -> tuple[int, str] | None:
    parts = [part for part in path.strip("/").split("/") if part]
    if len(parts) < 3 or parts[0] != "api" or parts[1] != "ai-repairs":
        return None
    try:
        repair_id = int(parts[2])
    except ValueError:
        return None
    action = parts[3] if len(parts) >= 4 else ""
    return repair_id, action


def parse_monitor_target_api_path(path: str) -> tuple[str, int | None, str] | None:
    parts = [part for part in path.strip("/").split("/") if part]
    if len(parts) < 3 or parts[0] != "api" or parts[1] != "monitor-targets":
        return None
    target_type = parts[2]
    if len(parts) == 3:
        return target_type, None, ""
    if parts[3].isdigit():
        index = int(parts[3])
        action = parts[4] if len(parts) >= 5 else ""
        return target_type, index, action
    return target_type, None, parts[3]


def audit_target_from_path(path: str) -> tuple[str, str, int | None]:
    monitor_request = parse_monitor_target_api_path(path)
    if monitor_request:
        target_type, index, action = monitor_request
        operation = f"monitor_target.{action or ('update' if index is not None or target_type == 'server' else 'create')}"
        return operation, f"monitor_target.{target_type}", index

    config_patch_request = parse_learning_config_patch_api_path(path)
    if config_patch_request:
        patch_id, action = config_patch_request
        operation = f"learning.config_patch.{action or 'read'}"
        return operation, "learning_config_patch", patch_id

    learning_request = parse_learning_recommendation_api_path(path)
    if learning_request:
        recommendation_id, action = learning_request
        operation = f"learning.recommendation.{action or 'read'}"
        return operation, "learning_recommendation", recommendation_id

    ai_repair_request = parse_ai_repair_api_path(path)
    if ai_repair_request:
        repair_id, action = ai_repair_request
        operation_name = (action or "read").replace("-", "_")
        operation = f"ai_repair.{operation_name}"
        return operation, "ai_repair", repair_id

    incident_ai_repair_request = parse_incident_ai_repair_api_path(path)
    if incident_ai_repair_request:
        incident_id, action = incident_ai_repair_request
        operation_name = (action or "read").replace("-", "_")
        operation = f"ai_repair.{operation_name}"
        return operation, "incident", incident_id

    project_ai_repair_request = parse_project_ai_repair_api_path(path)
    if project_ai_repair_request:
        _project_id, action = project_ai_repair_request
        operation_name = (action or "read").replace("-", "_")
        return f"ai_repair.project_{operation_name}", "project", None

    recommendation_request = parse_recommendation_api_path(path)
    if recommendation_request:
        recommendation_id, action = recommendation_request
        operation = f"recommendation.{action or 'read'}"
        return operation, "recommendation", recommendation_id

    action_request = parse_action_api_path(path)
    if action_request:
        action_id, action = action_request
        operation = f"action.{action or 'read'}"
        return operation, "action", action_id

    incident_request = parse_incident_api_path(path)
    if incident_request:
        incident_id, action = incident_request
        operation_name = (action or "read").replace("-", "_")
        operation = f"incident.{operation_name}"
        return operation, "incident", incident_id

    mapping = {
        "/api/audit-logs": ("audit.list", "audit", None),
        "/api/action-logs": ("action.list", "action", None),
        "/api/notification-logs": ("notification.list", "notification", None),
        "/api/config": ("config.read", "config", None),
        "/api/config/backups": ("config.backups", "config", None),
        "/api/config/validate": ("config.validate", "config", None),
        "/api/config/backup": ("config.backup", "config", None),
        "/api/config/apply": ("config.apply", "config", None),
        "/api/config/restore": ("config.restore", "config", None),
        "/api/config/deepseek": ("config.deepseek", "config", None),
        "/api/config/projects": ("config.projects.read", "config", None),
        "/api/config/projects/upsert": ("config.projects.upsert", "config", None),
        "/api/config/projects/delete": ("config.projects.delete", "config", None),
        "/api/config/ai-repair-policy": ("config.ai_repair_policy", "config", None),
        "/api/config/ai-repair-auto-trigger": ("config.ai_repair_auto_trigger", "config", None),
        "/api/monitor-targets": ("monitor_target.list", "monitor_target", None),
        "/api/playbooks": ("playbook.list", "playbook", None),
        "/api/playbooks/detail": ("playbook.detail", "playbook", None),
        "/api/projects": ("project.list", "project", None),
        "/api/projects/summary": ("project.summary", "project", None),
        "/api/projects/repair-readiness": ("project.repair_readiness", "project", None),
        "/api/actions/failed": ("action.failed", "action", None),
        "/api/actions/pending": ("action.pending", "action", None),
        "/api/incidents": ("incident.list", "incident", None),
        "/api/incidents/escalated": ("incident.escalated", "incident", None),
        "/api/classifications/summary": ("classification.summary", "classification", None),
        "/api/learning/config-patches": ("learning.config_patch.list", "learning_config_patch", None),
        "/api/learning/recommendations": ("learning.recommendation.list", "learning", None),
        "/api/learning/summary": ("learning.summary", "learning", None),
        "/api/ai-repairs": ("ai_repair.list", "ai_repair", None),
        "/api/ai-repairs/approval-queue": ("ai_repair.approval_queue", "ai_repair", None),
        "/api/ai-repairs/approval-queue/notify": ("ai_repair.approval_queue.notify", "ai_repair", None),
        "/api/change-events": ("change_event.list", "change_event", None),
        "/api/ops/metrics": ("ops.metrics", "ops", None),
        "/api/ops/report": ("ops.report", "ops", None),
        "/api/remediation/audit": ("remediation.audit", "remediation", None),
        "/api/recommendations": ("recommendation.list", "recommendation", None),
        "/api/recommendations/actionable": ("recommendation.actionable", "recommendation", None),
        "/api/recommendations/pending": ("recommendation.pending", "recommendation", None),
        "/api/summary": ("summary.read", "summary", None),
        "/api/results": ("result.list", "result", None),
    }
    return mapping.get(path, ("api.unknown", "", None))


def status_from_incident_action(action: str, body: dict) -> str:
    if action == "ack":
        return "acknowledged"
    if action in {"remediate", "remediating"}:
        return "remediating"
    if action == "verify":
        return "verifying"
    if action == "resolve":
        return "resolved"
    if action == "close":
        return "closed"
    if action == "transition":
        return str(body.get("status", ""))
    raise ValueError(f"unsupported incident action: {action}")


def safe(value: object) -> str:
    return html.escape(str(value))


def safe_body_dict(value: object) -> dict:
    return dict(value) if isinstance(value, dict) else {}


def public_config_patch_preview(preview: dict) -> dict:
    return {
        "valid": bool(preview.get("valid")),
        "errors": list(preview.get("errors") or []),
        "operation_count": int(preview.get("operation_count") or 0),
        "operations": list(preview.get("operations") or []),
    }

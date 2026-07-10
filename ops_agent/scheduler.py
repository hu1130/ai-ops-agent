from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import time
from pathlib import Path
from typing import Any

from ops_agent.ai.classifier import IncidentClassification, classify_incident
from ops_agent.ai.analyzer import analyze_incident
from ops_agent.ai.learning import build_learning_recommendations, format_learning_recommendations
from ops_agent.ai.repair import (
    AI_REPAIR_QUEUE_ACTIVE_STATUSES,
    build_ai_repair_proposal,
    dry_run_ai_repair_proposal,
    notify_ai_repair_approval_queue,
)
from ops_agent.alerts.notifier import Notifier
from ops_agent.alerts.routing import (
    alert_context_from_results,
    format_routing_header,
    route_alert,
    routed_dedupe_key,
)
from ops_agent.config import AppConfig
from ops_agent.diagnostics.collector import collect_diagnostics, format_snapshot
from ops_agent.diagnostics.suggestions import build_action_suggestions
from ops_agent.diagnosis import diagnostic_snapshot_evidence, persist_incident_diagnosis
from ops_agent.events import CheckResult, RunContext, apply_context
from ops_agent.monitors.business_flow_monitor import run_business_flow_checks
from ops_agent.monitors.docker_monitor import run_docker_checks
from ops_agent.monitors.http_monitor import run_http_checks
from ops_agent.monitors.json_api_monitor import run_json_checks
from ops_agent.monitors.log_monitor import run_log_checks
from ops_agent.monitors.server_monitor import run_server_checks
from ops_agent.remediation.actions import ActionResult, RemediationAction
from ops_agent.remediation.executor import MUTATING_ACTIONS, execute_action, format_action_plan
from ops_agent.remediation.playbooks import (
    playbook_failure_policy,
    playbook_identity,
    playbook_meta,
    playbook_rollback_actions,
)
from ops_agent.remediation.planner import build_remediation_plan, public_params
from ops_agent.remediation.policy import decide_action_policy
from ops_agent.remediation.verifier import verify_after_action
from ops_agent.retention import format_retention_result, run_retention_cleanup
from ops_agent.storage import Storage, fingerprint_target_keys


DEFAULT_AI_REPAIR_AUTO_TRIGGER_POLICY = {
    "enabled": False,
    "severities": ["critical"],
    "categories": [
        "service_unavailable",
        "dependency_failure",
        "performance_degraded",
        "probe_config_issue",
        "route_or_healthcheck_config_mismatch",
        "business_flow_failure",
        "synthetic_quality_fail",
    ],
    "excluded_categories": ["unknown", "unclassified"],
    "sources": [],
    "excluded_sources": [],
    "environments": [],
    "run_types": [],
    "min_classification_confidence": 0.65,
    "run_dry_run": True,
    "notify": True,
    "notify_states": ["needs_dry_run", "needs_sandbox", "ready_for_approval", "blocked", "review_only"],
    "notify_limit": 20,
    "max_active_proposals": 10,
    "max_triggers_per_window": 5,
    "trigger_window_minutes": 60,
}


@dataclass
class IssueState:
    failure_count: int = 0
    is_open: bool = False
    last_summary: str = ""
    incident_id: int | None = None


class OpsScheduler:
    def __init__(self, config: AppConfig, storage: Storage, notifier: Notifier):
        self.config = config
        self.storage = storage
        self.notifier = notifier
        self._last_run: dict[str, float] = {}
        self._issues: dict[str, IssueState] = {}
        self._last_daily_report_date: str = ""
        self._last_retention_cleanup_date: str = ""
        self._last_learning_optimization_at: float = 0.0

    def run_once(self, respect_intervals: bool = False) -> list[CheckResult]:
        cycle_started_at = time.time()
        context = build_run_context(self.config)
        results: list[CheckResult] = []
        results.extend(run_http_checks(self.due_checks("http", self.config.http_checks, respect_intervals, cycle_started_at)))
        results.extend(run_json_checks(self.due_checks("json", self.config.json_checks, respect_intervals, cycle_started_at)))
        results.extend(
            run_business_flow_checks(
                self.due_checks("business_flow", self.config.business_flow_checks, respect_intervals, cycle_started_at)
            )
        )
        results.extend(run_server_checks(self.config.server_checks, self.config.base_dir))
        results.extend(run_docker_checks(self.due_checks("docker", self.config.docker_checks, respect_intervals, cycle_started_at)))
        results.extend(run_log_checks(self.due_checks("log", self.config.log_checks, respect_intervals, cycle_started_at), self.config.base_dir))
        apply_context(results, context)
        if results:
            self.storage.save_results(results)

        self.process_alert_states(results)

        return results

    def process_alert_states(self, results: list[CheckResult]) -> None:
        threshold = int(self.config.alerts.get("consecutive_failures", 2))
        recovery_enabled = bool(self.config.alerts.get("recovery_enabled", True))
        new_alerts: list[CheckResult] = []
        recoveries: list[CheckResult] = []
        recovery_incident_ids: set[int] = set()
        repeated_by_incident: dict[int, list[CheckResult]] = {}
        ok_results_by_context: dict[tuple[str, str], dict[str, CheckResult]] = {}

        for result in results:
            key = check_key(result)
            state = self._issues.setdefault(key, IssueState())
            if result.is_problem:
                state.failure_count += 1
                state.last_summary = result.summary
                result_threshold = alert_threshold_for_result(result, threshold)
                if not state.is_open and state.failure_count >= result_threshold:
                    state.is_open = True
                    new_alerts.append(result)
                elif state.is_open and state.incident_id:
                    repeated_by_incident.setdefault(state.incident_id, []).append(result)
            else:
                if state.is_open and recovery_enabled:
                    recoveries.append(result)
                    if state.incident_id:
                        recovery_incident_ids.add(state.incident_id)
                state.failure_count = 0
                state.is_open = False
                state.last_summary = result.summary
                state.incident_id = None
                context_key = (result.environment or "prod", result.run_type or "normal")
                ok_results_by_context.setdefault(context_key, {})[key] = result

        if recovery_enabled:
            existing_recovery_keys = {check_key(result) for result in recoveries}
            for (environment, run_type), ok_results_by_key in ok_results_by_context.items():
                recovered_incidents = self.storage.find_recoverable_active_incidents(
                    environment,
                    run_type,
                    ok_results_by_key.keys(),
                )
                for incident in recovered_incidents:
                    recovery_incident_ids.add(int(incident["id"]))
                    for target_key in fingerprint_target_keys(str(incident.get("fingerprint", ""))):
                        result = ok_results_by_key.get(target_key)
                        if result and target_key not in existing_recovery_keys:
                            recoveries.append(result)
                            existing_recovery_keys.add(target_key)

        for incident_id, repeated_results in repeated_by_incident.items():
            updated = self.update_existing_incident(incident_id, repeated_results)
            if updated:
                escalated = self.send_escalation_alert_if_due(updated, repeated_results)
                if not escalated:
                    self.send_repeated_alert_if_due(updated, repeated_results)

        if new_alerts:
            severity = "critical" if any(item.status == "critical" for item in new_alerts) else "warning"
            title = f"Ops Agent detected {len(new_alerts)} issue(s)"
            fingerprint = incident_fingerprint(new_alerts)
            existing = self.storage.find_active_incident_by_fingerprint(fingerprint)
            if existing:
                incident_id = int(existing["id"])
                updated = self.update_existing_incident(incident_id, new_alerts, severity=severity, title=title)
                for result in new_alerts:
                    self._issues[check_key(result)].incident_id = incident_id
                if updated:
                    escalated = self.send_escalation_alert_if_due(updated, new_alerts)
                    if not escalated:
                        self.send_repeated_alert_if_due(updated, new_alerts)
                new_alerts = []

        if new_alerts:
            severity = "critical" if any(item.status == "critical" for item in new_alerts) else "warning"
            title = f"Ops Agent detected {len(new_alerts)} issue(s)"
            fingerprint = incident_fingerprint(new_alerts)
            analysis = analyze_incident(new_alerts, self.config.ai, self.config.classification_rules)
            diagnostics = format_snapshot(collect_diagnostics(new_alerts, self.config))
            suggestions = build_action_suggestions(new_alerts)
            action_plan = build_remediation_plan(new_alerts, self.config)
            analysis = f"{analysis}{suggestions}{diagnostics}"
            incident_id = self.storage.save_incident(
                severity,
                title,
                analysis,
                new_alerts,
                fingerprint=fingerprint,
                occurrence_count=len(new_alerts),
                classification=classification_payload(new_alerts, self.config.classification_rules),
            )
            action_results = self.process_remediation_actions(action_plan, new_alerts, incident_id=incident_id)
            diagnosis = persist_incident_diagnosis(
                self.storage,
                self.config,
                incident_id,
                collected_evidence=diagnostic_snapshot_evidence(diagnostics),
            )
            self.storage.save_incident_recommendations(
                incident_id,
                build_incident_recommendations(
                    action_plan,
                    action_results,
                    self.config,
                    context_from_results(new_alerts),
                ),
            )
            remediation_text = format_action_plan(action_plan, action_results)
            diagnosis_text = format_persisted_diagnosis_for_analysis(diagnosis)
            analysis = f"{analysis}{diagnosis_text}{remediation_text}"
            self.storage.update_incident_analysis(incident_id, analysis)
            auto_repair = self.process_ai_repair_auto_trigger(incident_id, new_alerts)
            if auto_repair.get("status") not in {"disabled", "skipped", "not_matched", "duplicate"}:
                analysis = f"{analysis}{format_ai_repair_auto_trigger_result(auto_repair)}"
                self.storage.update_incident_analysis(incident_id, analysis)
            for result in new_alerts:
                self._issues[check_key(result)].incident_id = incident_id
            next_status = incident_status_from_action_results(action_results)
            if next_status:
                self.storage.transition_incident(
                    incident_id,
                    next_status,
                    actor="scheduler",
                    note="remediation action processed",
                    metadata={"action_statuses": [item.status for item in action_results]},
                )
            self.send_alert_notification(
                title,
                analysis,
                problem_key(new_alerts),
                new_alerts,
                severity,
                incident_id=incident_id,
            )
            self.send_action_failure_escalation_if_needed(incident_id, action_results, new_alerts)

        if recoveries:
            title = f"Ops Agent recovered {len(recoveries)} issue(s)"
            text = build_recovery_message(recoveries)
            recovery_record_id = self.storage.save_incident("ok", title, text, recoveries)
            for incident_id in sorted(recovery_incident_ids):
                self.storage.transition_incident(
                    incident_id,
                    "resolved",
                    actor="scheduler",
                    note="monitor recovered",
                    metadata={"recovered_checks": [check_key(result) for result in recoveries]},
                )
            notification_incident_id = (
                next(iter(recovery_incident_ids))
                if len(recovery_incident_ids) == 1
                else recovery_record_id
            )
            self.send_alert_notification(
                title,
                text,
                "recovered:" + problem_key(recoveries),
                recoveries,
                "ok",
                incident_id=notification_incident_id,
            )

    def update_existing_incident(
        self,
        incident_id: int,
        results: list[CheckResult],
        severity: str = "",
        title: str = "",
    ) -> dict | None:
        if not results:
            return None
        merged_severity = severity or ("critical" if any(item.status == "critical" for item in results) else "warning")
        merged_title = title or f"Ops Agent detected {len(results)} issue(s)"
        try:
            return self.storage.update_incident_occurrence(
                incident_id,
                merged_severity,
                merged_title,
                results,
                increment=len(results),
                classification=classification_payload(results, self.config.classification_rules),
            )
        except ValueError:
            return None

    def send_alert_notification(
        self,
        title: str,
        text: str,
        dedupe_key: str,
        results: list[CheckResult] | None = None,
        severity: str = "",
        incident_id: int | None = None,
    ) -> bool:
        context = alert_context_from_results(
            results or [],
            severity=severity,
            title=title,
            classification_rules=self.config.classification_rules,
        )
        decision = route_alert(self.config.alerts, context)
        routed_key = routed_dedupe_key(dedupe_key, decision)
        if decision.suppressed:
            print(f"[alert suppressed by routing] {title}: {decision.reason}")
            self.storage.save_notification_log(
                title,
                routed_key,
                "suppressed",
                severity=context.severity,
                route_names=decision.route_names,
                channels=decision.channels,
                suppressed_reason=decision.reason,
                environment=context.environment,
                run_type=context.run_type,
                trace_id=context.trace_id,
                incident_id=incident_id,
            )
            return True

        header = format_routing_header(decision)
        routed_text = f"{header}\n\n{text}" if header else text
        try:
            sent = self.notifier.send(title, routed_text, dedupe_key=routed_key)
        except Exception as exc:
            self.storage.save_notification_log(
                title,
                routed_key,
                "failed",
                severity=context.severity,
                route_names=decision.route_names,
                channels=decision.channels,
                error=str(exc),
                environment=context.environment,
                run_type=context.run_type,
                trace_id=context.trace_id,
                incident_id=incident_id,
            )
            raise
        self.storage.save_notification_log(
            title,
            routed_key,
            "sent" if sent else "skipped",
            severity=context.severity,
            route_names=decision.route_names,
            channels=decision.channels,
            environment=context.environment,
            run_type=context.run_type,
            trace_id=context.trace_id,
            incident_id=incident_id,
        )
        return sent

    def send_repeated_alert_if_due(self, incident: dict, results: list[CheckResult]) -> bool:
        alerts = self.config.alerts
        if not alerts.get("repeat_notification_enabled", True):
            return False
        interval_seconds = int(alerts.get("repeat_notification_interval_seconds", 3600))
        if interval_seconds <= 0:
            return False
        now = datetime.now(timezone.utc)
        if not incident_notification_due(incident, interval_seconds, now):
            return False

        incident_id = int(incident["id"])
        title = f"Ops Agent repeated issue reminder #{incident_id}"
        text = build_repeated_alert_message(incident, results, interval_seconds)
        if self.send_alert_notification(
            title,
            text,
            f"repeated:{incident_id}",
            results,
            str(incident.get("severity") or ""),
            incident_id=incident_id,
        ):
            self.storage.update_incident_notification(incident_id, kind="repeat")
            return True
        return False

    def send_escalation_alert_if_due(self, incident: dict, results: list[CheckResult]) -> bool:
        alerts = self.config.alerts
        if not alerts.get("escalation_enabled", True):
            return False
        decision = escalation_decision(incident, alerts)
        if not decision:
            return False

        incident_id = int(incident["id"])
        title = f"[升级] Ops Agent incident #{incident_id} requires attention"
        text = build_escalation_message(incident, results, decision)
        if not self.send_alert_notification(
            title,
            text,
            f"escalation:{incident_id}:{decision['level']}",
            results,
            "critical",
            incident_id=incident_id,
        ):
            return False
        self.storage.escalate_incident(
            incident_id,
            int(decision["level"]),
            str(decision["reason"]),
            metadata=decision,
        )
        return True

    def send_action_failure_escalation_if_needed(
        self,
        incident_id: int,
        action_results: list[ActionResult],
        context_results: list[CheckResult],
    ) -> bool:
        if not self.config.alerts.get("escalation_enabled", True):
            return False
        failed_results = [result for result in action_results if action_failed(result)]
        if not failed_results:
            return False
        incident = self.storage.get_incident(incident_id)
        if not incident or int(incident.get("escalation_level") or 0) >= 1:
            return False
        decision = {
            "level": 1,
            "reason": f"{len(failed_results)} remediation action(s) failed",
            "rule": "remediation_action_failed",
            "failed_actions": [result.action.title for result in failed_results],
            "action_statuses": [result.status for result in action_results],
        }
        title = f"[升级] Ops Agent incident #{incident_id} requires attention"
        text = build_action_failure_escalation_message(incident, context_results, failed_results, decision)
        if not self.send_alert_notification(
            title,
            text,
            f"escalation:{incident_id}:action-failure",
            context_results,
            "critical",
            incident_id=incident_id,
        ):
            return False
        self.storage.escalate_incident(
            incident_id,
            int(decision["level"]),
            str(decision["reason"]),
            metadata=decision,
        )
        return True

    def process_ai_repair_auto_trigger(self, incident_id: int, results: list[CheckResult]) -> dict[str, Any]:
        policy = ai_repair_auto_trigger_policy(self.config)
        incident = self.storage.get_incident(incident_id) or {}
        decision = ai_repair_auto_trigger_decision(incident, results, policy, self.config)
        if decision["status"] != "matched":
            return decision

        existing = self.storage.latest_ai_repair_proposals(incident_id=incident_id, limit=1)
        if existing:
            return {
                "status": "duplicate",
                "reason": "incident already has an AI repair proposal",
                "repair_id": existing[0].get("id"),
                "policy": policy,
            }

        rate_limit = ai_repair_auto_trigger_rate_limit_decision(self.storage, policy)
        if rate_limit["status"] != "allowed":
            current_status = str(incident.get("status") or "open")
            self.storage.record_incident_event(
                incident_id,
                current_status,
                current_status,
                "scheduler",
                "AI repair auto-trigger rate-limited",
                metadata={"rate_limit": rate_limit, "decision": decision},
            )
            return {
                **rate_limit,
                "decision": decision,
                "policy": policy,
            }

        try:
            repair = build_ai_repair_proposal(
                self.storage,
                self.config,
                incident_id,
                request={
                    "actor": "scheduler",
                    "source": "auto_trigger",
                    "environment": incident.get("environment") or context_from_results(results).environment,
                    "run_type": incident.get("run_type") or context_from_results(results).run_type,
                },
            )
            if policy["run_dry_run"]:
                repair = dry_run_ai_repair_proposal(
                    self.storage,
                    int(repair["id"]),
                    actor="scheduler",
                    note="AI repair auto trigger dry-run",
                )
            notify_result: dict[str, Any] = {}
            if policy["notify"]:
                notify_result = notify_ai_repair_approval_queue(
                    self.storage,
                    self.config,
                    notifier=self.notifier,
                    limit=policy["notify_limit"],
                    states=policy["notify_states"],
                    repair_ids=[int(repair["id"])],
                    actor="scheduler",
                )
            current_status = str(incident.get("status") or "open")
            self.storage.record_incident_event(
                incident_id,
                current_status,
                current_status,
                "scheduler",
                "AI repair auto-triggered",
                metadata={
                    "repair_id": repair.get("id"),
                    "repair_status": repair.get("status"),
                    "notification_status": notify_result.get("status", ""),
                    "decision": decision,
                },
            )
            return {
                "status": "triggered",
                "reason": decision["reason"],
                "repair": repair,
                "notification": notify_result,
                "policy": policy,
            }
        except Exception as exc:
            current_status = str(incident.get("status") or "open")
            self.storage.record_incident_event(
                incident_id,
                current_status,
                current_status,
                "scheduler",
                "AI repair auto-trigger failed",
                metadata={"error": str(exc), "decision": decision},
            )
            return {
                "status": "failed",
                "reason": str(exc),
                "policy": policy,
                "decision": decision,
            }

    def process_remediation_actions(
        self,
        actions: list[RemediationAction],
        context_results: list[CheckResult] | None = None,
        incident_id: int | None = None,
    ) -> list[ActionResult]:
        if not actions:
            return []

        remediation = dict(self.config.raw.get("remediation", {}))
        mode = str(remediation.get("mode", "suggest"))
        dry_run = mode != "auto"
        context = context_from_results(context_results or [])
        results: list[ActionResult] = []
        halted_playbooks: set[str] = set()
        for action in actions:
            playbook_name = playbook_identity(action)
            if playbook_name and playbook_name in halted_playbooks:
                result = ActionResult(
                    action=action,
                    status="skipped",
                    error=f"playbook halted after previous failure: {playbook_name}",
                )
                self.record_action_result(result, context, incident_id)
                results.append(result)
                continue

            result = self.execute_and_record_action(action, mode, dry_run, context, incident_id)
            results.append(result)

            if not action_failed(result):
                continue

            handling_results, should_halt = self.handle_playbook_failure(
                action,
                result,
                mode,
                dry_run,
                context,
                incident_id,
            )
            results.extend(handling_results)
            if should_halt and playbook_name:
                halted_playbooks.add(playbook_name)
        return results

    def execute_and_record_action(
        self,
        action: RemediationAction,
        mode: str,
        dry_run: bool,
        context: RunContext,
        incident_id: int | None,
    ) -> ActionResult:
        if mode == "off":
            result = execute_action(action, self.config, dry_run=True)
        elif dry_run or not action.auto_execute:
            result = execute_action(action, self.config, dry_run=True)
        else:
            result = execute_action(action, self.config, dry_run=False)

        action_id = self.record_action_result(result, context, incident_id)
        if result.status != "executed":
            return result

        verification = verify_after_action(action, self.config)
        if verification.status == "verify_skipped":
            return result

        output = verification.output or verification.error
        self.storage.update_action_verification(action_id, verification.status, output)
        return ActionResult(
            action=action,
            status=verification.status,
            output=verification.output,
            error=verification.error,
        )

    def record_action_result(
        self,
        result: ActionResult,
        context: RunContext,
        incident_id: int | None,
    ) -> int:
        return self.storage.save_action_log(
            result.action.action_type,
            result.action.title,
            result.action.risk,
            result.status,
            result.action.reason,
            result.action.params,
            result.output,
            result.error,
            environment=context.environment,
            run_type=context.run_type,
            trace_id=context.trace_id,
            incident_id=incident_id,
        )

    def handle_playbook_failure(
        self,
        action: RemediationAction,
        result: ActionResult,
        mode: str,
        dry_run: bool,
        context: RunContext,
        incident_id: int | None,
    ) -> tuple[list[ActionResult], bool]:
        playbook_name = playbook_identity(action)
        if not playbook_name:
            return [], False

        policy = playbook_failure_policy(action)
        if policy == "continue":
            return [], False

        meta = playbook_meta(action)
        if policy == "escalate":
            self.escalate_playbook_failure(action, result, incident_id, meta)
            return [], True

        if policy == "rollback":
            rollback_results = []
            for rollback_action in playbook_rollback_actions(action):
                rollback_results.append(
                    self.execute_and_record_action(rollback_action, mode, dry_run, context, incident_id)
                )
            return rollback_results, True

        return [], True

    def escalate_playbook_failure(
        self,
        action: RemediationAction,
        result: ActionResult,
        incident_id: int | None,
        meta: dict,
    ) -> None:
        playbook_name = str(meta.get("name") or "")
        step_id = str(meta.get("step_id") or "")
        title = "Ops Agent playbook escalation"
        text = (
            f"Playbook: {playbook_name}\n"
            f"Step: {step_id}\n"
            f"Action: {action.title}\n"
            f"Status: {result.status}\n"
            f"Error: {result.error}"
        )
        self.send_alert_notification(
            title,
            text,
            f"playbook-escalation:{playbook_name}:{step_id}:{result.status}",
            severity="critical",
            incident_id=incident_id,
        )
        if not incident_id:
            return
        try:
            self.storage.transition_incident(
                incident_id,
                "remediating",
                actor="scheduler",
                note="playbook escalation",
                metadata={
                    "playbook": playbook_name,
                    "step_id": step_id,
                    "action_status": result.status,
                    "error": result.error,
                },
            )
        except ValueError:
            return

    def send_daily_report_if_due(self) -> None:
        report_config = self.config.alerts.get("daily_report", {})
        if not report_config.get("enabled", False):
            return

        now = datetime.now()
        report_hour = int(report_config.get("hour", 9))
        today = now.date().isoformat()
        if now.hour != report_hour or self._last_daily_report_date == today:
            return

        since = datetime.now(timezone.utc) - timedelta(hours=24)
        rows = self.storage.recent_results(since.isoformat())
        rows = filter_report_rows(rows, enabled_report_target_keys(self.config))
        title = str(report_config.get("title", "Ops Agent daily report"))
        self.notifier.send(title, build_daily_report(rows), dedupe_key=f"daily-report:{today}")
        self._last_daily_report_date = today

    def run_retention_cleanup_if_due(self) -> None:
        retention = dict(self.config.raw.get("retention", {}))
        if not retention.get("enabled", False):
            return

        now = datetime.now()
        cleanup_hour = int(retention.get("cleanup_hour", 3))
        today = now.date().isoformat()
        if now.hour != cleanup_hour or self._last_retention_cleanup_date == today:
            return

        result = run_retention_cleanup(self.storage, retention, dry_run=False)
        print(format_retention_result(result))
        self._last_retention_cleanup_date = today

    def run_learning_optimization_if_due(self, force: bool = False) -> list[dict]:
        learning = dict(self.config.raw.get("learning", {}))
        if not learning.get("enabled", True):
            return []

        now = time.time()
        interval_seconds = int(learning.get("interval_seconds", 6 * 60 * 60))
        if not force and self._last_learning_optimization_at and now - self._last_learning_optimization_at < interval_seconds:
            return []

        lookback_hours = int(learning.get("lookback_hours", 72))
        max_incidents = int(learning.get("max_incidents", 1000))
        since = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
        incidents = self.storage.recent_incidents(since.isoformat(), limit=max_incidents)
        recommendations = build_learning_recommendations(incidents, learning)
        saved = self.storage.save_learning_recommendations(recommendations)
        self._last_learning_optimization_at = now
        if saved:
            print(f"Learning optimization: {len(saved)} suggestion(s).")
        if saved and learning.get("notify", False):
            self.notifier.send(
                str(learning.get("notification_title", "Ops Agent learning optimization suggestions")),
                format_learning_recommendations(saved),
                dedupe_key="learning-optimization",
            )
        return saved

    def due_checks(self, source: str, checks: list[dict], respect_intervals: bool, now: float) -> list[dict]:
        enabled_checks = [check for check in checks if check.get("enabled", True)]
        if not respect_intervals:
            return enabled_checks

        due: list[dict] = []
        default_interval = int(self.config.app.get("interval_seconds", 60))
        for index, check in enumerate(enabled_checks):
            interval = int(check.get("interval_seconds", default_interval))
            key = f"{source}:{check.get('name', index)}"
            last_run = self._last_run.get(key)
            if last_run is None or now - last_run >= interval:
                due.append(check)
                self._last_run[key] = now
        return due

    def run_forever(self) -> None:
        interval = int(self.config.app.get("interval_seconds", 60))
        print(f"Ops Agent started. Interval: {interval}s. Base: {Path.cwd()}")
        while True:
            started = time.perf_counter()
            try:
                results = self.run_once(respect_intervals=True)
                self.send_daily_report_if_due()
                self.run_retention_cleanup_if_due()
                self.run_learning_optimization_if_due()
                print(f"Check complete: {len(results)} result(s).")
            except Exception as exc:
                print(f"Scheduler error: {exc}")
            elapsed = time.perf_counter() - started
            time.sleep(max(1, interval - elapsed))


def problem_key(problems: list[CheckResult]) -> str:
    return "|".join(f"{item.source}:{item.name}:{item.status}" for item in problems)


def ai_repair_auto_trigger_policy(config: AppConfig) -> dict[str, Any]:
    repair_config = safe_dict(safe_dict(config.raw.get("ai")).get("repair"))
    raw = safe_dict(repair_config.get("auto_trigger"))
    policy = dict(DEFAULT_AI_REPAIR_AUTO_TRIGGER_POLICY)
    for key in ("enabled", "run_dry_run", "notify"):
        if key in raw:
            policy[key] = bool(raw.get(key))
    for key in (
        "severities",
        "categories",
        "excluded_categories",
        "sources",
        "excluded_sources",
        "environments",
        "run_types",
        "notify_states",
    ):
        if key in raw:
            policy[key] = clean_string_list(raw.get(key))
    if "min_classification_confidence" in raw:
        policy["min_classification_confidence"] = safe_float(raw.get("min_classification_confidence"), 0.65)
    if "notify_limit" in raw:
        policy["notify_limit"] = max(1, safe_int(raw.get("notify_limit"), 20))
    if "max_active_proposals" in raw:
        policy["max_active_proposals"] = max(1, safe_int(raw.get("max_active_proposals"), 10))
    if "max_triggers_per_window" in raw:
        policy["max_triggers_per_window"] = max(1, safe_int(raw.get("max_triggers_per_window"), 5))
    if "trigger_window_minutes" in raw:
        policy["trigger_window_minutes"] = max(1, safe_int(raw.get("trigger_window_minutes"), 60))
    return policy


def ai_repair_auto_trigger_decision(
    incident: dict[str, Any],
    results: list[CheckResult],
    policy: dict[str, Any],
    config: AppConfig,
) -> dict[str, Any]:
    if not policy.get("enabled"):
        return {"status": "disabled", "reason": "AI repair auto trigger is disabled", "policy": policy}
    if safe_dict(config.ai).get("enabled") is False:
        return {"status": "disabled", "reason": "AI is disabled", "policy": policy}
    if not incident:
        return {"status": "skipped", "reason": "incident not found", "policy": policy}
    if int(incident.get("false_positive") or 0) == 1:
        return {"status": "skipped", "reason": "incident is marked false positive", "policy": policy}

    severity = str(incident.get("severity") or "").strip().lower()
    allowed_severities = normalized_set(policy.get("severities"))
    if allowed_severities and severity not in allowed_severities:
        return {"status": "not_matched", "reason": f"severity not allowed: {severity}", "policy": policy}

    category = str(incident.get("classification_category") or "").strip().lower()
    excluded_categories = normalized_set(policy.get("excluded_categories"))
    if category and category in excluded_categories:
        return {"status": "not_matched", "reason": f"category excluded: {category}", "policy": policy}
    allowed_categories = normalized_set(policy.get("categories"))
    if allowed_categories and category not in allowed_categories:
        return {"status": "not_matched", "reason": f"category not allowed: {category}", "policy": policy}

    confidence = safe_float(incident.get("classification_confidence"), 0.0)
    min_confidence = safe_float(policy.get("min_classification_confidence"), 0.65)
    if confidence < min_confidence:
        return {
            "status": "not_matched",
            "reason": f"classification confidence too low: {confidence}",
            "policy": policy,
        }

    sources = {result.source.strip().lower() for result in results if result.source}
    allowed_sources = normalized_set(policy.get("sources"))
    if allowed_sources and sources.isdisjoint(allowed_sources):
        return {"status": "not_matched", "reason": "source not allowed", "policy": policy}
    excluded_sources = normalized_set(policy.get("excluded_sources"))
    if excluded_sources and not sources.isdisjoint(excluded_sources):
        return {"status": "not_matched", "reason": "source excluded", "policy": policy}

    environment = str(incident.get("environment") or "").strip().lower()
    allowed_environments = normalized_set(policy.get("environments"))
    if allowed_environments and environment not in allowed_environments:
        return {"status": "not_matched", "reason": f"environment not allowed: {environment}", "policy": policy}

    run_type = str(incident.get("run_type") or "").strip().lower()
    allowed_run_types = normalized_set(policy.get("run_types"))
    if allowed_run_types and run_type not in allowed_run_types:
        return {"status": "not_matched", "reason": f"run type not allowed: {run_type}", "policy": policy}

    return {
        "status": "matched",
        "reason": "incident matched AI repair auto trigger policy",
        "severity": severity,
        "category": category,
        "confidence": confidence,
        "sources": sorted(sources),
        "policy": policy,
    }


def ai_repair_auto_trigger_rate_limit_decision(storage: Storage, policy: dict[str, Any]) -> dict[str, Any]:
    max_active = safe_int(policy.get("max_active_proposals"), 10)
    if max_active > 0:
        active = storage.latest_ai_repair_proposals(
            limit=max_active + 20,
            statuses=AI_REPAIR_QUEUE_ACTIVE_STATUSES,
        )
        active_auto = [repair for repair in active if ai_repair_auto_triggered(repair)]
        if len(active_auto) >= max_active:
            return {
                "status": "rate_limited",
                "reason": f"active auto-triggered AI repair proposals reached limit: {len(active_auto)}/{max_active}",
                "limit_type": "max_active_proposals",
                "active_auto_triggered": len(active_auto),
                "limit": max_active,
            }

    max_window = safe_int(policy.get("max_triggers_per_window"), 5)
    window_minutes = safe_int(policy.get("trigger_window_minutes"), 60)
    if max_window > 0 and window_minutes > 0:
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        recent = storage.latest_ai_repair_proposals(limit=max(max_window + 50, 100))
        recent_auto = [
            repair
            for repair in recent
            if ai_repair_auto_triggered(repair)
            and (parse_datetime(str(repair.get("created_at") or "")) or datetime.min.replace(tzinfo=timezone.utc)) >= since
        ]
        if len(recent_auto) >= max_window:
            return {
                "status": "rate_limited",
                "reason": f"auto-triggered AI repair proposals reached window limit: {len(recent_auto)}/{max_window} in {window_minutes} minutes",
                "limit_type": "max_triggers_per_window",
                "recent_auto_triggered": len(recent_auto),
                "limit": max_window,
                "window_minutes": window_minutes,
            }

    return {"status": "allowed", "reason": "AI repair auto trigger rate limits allow creation"}


def ai_repair_auto_triggered(repair: dict[str, Any]) -> bool:
    prompt = safe_dict(repair.get("prompt"))
    return str(prompt.get("source") or "").strip() == "auto_trigger" or str(prompt.get("requested_by") or "") == "scheduler"


def format_ai_repair_auto_trigger_result(result: dict[str, Any]) -> str:
    repair = safe_dict(result.get("repair"))
    notification = safe_dict(result.get("notification"))
    lines = [
        "",
        "",
        "AI repair auto trigger:",
        f"- status: {result.get('status', '')}",
        f"- reason: {result.get('reason', '')}",
    ]
    if repair:
        lines.extend(
            [
                f"- repair_id: {repair.get('id', '')}",
                f"- repair_status: {repair.get('status', '')}",
                f"- repair_risk: {repair.get('risk', '')}",
                f"- model_provider: {repair.get('model_provider', '')}",
            ]
        )
    if notification:
        lines.append(f"- notification_status: {notification.get('status', '')}")
    return "\n".join(lines)


def incident_fingerprint(results: list[CheckResult]) -> str:
    context = context_from_results(results)
    targets = sorted({check_key(result) for result in results})
    return f"{context.environment}:{context.run_type}:{'|'.join(targets)}"


def classification_payload(
    results: list[CheckResult],
    classification_rules: list[dict] | None = None,
) -> dict:
    classification = classify_incident(
        [result for result in results if result.is_problem],
        classification_rules,
    )
    return incident_classification_to_dict(classification)


def incident_classification_to_dict(classification: IncidentClassification) -> dict:
    return {
        "category": classification.category,
        "confidence": classification.confidence,
        "summary": classification.summary,
        "evidence": classification.evidence,
        "next_steps": classification.next_steps,
    }


def check_key(result: CheckResult) -> str:
    return f"{result.source}:{result.name}"


def build_run_context(config: AppConfig) -> RunContext:
    app = dict(config.app)
    return RunContext(
        environment=clean_context_value(app.get("environment"), "prod"),
        run_type=clean_context_value(app.get("run_type"), "normal"),
    )


def context_from_results(results: list[CheckResult]) -> RunContext:
    if not results:
        return RunContext(trace_id="")
    return RunContext(
        environment=common_context_value([result.environment for result in results], "prod"),
        run_type=common_context_value([result.run_type for result in results], "normal"),
        trace_id=common_context_value([result.trace_id for result in results], ""),
    )


def build_incident_recommendations(
    planned_actions: list[RemediationAction],
    action_results: list[ActionResult],
    config: AppConfig,
    context: RunContext,
) -> list[dict]:
    if action_results:
        return [
            recommendation_from_action_result(index, result, config, context)
            for index, result in enumerate(action_results, start=1)
        ]
    return [
        recommendation_from_action(index, action, config, context, status="suggested")
        for index, action in enumerate(planned_actions, start=1)
    ]


def recommendation_from_action_result(
    position: int,
    result: ActionResult,
    config: AppConfig,
    context: RunContext,
) -> dict:
    status = "suggested" if result.status == "dry_run" else result.status
    recommendation = recommendation_from_action(
        position,
        result.action,
        config,
        context,
        status=status,
    )
    if result.output:
        key = "dry_run_output" if result.status == "dry_run" else "output"
        recommendation["metadata"][key] = result.output
    if result.error:
        recommendation["metadata"]["error"] = result.error
    if result.status == "dry_run":
        recommendation["metadata"]["dry_run_status"] = result.status
    return recommendation


def recommendation_from_action(
    position: int,
    action: RemediationAction,
    config: AppConfig,
    context: RunContext,
    status: str,
) -> dict:
    decision = decide_action_policy(action, config)
    meta = playbook_meta(action)
    approval_required = decision.requires_approval if decision.configured else action.action_type in MUTATING_ACTIONS
    verification_required = bool(decision.verification_required or action.params.get("verify_after"))
    metadata = {
        "policy_configured": decision.configured,
        "policy_name": decision.policy_name,
        "policy_allowed": decision.allowed,
        "policy_reason": decision.reason,
        "playbook": meta,
    }
    return {
        "environment": context.environment,
        "run_type": context.run_type,
        "trace_id": context.trace_id,
        "position": position,
        "category": str(meta.get("stage") or infer_recommendation_category(action.action_type)),
        "action_type": action.action_type,
        "title": action.title,
        "reason": action.reason,
        "risk": action.risk,
        "approval_required": approval_required,
        "auto_execute": action.auto_execute,
        "verification_required": verification_required,
        "status": status,
        "params": public_params(action.params),
        "source": "playbook" if meta else "planner",
        "metadata": metadata,
    }


def infer_recommendation_category(action_type: str) -> str:
    if action_type in {"check_port", "check_process", "run_diagnostic_command"}:
        return "diagnose"
    if action_type in MUTATING_ACTIONS:
        return "remediate"
    return "action"


def common_context_value(values: list[str], default: str) -> str:
    cleaned = [value for value in values if value]
    if not cleaned:
        return default
    first = cleaned[0]
    if all(value == first for value in cleaned):
        return first
    return "mixed"


def clean_context_value(value: object, default: str) -> str:
    text = str(value or "").strip()
    return text or default


def safe_dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def clean_string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def normalized_set(value: Any) -> set[str]:
    return {item.lower() for item in clean_string_list(value)}


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def incident_status_from_action_results(action_results) -> str:
    if not action_results:
        return ""
    if any(result.status == "executed" and result.action.action_type in MUTATING_ACTIONS for result in action_results):
        return "verifying"
    if any(
        result.status not in {"dry_run", "skipped"} and result.action.action_type in MUTATING_ACTIONS
        for result in action_results
    ):
        return "remediating"
    return ""


def alert_threshold_for_result(result: CheckResult, default_threshold: int) -> int:
    for key in ("alert_after_failures", "consecutive_failures"):
        try:
            value = int(result.details.get(key))
        except (TypeError, ValueError):
            continue
        if value > 0:
            return value
    return max(1, int(default_threshold or 1))


def action_failed(result: ActionResult) -> bool:
    return result.status in {"failed", "verified_failed"}


def incident_notification_due(incident: dict, interval_seconds: int, now: datetime | None = None) -> bool:
    now = now or datetime.now(timezone.utc)
    last = parse_datetime(str(incident.get("last_notification_at") or incident.get("created_at") or ""))
    if not last:
        return True
    return (now - last).total_seconds() >= interval_seconds


def parse_datetime(value: str) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def build_repeated_alert_message(incident: dict, results: list[CheckResult], interval_seconds: int) -> str:
    lines = [
        "持续异常提醒",
        "",
        f"事件: #{incident.get('id')} {incident.get('title', '')}",
        f"严重级别: {incident.get('severity', '')}",
        f"当前状态: {incident.get('status', '')}",
        f"累计出现次数: {incident.get('occurrence_count', 0)}",
        f"最近摘要: {incident.get('last_summary', '')}",
        f"提醒间隔: {interval_seconds} 秒",
        "",
        "本轮异常:",
    ]
    for result in results:
        lines.append(f"- [{result.status.upper()}] {result.source}/{result.name}: {result.summary}")
    return "\n".join(lines)


def escalation_decision(
    incident: dict,
    alerts: dict,
    now: datetime | None = None,
) -> dict | None:
    if int(incident.get("escalation_level") or 0) >= 1:
        return None

    now = now or datetime.now(timezone.utc)
    first_seen = parse_datetime(str(incident.get("first_seen_at") or incident.get("created_at") or ""))
    age_seconds = int((now - first_seen).total_seconds()) if first_seen else 0
    age_threshold = int(alerts.get("escalation_after_seconds", 1800))
    if age_threshold > 0 and age_seconds >= age_threshold:
        return {
            "level": 1,
            "reason": f"incident active for {age_seconds} seconds",
            "rule": "active_duration",
            "age_seconds": age_seconds,
            "threshold_seconds": age_threshold,
        }

    critical_threshold = int(alerts.get("escalation_critical_occurrences", 10))
    occurrence_count = int(incident.get("occurrence_count") or 0)
    if (
        critical_threshold > 0
        and str(incident.get("severity") or "") == "critical"
        and occurrence_count >= critical_threshold
    ):
        return {
            "level": 1,
            "reason": f"critical incident occurred {occurrence_count} times",
            "rule": "critical_occurrences",
            "occurrence_count": occurrence_count,
            "threshold_count": critical_threshold,
        }
    return None


def build_escalation_message(incident: dict, results: list[CheckResult], decision: dict) -> str:
    lines = [
        "事件升级提醒",
        "",
        f"事件: #{incident.get('id')} {incident.get('title', '')}",
        f"升级级别: L{decision.get('level')}",
        f"升级原因: {decision.get('reason')}",
        f"严重级别: {incident.get('severity', '')}",
        f"当前状态: {incident.get('status', '')}",
        f"累计出现次数: {incident.get('occurrence_count', 0)}",
        f"首次出现: {incident.get('first_seen_at', '')}",
        f"最近出现: {incident.get('last_seen_at', '')}",
        f"最近摘要: {incident.get('last_summary', '')}",
        "",
        "本轮异常:",
    ]
    for result in results:
        lines.append(f"- [{result.status.upper()}] {result.source}/{result.name}: {result.summary}")
    lines.extend(
        [
            "",
            "建议处理:",
            "1. 优先人工确认影响范围和最近发布/配置变更。",
            "2. 查看事件关联的处置动作和验证结果。",
            "3. 如果确认是生产影响，按内部流程处理并在事件中心记录状态。",
        ]
    )
    return "\n".join(lines)


def build_action_failure_escalation_message(
    incident: dict,
    results: list[CheckResult],
    failed_results: list[ActionResult],
    decision: dict,
) -> str:
    lines = build_escalation_message(incident, results, decision).splitlines()
    lines.extend(["", "失败动作:"])
    for result in failed_results:
        lines.append(f"- [{result.status}] {result.action.title}")
        if result.error:
            lines.append(f"  错误: {result.error}")
        if result.output:
            lines.append(f"  输出: {result.output}")
    return "\n".join(lines)


def format_persisted_diagnosis_for_analysis(diagnosis: dict) -> str:
    causes = diagnosis.get("probable_causes") or []
    top = causes[0] if causes else {}
    decision = diagnosis.get("next_decision") or {}
    evidence = diagnosis.get("evidence") or {}
    signal_count = len(evidence.get("monitor_signals") or [])
    collected = evidence.get("collected") or {}
    collected_count = sum(len(value or []) for value in collected.values() if isinstance(value, list))
    return (
        "\n\n自动诊断记录:\n"
        f"- 诊断ID: {diagnosis.get('diagnosis_id', '')}\n"
        f"- 可能原因: {top.get('category', 'unknown')} confidence={top.get('confidence', 0)}\n"
        f"- 下一步: {decision.get('action', 'manual_triage')}\n"
        f"- 监控信号: {signal_count} 条；采集证据: {collected_count} 条\n"
    )


def build_recovery_message(results: list[CheckResult]) -> str:
    lines = ["以下监控项已经恢复正常:", ""]
    for result in results:
        lines.append(f"- {result.source}/{result.name}: {result.summary}")
    return "\n".join(lines)


def enabled_report_target_keys(config: AppConfig) -> set[tuple[str, str]]:
    targets: set[tuple[str, str]] = set()
    add_check_targets(targets, "http", config.http_checks, ("name", "url"), "HTTP check")
    add_check_targets(targets, "json_api", config.json_checks, ("name", "url"), "JSON API check")
    add_check_targets(targets, "business_flow", config.business_flow_checks, ("name",), "Business flow")
    add_check_targets(targets, "docker", config.docker_checks, ("name", "container"), "Docker container")
    add_log_targets(targets, config.log_checks)

    if config.server_checks.get("enabled", True):
        targets.update(
            {
                ("server", "Disk usage"),
                ("server", "Memory usage"),
                ("server", "CPU usage"),
                ("server", "Load average"),
            }
        )

    return targets


def add_check_targets(
    targets: set[tuple[str, str]],
    source: str,
    checks: list[dict[str, Any]],
    name_keys: tuple[str, ...],
    fallback: str,
) -> None:
    for check in checks:
        if not check.get("enabled", True):
            continue
        targets.add((source, configured_check_name(check, name_keys, fallback)))


def add_log_targets(targets: set[tuple[str, str]], checks: list[dict[str, Any]]) -> None:
    for check in checks:
        if not check.get("enabled", True):
            continue
        if check.get("container"):
            name = configured_check_name(check, ("name", "container"), "Docker log check")
        else:
            name = configured_check_name(check, ("name", "path"), "Log check")
        targets.add(("log", name))


def configured_check_name(check: dict[str, Any], keys: tuple[str, ...], fallback: str) -> str:
    for key in keys:
        value = str(check.get(key) or "").strip()
        if value:
            return value
    return fallback


def filter_report_rows(rows: list[dict], target_keys: set[tuple[str, str]]) -> list[dict]:
    if not target_keys:
        return []
    return [
        row
        for row in rows
        if (str(row.get("source") or ""), str(row.get("name") or "")) in target_keys
    ]


def build_daily_report(rows: list[dict]) -> str:
    total = len(rows)
    warnings = sum(1 for row in rows if row.get("status") == "warning")
    critical = sum(1 for row in rows if row.get("status") == "critical")
    ok = sum(1 for row in rows if row.get("status") == "ok")
    latest: dict[str, dict] = {}
    for row in rows:
        latest[f"{row.get('source')}/{row.get('name')}"] = row

    lines = [
        "AI 运维监控日报",
        "",
        f"过去 24 小时巡检记录: {total} 条",
        f"正常: {ok} 条; 警告: {warnings} 条; 严重: {critical} 条",
        "",
        "当前最近状态:",
    ]
    for key, row in sorted(latest.items()):
        lines.append(f"- [{row.get('status')}] {key}: {row.get('summary')}")
    return "\n".join(lines)

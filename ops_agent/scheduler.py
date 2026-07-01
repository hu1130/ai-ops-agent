from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import time
from pathlib import Path

from ops_agent.ai.analyzer import analyze_incident
from ops_agent.alerts.notifier import Notifier
from ops_agent.config import AppConfig
from ops_agent.diagnostics.collector import collect_diagnostics, format_snapshot
from ops_agent.diagnostics.suggestions import build_action_suggestions
from ops_agent.events import CheckResult, RunContext, apply_context
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
from ops_agent.remediation.planner import build_remediation_plan
from ops_agent.remediation.verifier import verify_after_action
from ops_agent.retention import format_retention_result, run_retention_cleanup
from ops_agent.storage import Storage, fingerprint_target_keys


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

    def run_once(self, respect_intervals: bool = False) -> list[CheckResult]:
        cycle_started_at = time.time()
        context = build_run_context(self.config)
        results: list[CheckResult] = []
        results.extend(run_http_checks(self.due_checks("http", self.config.http_checks, respect_intervals, cycle_started_at)))
        results.extend(run_json_checks(self.due_checks("json", self.config.json_checks, respect_intervals, cycle_started_at)))
        results.extend(run_server_checks(self.config.server_checks, self.config.base_dir))
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
                if not state.is_open and state.failure_count >= threshold:
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
            self.update_existing_incident(incident_id, repeated_results)

        if new_alerts:
            severity = "critical" if any(item.status == "critical" for item in new_alerts) else "warning"
            title = f"Ops Agent detected {len(new_alerts)} issue(s)"
            fingerprint = incident_fingerprint(new_alerts)
            existing = self.storage.find_active_incident_by_fingerprint(fingerprint)
            if existing:
                incident_id = int(existing["id"])
                self.update_existing_incident(incident_id, new_alerts, severity=severity, title=title)
                for result in new_alerts:
                    self._issues[check_key(result)].incident_id = incident_id
                new_alerts = []

        if new_alerts:
            severity = "critical" if any(item.status == "critical" for item in new_alerts) else "warning"
            title = f"Ops Agent detected {len(new_alerts)} issue(s)"
            fingerprint = incident_fingerprint(new_alerts)
            analysis = analyze_incident(new_alerts, self.config.ai)
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
            )
            action_results = self.process_remediation_actions(action_plan, new_alerts, incident_id=incident_id)
            remediation_text = format_action_plan(action_plan, action_results)
            analysis = f"{analysis}{remediation_text}"
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
            self.notifier.send(title, analysis, dedupe_key=problem_key(new_alerts))

        if recoveries:
            title = f"Ops Agent recovered {len(recoveries)} issue(s)"
            text = build_recovery_message(recoveries)
            self.storage.save_incident("ok", title, text, recoveries)
            for incident_id in sorted(recovery_incident_ids):
                self.storage.transition_incident(
                    incident_id,
                    "resolved",
                    actor="scheduler",
                    note="monitor recovered",
                    metadata={"recovered_checks": [check_key(result) for result in recoveries]},
                )
            self.notifier.send(title, text, dedupe_key="recovered:" + problem_key(recoveries))

    def update_existing_incident(
        self,
        incident_id: int,
        results: list[CheckResult],
        severity: str = "",
        title: str = "",
    ) -> None:
        if not results:
            return
        merged_severity = severity or ("critical" if any(item.status == "critical" for item in results) else "warning")
        merged_title = title or f"Ops Agent detected {len(results)} issue(s)"
        try:
            self.storage.update_incident_occurrence(
                incident_id,
                merged_severity,
                merged_title,
                results,
                increment=len(results),
            )
        except ValueError:
            return

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
        self.notifier.send(title, text, dedupe_key=f"playbook-escalation:{playbook_name}:{step_id}:{result.status}")
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

    def due_checks(self, source: str, checks: list[dict], respect_intervals: bool, now: float) -> list[dict]:
        if not respect_intervals:
            return checks

        due: list[dict] = []
        default_interval = int(self.config.app.get("interval_seconds", 60))
        for index, check in enumerate(checks):
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
                print(f"Check complete: {len(results)} result(s).")
            except Exception as exc:
                print(f"Scheduler error: {exc}")
            elapsed = time.perf_counter() - started
            time.sleep(max(1, interval - elapsed))


def problem_key(problems: list[CheckResult]) -> str:
    return "|".join(f"{item.source}:{item.name}:{item.status}" for item in problems)


def incident_fingerprint(results: list[CheckResult]) -> str:
    context = context_from_results(results)
    targets = sorted({check_key(result) for result in results})
    return f"{context.environment}:{context.run_type}:{'|'.join(targets)}"


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


def action_failed(result: ActionResult) -> bool:
    return result.status in {"failed", "verified_failed"}


def build_recovery_message(results: list[CheckResult]) -> str:
    lines = ["以下监控项已经恢复正常:", ""]
    for result in results:
        lines.append(f"- {result.source}/{result.name}: {result.summary}")
    return "\n".join(lines)


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

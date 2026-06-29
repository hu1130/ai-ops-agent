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
from ops_agent.events import CheckResult
from ops_agent.monitors.http_monitor import run_http_checks
from ops_agent.monitors.json_api_monitor import run_json_checks
from ops_agent.monitors.log_monitor import run_log_checks
from ops_agent.monitors.server_monitor import run_server_checks
from ops_agent.remediation.executor import execute_action, format_action_plan
from ops_agent.remediation.planner import build_remediation_plan
from ops_agent.storage import Storage


@dataclass
class IssueState:
    failure_count: int = 0
    is_open: bool = False
    last_summary: str = ""


class OpsScheduler:
    def __init__(self, config: AppConfig, storage: Storage, notifier: Notifier):
        self.config = config
        self.storage = storage
        self.notifier = notifier
        self._last_run: dict[str, float] = {}
        self._issues: dict[str, IssueState] = {}
        self._last_daily_report_date: str = ""

    def run_once(self, respect_intervals: bool = False) -> list[CheckResult]:
        cycle_started_at = time.time()
        results: list[CheckResult] = []
        results.extend(run_http_checks(self.due_checks("http", self.config.http_checks, respect_intervals, cycle_started_at)))
        results.extend(run_json_checks(self.due_checks("json", self.config.json_checks, respect_intervals, cycle_started_at)))
        results.extend(run_server_checks(self.config.server_checks, self.config.base_dir))
        results.extend(run_log_checks(self.due_checks("log", self.config.log_checks, respect_intervals, cycle_started_at), self.config.base_dir))
        if results:
            self.storage.save_results(results)

        self.process_alert_states(results)

        return results

    def process_alert_states(self, results: list[CheckResult]) -> None:
        threshold = int(self.config.alerts.get("consecutive_failures", 2))
        recovery_enabled = bool(self.config.alerts.get("recovery_enabled", True))
        new_alerts: list[CheckResult] = []
        recoveries: list[CheckResult] = []

        for result in results:
            key = check_key(result)
            state = self._issues.setdefault(key, IssueState())
            if result.is_problem:
                state.failure_count += 1
                state.last_summary = result.summary
                if not state.is_open and state.failure_count >= threshold:
                    state.is_open = True
                    new_alerts.append(result)
            else:
                if state.is_open and recovery_enabled:
                    recoveries.append(result)
                state.failure_count = 0
                state.is_open = False
                state.last_summary = result.summary

        if new_alerts:
            severity = "critical" if any(item.status == "critical" for item in new_alerts) else "warning"
            title = f"Ops Agent detected {len(new_alerts)} issue(s)"
            analysis = analyze_incident(new_alerts, self.config.ai)
            diagnostics = format_snapshot(collect_diagnostics(new_alerts, self.config))
            suggestions = build_action_suggestions(new_alerts)
            action_plan = build_remediation_plan(new_alerts, self.config)
            action_results = self.process_remediation_actions(action_plan)
            remediation_text = format_action_plan(action_plan, action_results)
            analysis = f"{analysis}{suggestions}{diagnostics}{remediation_text}"
            self.storage.save_incident(severity, title, analysis, new_alerts)
            self.notifier.send(title, analysis, dedupe_key=problem_key(new_alerts))

        if recoveries:
            title = f"Ops Agent recovered {len(recoveries)} issue(s)"
            text = build_recovery_message(recoveries)
            self.storage.save_incident("ok", title, text, recoveries)
            self.notifier.send(title, text, dedupe_key="recovered:" + problem_key(recoveries))

    def process_remediation_actions(self, actions):
        if not actions:
            return []

        remediation = dict(self.config.raw.get("remediation", {}))
        mode = str(remediation.get("mode", "suggest"))
        dry_run = mode != "auto"
        results = []
        for action in actions:
            if mode == "off":
                result = execute_action(action, self.config, dry_run=True)
            elif dry_run or not action.auto_execute:
                result = execute_action(action, self.config, dry_run=True)
            else:
                result = execute_action(action, self.config, dry_run=False)
            self.storage.save_action_log(
                action.action_type,
                action.title,
                action.risk,
                result.status,
                action.reason,
                action.params,
                result.output,
                result.error,
            )
            results.append(result)
        return results

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
                print(f"Check complete: {len(results)} result(s).")
            except Exception as exc:
                print(f"Scheduler error: {exc}")
            elapsed = time.perf_counter() - started
            time.sleep(max(1, interval - elapsed))


def problem_key(problems: list[CheckResult]) -> str:
    return "|".join(f"{item.source}:{item.name}:{item.status}" for item in problems)


def check_key(result: CheckResult) -> str:
    return f"{result.source}:{result.name}"


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

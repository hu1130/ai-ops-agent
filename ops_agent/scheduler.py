from __future__ import annotations

import time
from pathlib import Path

from ops_agent.ai.analyzer import analyze_incident
from ops_agent.alerts.notifier import Notifier
from ops_agent.config import AppConfig
from ops_agent.events import CheckResult
from ops_agent.monitors.http_monitor import run_http_checks
from ops_agent.monitors.json_api_monitor import run_json_checks
from ops_agent.monitors.log_monitor import run_log_checks
from ops_agent.monitors.server_monitor import run_server_checks
from ops_agent.storage import Storage


class OpsScheduler:
    def __init__(self, config: AppConfig, storage: Storage, notifier: Notifier):
        self.config = config
        self.storage = storage
        self.notifier = notifier
        self._last_run: dict[str, float] = {}

    def run_once(self, respect_intervals: bool = False) -> list[CheckResult]:
        results: list[CheckResult] = []
        results.extend(run_http_checks(self.due_checks("http", self.config.http_checks, respect_intervals)))
        results.extend(run_json_checks(self.due_checks("json", self.config.json_checks, respect_intervals)))
        results.extend(run_server_checks(self.config.server_checks, self.config.base_dir))
        results.extend(run_log_checks(self.due_checks("log", self.config.log_checks, respect_intervals), self.config.base_dir))
        if results:
            self.storage.save_results(results)

        problems = [result for result in results if result.is_problem]
        if problems:
            severity = "critical" if any(item.status == "critical" for item in problems) else "warning"
            title = f"Ops Agent detected {len(problems)} issue(s)"
            analysis = analyze_incident(results, self.config.ai)
            self.storage.save_incident(severity, title, analysis, problems)
            self.notifier.send(title, analysis, dedupe_key=problem_key(problems))

        return results

    def due_checks(self, source: str, checks: list[dict], respect_intervals: bool) -> list[dict]:
        if not respect_intervals:
            return checks

        now = time.time()
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
                print(f"Check complete: {len(results)} result(s).")
            except Exception as exc:
                print(f"Scheduler error: {exc}")
            elapsed = time.perf_counter() - started
            time.sleep(max(1, interval - elapsed))


def problem_key(problems: list[CheckResult]) -> str:
    return "|".join(f"{item.source}:{item.name}:{item.status}" for item in problems)

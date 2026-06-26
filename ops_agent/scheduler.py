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

    def run_once(self) -> list[CheckResult]:
        results: list[CheckResult] = []
        results.extend(run_http_checks(self.config.http_checks))
        results.extend(run_json_checks(self.config.json_checks))
        results.extend(run_server_checks(self.config.server_checks, self.config.base_dir))
        results.extend(run_log_checks(self.config.log_checks, self.config.base_dir))
        self.storage.save_results(results)

        problems = [result for result in results if result.is_problem]
        if problems:
            severity = "critical" if any(item.status == "critical" for item in problems) else "warning"
            title = f"Ops Agent detected {len(problems)} issue(s)"
            analysis = analyze_incident(results, self.config.ai)
            self.storage.save_incident(severity, title, analysis, problems)
            self.notifier.send(title, analysis, dedupe_key=problem_key(problems))

        return results

    def run_forever(self) -> None:
        interval = int(self.config.app.get("interval_seconds", 60))
        print(f"Ops Agent started. Interval: {interval}s. Base: {Path.cwd()}")
        while True:
            started = time.perf_counter()
            try:
                results = self.run_once()
                print(f"Check complete: {len(results)} result(s).")
            except Exception as exc:
                print(f"Scheduler error: {exc}")
            elapsed = time.perf_counter() - started
            time.sleep(max(1, interval - elapsed))


def problem_key(problems: list[CheckResult]) -> str:
    return "|".join(f"{item.source}:{item.name}:{item.status}" for item in problems)

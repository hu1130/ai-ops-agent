from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from ops_agent.storage import Storage


@dataclass(frozen=True)
class RetentionResult:
    deleted_check_results: int = 0
    deleted_incidents: int = 0
    deleted_action_logs: int = 0
    vacuumed: bool = False
    dry_run: bool = True

    @property
    def total_deleted(self) -> int:
        return self.deleted_check_results + self.deleted_incidents + self.deleted_action_logs

    def to_dict(self) -> dict[str, Any]:
        return {
            "deleted_check_results": self.deleted_check_results,
            "deleted_incidents": self.deleted_incidents,
            "deleted_action_logs": self.deleted_action_logs,
            "total_deleted": self.total_deleted,
            "vacuumed": self.vacuumed,
            "dry_run": self.dry_run,
        }


def run_retention_cleanup(storage: Storage, config: dict[str, Any], dry_run: bool = False) -> RetentionResult:
    if not config.get("enabled", True):
        return RetentionResult(dry_run=dry_run)

    now = datetime.now(timezone.utc)
    check_days = int(config.get("check_results_days", 30))
    check_cutoff = cutoff(now, check_days)
    incident_cutoff = cutoff(now, int(config.get("incidents_days", 90)))
    action_cutoff = cutoff(now, int(config.get("action_logs_days", 90)))
    configured_problem_days = int(config.get("problem_results_days", max(90, check_days)))
    keep_problem_days = max(check_days, configured_problem_days)
    problem_cutoff = cutoff(now, keep_problem_days)
    test_results_days = int(config.get("test_results_days", 7))
    test_incidents_days = int(config.get("test_incidents_days", max(7, test_results_days)))
    test_action_logs_days = int(config.get("test_action_logs_days", max(7, test_results_days)))
    test_check_cutoff = cutoff(now, test_results_days)
    test_incident_cutoff = cutoff(now, test_incidents_days)
    test_action_cutoff = cutoff(now, test_action_logs_days)
    test_environments = string_list(config.get("test_environments", ["test"]))
    test_run_types = string_list(config.get("test_run_types", ["manual_test", "synthetic_test"]))

    if dry_run:
        counts = storage.count_retention_candidates(
            check_cutoff,
            problem_cutoff,
            incident_cutoff,
            action_cutoff,
            test_check_cutoff,
            test_incident_cutoff,
            test_action_cutoff,
            test_environments,
            test_run_types,
        )
        return RetentionResult(
            deleted_check_results=counts["check_results"],
            deleted_incidents=counts["incidents"],
            deleted_action_logs=counts["action_logs"],
            dry_run=True,
        )

    deleted = storage.delete_retention_candidates(
        check_cutoff,
        problem_cutoff,
        incident_cutoff,
        action_cutoff,
        test_check_cutoff,
        test_incident_cutoff,
        test_action_cutoff,
        test_environments,
        test_run_types,
    )
    vacuumed = bool(config.get("vacuum", False)) and sum(deleted.values()) > 0
    if vacuumed:
        storage.vacuum()
    return RetentionResult(
        deleted_check_results=deleted["check_results"],
        deleted_incidents=deleted["incidents"],
        deleted_action_logs=deleted["action_logs"],
        vacuumed=vacuumed,
        dry_run=False,
    )


def cutoff(now: datetime, days: int) -> str:
    return (now - timedelta(days=max(1, days))).isoformat()


def string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return []


def format_retention_result(result: RetentionResult) -> str:
    mode = "预览" if result.dry_run else "执行"
    return (
        f"数据保留清理{mode}结果:\n"
        f"- check_results: {result.deleted_check_results}\n"
        f"- incidents: {result.deleted_incidents}\n"
        f"- action_logs: {result.deleted_action_logs}\n"
        f"- total: {result.total_deleted}\n"
        f"- vacuumed: {result.vacuumed}"
    )

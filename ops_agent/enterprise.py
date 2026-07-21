from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any

from ops_agent.config import AppConfig
from ops_agent.heartbeat import heartbeat_policy
from ops_agent.monitor_targets import list_monitor_targets
from ops_agent.projects import list_projects
from ops_agent.remediation.executor import MUTATING_ACTIONS


@dataclass(frozen=True)
class ReadinessCheck:
    category: str
    name: str
    status: str
    summary: str
    detail: dict[str, Any]


def enterprise_readiness_snapshot(config: AppConfig) -> dict[str, Any]:
    checks: list[ReadinessCheck] = []
    checks.extend(project_governance_checks(config))
    checks.extend(alert_governance_checks(config))
    checks.extend(remediation_governance_checks(config))
    checks.extend(ai_repair_governance_checks(config))
    checks.extend(resilience_governance_checks(config))
    checks.extend(storage_and_audit_checks(config))
    checks.extend(security_governance_checks(config))

    counts = status_counts(checks)
    status = overall_status(counts)
    return {
        "status": status,
        "score": readiness_score(counts, len(checks)),
        "summary": {
            "total": len(checks),
            "passed": counts.get("pass", 0),
            "warnings": counts.get("warning", 0),
            "blockers": counts.get("blocker", 0),
        },
        "checks": [check.__dict__ for check in checks],
        "next_steps": next_steps(checks),
    }


def project_governance_checks(config: AppConfig) -> list[ReadinessCheck]:
    projects = list_projects(config)
    targets = enabled_monitor_targets(config)
    checks = [
        ReadinessCheck(
            "projects",
            "project_inventory",
            "pass" if projects else "blocker",
            f"{len(projects)} project(s) configured.",
            {"project_ids": [str(project.get("id") or "") for project in projects]},
        )
    ]

    enabled_projects = [project for project in projects if bool(project.get("enabled", True))]
    disabled_projects = [project for project in projects if not bool(project.get("enabled", True))]
    checks.append(
        ReadinessCheck(
            "projects",
            "enabled_project_inventory",
            "pass" if enabled_projects else "warning",
            f"{len(enabled_projects)} enabled project(s), {len(disabled_projects)} disabled project(s).",
            {
                "enabled": [str(project.get("id") or "") for project in enabled_projects],
                "disabled": [str(project.get("id") or "") for project in disabled_projects],
            },
        )
    )

    stale = disabled_project_target_matches(disabled_projects, targets)
    checks.append(
        ReadinessCheck(
            "projects",
            "disabled_project_monitor_drift",
            "blocker" if stale else "pass",
            "Disabled projects have enabled monitor targets." if stale else "Disabled projects do not have enabled monitor targets.",
            {"matches": stale},
        )
    )

    uncovered = uncovered_enabled_projects(enabled_projects, targets)
    checks.append(
        ReadinessCheck(
            "projects",
            "enabled_project_monitor_coverage",
            "warning" if uncovered else "pass",
            "Some enabled projects have no obvious monitor target." if uncovered else "Enabled projects have monitor coverage.",
            {"uncovered_project_ids": uncovered},
        )
    )
    return checks


def alert_governance_checks(config: AppConfig) -> list[ReadinessCheck]:
    alerts = safe_dict(config.raw.get("alerts"))
    email = safe_dict(alerts.get("email"))
    channels = string_list(alerts.get("default_channels"))
    routes = [route for route in safe_list(alerts.get("routes")) if isinstance(route, dict) and route.get("enabled", True)]
    silence_windows = [
        window for window in safe_list(alerts.get("silence_windows")) if isinstance(window, dict) and window.get("enabled", True)
    ]
    has_delivery = bool(str(alerts.get("webhook_url") or "").strip()) or bool(email.get("enabled")) or bool(channels) or bool(routes)
    repeat_enabled = bool(alerts.get("repeat_notification_enabled", True))
    repeat_interval = int(alerts.get("repeat_notification_interval_seconds", 3600) or 3600)
    repeat_ok = repeat_enabled and repeat_interval > 0
    noise_status = "pass" if repeat_ok and silence_windows else "warning"
    if repeat_ok and silence_windows:
        noise_summary = "Repeat alert interval and silence windows are configured."
    elif repeat_ok:
        noise_summary = "Repeat alert interval is configured, but no active silence windows are configured."
    else:
        noise_summary = "Repeat alert interval is not fully configured."
    return [
        ReadinessCheck(
            "alerts",
            "notification_delivery",
            "pass" if has_delivery else "blocker",
            "At least one alert delivery path is configured." if has_delivery else "No alert delivery path is configured.",
            {
                "webhook": bool(str(alerts.get("webhook_url") or "").strip()),
                "email": bool(email.get("enabled")),
                "default_channels": channels,
                "enabled_routes": [str(route.get("name") or "") for route in routes],
            },
        ),
        ReadinessCheck(
            "alerts",
            "noise_controls",
            noise_status,
            noise_summary,
            {
                "repeat_notification_enabled": repeat_enabled,
                "repeat_notification_interval_seconds": repeat_interval,
                "silence_windows": [str(window.get("name") or "") for window in silence_windows],
            },
        ),
        ReadinessCheck(
            "alerts",
            "escalation_policy",
            "pass" if alerts.get("escalation_enabled", True) else "warning",
            "Escalation is enabled." if alerts.get("escalation_enabled", True) else "Escalation is disabled.",
            {
                "escalation_enabled": bool(alerts.get("escalation_enabled", True)),
                "escalation_after_seconds": int(alerts.get("escalation_after_seconds", 0) or 0),
            },
        ),
    ]


def resilience_governance_checks(config: AppConfig) -> list[ReadinessCheck]:
    database_checks = [
        item
        for item in safe_list(config.raw.get("database_checks"))
        if isinstance(item, dict) and item.get("enabled", True)
    ]
    discovery = safe_dict(config.raw.get("asset_discovery"))
    backups = safe_dict(config.raw.get("backups"))
    heartbeat = heartbeat_policy(config)
    heartbeat_configured = bool(heartbeat.get("enabled")) and bool(heartbeat.get("url"))
    backup_targets = [
        item
        for item in safe_list(backups.get("targets"))
        if isinstance(item, dict) and item.get("enabled", True)
    ]
    targets_without_drill = [
        str(target.get("id") or "")
        for target in backup_targets
        if not safe_dict(target.get("restore_drill")).get("enabled", False)
    ]
    return [
        ReadinessCheck(
            "resilience",
            "database_monitoring",
            "pass" if database_checks else "warning",
            f"{len(database_checks)} database monitor(s) configured."
            if database_checks
            else "No database query monitor is configured.",
            {"database_monitors": [str(item.get("name") or item.get("container") or "") for item in database_checks]},
        ),
        ReadinessCheck(
            "resilience",
            "runtime_asset_discovery",
            "pass" if discovery.get("enabled", False) else "warning",
            "Runtime asset discovery is enabled."
            if discovery.get("enabled", False)
            else "Runtime asset discovery is disabled.",
            {"enabled": bool(discovery.get("enabled", False))},
        ),
        ReadinessCheck(
            "resilience",
            "backup_policy",
            "pass" if backups.get("enabled", False) and backup_targets else "warning",
            f"{len(backup_targets)} backup target(s) configured."
            if backups.get("enabled", False) and backup_targets
            else "Automated backups are not fully configured.",
            {"enabled": bool(backups.get("enabled", False)), "target_ids": [str(item.get("id") or "") for item in backup_targets]},
        ),
        ReadinessCheck(
            "resilience",
            "restore_drill_policy",
            "pass" if backup_targets and not targets_without_drill else "warning",
            "All backup targets have isolated restore drills enabled."
            if backup_targets and not targets_without_drill
            else "Some backup targets do not have restore drills enabled.",
            {"targets_without_restore_drill": targets_without_drill},
        ),
        ReadinessCheck(
            "resilience",
            "external_deadman_heartbeat",
            "pass" if heartbeat_configured else "warning",
            "External dead-man heartbeat is configured."
            if heartbeat_configured
            else "External dead-man heartbeat is not configured.",
            {"enabled": bool(heartbeat.get("enabled")), "url_env": str(heartbeat.get("url_env") or "")},
        ),
    ]
def remediation_governance_checks(config: AppConfig) -> list[ReadinessCheck]:
    remediation = safe_dict(config.raw.get("remediation"))
    policies = [policy for policy in safe_list(remediation.get("policies")) if isinstance(policy, dict)]
    playbooks = [playbook for playbook in safe_list(remediation.get("playbooks")) if isinstance(playbook, dict) and playbook.get("enabled", True)]
    unsafe = unsafe_mutating_policies(policies)
    verification = safe_dict(remediation.get("verification"))
    guardrails = safe_dict(remediation.get("guardrails"))
    return [
        ReadinessCheck(
            "remediation",
            "remediation_enabled",
            "pass" if remediation.get("enabled", False) else "warning",
            "Remediation engine is enabled." if remediation.get("enabled", False) else "Remediation engine is disabled.",
            {"mode": str(remediation.get("mode") or ""), "enabled": bool(remediation.get("enabled", False))},
        ),
        ReadinessCheck(
            "remediation",
            "policy_allowlist",
            "pass" if policies else "blocker",
            f"{len(policies)} remediation policie(s) configured." if policies else "No remediation policy allowlist is configured.",
            {"policy_names": [str(policy.get("name") or policy.get("action_type") or "") for policy in policies]},
        ),
        ReadinessCheck(
            "remediation",
            "mutating_action_guardrails",
            "blocker" if unsafe else "pass",
            "Unsafe mutating remediation policies were found." if unsafe else "Mutating remediation policies require approval and verification.",
            {"unsafe_policies": unsafe},
        ),
        ReadinessCheck(
            "remediation",
            "verification_closed_loop",
            "pass" if verification.get("enabled", False) else "warning",
            "Post-action verification is enabled." if verification.get("enabled", False) else "Post-action verification is disabled.",
            {"verification": verification},
        ),
        ReadinessCheck(
            "remediation",
            "playbook_inventory",
            "pass" if playbooks else "warning",
            f"{len(playbooks)} enabled playbook(s)." if playbooks else "No enabled remediation playbooks.",
            {"playbooks": [str(playbook.get("name") or "") for playbook in playbooks]},
        ),
        ReadinessCheck(
            "remediation",
            "mutating_guardrail_thresholds",
            "pass" if guardrails else "warning",
            "Mutating action guardrail thresholds are configured." if guardrails else "Mutating action guardrail thresholds are not configured.",
            {"guardrails": guardrails},
        ),
    ]


def ai_repair_governance_checks(config: AppConfig) -> list[ReadinessCheck]:
    ai = safe_dict(config.raw.get("ai"))
    repair = safe_dict(ai.get("repair"))
    policy = safe_dict(repair.get("policy"))
    auto_trigger = safe_dict(repair.get("auto_trigger"))
    auto_approve = bool(policy.get("auto_approve", False))
    return [
        ReadinessCheck(
            "ai_repair",
            "ai_repair_policy",
            "pass" if policy else "warning",
            "AI repair policy is configured." if policy else "AI repair policy is not configured.",
            {"provider": str(repair.get("provider") or ""), "policy": redact_policy(policy)},
        ),
        ReadinessCheck(
            "ai_repair",
            "human_approval_default",
            "warning" if auto_approve else "pass",
            "AI repair auto approval is enabled." if auto_approve else "AI repair requires human approval by default.",
            {"auto_approve": auto_approve, "auto_approve_risks": string_list(policy.get("auto_approve_risks"))},
        ),
        ReadinessCheck(
            "ai_repair",
            "auto_trigger_safety",
            "pass" if not auto_trigger.get("enabled", False) or auto_trigger.get("run_dry_run", True) else "warning",
            "AI repair auto trigger is dry-run or disabled." if not auto_trigger.get("enabled", False) or auto_trigger.get("run_dry_run", True) else "AI repair auto trigger can run without dry-run.",
            {"auto_trigger": auto_trigger},
        ),
    ]


def storage_and_audit_checks(config: AppConfig) -> list[ReadinessCheck]:
    app = safe_dict(config.raw.get("app"))
    retention = safe_dict(config.raw.get("retention"))
    database_path = str(app.get("database_path") or "").strip()
    backend = str(app.get("storage_backend") or "sqlite").strip().lower()
    database_configured = bool(database_path) if backend == "sqlite" else backend == "mysql"
    return [
        ReadinessCheck(
            "storage",
            "database_configured",
            "pass" if database_configured else "blocker",
            "Database backend is configured." if database_configured else "Database backend configuration is missing.",
            {"backend": backend, "database_path": database_path},
        ),
        ReadinessCheck(
            "storage",
            "enterprise_database_backend",
            "warning" if backend == "sqlite" else "pass",
            "SQLite is acceptable for internal use, but enterprise SaaS should migrate to Postgres/MySQL."
            if backend == "sqlite"
            else "Database backend uses MySQL.",
            {"backend": backend, "database_path": database_path},
        ),
        ReadinessCheck(
            "audit",
            "retention_policy",
            "pass" if retention.get("enabled", False) else "warning",
            "Retention cleanup is enabled." if retention.get("enabled", False) else "Retention cleanup is disabled.",
            {
                "enabled": bool(retention.get("enabled", False)),
                "api_audit_logs_days": int(retention.get("api_audit_logs_days", 0) or 0),
                "notification_logs_days": int(retention.get("notification_logs_days", 0) or 0),
            },
        ),
    ]


def security_governance_checks(config: AppConfig) -> list[ReadinessCheck]:
    app = safe_dict(config.raw.get("app"))
    tokens = safe_list(app.get("api_tokens"))
    legacy_token = str(app.get("api_token") or "").strip()
    auth_configured = bool(tokens or legacy_token)
    protect_reads = bool(app.get("api_auth_required_for_reads", False))
    return [
        ReadinessCheck(
            "security",
            "api_authentication",
            "pass" if auth_configured else "blocker",
            "API authentication token(s) are configured." if auth_configured else "API authentication is not configured.",
            {
                "api_tokens_count": len(tokens),
                "legacy_api_token_configured": bool(legacy_token),
                "api_auth_required_for_reads": bool(app.get("api_auth_required_for_reads", False)),
            },
        ),
        ReadinessCheck(
            "security",
            "read_api_authentication",
            "pass" if auth_configured and protect_reads else "warning",
            "Read APIs require an authenticated viewer token."
            if auth_configured and protect_reads
            else "Read APIs are accessible without authentication.",
            {"api_auth_required_for_reads": protect_reads},
        ),
    ]


def format_enterprise_readiness(snapshot: dict[str, Any]) -> str:
    lines = [
        f"Enterprise readiness: {snapshot.get('status')} score={snapshot.get('score')}",
        f"Checks: pass={snapshot.get('summary', {}).get('passed', 0)} "
        f"warning={snapshot.get('summary', {}).get('warnings', 0)} "
        f"blocker={snapshot.get('summary', {}).get('blockers', 0)}",
        "",
    ]
    for check in snapshot.get("checks", []):
        lines.append(f"- [{check.get('status')}] {check.get('category')}/{check.get('name')}: {check.get('summary')}")
    next_items = snapshot.get("next_steps") or []
    if next_items:
        lines.extend(["", "Next steps:"])
        lines.extend(f"- {item}" for item in next_items)
    return "\n".join(lines)


def enabled_monitor_targets(config: AppConfig) -> list[dict[str, Any]]:
    payload = list_monitor_targets(config.raw)
    targets = [target for target in safe_list(payload.get("targets")) if isinstance(target, dict)]
    server = payload.get("server")
    if isinstance(server, dict):
        targets.append(server)
    return [target for target in targets if bool(target.get("enabled", True))]


def disabled_project_target_matches(projects: list[dict[str, Any]], targets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for project in projects:
        needles = project_needles(project)
        if not needles:
            continue
        for target in targets:
            haystack = target_text(target)
            matched = [needle for needle in needles if needle in haystack]
            if matched:
                matches.append(
                    {
                        "project_id": str(project.get("id") or ""),
                        "project_name": str(project.get("name") or ""),
                        "target_id": str(target.get("id") or ""),
                        "target_name": str(target.get("name") or ""),
                        "matched": matched[:5],
                    }
                )
    return matches


def uncovered_enabled_projects(projects: list[dict[str, Any]], targets: list[dict[str, Any]]) -> list[str]:
    uncovered: list[str] = []
    for project in projects:
        needles = project_needles(project)
        if not needles:
            uncovered.append(str(project.get("id") or ""))
            continue
        if not any(any(needle in target_text(target) for needle in needles) for target in targets):
            uncovered.append(str(project.get("id") or ""))
    return uncovered


def project_needles(project: dict[str, Any]) -> list[str]:
    values = [
        str(project.get("id") or ""),
        str(project.get("name") or ""),
        str(project.get("repo_root") or ""),
        *string_list(project.get("health_urls")),
    ]
    needles = []
    for value in values:
        text = value.strip().casefold()
        if len(text) >= 4 and text not in {"prod", "main", "normal"}:
            needles.append(text)
    return unique(needles)


def target_text(target: dict[str, Any]) -> str:
    return json.dumps(target, ensure_ascii=False, sort_keys=True).casefold()


def unsafe_mutating_policies(policies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unsafe: list[dict[str, Any]] = []
    for policy in policies:
        action_type = str(policy.get("action_type") or "")
        if action_type not in MUTATING_ACTIONS or not policy.get("enabled", True):
            continue
        requires_approval = bool(policy.get("requires_approval", True))
        verification_required = bool(policy.get("verification_required", False))
        auto_execute = bool(policy.get("auto_execute", False))
        if auto_execute and (not requires_approval or not verification_required):
            unsafe.append(
                {
                    "name": str(policy.get("name") or action_type),
                    "action_type": action_type,
                    "auto_execute": auto_execute,
                    "requires_approval": requires_approval,
                    "verification_required": verification_required,
                }
            )
    return unsafe


def status_counts(checks: list[ReadinessCheck]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for check in checks:
        counts[check.status] = counts.get(check.status, 0) + 1
    return counts


def overall_status(counts: dict[str, int]) -> str:
    if counts.get("blocker", 0):
        return "not_enterprise_ready"
    if counts.get("warning", 0):
        return "enterprise_foundation"
    return "enterprise_ready"


def readiness_score(counts: dict[str, int], total: int) -> int:
    if total <= 0:
        return 0
    raw = (counts.get("pass", 0) * 100 + counts.get("warning", 0) * 60) / total
    return int(round(raw))


def next_steps(checks: list[ReadinessCheck]) -> list[str]:
    items = []
    for check in checks:
        if check.status == "blocker":
            items.append(f"Fix blocker: {check.category}/{check.name} - {check.summary}")
    for check in checks:
        if check.status == "warning":
            items.append(f"Improve: {check.category}/{check.name} - {check.summary}")
    return items[:10]


def safe_dict(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def safe_list(value: Any) -> list:
    return list(value) if isinstance(value, list) else []


def string_list(value: Any) -> list[str]:
    return [str(item).strip() for item in safe_list(value) if str(item).strip()]


def unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def redact_policy(policy: dict[str, Any]) -> dict[str, Any]:
    return {
        key: ("***" if "key" in str(key).lower() or "token" in str(key).lower() else value)
        for key, value in policy.items()
    }

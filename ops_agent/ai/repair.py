from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any
import urllib.error
import urllib.request

from ops_agent.alerts.notifier import Notifier
from ops_agent.config import AppConfig
from ops_agent.events import CheckResult
from ops_agent.projects import list_projects
from ops_agent.storage import Storage


SAFE_STATUSES = {"passed", "failed", "skipped", "not_run"}
DEFAULT_TEST_COMMANDS = ["python -m unittest discover -s tests"]
MODEL_PROVIDERS = {"openai", "openai_compatible", "llm", "deepseek"}
DEFAULT_MODEL_ENDPOINT = "https://api.openai.com/v1/chat/completions"
DEEPSEEK_MODEL_ENDPOINT = "https://api.deepseek.com/chat/completions"
DEEPSEEK_DEFAULT_MODEL = "deepseek-v4-flash"
DEFAULT_MODEL_TIMEOUT_SECONDS = 45
DEFAULT_MAX_PROMPT_CHARS = 12000
DEFAULT_MAX_RESPONSE_CHARS = 60000
DEFAULT_SANDBOX_TEST_TIMEOUT_SECONDS = 120
DEFAULT_SANDBOX_MAX_OUTPUT_CHARS = 12000
DEFAULT_GIT_TIMEOUT_SECONDS = 60
DEFAULT_GIT_PUSH_TIMEOUT_SECONDS = 120
DEFAULT_GITHUB_TIMEOUT_SECONDS = 30
DEFAULT_DEPLOY_TIMEOUT_SECONDS = 180
DEFAULT_DEPLOY_VERIFY_TIMEOUT_SECONDS = 10
CONTROLLED_BRANCH_PREFIX = "ai-repair"
CONTROLLED_WORKTREE_SUFFIX = "ai-repair-worktrees"
MAX_DIFF_CHARS = 80000
ALLOWED_DIFF_SUFFIXES = {
    ".cfg",
    ".css",
    ".html",
    ".ini",
    ".js",
    ".json",
    ".md",
    ".py",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".yaml",
    ".yml",
}
ALLOWED_DIFF_FILENAMES = {"Dockerfile", "Makefile", "Procfile"}
SAFE_TEST_COMMAND_PREFIXES = (
    "python -m unittest",
    "python3 -m unittest",
    "py -m unittest",
    "python -m pytest",
    "python3 -m pytest",
    "pytest",
    "python -m py_compile",
    "python3 -m py_compile",
)
DEFAULT_DEPLOY_COMMANDS = ["python -m unittest discover -s tests"]
SAFE_DEPLOY_COMMAND_PREFIXES = (
    *SAFE_TEST_COMMAND_PREFIXES,
    "systemctl restart ops-agent",
    "systemctl reload ops-agent",
)
SENSITIVE_FILENAMES = {
    ".env",
    ".env.local",
    ".env.production",
    "authorized_keys",
    "id_ed25519",
    "id_rsa",
}
SENSITIVE_FILE_SUFFIXES = {".key", ".pem", ".p12", ".pfx"}
SENSITIVE_PATH_PARTS = {".git", ".ssh", "secrets", "__pycache__"}
REPOSITORY_CONTEXT_EXCLUDED_PARTS = SENSITIVE_PATH_PARTS | {
    ".mypy_cache",
    ".pytest_cache",
    ".venv",
    "build",
    "dist",
    "node_modules",
    "venv",
}
DEFAULT_REPOSITORY_CONTEXT_SETTINGS = {
    "enabled": True,
    "max_files": 8,
    "max_file_chars": 4000,
    "max_total_chars": 16000,
    "max_tree_files": 80,
    "max_file_bytes": 262144,
}
DEFAULT_AI_REPAIR_POLICY = {
    "enabled": True,
    "auto_approve": False,
    "auto_approve_risks": ["low"],
    "prepare_branch": False,
    "create_pr": False,
    "max_changed_files": 5,
    "allowed_patch_types": ["unified_diff"],
    "require_human_approval_risks": ["medium", "high", "critical"],
}
DEFAULT_SANDBOX_MAX_COMMANDS = 5
AI_REPAIR_RISK_SCORES = {"low": 10, "medium": 40, "high": 70, "critical": 90}
AI_REPAIR_QUEUE_ACTIVE_STATUSES = [
    "proposed",
    "dry_run_failed",
    "dry_run_passed",
    "test_failed",
    "test_not_run",
    "test_passed",
    "approved",
    "branch_failed",
    "branch_prepared",
    "pr_failed",
    "pr_created",
    "merge_pending",
    "deploy_failed",
    "rollback_failed",
]
AI_REPAIR_QUEUE_DONE_STATUSES = ["deployed", "rollback_succeeded", "rejected"]


def build_ai_repair_proposal(
    storage: Storage,
    config: AppConfig | None,
    incident_id: int,
    request: dict[str, Any] | None = None,
) -> dict[str, Any]:
    incident = storage.get_incident(incident_id)
    if not incident:
        raise ValueError(f"incident not found: {incident_id}")
    diagnoses = storage.latest_incident_diagnoses(incident_id, limit=1)
    diagnosis = diagnoses[0] if diagnoses else {}
    recommendations = storage.latest_incident_recommendations(incident_id)
    actions = storage.latest_action_logs(20, incident_id=incident_id)
    context = proposal_context(incident, diagnosis, recommendations, actions, config, request)
    proposal = model_based_repair(context) if should_use_model(context) else rule_based_repair(context)
    return storage.save_ai_repair_proposal(incident_id, proposal)


def ai_repair_approval_queue(
    storage: Storage,
    limit: int = 50,
    statuses: list[str] | None = None,
    include_done: bool = False,
    risk: str = "",
    model_provider: str = "",
) -> dict[str, Any]:
    requested_statuses = [str(status).strip() for status in safe_list(statuses) if str(status).strip()]
    effective_statuses = requested_statuses or (None if include_done else AI_REPAIR_QUEUE_ACTIVE_STATUSES)
    repairs = storage.latest_ai_repair_proposals(
        limit=limit,
        statuses=effective_statuses,
        risk=risk,
        model_provider=model_provider,
    )
    items = [ai_repair_approval_queue_item(storage, repair) for repair in repairs]
    by_state: dict[str, int] = {}
    by_status: dict[str, int] = {}
    by_risk: dict[str, int] = {}
    for item in items:
        by_state[str(item.get("queue_state") or "unknown")] = by_state.get(str(item.get("queue_state") or "unknown"), 0) + 1
        by_status[str(item.get("status") or "unknown")] = by_status.get(str(item.get("status") or "unknown"), 0) + 1
        by_risk[str(item.get("risk") or "unknown")] = by_risk.get(str(item.get("risk") or "unknown"), 0) + 1
    return {
        "mode": "ai_repair_approval_queue",
        "summary": {
            "total": len(items),
            "ready_for_approval": sum(1 for item in items if item.get("can_approve")),
            "needs_sandbox": sum(1 for item in items if item.get("queue_state") == "needs_sandbox"),
            "blocked": sum(1 for item in items if item.get("queue_state") == "blocked"),
            "review_only": sum(1 for item in items if item.get("queue_state") == "review_only"),
            "by_state": by_state,
            "by_status": by_status,
            "by_risk": by_risk,
        },
        "filters": {
            "limit": limit,
            "statuses": effective_statuses or [],
            "include_done": include_done,
            "risk": risk,
            "model_provider": model_provider,
        },
        "items": items,
    }


def notify_ai_repair_approval_queue(
    storage: Storage,
    config: AppConfig | None,
    notifier: Notifier | None = None,
    limit: int = 50,
    states: list[str] | None = None,
    repair_ids: list[int] | None = None,
    include_done: bool = False,
    actor: str = "operator",
) -> dict[str, Any]:
    target_states = [str(item).strip() for item in safe_list(states) if str(item).strip()] or ["ready_for_approval"]
    target_repair_ids = {safe_int(item) for item in safe_list(repair_ids) if safe_int(item) > 0}
    queue = ai_repair_approval_queue(storage, limit=limit, include_done=include_done)
    items = [
        item
        for item in safe_list(queue.get("items"))
        if safe_dict(item).get("queue_state") in set(target_states)
        and (not target_repair_ids or safe_int(safe_dict(item).get("id")) in target_repair_ids)
    ]
    title = f"Ops Agent AI repair approval queue: {len(items)} item(s)"
    dedupe_key = "ai-repair-approval-queue:" + ",".join(target_states) + ":" + ",".join(
        str(safe_dict(item).get("id") or "") for item in items
    )
    environment = str(safe_dict(config.app if config else {}).get("environment") or "prod")
    run_type = str(safe_dict(config.app if config else {}).get("run_type") or "normal")
    channels = notification_channels_from_config(config)
    if not items:
        log_id = storage.save_notification_log(
            title,
            dedupe_key,
            "suppressed",
            severity="warning",
            route_names=["ai-repair-approval-queue"],
            channels=channels,
            suppressed_reason="no matching queue items",
            environment=environment,
            run_type=run_type,
            metadata={
                "states": target_states,
                "actor": actor,
                "repair_ids": sorted(target_repair_ids),
                "queue_summary": safe_dict(queue.get("summary")),
            },
        )
        return {
            "mode": "ai_repair_approval_queue_notification",
            "status": "skipped",
            "reason": "no matching queue items",
            "notification_log_id": log_id,
            "queue": queue,
            "items": [],
        }

    text = format_ai_repair_approval_queue_notification(queue, items, target_states)
    sender = notifier or Notifier(
        webhook_url=str(safe_dict(config.alerts if config else {}).get("webhook_url") or ""),
        cooldown_seconds=safe_int(safe_dict(config.alerts if config else {}).get("cooldown_seconds"), 300),
        email=safe_dict(safe_dict(config.alerts if config else {}).get("email")),
    )
    status = "sent"
    error = ""
    suppressed_reason = ""
    try:
        sent = sender.send(title, text, dedupe_key=dedupe_key)
        if not sent:
            status = "suppressed"
            suppressed_reason = "notifier cooldown"
    except Exception as exc:
        status = "failed"
        error = str(exc)
    log_id = storage.save_notification_log(
        title,
        dedupe_key,
        status,
        severity="warning",
        route_names=["ai-repair-approval-queue"],
        channels=channels,
        suppressed_reason=suppressed_reason,
        error=error,
        environment=environment,
        run_type=run_type,
        metadata={
            "states": target_states,
            "actor": actor,
            "repair_ids": sorted(target_repair_ids),
            "queue_summary": safe_dict(queue.get("summary")),
            "item_ids": [safe_int(safe_dict(item).get("id")) for item in items],
        },
    )
    return {
        "mode": "ai_repair_approval_queue_notification",
        "status": status,
        "error": error,
        "notification_log_id": log_id,
        "title": title,
        "text": text,
        "queue": queue,
        "items": items,
    }


def run_ai_repair_queue_next_action(
    storage: Storage,
    config: AppConfig | None,
    repair_id: int,
    actor: str = "operator",
    request: dict[str, Any] | None = None,
) -> dict[str, Any]:
    request_payload = safe_dict(request)
    repair = require_ai_repair(storage, repair_id)
    before = ai_repair_approval_queue_item(storage, repair)
    next_action = safe_dict(before.get("next_action"))
    action_type = str(request_payload.get("action") or next_action.get("type") or "").strip()
    if not action_type:
        raise ValueError(f"AI repair #{repair_id} has no executable next action")
    if next_action.get("type") and action_type != next_action.get("type") and not bool(request_payload.get("force")):
        raise ValueError(f"next action is {next_action.get('type')}, not {action_type}")

    runtime = empty_queue_action_runtime()
    note = str(request_payload.get("note") or request_payload.get("reason") or f"queue next action: {action_type}")
    if action_type == "dry-run":
        updated = dry_run_ai_repair_proposal(storage, repair_id, actor=actor, note=note)
    elif action_type == "sandbox-test":
        runtime = queue_action_runtime(config, repair, request_payload)
        updated = sandbox_test_ai_repair_proposal(
            storage,
            repair_id,
            runtime["repo_root"],
            actor=actor,
            note=note,
            commands=runtime["commands"],
            policy=safe_dict(runtime.get("policy")),
        )
    elif action_type == "approve":
        if not before.get("can_approve"):
            raise ValueError(f"AI repair #{repair_id} is not ready for approval")
        updated = storage.update_ai_repair_proposal_status(repair_id, "approved", actor=actor, note=note)
    elif action_type == "prepare-branch":
        if not before.get("can_prepare_branch"):
            raise ValueError(f"AI repair #{repair_id} is not ready to prepare a branch")
        runtime = queue_action_runtime(config, repair, request_payload)
        updated = prepare_ai_repair_branch(
            storage,
            repair_id,
            runtime["repo_root"],
            actor=actor,
            note=note,
            commands=runtime["commands"],
        )
    elif action_type == "create-pr":
        if not before.get("can_create_pr"):
            raise ValueError(f"AI repair #{repair_id} is not ready to create a PR")
        runtime = queue_action_runtime(config, repair, request_payload)
        updated = publish_ai_repair_pull_request(
            storage,
            repair_id,
            runtime["repo_root"],
            actor=actor,
            note=note,
            remote=runtime["remote"],
            base=runtime["base"],
            draft=runtime["draft"],
        )
    elif action_type == "deploy-merged":
        if not before.get("can_deploy"):
            raise ValueError(f"AI repair #{repair_id} is not ready for deployment verification")
        runtime = queue_action_runtime(config, repair, request_payload)
        updated = deploy_ai_repair_after_merge(
            storage,
            repair_id,
            runtime["repo_root"],
            actor=actor,
            note=note,
            remote=runtime["remote"],
            base=runtime["base"],
            commands=runtime["commands"],
            verify_urls=runtime["verify_urls"],
            rollback_commands=runtime["rollback_commands"],
            rollback_verify_urls=runtime["rollback_verify_urls"],
        )
    else:
        raise ValueError(f"unsupported AI repair queue action: {action_type}")

    return {
        "mode": "ai_repair_queue_next_action",
        "action": action_type,
        "repair": updated,
        "before": before,
        "after": ai_repair_approval_queue_item(storage, updated),
        "runtime": {
            "repo_root": str(runtime["repo_root"]),
            "commands": runtime["commands"] or [],
            "remote": runtime["remote"],
            "base": runtime["base"],
        },
    }


def format_ai_repair_approval_queue_notification(
    queue: dict[str, Any],
    items: list[dict[str, Any]],
    states: list[str],
) -> str:
    summary = safe_dict(queue.get("summary"))
    lines = [
        "AI 修复审批队列需要处理。",
        "",
        f"匹配状态: {', '.join(states)}",
        f"待处理: {len(items)}",
        f"可审批: {summary.get('ready_for_approval', 0)}; 需要沙箱: {summary.get('needs_sandbox', 0)}; 阻塞: {summary.get('blocked', 0)}; 仅建议: {summary.get('review_only', 0)}",
        "",
        "队列明细:",
    ]
    for item in items[:10]:
        payload = safe_dict(item)
        next_action = safe_dict(payload.get("next_action"))
        incident = safe_dict(payload.get("incident"))
        lines.extend(
            [
                f"- #{payload.get('id')} [{payload.get('queue_state')}] {payload.get('title')}",
                f"  风险: {payload.get('risk')}; 事件: #{incident.get('id')} {incident.get('title')}",
                f"  下一步: {next_action.get('type') or 'manual-review'} {next_action.get('path') or ''}",
            ]
        )
        blockers = [str(item) for item in safe_list(payload.get("blockers")) if str(item)]
        if blockers:
            lines.append(f"  阻塞: {'; '.join(blockers[:3])}")
    if len(items) > 10:
        lines.append(f"- 还有 {len(items) - 10} 条未展示")
    return "\n".join(lines)


def ai_repair_approval_queue_item(storage: Storage, repair: dict[str, Any]) -> dict[str, Any]:
    repair_id = safe_int(repair.get("id"))
    incident_id = safe_int(repair.get("incident_id"))
    incident = storage.get_incident(incident_id) if incident_id else None
    state = ai_repair_queue_state(repair)
    patch = safe_dict(repair.get("patch"))
    dry_run = safe_dict(repair.get("dry_run"))
    test_result = safe_dict(repair.get("test_result"))
    approval_report = safe_dict(test_result.get("approval_report"))
    guardrails = safe_dict(test_result.get("guardrails"))
    controlled_apply = safe_dict(test_result.get("controlled_apply"))
    pull_request = safe_dict(test_result.get("pull_request"))
    deploy_result = safe_dict(test_result.get("deploy_result"))
    return {
        "id": repair_id,
        "incident_id": incident_id,
        "status": str(repair.get("status") or ""),
        "queue_state": state["queue_state"],
        "risk": str(repair.get("risk") or ""),
        "title": str(repair.get("title") or ""),
        "summary": str(repair.get("summary") or ""),
        "model_provider": str(repair.get("model_provider") or ""),
        "model_name": str(repair.get("model_name") or ""),
        "created_at": str(repair.get("created_at") or ""),
        "updated_at": str(repair.get("updated_at") or ""),
        "incident": public_queue_incident(incident or {}),
        "patch": {
            "patch_type": str(patch.get("patch_type") or ""),
            "apply_mode": str(patch.get("apply_mode") or ""),
            "has_diff": bool(str(patch.get("diff") or "").strip()),
            "file_count": len(safe_list(patch.get("files"))),
            "files": [
                str(safe_dict(item).get("path") or "")
                for item in safe_list(patch.get("files"))
                if str(safe_dict(item).get("path") or "")
            ],
        },
        "dry_run": {
            "valid": bool(dry_run.get("valid")),
            "mutates_files": bool(dry_run.get("mutates_files")),
            "errors": [str(item) for item in safe_list(dry_run.get("errors"))],
            "warnings": [str(item) for item in safe_list(dry_run.get("warnings"))],
            "checked_files": [str(item) for item in safe_list(dry_run.get("checked_files"))],
        },
        "test": {
            "status": str(test_result.get("status") or ""),
            "error": str(test_result.get("error") or ""),
            "approval_ready": bool(approval_report.get("ready_to_approve")),
            "approval_decision": str(approval_report.get("decision") or ""),
            "guardrail_status": str(guardrails.get("status") or ""),
            "risk_assessment": safe_dict(approval_report.get("risk_assessment")),
            "execution_plan": safe_dict(approval_report.get("execution_plan")),
            "sandbox_status": str(safe_dict(test_result.get("sandbox")).get("status") or ""),
            "controlled_branch_ready": bool(controlled_apply.get("ready_for_pr")),
            "pull_request_ready": bool(pull_request.get("ready_for_review")),
            "deploy_status": str(deploy_result.get("status") or ""),
        },
        "blockers": state["blockers"],
        "warnings": state["warnings"],
        "can_approve": state["can_approve"],
        "can_prepare_branch": state["can_prepare_branch"],
        "can_create_pr": state["can_create_pr"],
        "can_deploy": state["can_deploy"],
        "next_action": state["next_action"],
    }


def ai_repair_queue_state(repair: dict[str, Any]) -> dict[str, Any]:
    repair_id = safe_int(repair.get("id"))
    status = str(repair.get("status") or "proposed")
    patch = safe_dict(repair.get("patch"))
    dry_run = safe_dict(repair.get("dry_run"))
    test_result = safe_dict(repair.get("test_result"))
    approval_report = safe_dict(test_result.get("approval_report"))
    controlled_apply = safe_dict(test_result.get("controlled_apply"))
    has_diff = bool(str(patch.get("diff") or "").strip())
    approval_ready = bool(approval_report.get("ready_to_approve"))
    blockers = unique_strings(
        [
            *[str(item) for item in safe_list(dry_run.get("errors"))],
            *[str(item) for item in safe_list(approval_report.get("blockers"))],
            str(test_result.get("error") or ""),
        ]
    )
    warnings = unique_strings(
        [
            *[str(item) for item in safe_list(dry_run.get("warnings"))],
            *[str(item) for item in safe_list(approval_report.get("warnings"))],
        ]
    )
    queue_state = "unknown"
    next_action: dict[str, Any] = {}
    can_approve = False
    can_prepare_branch = False
    can_create_pr = False
    can_deploy = False

    if status == "proposed":
        queue_state = "needs_dry_run"
        next_action = action_descriptor(repair_id, "dry-run", "Run dry-run validation")
    elif status == "dry_run_failed":
        queue_state = "blocked"
    elif status == "dry_run_passed":
        if has_diff:
            queue_state = "needs_sandbox"
            next_action = action_descriptor(repair_id, "sandbox-test", "Run sandbox test")
        else:
            queue_state = "review_only"
            warnings = unique_strings([*warnings, "No patch diff was generated; review the guidance manually."])
    elif status in {"test_failed", "branch_failed", "pr_failed", "deploy_failed", "rollback_failed"}:
        queue_state = "blocked"
    elif status == "test_not_run":
        queue_state = "needs_sandbox"
        next_action = action_descriptor(repair_id, "sandbox-test", "Run sandbox test")
    elif status == "test_passed":
        if approval_ready and has_diff:
            queue_state = "ready_for_approval"
            can_approve = True
            next_action = action_descriptor(repair_id, "approve", "Approve repair")
        else:
            queue_state = "blocked"
            if not has_diff:
                blockers = unique_strings([*blockers, "patch has no unified diff to approve"])
            if not approval_ready:
                blockers = unique_strings([*blockers, "approval report is not ready"])
    elif status == "approved":
        if approval_ready and has_diff:
            queue_state = "approved_needs_branch"
            can_prepare_branch = True
            next_action = action_descriptor(repair_id, "prepare-branch", "Prepare controlled branch")
        else:
            queue_state = "approved_manual_review"
            warnings = unique_strings([*warnings, "Approved repair cannot prepare a branch without a ready patch."])
    elif status == "branch_prepared":
        queue_state = "ready_for_pr"
        can_create_pr = bool(controlled_apply.get("ready_for_pr"))
        next_action = action_descriptor(repair_id, "create-pr", "Create pull request") if can_create_pr else {}
    elif status == "pr_created":
        queue_state = "waiting_for_merge"
        warnings = unique_strings([*warnings, "Pull request exists; merge it before deployment verification."])
    elif status == "merge_pending":
        queue_state = "ready_for_deploy"
        can_deploy = True
        next_action = action_descriptor(repair_id, "deploy-merged", "Verify merged deployment")
    elif status in AI_REPAIR_QUEUE_DONE_STATUSES:
        queue_state = "done"

    return {
        "queue_state": queue_state,
        "blockers": blockers,
        "warnings": warnings,
        "can_approve": can_approve,
        "can_prepare_branch": can_prepare_branch,
        "can_create_pr": can_create_pr,
        "can_deploy": can_deploy,
        "next_action": next_action,
    }


def action_descriptor(repair_id: int, action: str, label: str) -> dict[str, Any]:
    return {
        "type": action,
        "label": label,
        "method": "POST",
        "path": f"/api/ai-repairs/{repair_id}/{action}",
    }


def public_queue_incident(incident: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": safe_int(incident.get("id")),
        "status": str(incident.get("status") or ""),
        "severity": str(incident.get("severity") or ""),
        "title": str(incident.get("title") or ""),
        "environment": str(incident.get("environment") or ""),
        "run_type": str(incident.get("run_type") or ""),
        "last_summary": str(incident.get("last_summary") or ""),
    }


def queue_action_runtime(
    config: AppConfig | None,
    repair: dict[str, Any],
    request: dict[str, Any],
) -> dict[str, Any]:
    project = repair_project_from_context(config, repair, request)
    fallback = config.base_dir if config is not None else Path(".")
    commands = request.get("commands")
    verify_urls = request.get("verify_urls") or request.get("verification_urls")
    rollback_commands = request.get("rollback_commands")
    rollback_verify_urls = request.get("rollback_verify_urls") or request.get("rollback_verification_urls")
    return {
        "project": project,
        "repo_root": resolve_repair_repo_root(config, project, request, fallback),
        "commands": commands if isinstance(commands, list) else string_list(project.get("test_commands")) or None,
        "policy": ai_repair_policy_from_config(config, project=project),
        "remote": str(request.get("remote") or project.get("git_remote") or "origin"),
        "base": str(request.get("base") or project.get("base_branch") or "main"),
        "draft": bool(request.get("draft", True)),
        "verify_urls": verify_urls if isinstance(verify_urls, list) else None,
        "rollback_commands": rollback_commands if isinstance(rollback_commands, list) else None,
        "rollback_verify_urls": rollback_verify_urls if isinstance(rollback_verify_urls, list) else None,
    }


def empty_queue_action_runtime() -> dict[str, Any]:
    return {
        "project": {},
        "repo_root": "",
        "commands": [],
        "policy": {},
        "remote": "",
        "base": "",
        "draft": True,
        "verify_urls": None,
        "rollback_commands": None,
        "rollback_verify_urls": None,
    }


def repair_project_from_context(
    config: AppConfig | None,
    repair: dict[str, Any],
    request: dict[str, Any],
) -> dict[str, Any]:
    requested = str(request.get("project_id") or request.get("project") or "").strip()
    if requested and config is not None:
        project = find_repair_project_by_id(config, requested)
        if project:
            return project
    prompt_project = safe_dict(repair_prompt_payload(repair).get("project"))
    prompt_project_id = str(prompt_project.get("id") or prompt_project.get("name") or "").strip()
    if prompt_project_id and config is not None:
        project = find_repair_project_by_id(config, prompt_project_id)
        if project:
            return project
    return prompt_project


def repair_prompt_payload(repair: dict[str, Any]) -> dict[str, Any]:
    prompt = safe_dict(repair.get("prompt"))
    user = str(prompt.get("user") or "")
    if not user.strip():
        return {}
    if user.strip().endswith("...[truncated]"):
        user = user.rsplit("\n...[truncated]", 1)[0]
    return parse_json_object(user)


def notification_channels_from_config(config: AppConfig | None) -> list[str]:
    alerts = safe_dict(config.alerts if config else {})
    channels: list[str] = []
    if str(alerts.get("webhook_url") or "").strip():
        channels.append("webhook")
    if bool(safe_dict(alerts.get("email")).get("enabled")):
        channels.append("email")
    return channels or ["console"]


def run_ai_repair_pipeline_for_incident(
    storage: Storage,
    config: AppConfig | None,
    incident_id: int,
    repo_root: Path | str,
    actor: str = "operator",
    note: str = "",
    commands: list[str] | None = None,
    auto_approve: bool | None = None,
    auto_approve_risks: list[str] | None = None,
    prepare_branch: bool | None = None,
    create_pr: bool | None = None,
    remote: str = "origin",
    base: str = "main",
    draft: bool = True,
    request: dict[str, Any] | None = None,
) -> dict[str, Any]:
    incident = storage.get_incident(incident_id)
    if not incident:
        raise ValueError(f"incident not found: {incident_id}")
    request_payload = safe_dict(request)
    diagnosis_rows = storage.latest_incident_diagnoses(incident_id, limit=1)
    diagnosis = diagnosis_rows[0] if diagnosis_rows else {}
    project = select_repair_project(config, incident, diagnosis, request_payload)
    effective_repo_root = resolve_repair_repo_root(config, project, request_payload, repo_root)
    effective_commands = commands if commands is not None else string_list(project.get("test_commands"))
    effective_remote = str(request_payload.get("remote") or project.get("git_remote") or remote)
    effective_base = str(request_payload.get("base") or project.get("base_branch") or base)
    proposal = build_ai_repair_proposal(
        storage,
        config,
        incident_id,
        request={**request_payload, "actor": actor},
    )
    policy = ai_repair_policy_from_config(config, project=project)
    return run_ai_repair_pipeline(
        storage,
        proposal["id"],
        effective_repo_root,
        actor=actor,
        note=note,
        commands=effective_commands or None,
        auto_approve=auto_approve,
        auto_approve_risks=auto_approve_risks,
        prepare_branch=prepare_branch,
        create_pr=create_pr,
        remote=effective_remote,
        base=effective_base,
        draft=draft,
        policy=policy,
        initial_pipeline_stage={"name": "proposal", "status": "passed", "repair_id": proposal["id"]},
    )


def run_project_ai_repair_drill(
    storage: Storage,
    config: AppConfig | None,
    project_id: str,
    actor: str = "operator",
    request: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if config is None:
        raise ValueError("config is not configured")
    project = find_repair_project_by_id(config, project_id)
    if not project:
        raise ValueError(f"project not found: {project_id}")

    request_payload = safe_dict(request)
    project_key = str(project.get("id") or project_id)
    run_types = string_list(project.get("run_types"))
    environment = str(
        request_payload.get("environment")
        or project.get("environment")
        or config.app.get("environment")
        or "prod"
    )
    run_type = str(
        request_payload.get("run_type")
        or (run_types[0] if run_types else "")
        or config.app.get("run_type")
        or "normal"
    )
    severity = normalize_drill_severity(request_payload.get("severity") or request_payload.get("status"))
    summary = str(
        request_payload.get("summary")
        or request_payload.get("last_summary")
        or f"Synthetic AI repair drill for project {project_key}"
    )
    title = str(
        request_payload.get("title")
        or f"AI repair drill for {project.get('name') or project_key}"
    )
    details = safe_dict(request_payload.get("details"))
    details.update(
        {
            "drill": True,
            "project_id": project_key,
            "mutates_production": False,
        }
    )
    result = CheckResult(
        source=str(request_payload.get("source") or "ai_repair_drill"),
        name=str(request_payload.get("name") or project.get("name") or project_key),
        status=severity,
        summary=summary,
        details=details,
        environment=environment,
        run_type=run_type,
    )
    incident_id = storage.save_incident(
        severity,
        title,
        str(
            request_payload.get("analysis")
            or "Project-level AI repair drill. This record is synthetic and does not mutate production."
        ),
        [result],
        status=str(request_payload.get("incident_status") or "resolved"),
        classification={
            "category": str(request_payload.get("category") or "ai_repair_drill"),
            "confidence": request_payload.get("confidence", 0.75),
            "summary": summary,
            "evidence": [summary],
            "next_steps": ["review generated proposal", "run sandbox test if a patch is present"],
        },
    )
    proposal = build_ai_repair_proposal(
        storage,
        config,
        incident_id,
        request={**request_payload, "actor": actor, "project_id": project_key, "drill": True},
    )
    repair = dry_run_ai_repair_proposal(
        storage,
        int(proposal["id"]),
        actor=actor,
        note=str(request_payload.get("note") or "project AI repair drill dry-run"),
    )
    sandbox_result: dict[str, Any] = {}
    run_sandbox = bool(request_payload.get("run_sandbox") or request_payload.get("sandbox_test"))
    patch = safe_dict(repair.get("patch"))
    if run_sandbox and repair.get("status") == "dry_run_passed" and str(patch.get("diff") or "").strip():
        commands = request_payload.get("commands")
        repo_root = resolve_repair_repo_root(config, project, request_payload, config.base_dir)
        repair = sandbox_test_ai_repair_proposal(
            storage,
            int(proposal["id"]),
            repo_root,
            actor=actor,
            note=str(request_payload.get("note") or "project AI repair drill sandbox test"),
            commands=commands if isinstance(commands, list) else string_list(project.get("test_commands")) or None,
            policy=ai_repair_policy_from_config(config, project=project),
        )
        sandbox_result = safe_dict(repair.get("test_result"))
    elif run_sandbox:
        sandbox_result = {
            "status": "skipped",
            "reason": "dry_run_failed_or_no_patch_diff",
        }

    return {
        "mode": "project_ai_repair_drill",
        "status": str(repair.get("status") or "unknown"),
        "mutates_production": False,
        "project": public_project_context(project),
        "incident": storage.get_incident(incident_id),
        "proposal": repair,
        "dry_run": safe_dict(repair.get("dry_run")),
        "sandbox_result": sandbox_result,
        "next_steps": project_drill_next_steps(repair, run_sandbox),
    }


def run_ai_repair_pipeline(
    storage: Storage,
    repair_id: int,
    repo_root: Path | str,
    actor: str = "operator",
    note: str = "",
    commands: list[str] | None = None,
    auto_approve: bool | None = None,
    auto_approve_risks: list[str] | None = None,
    prepare_branch: bool | None = None,
    create_pr: bool | None = None,
    remote: str = "origin",
    base: str = "main",
    draft: bool = True,
    policy: dict[str, Any] | None = None,
    initial_pipeline_stage: dict[str, Any] | None = None,
) -> dict[str, Any]:
    repair_policy = normalize_ai_repair_policy(policy)
    auto_approve_enabled = bool(auto_approve) if auto_approve is not None else bool(repair_policy.get("auto_approve"))
    prepare_branch_enabled = (
        bool(prepare_branch) if prepare_branch is not None else bool(repair_policy.get("prepare_branch"))
    )
    create_pr_enabled = bool(create_pr) if create_pr is not None else bool(repair_policy.get("create_pr"))
    if create_pr_enabled:
        prepare_branch_enabled = True
    approved_risks = normalize_auto_approve_risks(auto_approve_risks or repair_policy.get("auto_approve_risks"))
    pipeline = {
        "mode": "ai_repair_pipeline",
        "status": "running",
        "stopped_at": "",
        "policy": repair_policy,
        "auto_approve_requested": auto_approve_enabled,
        "auto_approve_risks": approved_risks,
        "prepare_branch_requested": prepare_branch_enabled,
        "create_pr_requested": create_pr_enabled,
        "stages": [],
    }
    if initial_pipeline_stage:
        pipeline["stages"].append(safe_dict(initial_pipeline_stage))

    repair = dry_run_ai_repair_proposal(storage, repair_id, actor=actor, note=note)
    append_pipeline_stage(pipeline, "dry_run", repair)
    if repair.get("status") != "dry_run_passed":
        return finish_ai_repair_pipeline(storage, repair, pipeline, "failed", "dry_run_failed", actor, note)

    patch = safe_dict(repair.get("patch"))
    if not str(patch.get("diff") or "").strip():
        return finish_ai_repair_pipeline(storage, repair, pipeline, "blocked", "no_patch_diff", actor, note)

    repair = sandbox_test_ai_repair_proposal(
        storage,
        repair_id,
        repo_root,
        actor=actor,
        note=note,
        commands=commands,
        policy=repair_policy,
    )
    append_pipeline_stage(pipeline, "sandbox_test", repair)
    if repair.get("status") != "test_passed":
        return finish_ai_repair_pipeline(storage, repair, pipeline, "failed", "sandbox_failed", actor, note)

    if not auto_approve_enabled:
        return finish_ai_repair_pipeline(storage, repair, pipeline, "blocked", "approval_required", actor, note)

    auto_approve_decision = auto_approval_decision(repair, repair_policy, approved_risks)
    pipeline["auto_approve_decision"] = auto_approve_decision
    if not auto_approve_decision["eligible"]:
        return finish_ai_repair_pipeline(storage, repair, pipeline, "blocked", "auto_approve_blocked", actor, note)

    repair = storage.update_ai_repair_proposal_status(repair_id, "approved", actor=actor, note=note)
    append_pipeline_stage(pipeline, "approval", repair)
    if not prepare_branch_enabled:
        return finish_ai_repair_pipeline(storage, repair, pipeline, "completed", "approved", actor, note)

    repair = prepare_ai_repair_branch(
        storage,
        repair_id,
        repo_root,
        actor=actor,
        note=note,
        commands=commands,
    )
    append_pipeline_stage(pipeline, "prepare_branch", repair)
    if repair.get("status") != "branch_prepared":
        return finish_ai_repair_pipeline(storage, repair, pipeline, "failed", "branch_failed", actor, note)
    if not create_pr_enabled:
        return finish_ai_repair_pipeline(storage, repair, pipeline, "completed", "branch_prepared", actor, note)

    repair = publish_ai_repair_pull_request(
        storage,
        repair_id,
        repo_root,
        actor=actor,
        note=note,
        remote=remote,
        base=base,
        draft=draft,
    )
    append_pipeline_stage(pipeline, "create_pr", repair)
    if repair.get("status") != "pr_created":
        return finish_ai_repair_pipeline(storage, repair, pipeline, "failed", "pr_failed", actor, note)
    return finish_ai_repair_pipeline(storage, repair, pipeline, "completed", "pr_created", actor, note)


def dry_run_ai_repair_proposal(storage: Storage, repair_id: int, actor: str = "operator", note: str = "") -> dict:
    repair = require_ai_repair(storage, repair_id)
    patch = safe_dict(repair.get("patch"))
    result = validate_patch_dry_run(patch)
    next_status = "dry_run_passed" if result["valid"] else "dry_run_failed"
    return storage.update_ai_repair_proposal_status(
        repair_id,
        next_status,
        actor=actor,
        note=note,
        dry_run=result,
    )


def record_ai_repair_test_result(
    storage: Storage,
    repair_id: int,
    result: dict[str, Any] | None = None,
    actor: str = "operator",
    note: str = "",
) -> dict:
    repair = require_ai_repair(storage, repair_id)
    payload = normalize_test_result(result or {}, repair)
    next_status = "test_passed" if payload["status"] == "passed" else "test_failed"
    if payload["status"] in {"skipped", "not_run"}:
        next_status = "test_not_run"
    return storage.update_ai_repair_proposal_status(
        repair_id,
        next_status,
        actor=actor,
        note=note,
        test_result=payload,
    )


def sandbox_test_ai_repair_proposal(
    storage: Storage,
    repair_id: int,
    repo_root: Path | str,
    actor: str = "operator",
    note: str = "",
    commands: list[str] | None = None,
    policy: dict[str, Any] | None = None,
) -> dict:
    repair = require_ai_repair(storage, repair_id)
    patch = safe_dict(repair.get("patch"))
    validation = validate_patch_dry_run(patch)
    requested_commands = (
        safe_list(commands) if commands is not None else safe_list(safe_dict(repair.get("test_plan")).get("commands"))
    )
    guardrails = build_sandbox_guardrail_report(patch, requested_commands, validation=validation, policy=policy)
    sandbox = run_patch_in_sandbox(
        Path(repo_root),
        patch,
        requested_commands,
    )
    report = build_approval_report(repair, validation, sandbox, guardrails=guardrails)
    status = "passed" if report["ready_to_approve"] else "failed"
    if not str(patch.get("diff") or "").strip():
        status = "skipped"
    result = {
        "status": status,
        "commands": sandbox.get("commands", []),
        "output": sandbox.get("output", ""),
        "error": sandbox.get("error", ""),
        "note": note or "sandbox patch validation completed",
        "validation": validation,
        "guardrails": guardrails,
        "sandbox": sandbox,
        "approval_report": report,
    }
    return record_ai_repair_test_result(storage, repair_id, result=result, actor=actor, note=note)


def prepare_ai_repair_branch(
    storage: Storage,
    repair_id: int,
    repo_root: Path | str,
    actor: str = "operator",
    note: str = "",
    commands: list[str] | None = None,
) -> dict:
    repair = require_ai_repair(storage, repair_id)
    if str(repair.get("status") or "") not in {"approved", "branch_prepared", "branch_failed"}:
        raise ValueError("AI repair must be approved before preparing a controlled branch")
    approval_report = safe_dict(safe_dict(repair.get("test_result")).get("approval_report"))
    if not approval_report.get("ready_to_approve"):
        raise ValueError("approval report is not ready; run sandbox-test before approval")
    patch = safe_dict(repair.get("patch"))
    requested_commands = (
        safe_list(commands) if commands is not None else safe_list(safe_dict(repair.get("test_plan")).get("commands"))
    )
    controlled_apply = prepare_patch_branch(Path(repo_root), repair, patch, requested_commands)
    next_status = "branch_prepared" if controlled_apply.get("ready_for_pr") else "branch_failed"
    result = {
        "status": "passed" if controlled_apply.get("ready_for_pr") else "failed",
        "commands": controlled_apply.get("commands", []),
        "output": controlled_apply.get("output", ""),
        "error": controlled_apply.get("error", ""),
        "note": note or "approved repair branch preparation completed",
        "validation": safe_dict(controlled_apply.get("validation")),
        "guardrails": safe_dict(safe_dict(repair.get("test_result")).get("guardrails")),
        "sandbox": safe_dict(safe_dict(repair.get("test_result")).get("sandbox")),
        "approval_report": approval_report,
        "controlled_apply": controlled_apply,
    }
    return storage.update_ai_repair_proposal_status(
        repair_id,
        next_status,
        actor=actor,
        note=note,
        test_result=result,
    )


def publish_ai_repair_pull_request(
    storage: Storage,
    repair_id: int,
    repo_root: Path | str,
    actor: str = "operator",
    note: str = "",
    remote: str = "origin",
    base: str = "main",
    draft: bool = True,
) -> dict:
    repair = require_ai_repair(storage, repair_id)
    if str(repair.get("status") or "") not in {"branch_prepared", "pr_failed", "pr_created"}:
        raise ValueError("AI repair branch must be prepared before creating a pull request")
    result_payload = safe_dict(repair.get("test_result"))
    controlled_apply = safe_dict(result_payload.get("controlled_apply"))
    if not controlled_apply.get("ready_for_pr"):
        raise ValueError("controlled branch is not ready for PR creation")
    pull_request = publish_prepared_branch_pull_request(
        Path(repo_root),
        repair,
        controlled_apply,
        remote=remote,
        base=base,
        draft=draft,
    )
    next_status = "pr_created" if pull_request.get("ready_for_review") else "pr_failed"
    result = {
        **result_payload,
        "status": "passed" if pull_request.get("ready_for_review") else "failed",
        "note": note or "AI repair pull request publication completed",
        "error": pull_request.get("error", ""),
        "pull_request": pull_request,
    }
    return storage.update_ai_repair_proposal_status(
        repair_id,
        next_status,
        actor=actor,
        note=note,
        test_result=result,
    )


def deploy_ai_repair_after_merge(
    storage: Storage,
    repair_id: int,
    repo_root: Path | str,
    actor: str = "operator",
    note: str = "",
    remote: str = "origin",
    base: str = "main",
    commands: list[str] | None = None,
    verify_urls: list[str] | None = None,
    rollback_commands: list[str] | None = None,
    rollback_verify_urls: list[str] | None = None,
    assume_merged: bool = False,
) -> dict:
    repair = require_ai_repair(storage, repair_id)
    if str(repair.get("status") or "") not in {
        "pr_created",
        "merge_pending",
        "deploy_failed",
        "rollback_succeeded",
        "rollback_failed",
        "deployed",
    }:
        raise ValueError("AI repair pull request must be created before merged deployment")
    result_payload = safe_dict(repair.get("test_result"))
    pull_request = safe_dict(result_payload.get("pull_request"))
    if not pull_request.get("ready_for_review"):
        raise ValueError("pull request metadata is not ready for deployment")
    pr_status = (
        {"status": "merged", "merged": True, "source": "assumed", "error": ""}
        if assume_merged
        else github_pull_request_status(Path(repo_root), pull_request, remote=remote)
    )
    if not pr_status.get("merged"):
        deploy_result = {
            "status": "skipped",
            "ready": False,
            "reason": "pull request is not merged",
            "error": pr_status.get("error", ""),
        }
        updated_result = {
            **result_payload,
            "status": "not_run",
            "note": note or "PR merge check completed; deployment not started",
            "pull_request_status": pr_status,
            "deploy_result": deploy_result,
        }
        return storage.update_ai_repair_proposal_status(
            repair_id,
            "merge_pending",
            actor=actor,
            note=note,
            test_result=updated_result,
        )

    deploy_result = deploy_merged_pull_request(
        Path(repo_root),
        remote=remote,
        base=base,
        commands=safe_list(commands) if commands is not None else DEFAULT_DEPLOY_COMMANDS,
        verify_urls=safe_list(verify_urls) if verify_urls is not None else [],
        rollback_commands=safe_list(rollback_commands) if rollback_commands is not None else None,
        rollback_verify_urls=safe_list(rollback_verify_urls) if rollback_verify_urls is not None else None,
    )
    rollback_result = safe_dict(deploy_result.get("rollback"))
    if deploy_result.get("ready"):
        next_status = "deployed"
    elif rollback_result.get("ready"):
        next_status = "rollback_succeeded"
    elif rollback_result.get("status") == "failed":
        next_status = "rollback_failed"
    else:
        next_status = "deploy_failed"
    updated_result = {
        **result_payload,
        "status": "passed" if deploy_result.get("ready") else "failed",
        "note": note or "merged PR deployment completed",
        "error": deploy_result.get("error", ""),
        "pull_request_status": pr_status,
        "deploy_result": deploy_result,
    }
    updated = storage.update_ai_repair_proposal_status(
        repair_id,
        next_status,
        actor=actor,
        note=note,
        test_result=updated_result,
    )
    record_ai_repair_deployment_change(
        storage,
        updated,
        deploy_result,
        pr_status,
        actor=actor,
        note=note,
        remote=remote,
        base=base,
    )
    return updated


def record_ai_repair_deployment_change(
    storage: Storage,
    repair: dict[str, Any],
    deploy_result: dict[str, Any],
    pr_status: dict[str, Any],
    actor: str,
    note: str,
    remote: str,
    base: str,
) -> dict:
    repair_id = safe_int(repair.get("id"))
    incident_id = safe_int(repair.get("incident_id"))
    incident = storage.get_incident(incident_id) if incident_id > 0 else {}
    rollback = safe_dict(deploy_result.get("rollback"))
    status = str(repair.get("status") or "")
    change_type = "rollback" if status.startswith("rollback") else "deployment"
    event_status = "completed" if status in {"deployed", "rollback_succeeded"} else "failed"
    commit_sha = str(deploy_result.get("after_commit") or rollback.get("after_commit") or "")
    pull_request = safe_dict(safe_dict(repair.get("test_result")).get("pull_request"))
    pr_url = str(pr_status.get("pr_url") or pull_request.get("pr_url") or "")
    links = [{"type": "pull_request", "url": pr_url}] if pr_url else []
    return storage.save_change_event(
        {
            "environment": str(safe_dict(incident).get("environment") or "prod"),
            "run_type": str(safe_dict(incident).get("run_type") or "normal"),
            "source": "ai_repair",
            "change_type": change_type,
            "title": f"AI repair #{repair_id} {status}",
            "summary": str(deploy_result.get("error") or note or repair.get("summary") or ""),
            "actor": actor,
            "status": event_status,
            "risk": str(repair.get("risk") or "medium"),
            "commit_sha": commit_sha,
            "branch": base,
            "related_incident_id": incident_id,
            "related_ai_repair_id": repair_id,
            "links": links,
            "metadata": {
                "repair_status": status,
                "repair_title": str(repair.get("title") or ""),
                "remote": remote,
                "base": base,
                "pull_request_status": pr_status,
                "deploy_result": deploy_result,
            },
        }
    )


def require_ai_repair(storage: Storage, repair_id: int) -> dict:
    repair = storage.get_ai_repair_proposal(repair_id)
    if not repair:
        raise ValueError(f"AI repair proposal not found: #{repair_id}")
    return repair


def proposal_context(
    incident: dict[str, Any],
    diagnosis: dict[str, Any],
    recommendations: list[dict],
    actions: list[dict],
    config: AppConfig | None,
    request: dict[str, Any] | None,
) -> dict[str, Any]:
    ai_config = safe_dict(config.raw.get("ai") if config else {})
    repair_config = safe_dict(ai_config.get("repair"))
    request_payload = safe_dict(request)
    project = select_repair_project(config, incident, diagnosis, request_payload)
    repository_context = build_repository_context(
        config,
        repair_config,
        incident,
        diagnosis,
        recommendations,
        project,
        request_payload,
    )
    return {
        "incident": incident,
        "diagnosis": diagnosis,
        "recommendations": recommendations,
        "actions": actions,
        "project": project,
        "repository_context": repository_context,
        "config": {
            "base_dir": str(config.base_dir) if config else "",
            "repair": repair_config,
            "provider": repair_config.get("provider") or "",
            "model": repair_config.get("model") or "",
            "project": project,
        },
        "request": request_payload,
    }


def should_use_model(context: dict[str, Any]) -> bool:
    config_context = safe_dict(context.get("config"))
    settings = safe_dict(config_context.get("repair"))
    provider = str(settings.get("provider") or config_context.get("provider") or "rules").strip().lower()
    if provider not in MODEL_PROVIDERS:
        return False
    if "enabled" in settings and not bool(settings.get("enabled")):
        return False
    return True


def model_based_repair(context: dict[str, Any]) -> dict[str, Any]:
    fallback = rule_based_repair(context)
    settings = repair_settings(context)
    prompt = build_model_prompt(context, settings)
    try:
        response_text = configured_model_response(settings, prompt)
        payload = parse_model_response(response_text)
        proposal = normalize_model_repair_payload(payload, context, fallback, prompt, settings)
    except ValueError as exc:
        return model_unavailable_repair(context, fallback, str(exc))
    return proposal


def repair_settings(context: dict[str, Any]) -> dict[str, Any]:
    config_context = safe_dict(context.get("config"))
    raw = safe_dict(config_context.get("repair"))
    provider = str(raw.get("provider") or config_context.get("provider") or "rules").strip().lower()
    endpoint_default = DEEPSEEK_MODEL_ENDPOINT if provider == "deepseek" else DEFAULT_MODEL_ENDPOINT
    model_default = DEEPSEEK_DEFAULT_MODEL if provider == "deepseek" else "gpt-4.1-mini"
    api_key_env_default = "DEEPSEEK_API_KEY" if provider == "deepseek" else "OPS_AGENT_LLM_API_KEY"
    return {
        "provider": provider,
        "model": str(raw.get("model") or config_context.get("model") or model_default),
        "endpoint_url": str(raw.get("endpoint_url") or endpoint_default),
        "api_key": str(raw.get("api_key") or ""),
        "api_key_env": str(raw.get("api_key_env") or api_key_env_default),
        "timeout_seconds": safe_int(raw.get("timeout_seconds"), DEFAULT_MODEL_TIMEOUT_SECONDS),
        "max_prompt_chars": safe_int(raw.get("max_prompt_chars"), DEFAULT_MAX_PROMPT_CHARS),
        "max_response_chars": safe_int(raw.get("max_response_chars"), DEFAULT_MAX_RESPONSE_CHARS),
        "mock_response": raw.get("mock_response"),
    }


def build_model_prompt(context: dict[str, Any], settings: dict[str, Any]) -> dict[str, Any]:
    incident = public_incident_context(safe_dict(context.get("incident")))
    diagnosis = safe_dict(context.get("diagnosis"))
    project = public_project_context(safe_dict(context.get("project")))
    repository_context = safe_dict(context.get("repository_context"))
    recommendations = [
        public_recommendation_context(item)
        for item in safe_list(context.get("recommendations"))[:10]
    ]
    actions = [
        public_action_context(item)
        for item in safe_list(context.get("actions"))[:10]
    ]
    user_payload = {
        "objective": "Generate a minimal repair proposal for this incident.",
        "incident": incident,
        "diagnosis": diagnosis,
        "recommendations": recommendations,
        "actions": actions,
        "project": project,
        "repository_context": repository_context,
        "output_schema": {
            "title": "short title",
            "summary": "short summary",
            "risk": "low|medium|high|critical",
            "root_cause": "probable root cause",
            "repair_plan": ["ordered repair steps"],
            "patch": {
                "schema_version": 1,
                "patch_type": "unified_diff|config_review|manual_code_review",
                "apply_mode": "proposal_only",
                "diff": "optional unified diff",
                "files": [{"path": "relative/path.py", "change_type": "modify|add|review", "reason": "why"}],
            },
            "test_plan": {"commands": ["python -m unittest discover -s tests"]},
        },
        "constraints": [
            "Return only a JSON object.",
            "Do not include secrets, credentials, private keys, tokens, or environment variable values.",
            "Use proposal_only apply mode. Do not ask to directly mutate production.",
            "Generate the smallest safe patch. Prefer diagnostics if evidence is insufficient.",
            "Use relative paths only. Do not modify .env, .ssh, .git, secrets, or private key files.",
            "Use repository_context.files as the primary source for unified diffs.",
            "If repository_context is missing or insufficient, return manual_code_review instead of inventing code.",
        ],
    }
    user_text = json.dumps(user_payload, ensure_ascii=False, sort_keys=True)
    max_prompt_chars = safe_int(settings.get("max_prompt_chars"), DEFAULT_MAX_PROMPT_CHARS)
    if len(user_text) > max_prompt_chars:
        user_text = user_text[:max_prompt_chars] + "\n...[truncated]"
    return {
        "system": (
            "You are an AI operations repair assistant. Produce safe, reviewable repair proposals. "
            "Never claim that a patch was applied. Never include secrets."
        ),
        "user": user_text,
    }


def configured_model_response(settings: dict[str, Any], prompt: dict[str, Any]) -> str:
    mock_response = settings.get("mock_response")
    if isinstance(mock_response, dict):
        return json.dumps(mock_response, ensure_ascii=False)
    if isinstance(mock_response, str) and mock_response.strip():
        return mock_response
    api_key = model_api_key(settings)
    if not api_key:
        raise ValueError(
            f"model API key is not configured; set {settings.get('api_key_env') or 'OPS_AGENT_LLM_API_KEY'}"
        )
    return call_openai_compatible_model(settings, prompt, api_key)


def call_openai_compatible_model(settings: dict[str, Any], prompt: dict[str, Any], api_key: str) -> str:
    body = {
        "model": str(settings.get("model") or "gpt-4.1-mini"),
        "messages": [
            {"role": "system", "content": str(prompt.get("system") or "")},
            {"role": "user", "content": str(prompt.get("user") or "")},
        ],
        "temperature": 0.1,
        "response_format": {"type": "json_object"},
    }
    data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        normalize_model_endpoint_url(settings),
        data=data,
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
    )
    timeout = safe_int(settings.get("timeout_seconds"), DEFAULT_MODEL_TIMEOUT_SECONDS)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as exc:
        raise ValueError(f"model request failed: {exc}") from exc
    if len(raw) > safe_int(settings.get("max_response_chars"), DEFAULT_MAX_RESPONSE_CHARS):
        raise ValueError("model response exceeded max_response_chars")
    parsed = parse_json_object(raw)
    choices = safe_list(parsed.get("choices"))
    first = safe_dict(choices[0]) if choices else {}
    message = safe_dict(first.get("message"))
    content = str(message.get("content") or "")
    if not content.strip():
        raise ValueError("model response did not include message content")
    return content


def normalize_model_endpoint_url(settings: dict[str, Any]) -> str:
    provider = str(settings.get("provider") or "").strip().lower()
    endpoint = str(settings.get("endpoint_url") or "").strip().rstrip("/")
    if not endpoint:
        return DEEPSEEK_MODEL_ENDPOINT if provider == "deepseek" else DEFAULT_MODEL_ENDPOINT
    if provider == "deepseek" and endpoint in {"https://api.deepseek.com", "https://api.deepseek.com/v1"}:
        return f"{endpoint}/chat/completions"
    return endpoint


def model_api_key(settings: dict[str, Any]) -> str:
    direct = str(settings.get("api_key") or "").strip()
    if direct:
        return direct
    env_name = str(settings.get("api_key_env") or "OPS_AGENT_LLM_API_KEY").strip()
    return os.environ.get(env_name, "").strip() if env_name else ""


def parse_model_response(response_text: str) -> dict[str, Any]:
    text = response_text.strip()
    parsed = parse_json_object(text)
    if parsed:
        return parsed
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        parsed = parse_json_object(text[start : end + 1])
    if not parsed:
        raise ValueError("model response is not valid JSON")
    return parsed


def normalize_model_repair_payload(
    payload: dict[str, Any],
    context: dict[str, Any],
    fallback: dict[str, Any],
    prompt: dict[str, Any],
    settings: dict[str, Any],
) -> dict[str, Any]:
    patch = safe_dict(payload.get("patch")) or safe_dict(fallback.get("patch"))
    patch["schema_version"] = safe_int(patch.get("schema_version"), 1)
    patch["apply_mode"] = "proposal_only"
    if "patch_type" not in patch:
        patch["patch_type"] = "unified_diff" if str(patch.get("diff") or "").strip() else "manual_code_review"
    validation = validate_patch_dry_run(patch)
    repair_plan = safe_list(payload.get("repair_plan")) or safe_list(safe_dict(fallback.get("proposal")).get("repair_plan"))
    limitations = [
        "No production code is changed by this proposal.",
        "Generated patches require dry-run validation, tests, and approval before use.",
    ]
    if not validation["valid"]:
        limitations.append("Generated patch failed safety validation and must be revised.")
    return {
        "title": str(payload.get("title") or fallback.get("title") or "AI repair proposal"),
        "summary": str(payload.get("summary") or fallback.get("summary") or ""),
        "risk": normalize_risk(payload.get("risk") or fallback.get("risk")),
        "root_cause": str(payload.get("root_cause") or fallback.get("root_cause") or ""),
        "model_provider": str(settings.get("provider") or "openai_compatible"),
        "model_name": str(settings.get("model") or ""),
        "prompt": {
            "mode": "model_repair_proposal",
            "provider": str(settings.get("provider") or ""),
            "model": str(settings.get("model") or ""),
            "system": prompt.get("system"),
            "user": prompt.get("user"),
            "validation": validation,
            "requested_by": safe_dict(context.get("request")).get("actor") or "",
        },
        "proposal": {
            "root_cause": str(payload.get("root_cause") or fallback.get("root_cause") or ""),
            "repair_plan": [str(item) for item in repair_plan],
            "review_required": True,
            "limitations": limitations,
        },
        "patch": patch,
        "test_plan": normalize_test_plan(payload.get("test_plan") or fallback.get("test_plan")),
    }


def model_unavailable_repair(context: dict[str, Any], fallback: dict[str, Any], reason: str) -> dict[str, Any]:
    config_context = safe_dict(context.get("config"))
    settings = safe_dict(config_context.get("repair"))
    proposal = safe_dict(fallback.get("proposal"))
    limitations = safe_list(proposal.get("limitations"))
    limitations.append(f"Model repair generation unavailable: {reason}")
    fallback["model_provider"] = str(settings.get("provider") or "openai_compatible")
    fallback["model_name"] = str(settings.get("model") or "")
    fallback["summary"] = f"{fallback.get('summary', '')} Model generation was skipped; rules fallback was used.".strip()
    fallback["prompt"] = {
        **safe_dict(fallback.get("prompt")),
        "mode": "rules_fallback_after_model_unavailable",
        "model_unavailable_reason": reason,
    }
    fallback["proposal"] = {**proposal, "limitations": limitations}
    return fallback


def rule_based_repair(context: dict[str, Any]) -> dict[str, Any]:
    incident = safe_dict(context.get("incident"))
    diagnosis = safe_dict(context.get("diagnosis"))
    summary = str(incident.get("last_summary") or incident.get("title") or "")
    category = str(
        diagnosis.get("top_category")
        or incident.get("classification_category")
        or ""
    )
    if is_healthcheck_config_issue(summary, category):
        return healthcheck_config_repair(context)
    if category in {"unknown", "unclassified", ""}:
        return classifier_repair(context)
    return generic_repair(context)


def healthcheck_config_repair(context: dict[str, Any]) -> dict[str, Any]:
    incident = safe_dict(context.get("incident"))
    url = extract_url(str(incident.get("last_summary") or ""))
    return base_repair(
        context,
        title=f"Review health check endpoint for incident #{incident.get('id')}",
        summary=(
            "The incident looks like a monitor or health-check route mismatch. "
            "Generate a configuration patch proposal before changing production code."
        ),
        risk="low",
        root_cause="Health endpoint returned 404 while the primary site may still be reachable.",
        repair_plan=[
            "Confirm the service's real health endpoint from the deployed application or reverse proxy.",
            "Update the monitor target to a real health route or add a lightweight health endpoint.",
            "Run API/dashboard tests before deployment.",
        ],
        patch={
            "schema_version": 1,
            "patch_type": "config_or_route_review",
            "apply_mode": "proposal_only",
            "operations": [
                {
                    "op": "review_monitor_target",
                    "path": ["http_checks"],
                    "match": {"url": url, "status_code": 404},
                    "recommended_change": "Replace missing /healthz monitor path with a valid health endpoint or add the route in application code.",
                }
            ],
            "files": [
                {
                    "path": "config.json",
                    "change_type": "review",
                    "reason": "Monitor URL may point to a missing route.",
                }
            ],
        },
        test_plan=DEFAULT_TEST_COMMANDS,
    )


def classifier_repair(context: dict[str, Any]) -> dict[str, Any]:
    incident = safe_dict(context.get("incident"))
    return base_repair(
        context,
        title=f"Improve classification rule for incident #{incident.get('id')}",
        summary="The incident lacks a confident category; propose a classifier/playbook tuning task.",
        risk="medium",
        root_cause="Classifier confidence is missing or too low for safe automated repair.",
        repair_plan=[
            "Collect examples from the incident and related events.",
            "Add a draft classifier rule with positive and negative evidence.",
            "Keep the rule disabled until reviewed.",
        ],
        patch={
            "schema_version": 1,
            "patch_type": "classifier_review",
            "apply_mode": "proposal_only",
            "operations": [
                {
                    "op": "draft_classifier_rule",
                    "path": ["classification_rules"],
                    "recommended_change": "Add a disabled classifier rule after owner review.",
                }
            ],
            "files": [
                {
                    "path": "config.json",
                    "change_type": "review",
                    "reason": "Classifier rules live in configuration.",
                }
            ],
        },
        test_plan=DEFAULT_TEST_COMMANDS,
    )


def generic_repair(context: dict[str, Any]) -> dict[str, Any]:
    incident = safe_dict(context.get("incident"))
    category = str(incident.get("classification_category") or "general")
    return base_repair(
        context,
        title=f"AI repair draft for incident #{incident.get('id')}",
        summary="Create a repair proposal from incident context. Human review is required before patch application.",
        risk="medium",
        root_cause=f"Incident category: {category}. More evidence is required before code changes.",
        repair_plan=[
            "Review diagnosis, failed actions, and recent deployment changes.",
            "Identify the smallest code or configuration change.",
            "Apply only in a temporary branch or sandbox, then run tests.",
        ],
        patch={
            "schema_version": 1,
            "patch_type": "manual_code_review",
            "apply_mode": "proposal_only",
            "operations": [
                {
                    "op": "manual_patch_required",
                    "path": [],
                    "recommended_change": "Generate a concrete diff after model provider is configured.",
                }
            ],
            "files": [],
        },
        test_plan=DEFAULT_TEST_COMMANDS,
    )


def base_repair(
    context: dict[str, Any],
    title: str,
    summary: str,
    risk: str,
    root_cause: str,
    repair_plan: list[str],
    patch: dict[str, Any],
    test_plan: list[str],
) -> dict[str, Any]:
    request = safe_dict(context.get("request"))
    config_context = safe_dict(context.get("config"))
    return {
        "title": title,
        "summary": summary,
        "risk": risk,
        "root_cause": root_cause,
        "model_provider": str(config_context.get("provider") or "rules"),
        "model_name": str(config_context.get("model") or "rule-based-repair-v1"),
        "prompt": {
            "mode": "rules_until_model_configured",
            "requested_by": request.get("actor") or "",
            "incident": safe_dict(context.get("incident")),
            "diagnosis": safe_dict(context.get("diagnosis")),
            "recommendation_count": len(safe_list(context.get("recommendations"))),
            "action_count": len(safe_list(context.get("actions"))),
        },
        "proposal": {
            "root_cause": root_cause,
            "repair_plan": repair_plan,
            "review_required": True,
            "limitations": [
                "No production code is changed by this proposal.",
                "A configured model provider is required for concrete source-code diffs.",
            ],
        },
        "patch": patch,
        "test_plan": {
            "commands": test_plan,
            "requires_sandbox": True,
            "run_before_merge": True,
        },
    }


def validate_patch_dry_run(patch: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    operations = safe_list(patch.get("operations"))
    files = safe_list(patch.get("files"))
    diff = str(patch.get("diff") or "")
    apply_mode = str(patch.get("apply_mode") or "proposal_only")
    patch_type = str(patch.get("patch_type") or "")
    if apply_mode != "proposal_only":
        errors.append("patch apply_mode must be proposal_only")
    if len(diff) > MAX_DIFF_CHARS:
        errors.append(f"diff is too large: {len(diff)} chars")
    if not operations and not files and not diff.strip():
        if patch_type in {"manual_code_review", "config_review", "config_or_route_review"}:
            warnings.append("review-only proposal has no patch operations, files, or diff")
        else:
            errors.append("patch has no operations, files, or diff")
    for file_item in files:
        file_payload = safe_dict(file_item)
        path = str(file_payload.get("path") or "")
        if not is_safe_patch_path(path):
            errors.append(f"unsafe file path: {path}")
    for diff_path in diff_paths(diff):
        if not is_safe_patch_path(diff_path):
            errors.append(f"unsafe diff path: {diff_path}")
    if not diff.strip():
        warnings.append("no unified diff was generated; proposal remains review-only")
    checked_files = sorted(
        {
            str(safe_dict(item).get("path") or "")
            for item in files
            if str(safe_dict(item).get("path") or "")
        }
        | set(diff_paths(diff))
    )
    return {
        "valid": not errors,
        "errors": errors,
        "warnings": warnings,
        "checked_files": checked_files,
        "operation_count": len(operations),
        "diff_path_count": len(diff_paths(diff)),
        "mutates_files": bool(diff.strip()),
    }


def build_sandbox_guardrail_report(
    patch: dict[str, Any],
    commands: list[Any],
    validation: dict[str, Any] | None = None,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    validation_payload = safe_dict(validation) or validate_patch_dry_run(patch)
    policy_payload = normalize_ai_repair_policy(policy or {})
    diff = str(patch.get("diff") or "")
    checked_files = [
        str(path)
        for path in safe_list(validation_payload.get("checked_files"))
        if str(path).strip()
    ]
    requested_commands = [str(item).strip() for item in commands if str(item).strip()]
    if not requested_commands:
        requested_commands = list(DEFAULT_TEST_COMMANDS)

    blockers: list[str] = []
    warnings: list[str] = []
    if not validation_payload.get("valid"):
        blockers.extend(str(error) for error in safe_list(validation_payload.get("errors")))
    if not diff.strip():
        blockers.append("patch has no unified diff to sandbox")
    max_changed_files = safe_int(
        policy_payload.get("max_changed_files"),
        safe_int(DEFAULT_AI_REPAIR_POLICY["max_changed_files"], 5),
    )
    if len(checked_files) > max_changed_files:
        blockers.append(f"patch changes too many files: {len(checked_files)} > {max_changed_files}")
    for path in checked_files:
        reason = patch_path_guardrail_reason(path)
        if reason:
            blockers.append(f"{reason}: {path}")

    if len(requested_commands) > DEFAULT_SANDBOX_MAX_COMMANDS:
        blockers.append(f"too many sandbox test commands: {len(requested_commands)} > {DEFAULT_SANDBOX_MAX_COMMANDS}")
    for command in requested_commands:
        if not is_safe_test_command(command):
            blockers.append(f"unsafe test command: {command}")

    warnings.extend(str(item) for item in safe_list(validation_payload.get("warnings")))
    return {
        "status": "blocked" if blockers else "passed",
        "blockers": unique_strings(blockers),
        "warnings": unique_strings(warnings),
        "checked_files": checked_files,
        "commands": requested_commands,
        "limits": {
            "max_changed_files": max_changed_files,
            "max_commands": DEFAULT_SANDBOX_MAX_COMMANDS,
            "max_diff_chars": MAX_DIFF_CHARS,
        },
    }


def normalize_test_result(result: dict[str, Any], repair: dict[str, Any]) -> dict[str, Any]:
    status = str(result.get("status") or "").strip().lower()
    if status not in SAFE_STATUSES:
        status = "not_run"
    commands = safe_list(result.get("commands"))
    if not commands:
        commands = safe_list(safe_dict(repair.get("test_plan")).get("commands"))
    return {
        "status": status,
        "commands": [str(item) for item in commands],
        "output": str(result.get("output") or ""),
        "error": str(result.get("error") or ""),
        "note": str(result.get("note") or "test execution is external until sandbox runner is configured"),
        "validation": safe_dict(result.get("validation")),
        "guardrails": safe_dict(result.get("guardrails")),
        "sandbox": safe_dict(result.get("sandbox")),
        "approval_report": safe_dict(result.get("approval_report")),
        "controlled_apply": safe_dict(result.get("controlled_apply")),
        "pull_request": safe_dict(result.get("pull_request")),
        "pull_request_status": safe_dict(result.get("pull_request_status")),
        "deploy_result": safe_dict(result.get("deploy_result")),
    }


def run_patch_in_sandbox(repo_root: Path, patch: dict[str, Any], commands: list[Any]) -> dict[str, Any]:
    started = time.monotonic()
    validation = validate_patch_dry_run(patch)
    requested_commands = [str(item).strip() for item in commands if str(item).strip()]
    if not requested_commands:
        requested_commands = DEFAULT_TEST_COMMANDS
    sandbox_result: dict[str, Any] = {
        "status": "failed",
        "repo_root": str(repo_root),
        "commands": requested_commands,
        "patch_applied": False,
        "cleanup": True,
        "output": "",
        "error": "",
        "validation": validation,
    }
    if not validation["valid"]:
        sandbox_result["error"] = "; ".join(validation["errors"])
        sandbox_result["duration_seconds"] = round(time.monotonic() - started, 3)
        return sandbox_result
    diff = str(patch.get("diff") or "")
    if not diff.strip():
        sandbox_result["status"] = "skipped"
        sandbox_result["error"] = "patch has no unified diff to apply in sandbox"
        sandbox_result["duration_seconds"] = round(time.monotonic() - started, 3)
        return sandbox_result
    root = repo_root.resolve()
    if not root.exists() or not root.is_dir():
        sandbox_result["error"] = f"repo root not found: {root}"
        sandbox_result["duration_seconds"] = round(time.monotonic() - started, 3)
        return sandbox_result
    unsafe_command = next((command for command in requested_commands if not is_safe_test_command(command)), "")
    if unsafe_command:
        sandbox_result["error"] = f"unsafe test command: {unsafe_command}"
        sandbox_result["duration_seconds"] = round(time.monotonic() - started, 3)
        return sandbox_result
    with tempfile.TemporaryDirectory(prefix=f"ops-agent-repair-{safe_int(patch.get('schema_version'), 1)}-") as tmp:
        sandbox_dir = Path(tmp) / "repo"
        copy_repo_to_sandbox(root, sandbox_dir)
        patch_path = Path(tmp) / "repair.patch"
        patch_path.write_text(diff, encoding="utf-8")
        check = run_subprocess(["git", "init"], sandbox_dir, timeout_seconds=30)
        if check["returncode"] != 0:
            sandbox_result["error"] = f"git init failed: {check['stderr']}"
            sandbox_result["duration_seconds"] = round(time.monotonic() - started, 3)
            return sandbox_result
        check = run_subprocess(["git", "apply", "--check", str(patch_path)], sandbox_dir, timeout_seconds=30)
        if check["returncode"] != 0:
            sandbox_result["error"] = f"git apply --check failed: {check['stderr'] or check['stdout']}"
            sandbox_result["duration_seconds"] = round(time.monotonic() - started, 3)
            return sandbox_result
        applied = run_subprocess(["git", "apply", str(patch_path)], sandbox_dir, timeout_seconds=30)
        if applied["returncode"] != 0:
            sandbox_result["error"] = f"git apply failed: {applied['stderr'] or applied['stdout']}"
            sandbox_result["duration_seconds"] = round(time.monotonic() - started, 3)
            return sandbox_result
        sandbox_result["patch_applied"] = True
        test_execution = run_safe_test_commands(sandbox_dir, requested_commands)
        sandbox_result.update(
            {
                **test_execution,
                "duration_seconds": round(time.monotonic() - started, 3),
            }
        )
    return sandbox_result


def prepare_patch_branch(
    repo_root: Path,
    repair: dict[str, Any],
    patch: dict[str, Any],
    commands: list[Any],
) -> dict[str, Any]:
    started = time.monotonic()
    validation = validate_patch_dry_run(patch)
    requested_commands = [str(item).strip() for item in commands if str(item).strip()]
    if not requested_commands:
        requested_commands = DEFAULT_TEST_COMMANDS
    repair_id = safe_int(repair.get("id"))
    result: dict[str, Any] = {
        "status": "failed",
        "ready_for_pr": False,
        "repo_root": str(repo_root),
        "commands": requested_commands,
        "branch_name": "",
        "worktree_path": "",
        "commit": "",
        "changed_files": [],
        "patch_applied": False,
        "commit_created": False,
        "output": "",
        "error": "",
        "validation": validation,
        "blockers": [],
    }
    blockers = controlled_apply_blockers(repo_root, repair, patch, validation, requested_commands)
    if blockers:
        result["blockers"] = blockers
        result["error"] = "; ".join(blockers)
        result["duration_seconds"] = round(time.monotonic() - started, 3)
        return result

    root = repo_root.resolve()
    timestamp = time.strftime("%Y%m%d%H%M%S", time.gmtime())
    branch_name = f"{CONTROLLED_BRANCH_PREFIX}-{repair_id}-{timestamp}"
    worktree_base = root.parent / f"{root.name}-{CONTROLLED_WORKTREE_SUFFIX}"
    worktree_base.mkdir(parents=True, exist_ok=True)
    worktree_dir = worktree_base / f"repair-{repair_id}-{timestamp}"
    suffix = 1
    while worktree_dir.exists():
        branch_name = f"{CONTROLLED_BRANCH_PREFIX}-{repair_id}-{timestamp}-{suffix}"
        worktree_dir = worktree_base / f"repair-{repair_id}-{timestamp}-{suffix}"
        suffix += 1

    diff = str(patch.get("diff") or "")
    patch_path = worktree_base / f"{branch_name}.patch"
    patch_path.write_text(diff, encoding="utf-8")
    result.update({"branch_name": branch_name, "worktree_path": str(worktree_dir), "patch_path": str(patch_path)})

    added = run_git(["worktree", "add", "-b", branch_name, str(worktree_dir), "HEAD"], root)
    if added["returncode"] != 0:
        result["error"] = f"git worktree add failed: {added['stderr'] or added['stdout']}"
        result["duration_seconds"] = round(time.monotonic() - started, 3)
        return result
    checked = run_git(["apply", "--check", str(patch_path)], worktree_dir)
    if checked["returncode"] != 0:
        result["error"] = f"git apply --check failed: {checked['stderr'] or checked['stdout']}"
        result["duration_seconds"] = round(time.monotonic() - started, 3)
        return result
    applied = run_git(["apply", str(patch_path)], worktree_dir)
    if applied["returncode"] != 0:
        result["error"] = f"git apply failed: {applied['stderr'] or applied['stdout']}"
        result["duration_seconds"] = round(time.monotonic() - started, 3)
        return result
    result["patch_applied"] = True

    test_execution = run_safe_test_commands(worktree_dir, requested_commands)
    result.update(test_execution)
    if test_execution["status"] != "passed":
        result["duration_seconds"] = round(time.monotonic() - started, 3)
        return result

    status = run_git(["status", "--porcelain"], worktree_dir)
    if status["returncode"] != 0:
        result["error"] = f"git status failed: {status['stderr'] or status['stdout']}"
        result["duration_seconds"] = round(time.monotonic() - started, 3)
        return result
    changed_files = git_status_paths(status["stdout"])
    intended_files = [str(path) for path in safe_list(validation.get("checked_files")) if str(path).strip()]
    result["changed_files"] = intended_files
    result["worktree_extra_changes"] = sorted(path for path in changed_files if path not in set(intended_files))
    if not intended_files:
        result["error"] = "patch applied but produced no git changes"
        result["duration_seconds"] = round(time.monotonic() - started, 3)
        return result

    added_files = run_git(["add", "--", *intended_files], worktree_dir)
    if added_files["returncode"] != 0:
        result["error"] = f"git add failed: {added_files['stderr'] or added_files['stdout']}"
        result["duration_seconds"] = round(time.monotonic() - started, 3)
        return result
    staged = run_git(["diff", "--cached", "--name-only"], worktree_dir)
    if staged["returncode"] != 0:
        result["error"] = f"git diff --cached failed: {staged['stderr'] or staged['stdout']}"
        result["duration_seconds"] = round(time.monotonic() - started, 3)
        return result
    staged_files = [line.strip() for line in staged["stdout"].splitlines() if line.strip()]
    result["changed_files"] = staged_files
    if not staged_files:
        result["error"] = "patch applied but no intended files were staged"
        result["duration_seconds"] = round(time.monotonic() - started, 3)
        return result
    committed = run_subprocess(
        [
            "git",
            "-c",
            "user.name=Ops Agent",
            "-c",
            "user.email=ops-agent@example.local",
            "commit",
            "-m",
            f"Apply AI repair #{repair_id}",
        ],
        worktree_dir,
        timeout_seconds=DEFAULT_GIT_TIMEOUT_SECONDS,
    )
    if committed["returncode"] != 0:
        result["error"] = f"git commit failed: {committed['stderr'] or committed['stdout']}"
        result["duration_seconds"] = round(time.monotonic() - started, 3)
        return result
    head = run_git(["rev-parse", "HEAD"], worktree_dir)
    if head["returncode"] != 0:
        result["error"] = f"git rev-parse failed: {head['stderr'] or head['stdout']}"
        result["duration_seconds"] = round(time.monotonic() - started, 3)
        return result
    result.update(
        {
            "status": "passed",
            "ready_for_pr": True,
            "commit_created": True,
            "commit": head["stdout"].strip(),
            "duration_seconds": round(time.monotonic() - started, 3),
        }
    )
    return result


def publish_prepared_branch_pull_request(
    repo_root: Path,
    repair: dict[str, Any],
    controlled_apply: dict[str, Any],
    remote: str = "origin",
    base: str = "main",
    draft: bool = True,
) -> dict[str, Any]:
    started = time.monotonic()
    branch_name = str(controlled_apply.get("branch_name") or "").strip()
    worktree_path = str(controlled_apply.get("worktree_path") or "").strip()
    remote_name = normalize_git_ref(remote, "origin")
    base_branch = normalize_git_ref(base, "main")
    result: dict[str, Any] = {
        "status": "failed",
        "ready_for_review": False,
        "branch_name": branch_name,
        "base": base_branch,
        "remote": remote_name,
        "repo_slug": "",
        "pushed": False,
        "pr_url": "",
        "pr_number": None,
        "method": "",
        "draft": bool(draft),
        "title": "",
        "body": "",
        "error": "",
    }
    if not branch_name:
        result["error"] = "controlled apply result has no branch name"
        result["duration_seconds"] = round(time.monotonic() - started, 3)
        return result
    if not worktree_path:
        result["error"] = "controlled apply result has no worktree path"
        result["duration_seconds"] = round(time.monotonic() - started, 3)
        return result
    worktree = Path(worktree_path).resolve()
    if not worktree.exists() or not worktree.is_dir():
        result["error"] = f"worktree not found: {worktree}"
        result["duration_seconds"] = round(time.monotonic() - started, 3)
        return result

    current_branch = run_git(["rev-parse", "--abbrev-ref", "HEAD"], worktree)
    if current_branch["returncode"] != 0 or current_branch["stdout"].strip() != branch_name:
        result["error"] = f"worktree is not on expected branch: {current_branch['stdout'] or current_branch['stderr']}"
        result["duration_seconds"] = round(time.monotonic() - started, 3)
        return result
    push = run_git(
        ["push", "-u", remote_name, f"{branch_name}:{branch_name}"],
        worktree,
        timeout_seconds=DEFAULT_GIT_PUSH_TIMEOUT_SECONDS,
    )
    if push["returncode"] != 0:
        result["error"] = f"git push failed: {push['stderr'] or push['stdout']}"
        result["duration_seconds"] = round(time.monotonic() - started, 3)
        return result
    result["pushed"] = True

    remote_url = run_git(["remote", "get-url", remote_name], worktree)
    repo_slug = github_repo_slug(remote_url["stdout"].strip()) if remote_url["returncode"] == 0 else ""
    title = pull_request_title(repair, branch_name)
    body = pull_request_body(repair, controlled_apply, base_branch)
    result.update({"repo_slug": repo_slug, "title": title, "body": body})

    pr_result = create_github_pull_request(
        worktree,
        repo_slug=repo_slug,
        head=branch_name,
        base=base_branch,
        title=title,
        body=body,
        draft=draft,
    )
    result.update(pr_result)
    result["duration_seconds"] = round(time.monotonic() - started, 3)
    return result


def create_github_pull_request(
    worktree: Path,
    repo_slug: str,
    head: str,
    base: str,
    title: str,
    body: str,
    draft: bool,
) -> dict[str, Any]:
    gh_result = create_github_pull_request_with_gh(
        worktree,
        repo_slug=repo_slug,
        head=head,
        base=base,
        title=title,
        body=body,
        draft=draft,
    )
    if gh_result.get("ready_for_review"):
        return gh_result
    api_result = create_github_pull_request_with_api(
        repo_slug=repo_slug,
        head=head,
        base=base,
        title=title,
        body=body,
        draft=draft,
    )
    if api_result.get("ready_for_review"):
        return api_result
    errors = [str(item.get("error") or "") for item in (gh_result, api_result) if item.get("error")]
    return {
        "status": "failed",
        "ready_for_review": False,
        "method": "github",
        "pr_url": "",
        "pr_number": None,
        "error": "; ".join(errors) or "unable to create GitHub pull request",
    }


def create_github_pull_request_with_gh(
    worktree: Path,
    repo_slug: str,
    head: str,
    base: str,
    title: str,
    body: str,
    draft: bool,
) -> dict[str, Any]:
    command = ["gh", "pr", "create", "--head", head, "--base", base, "--title", title, "--body", body]
    if repo_slug:
        command.extend(["--repo", repo_slug])
    if draft:
        command.append("--draft")
    created = run_subprocess(command, worktree, timeout_seconds=DEFAULT_GITHUB_TIMEOUT_SECONDS)
    if created["returncode"] != 0:
        return {
            "status": "failed",
            "ready_for_review": False,
            "method": "gh",
            "pr_url": "",
            "pr_number": None,
            "error": f"gh pr create failed: {created['stderr'] or created['stdout']}",
        }
    pr_url = first_url(created["stdout"] or created["stderr"])
    return {
        "status": "passed",
        "ready_for_review": bool(pr_url),
        "method": "gh",
        "pr_url": pr_url,
        "pr_number": pr_number_from_url(pr_url),
        "error": "" if pr_url else "gh pr create did not return a PR URL",
    }


def create_github_pull_request_with_api(
    repo_slug: str,
    head: str,
    base: str,
    title: str,
    body: str,
    draft: bool,
) -> dict[str, Any]:
    if not repo_slug:
        return {
            "status": "failed",
            "ready_for_review": False,
            "method": "github_api",
            "pr_url": "",
            "pr_number": None,
            "error": "cannot infer GitHub repository from git remote",
        }
    token = github_token()
    if not token:
        return {
            "status": "failed",
            "ready_for_review": False,
            "method": "github_api",
            "pr_url": "",
            "pr_number": None,
            "error": "missing GITHUB_TOKEN or GH_TOKEN for GitHub API fallback",
        }
    request_body = json.dumps(
        {
            "title": title,
            "head": head,
            "base": base,
            "body": body,
            "draft": bool(draft),
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repo_slug}/pulls",
        data=request_body,
        method="POST",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "ops-agent",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=DEFAULT_GITHUB_TIMEOUT_SECONDS) as response:
            payload = parse_json_object(response.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="replace")
        return {
            "status": "failed",
            "ready_for_review": False,
            "method": "github_api",
            "pr_url": "",
            "pr_number": None,
            "error": f"GitHub API failed HTTP {exc.code}: {truncate_text(error_body, 1000)}",
        }
    except urllib.error.URLError as exc:
        return {
            "status": "failed",
            "ready_for_review": False,
            "method": "github_api",
            "pr_url": "",
            "pr_number": None,
            "error": f"GitHub API request failed: {exc}",
        }
    return {
        "status": "passed",
        "ready_for_review": bool(payload.get("html_url")),
        "method": "github_api",
        "pr_url": str(payload.get("html_url") or ""),
        "pr_number": safe_int(payload.get("number")),
        "error": "" if payload.get("html_url") else "GitHub API response did not include html_url",
    }


def github_pull_request_status(repo_root: Path, pull_request: dict[str, Any], remote: str = "origin") -> dict[str, Any]:
    pr_url = str(pull_request.get("pr_url") or "")
    pr_number = safe_int(pull_request.get("pr_number"))
    repo_slug = str(pull_request.get("repo_slug") or "").strip()
    if not repo_slug:
        remote_url = run_git(["remote", "get-url", normalize_git_ref(remote, "origin")], repo_root)
        if remote_url["returncode"] == 0:
            repo_slug = github_repo_slug(remote_url["stdout"].strip())
    gh_status = github_pull_request_status_with_gh(repo_root, pr_url, pr_number, repo_slug)
    if gh_status.get("checked"):
        return gh_status
    api_status = github_pull_request_status_with_api(repo_slug, pr_number)
    if api_status.get("checked"):
        return api_status
    errors = [str(item.get("error") or "") for item in (gh_status, api_status) if item.get("error")]
    return {
        "checked": False,
        "merged": False,
        "status": "unknown",
        "source": "github",
        "error": "; ".join(errors) or "unable to check pull request merge status",
    }


def github_pull_request_status_with_gh(
    repo_root: Path,
    pr_url: str,
    pr_number: int,
    repo_slug: str,
) -> dict[str, Any]:
    target = pr_url or str(pr_number or "")
    if not target:
        return {"checked": False, "merged": False, "status": "unknown", "source": "gh", "error": "missing PR URL/number"}
    command = [
        "gh",
        "pr",
        "view",
        target,
        "--json",
        "state,mergedAt,mergeCommit,url,number,headRefName,baseRefName",
    ]
    if repo_slug:
        command.extend(["--repo", repo_slug])
    viewed = run_subprocess(command, repo_root, timeout_seconds=DEFAULT_GITHUB_TIMEOUT_SECONDS)
    if viewed["returncode"] != 0:
        return {
            "checked": False,
            "merged": False,
            "status": "unknown",
            "source": "gh",
            "error": f"gh pr view failed: {viewed['stderr'] or viewed['stdout']}",
        }
    payload = parse_json_object(viewed["stdout"])
    if not payload:
        return {
            "checked": False,
            "merged": False,
            "status": "unknown",
            "source": "gh",
            "error": "gh pr view did not return JSON",
        }
    return normalize_pull_request_status(payload, "gh")


def github_pull_request_status_with_api(repo_slug: str, pr_number: int) -> dict[str, Any]:
    if not repo_slug or pr_number <= 0:
        return {
            "checked": False,
            "merged": False,
            "status": "unknown",
            "source": "github_api",
            "error": "missing GitHub repository or PR number",
        }
    token = github_token()
    if not token:
        return {
            "checked": False,
            "merged": False,
            "status": "unknown",
            "source": "github_api",
            "error": "missing GITHUB_TOKEN or GH_TOKEN for GitHub API fallback",
        }
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repo_slug}/pulls/{pr_number}",
        method="GET",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "ops-agent",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=DEFAULT_GITHUB_TIMEOUT_SECONDS) as response:
            payload = parse_json_object(response.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="replace")
        return {
            "checked": False,
            "merged": False,
            "status": "unknown",
            "source": "github_api",
            "error": f"GitHub API failed HTTP {exc.code}: {truncate_text(error_body, 1000)}",
        }
    except urllib.error.URLError as exc:
        return {
            "checked": False,
            "merged": False,
            "status": "unknown",
            "source": "github_api",
            "error": f"GitHub API request failed: {exc}",
        }
    return normalize_pull_request_status(payload, "github_api")


def normalize_pull_request_status(payload: dict[str, Any], source: str) -> dict[str, Any]:
    state = str(payload.get("state") or "").lower()
    merged_at = str(payload.get("mergedAt") or payload.get("merged_at") or "")
    merge_commit = payload.get("mergeCommit") or payload.get("merge_commit_sha") or {}
    merge_sha = str(safe_dict(merge_commit).get("oid") or merge_commit or "")
    merged = state == "merged" or bool(merged_at)
    return {
        "checked": True,
        "merged": merged,
        "status": "merged" if merged else (state or "open"),
        "source": source,
        "pr_url": str(payload.get("url") or payload.get("html_url") or ""),
        "pr_number": safe_int(payload.get("number")),
        "merged_at": merged_at,
        "merge_commit": merge_sha,
        "head": str(payload.get("headRefName") or safe_dict(payload.get("head")).get("ref") or ""),
        "base": str(payload.get("baseRefName") or safe_dict(payload.get("base")).get("ref") or ""),
        "error": "",
    }


def deploy_merged_pull_request(
    repo_root: Path,
    remote: str,
    base: str,
    commands: list[Any],
    verify_urls: list[Any],
    rollback_commands: list[Any] | None = None,
    rollback_verify_urls: list[Any] | None = None,
) -> dict[str, Any]:
    started = time.monotonic()
    root = repo_root.resolve()
    remote_name = normalize_git_ref(remote, "origin")
    base_branch = normalize_git_ref(base, "main")
    requested_commands = [str(item).strip() for item in commands if str(item).strip()]
    if not requested_commands:
        requested_commands = DEFAULT_DEPLOY_COMMANDS
    verification_targets = [str(item).strip() for item in verify_urls if str(item).strip()]
    rollback_command_list = (
        [str(item).strip() for item in rollback_commands if str(item).strip()]
        if rollback_commands is not None
        else list(requested_commands)
    )
    rollback_targets = (
        [str(item).strip() for item in rollback_verify_urls if str(item).strip()]
        if rollback_verify_urls is not None
        else list(verification_targets)
    )
    result: dict[str, Any] = {
        "status": "failed",
        "ready": False,
        "repo_root": str(root),
        "remote": remote_name,
        "base": base_branch,
        "before_commit": "",
        "after_commit": "",
        "commands": requested_commands,
        "command_results": [],
        "verification": {"status": "skipped", "targets": []},
        "rollback": {"status": "not_needed", "ready": False, "reason": ""},
        "output": "",
        "error": "",
    }
    blockers = deploy_blockers(root, requested_commands)
    if blockers:
        result["error"] = "; ".join(blockers)
        result["blockers"] = blockers
        result["duration_seconds"] = round(time.monotonic() - started, 3)
        return result
    before = run_git(["rev-parse", "HEAD"], root)
    if before["returncode"] != 0:
        result["error"] = f"git rev-parse failed: {before['stderr'] or before['stdout']}"
        result["duration_seconds"] = round(time.monotonic() - started, 3)
        return result
    result["before_commit"] = before["stdout"].strip()
    fetch = run_git(["fetch", remote_name, base_branch], root, timeout_seconds=DEFAULT_GIT_PUSH_TIMEOUT_SECONDS)
    if fetch["returncode"] != 0:
        result["error"] = f"git fetch failed: {fetch['stderr'] or fetch['stdout']}"
        result["duration_seconds"] = round(time.monotonic() - started, 3)
        return result
    checkout = run_git(["checkout", base_branch], root)
    if checkout["returncode"] != 0:
        result["error"] = f"git checkout failed: {checkout['stderr'] or checkout['stdout']}"
        result["duration_seconds"] = round(time.monotonic() - started, 3)
        return result
    pull = run_git(["pull", "--ff-only", remote_name, base_branch], root, timeout_seconds=DEFAULT_GIT_PUSH_TIMEOUT_SECONDS)
    if pull["returncode"] != 0:
        result["error"] = f"git pull --ff-only failed: {pull['stderr'] or pull['stdout']}"
        result["duration_seconds"] = round(time.monotonic() - started, 3)
        return result
    after = run_git(["rev-parse", "HEAD"], root)
    if after["returncode"] == 0:
        result["after_commit"] = after["stdout"].strip()

    command_execution = run_safe_deploy_commands(root, requested_commands)
    result.update(command_execution)
    if command_execution["status"] != "passed":
        result["rollback"] = rollback_deployment(root, result["before_commit"], rollback_command_list, rollback_targets)
        result["duration_seconds"] = round(time.monotonic() - started, 3)
        return result

    verification = verify_deployment_urls(verification_targets)
    result["verification"] = verification
    if verification["status"] != "passed":
        result["status"] = "failed"
        result["error"] = verification.get("error", "")
        result["rollback"] = rollback_deployment(root, result["before_commit"], rollback_command_list, rollback_targets)
        result["duration_seconds"] = round(time.monotonic() - started, 3)
        return result
    result.update({"status": "passed", "ready": True, "duration_seconds": round(time.monotonic() - started, 3)})
    return result


def rollback_deployment(
    repo_root: Path,
    target_commit: str,
    commands: list[str],
    verify_urls: list[str],
) -> dict[str, Any]:
    started = time.monotonic()
    result: dict[str, Any] = {
        "status": "failed",
        "ready": False,
        "target_commit": target_commit,
        "after_commit": "",
        "commands": commands,
        "command_results": [],
        "verification": {"status": "skipped", "targets": []},
        "output": "",
        "error": "",
    }
    if not target_commit:
        result["error"] = "rollback target commit is empty"
        result["duration_seconds"] = round(time.monotonic() - started, 3)
        return result
    blockers = rollback_blockers(repo_root, commands)
    if blockers:
        result["error"] = "; ".join(blockers)
        result["blockers"] = blockers
        result["duration_seconds"] = round(time.monotonic() - started, 3)
        return result
    checkout = run_git(["checkout", "--detach", target_commit], repo_root)
    if checkout["returncode"] != 0:
        result["error"] = f"git checkout rollback target failed: {checkout['stderr'] or checkout['stdout']}"
        result["duration_seconds"] = round(time.monotonic() - started, 3)
        return result
    after = run_git(["rev-parse", "HEAD"], repo_root)
    if after["returncode"] == 0:
        result["after_commit"] = after["stdout"].strip()

    command_execution = run_safe_deploy_commands(repo_root, commands)
    result.update(command_execution)
    if command_execution["status"] != "passed":
        result["duration_seconds"] = round(time.monotonic() - started, 3)
        return result

    verification = verify_deployment_urls(verify_urls)
    result["verification"] = verification
    if verification["status"] != "passed":
        result["status"] = "failed"
        result["error"] = verification.get("error", "")
        result["duration_seconds"] = round(time.monotonic() - started, 3)
        return result

    result.update({"status": "passed", "ready": True, "duration_seconds": round(time.monotonic() - started, 3)})
    return result


def rollback_blockers(repo_root: Path, requested_commands: list[str]) -> list[str]:
    blockers: list[str] = []
    if not repo_root.exists() or not repo_root.is_dir():
        blockers.append(f"repo root not found: {repo_root}")
        return blockers
    unsafe_command = next((command for command in requested_commands if not is_safe_deploy_command(command)), "")
    if unsafe_command:
        blockers.append(f"unsafe rollback command: {unsafe_command}")
    inside = run_git(["rev-parse", "--is-inside-work-tree"], repo_root)
    if inside["returncode"] != 0 or inside["stdout"].strip().lower() != "true":
        blockers.append(f"repo root is not a git work tree: {repo_root}")
        return blockers
    tracked_status = run_git(["status", "--porcelain", "--untracked-files=no"], repo_root)
    if tracked_status["returncode"] != 0:
        blockers.append(f"git status failed: {tracked_status['stderr'] or tracked_status['stdout']}")
    elif tracked_status["stdout"].strip():
        blockers.append("repo has tracked uncommitted changes; rollback requires tracked files to be clean")
    head = run_git(["rev-parse", "--verify", "HEAD"], repo_root)
    if head["returncode"] != 0:
        blockers.append("repo has no HEAD commit for rollback")
    return blockers


def deploy_blockers(repo_root: Path, requested_commands: list[str]) -> list[str]:
    blockers: list[str] = []
    if not repo_root.exists() or not repo_root.is_dir():
        blockers.append(f"repo root not found: {repo_root}")
        return blockers
    unsafe_command = next((command for command in requested_commands if not is_safe_deploy_command(command)), "")
    if unsafe_command:
        blockers.append(f"unsafe deploy command: {unsafe_command}")
    inside = run_git(["rev-parse", "--is-inside-work-tree"], repo_root)
    if inside["returncode"] != 0 or inside["stdout"].strip().lower() != "true":
        blockers.append(f"repo root is not a git work tree: {repo_root}")
    status = run_git(["status", "--porcelain"], repo_root)
    if status["returncode"] != 0:
        blockers.append(f"git status failed: {status['stderr'] or status['stdout']}")
    elif status["stdout"].strip():
        blockers.append("repo has uncommitted changes; deployment requires a clean work tree")
    return blockers


def run_safe_deploy_commands(cwd: Path, requested_commands: list[str]) -> dict[str, Any]:
    command_results: list[dict[str, Any]] = []
    combined_output: list[str] = []
    combined_error: list[str] = []
    all_passed = True
    for command in requested_commands:
        executed_command = runtime_test_command(command)
        result = run_subprocess(executed_command, cwd, timeout_seconds=DEFAULT_DEPLOY_TIMEOUT_SECONDS)
        command_result = {
            "command": command,
            "executed_command": executed_command,
            "returncode": result["returncode"],
            "stdout": truncate_text(result["stdout"], DEFAULT_SANDBOX_MAX_OUTPUT_CHARS),
            "stderr": truncate_text(result["stderr"], DEFAULT_SANDBOX_MAX_OUTPUT_CHARS),
            "timed_out": bool(result.get("timed_out")),
        }
        command_results.append(command_result)
        if command_result["stdout"]:
            combined_output.append(f"$ {command}\n{command_result['stdout']}")
        if command_result["stderr"]:
            combined_error.append(f"$ {command}\n{command_result['stderr']}")
        if result["returncode"] != 0:
            all_passed = False
            break
    return {
        "status": "passed" if all_passed else "failed",
        "command_results": command_results,
        "output": truncate_text("\n".join(combined_output), DEFAULT_SANDBOX_MAX_OUTPUT_CHARS),
        "error": truncate_text("\n".join(combined_error), DEFAULT_SANDBOX_MAX_OUTPUT_CHARS),
    }


def verify_deployment_urls(urls: list[str]) -> dict[str, Any]:
    if not urls:
        return {"status": "skipped", "targets": [], "error": "no verification URLs configured"}
    targets: list[dict[str, Any]] = []
    all_passed = True
    for url in urls:
        started = time.monotonic()
        target = {"url": url, "status": "failed", "status_code": 0, "latency_ms": 0, "error": ""}
        try:
            request = urllib.request.Request(url=url, method="GET", headers={"User-Agent": "ops-agent/0.1"})
            with urllib.request.urlopen(request, timeout=DEFAULT_DEPLOY_VERIFY_TIMEOUT_SECONDS) as response:
                target["status_code"] = int(response.status)
                response.read(300)
            target["status"] = "passed" if target["status_code"] == 200 else "failed"
        except urllib.error.HTTPError as exc:
            target["status_code"] = int(exc.code)
            target["error"] = str(exc)
        except urllib.error.URLError as exc:
            target["error"] = str(exc)
        finally:
            target["latency_ms"] = int((time.monotonic() - started) * 1000)
        if target["status"] != "passed":
            all_passed = False
        targets.append(target)
    return {
        "status": "passed" if all_passed else "failed",
        "targets": targets,
        "error": "" if all_passed else "one or more verification URLs failed",
    }


def controlled_apply_blockers(
    repo_root: Path,
    repair: dict[str, Any],
    patch: dict[str, Any],
    validation: dict[str, Any],
    requested_commands: list[str],
) -> list[str]:
    blockers: list[str] = []
    if str(repair.get("status") or "") not in {"approved", "branch_prepared", "branch_failed"}:
        blockers.append("AI repair must be approved before preparing a controlled branch")
    approval_report = safe_dict(safe_dict(repair.get("test_result")).get("approval_report"))
    if not approval_report.get("ready_to_approve"):
        blockers.append("approval report is not ready; run sandbox-test before approval")
    if not validation.get("valid"):
        blockers.extend(str(error) for error in safe_list(validation.get("errors")))
    if not str(patch.get("diff") or "").strip():
        blockers.append("patch has no unified diff to apply")
    root = repo_root.resolve()
    if not root.exists() or not root.is_dir():
        blockers.append(f"repo root not found: {root}")
        return blockers
    unsafe_command = next((command for command in requested_commands if not is_safe_test_command(command)), "")
    if unsafe_command:
        blockers.append(f"unsafe test command: {unsafe_command}")
    inside = run_git(["rev-parse", "--is-inside-work-tree"], root)
    if inside["returncode"] != 0 or inside["stdout"].strip().lower() != "true":
        blockers.append(f"repo root is not a git work tree: {root}")
    head = run_git(["rev-parse", "--verify", "HEAD"], root)
    if head["returncode"] != 0:
        blockers.append("repo has no HEAD commit for branch preparation")
    return blockers


def run_safe_test_commands(cwd: Path, requested_commands: list[str]) -> dict[str, Any]:
    command_results: list[dict[str, Any]] = []
    combined_output: list[str] = []
    combined_error: list[str] = []
    all_passed = True
    for command in requested_commands:
        executed_command = runtime_test_command(command)
        result = run_subprocess(executed_command, cwd, timeout_seconds=DEFAULT_SANDBOX_TEST_TIMEOUT_SECONDS)
        command_result = {
            "command": command,
            "executed_command": executed_command,
            "returncode": result["returncode"],
            "stdout": truncate_text(result["stdout"], DEFAULT_SANDBOX_MAX_OUTPUT_CHARS),
            "stderr": truncate_text(result["stderr"], DEFAULT_SANDBOX_MAX_OUTPUT_CHARS),
            "timed_out": bool(result.get("timed_out")),
        }
        command_results.append(command_result)
        if command_result["stdout"]:
            combined_output.append(f"$ {command}\n{command_result['stdout']}")
        if command_result["stderr"]:
            combined_error.append(f"$ {command}\n{command_result['stderr']}")
        if result["returncode"] != 0:
            all_passed = False
            break
    return {
        "status": "passed" if all_passed else "failed",
        "command_results": command_results,
        "output": truncate_text("\n".join(combined_output), DEFAULT_SANDBOX_MAX_OUTPUT_CHARS),
        "error": truncate_text("\n".join(combined_error), DEFAULT_SANDBOX_MAX_OUTPUT_CHARS),
    }


def run_git(args: list[str], cwd: Path, timeout_seconds: int = DEFAULT_GIT_TIMEOUT_SECONDS) -> dict[str, Any]:
    return run_subprocess(["git", *args], cwd, timeout_seconds=timeout_seconds)


def git_status_paths(output: str) -> list[str]:
    paths: list[str] = []
    for line in output.splitlines():
        if len(line) < 4:
            continue
        paths.append(line[3:])
    return paths


def normalize_git_ref(value: str, default: str) -> str:
    candidate = str(value or default).strip()
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._/-")
    return candidate if candidate and set(candidate) <= allowed and ".." not in candidate else default


def github_repo_slug(remote_url: str) -> str:
    url = remote_url.strip()
    if url.endswith(".git"):
        url = url[:-4]
    if url.startswith("git@github.com:"):
        return url.split(":", 1)[1].strip("/")
    marker = "github.com/"
    if marker in url:
        return url.split(marker, 1)[1].strip("/")
    return ""


def pull_request_title(repair: dict[str, Any], branch_name: str) -> str:
    title = str(repair.get("title") or "").strip()
    return title if title else f"AI repair {branch_name}"


def pull_request_body(repair: dict[str, Any], controlled_apply: dict[str, Any], base: str) -> str:
    test_result = safe_dict(repair.get("test_result"))
    approval_report = safe_dict(test_result.get("approval_report"))
    execution_plan = safe_dict(approval_report.get("execution_plan"))
    impact = safe_dict(execution_plan.get("impact"))
    rollback_plan = safe_dict(execution_plan.get("rollback_plan"))
    sandbox = safe_dict(test_result.get("sandbox"))
    changed_files = [str(item) for item in safe_list(controlled_apply.get("changed_files"))]
    command_results = safe_list(controlled_apply.get("command_results"))
    commands = [str(item.get("command") or "") for item in command_results if isinstance(item, dict)]
    pre_deploy_checks = [str(item) for item in safe_list(execution_plan.get("pre_deploy_checks")) if str(item).strip()]
    validation_steps = execution_plan_validation_lines(safe_list(execution_plan.get("validation_steps")))
    body = [
        "## AI Ops Repair",
        "",
        f"- Repair ID: #{repair.get('id')}",
        f"- Incident ID: #{repair.get('incident_id')}",
        f"- Base branch: `{base}`",
        f"- Risk: `{repair.get('risk') or 'medium'}`",
        f"- Assessed risk: `{safe_dict(approval_report.get('risk_assessment')).get('level') or 'unknown'}`",
        f"- Commit: `{controlled_apply.get('commit') or ''}`",
        "",
        "## Summary",
        str(repair.get("summary") or "AI-generated repair proposal."),
        "",
        "## Root Cause",
        str(repair.get("root_cause") or "Not specified."),
        "",
        "## Changed Files",
        "\n".join(f"- `{path}`" for path in changed_files) if changed_files else "- No files reported",
        "",
        "## Execution Plan",
        f"- Plan status: `{execution_plan.get('status') or 'unknown'}`",
        f"- Patch type: `{impact.get('patch_type') or 'unknown'}`",
        f"- Changed files: `{impact.get('changed_file_count', len(changed_files))}`",
        "\n".join(f"- {item}" for item in pre_deploy_checks) if pre_deploy_checks else "- Review approval report before merge.",
        "",
        "## Validation",
        f"- Sandbox status: `{sandbox.get('status') or 'unknown'}`",
        f"- Approval readiness: `{approval_report.get('decision') or 'unknown'}`",
        f"- Controlled branch status: `{controlled_apply.get('status') or 'unknown'}`",
        "\n".join(f"- {item}" for item in validation_steps) if validation_steps else "- No validation steps reported",
        "",
        "## Test Commands",
        "\n".join(f"- `{command}`" for command in commands) if commands else "- No commands reported",
        "",
        "## Rollback Plan",
        f"- Automatic rollback: `{bool(rollback_plan.get('automatic'))}`",
        f"- Strategy: `{rollback_plan.get('strategy') or 'restore_previous_git_commit_and_rerun_safe_commands'}`",
        f"- Target: {rollback_plan.get('target') or 'deploy_result.before_commit'}",
        f"- Commands: {rollback_plan.get('commands') or 'rollback_commands or deployment commands'}",
        f"- Verification: {rollback_plan.get('verification') or 'rollback_verify_urls or deploy verification URLs'}",
        "",
        "## Operator Note",
        "Review before merge. This PR was prepared by Ops Agent after sandbox validation and human approval.",
    ]
    return "\n".join(body)


def execution_plan_validation_lines(steps: list[Any]) -> list[str]:
    lines: list[str] = []
    for item in steps:
        step = safe_dict(item)
        command = str(step.get("command") or "").strip()
        summary = str(step.get("summary") or "").strip()
        step_type = str(step.get("type") or "validation").strip()
        if command:
            lines.append(f"{step_type}: `{command}`")
        elif summary:
            lines.append(f"{step_type}: {summary}")
    return lines


def first_url(value: str) -> str:
    for token in value.replace("\r", " ").replace("\n", " ").split():
        if token.startswith("http://") or token.startswith("https://"):
            return token.strip()
    return ""


def pr_number_from_url(url: str) -> int | None:
    tail = url.rstrip("/").rsplit("/", 1)[-1]
    try:
        return int(tail)
    except ValueError:
        return None


def github_token() -> str:
    return os.environ.get("GITHUB_TOKEN", "").strip() or os.environ.get("GH_TOKEN", "").strip()


def copy_repo_to_sandbox(repo_root: Path, sandbox_dir: Path) -> None:
    ignore = shutil.ignore_patterns(
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "__pycache__",
        "*.pyc",
        "data",
        "node_modules",
        ".venv",
        "venv",
    )
    shutil.copytree(repo_root, sandbox_dir, ignore=ignore)


def run_subprocess(command: str | list[str], cwd: Path, timeout_seconds: int) -> dict[str, Any]:
    resolved_command = command
    if isinstance(command, list) and command:
        executable = shutil.which(command[0])
        if executable:
            resolved_command = [executable, *command[1:]]
    try:
        completed = subprocess.run(
            resolved_command,
            cwd=str(cwd),
            shell=isinstance(resolved_command, str),
            text=True,
            capture_output=True,
            timeout=timeout_seconds,
        )
        return {
            "returncode": int(completed.returncode),
            "stdout": completed.stdout or "",
            "stderr": completed.stderr or "",
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "returncode": 124,
            "stdout": exc.stdout or "",
            "stderr": (exc.stderr or "") + f"\ncommand timed out after {timeout_seconds}s",
            "timed_out": True,
        }
    except OSError as exc:
        return {
            "returncode": 127,
            "stdout": "",
            "stderr": str(exc),
            "timed_out": False,
        }


def build_approval_report(
    repair: dict[str, Any],
    validation: dict[str, Any],
    sandbox: dict[str, Any],
    guardrails: dict[str, Any] | None = None,
) -> dict[str, Any]:
    blockers: list[str] = []
    warnings: list[str] = []
    guardrail_report = safe_dict(guardrails)
    if not validation.get("valid"):
        blockers.extend(str(error) for error in safe_list(validation.get("errors")))
    if guardrail_report.get("status") == "blocked":
        blockers.extend(str(item) for item in safe_list(guardrail_report.get("blockers")))
    if str(sandbox.get("status") or "") == "skipped":
        blockers.append("sandbox test skipped because no diff was available")
    if not sandbox.get("patch_applied"):
        blockers.append("patch was not applied in sandbox")
    if str(sandbox.get("status") or "") == "failed":
        blockers.append("sandbox tests failed")
    warnings.extend(str(item) for item in safe_list(validation.get("warnings")))
    warnings.extend(str(item) for item in safe_list(guardrail_report.get("warnings")))
    blockers = unique_strings(blockers)
    warnings = unique_strings(warnings)
    risk_assessment = build_repair_risk_assessment(
        repair,
        validation,
        sandbox,
        guardrail_report,
        blockers,
        warnings,
    )
    execution_plan = build_repair_execution_plan(
        repair,
        validation,
        sandbox,
        guardrail_report,
        risk_assessment,
        blockers,
        warnings,
    )
    ready = not blockers
    return {
        "ready_to_approve": ready,
        "decision": "ready_for_human_approval" if ready else "blocked",
        "blockers": blockers,
        "warnings": warnings,
        "guardrail_status": str(guardrail_report.get("status") or ""),
        "risk_assessment": risk_assessment,
        "execution_plan": execution_plan,
        "repair_id": repair.get("id"),
        "incident_id": repair.get("incident_id"),
        "checked_files": safe_list(validation.get("checked_files")),
        "test_status": str(sandbox.get("status") or ""),
        "summary": (
            "Patch applied in sandbox and tests passed."
            if ready
            else "Patch is not ready for approval; review blockers first."
        ),
    }


def build_repair_risk_assessment(
    repair: dict[str, Any],
    validation: dict[str, Any],
    sandbox: dict[str, Any],
    guardrails: dict[str, Any],
    blockers: list[str],
    warnings: list[str],
) -> dict[str, Any]:
    patch = safe_dict(repair.get("patch"))
    model_risk = normalize_risk(repair.get("risk"))
    score = safe_int(AI_REPAIR_RISK_SCORES.get(model_risk), AI_REPAIR_RISK_SCORES["medium"])
    factors: list[dict[str, Any]] = [
        {
            "type": "model_risk",
            "impact": score,
            "summary": f"model classified repair risk as {model_risk}",
        }
    ]

    checked_files = [str(path) for path in safe_list(validation.get("checked_files")) if str(path).strip()]
    if len(checked_files) > 1:
        impact = min(20, (len(checked_files) - 1) * 5)
        score += impact
        factors.append(
            {
                "type": "blast_radius",
                "impact": impact,
                "summary": f"patch touches {len(checked_files)} files",
            }
        )

    patch_type = str(patch.get("patch_type") or "")
    if patch_type and patch_type != "unified_diff":
        score += 10
        factors.append({"type": "patch_type", "impact": 10, "summary": f"patch type is {patch_type}"})
    if not str(patch.get("diff") or "").strip():
        score += 20
        factors.append({"type": "review_only", "impact": 20, "summary": "patch has no unified diff"})
    if not validation.get("valid"):
        score += 30
        factors.append({"type": "dry_run", "impact": 30, "summary": "dry-run validation failed"})

    guardrail_blockers = safe_list(guardrails.get("blockers"))
    if guardrails.get("status") == "blocked":
        impact = 40 if guardrail_blockers else 25
        score += impact
        factors.append({"type": "guardrail", "impact": impact, "summary": "sandbox guardrails blocked approval"})

    sandbox_status = str(sandbox.get("status") or "")
    if sandbox_status == "failed":
        score += 30
        factors.append({"type": "sandbox", "impact": 30, "summary": "sandbox tests failed"})
    elif sandbox_status == "skipped":
        score += 20
        factors.append({"type": "sandbox", "impact": 20, "summary": "sandbox test was skipped"})

    if blockers:
        impact = min(30, len(blockers) * 10)
        score += impact
        factors.append({"type": "approval_blockers", "impact": impact, "summary": f"{len(blockers)} approval blockers"})
    elif warnings:
        impact = min(10, len(warnings) * 2)
        score += impact
        factors.append({"type": "warnings", "impact": impact, "summary": f"{len(warnings)} approval warnings"})

    score = max(0, min(100, score))
    level = risk_level_from_score(score)
    if blockers:
        next_action = "fix_blockers"
    elif level in {"high", "critical"}:
        next_action = "manual_security_review"
    elif level == "medium":
        next_action = "manual_review"
    else:
        next_action = "eligible_for_human_approval"
    return {
        "score": score,
        "level": level,
        "model_risk": model_risk,
        "factors": factors,
        "blocker_count": len(blockers),
        "warning_count": len(warnings),
        "changed_file_count": len(checked_files),
        "recommended_next_action": next_action,
    }


def build_repair_execution_plan(
    repair: dict[str, Any],
    validation: dict[str, Any],
    sandbox: dict[str, Any],
    guardrails: dict[str, Any],
    risk_assessment: dict[str, Any],
    blockers: list[str],
    warnings: list[str],
) -> dict[str, Any]:
    patch = safe_dict(repair.get("patch"))
    changed_files = [str(path) for path in safe_list(validation.get("checked_files")) if str(path).strip()]
    commands = [str(item) for item in safe_list(sandbox.get("commands")) if str(item).strip()]
    risk_level = str(risk_assessment.get("level") or normalize_risk(repair.get("risk")))
    dry_run_passed = bool(validation.get("valid"))
    guardrails_passed = str(guardrails.get("status") or "") == "passed"
    sandbox_passed = str(sandbox.get("status") or "") == "passed" and bool(sandbox.get("patch_applied"))
    ready = not blockers and dry_run_passed and guardrails_passed and sandbox_passed
    gates = [
        {
            "name": "dry_run",
            "status": "passed" if dry_run_passed else "blocked",
            "required": True,
            "summary": "patch schema and file paths are valid",
        },
        {
            "name": "guardrails",
            "status": "passed" if guardrails_passed else "blocked",
            "required": True,
            "summary": "sensitive paths, command whitelist, and patch limits are acceptable",
        },
        {
            "name": "sandbox",
            "status": "passed" if sandbox_passed else "blocked",
            "required": True,
            "summary": "patch applies to a copied worktree and tests pass",
        },
        {
            "name": "risk_review",
            "status": "attention" if risk_level in {"medium", "high", "critical"} and ready else "passed",
            "required": risk_level in {"high", "critical"},
            "summary": f"assessed risk level is {risk_level}",
        },
    ]
    pre_deploy_checks = [
        "Review the unified diff and changed file list before approval.",
        "Confirm approval_report.ready_to_approve is true and blockers is empty.",
        "Confirm the prepared branch contains only the intended changed files.",
        "Provide deploy verification URLs before running deploy-merged.",
    ]
    validation_steps = [
        {"type": "sandbox_command", "command": command, "required": True} for command in commands
    ]
    validation_steps.append(
        {
            "type": "deploy_verification",
            "summary": "After merge, deploy-merged must run configured verification URLs.",
            "required": True,
        }
    )
    rollback_plan = {
        "automatic": True,
        "strategy": "restore_previous_git_commit_and_rerun_safe_commands",
        "trigger_conditions": [
            "deploy command failed",
            "deploy verification URL failed",
        ],
        "target": "deploy_result.before_commit captured immediately before deployment",
        "commands": "rollback_commands from deploy request, otherwise deployment commands",
        "verification": "rollback_verify_urls from deploy request, otherwise deploy verification URLs",
        "manual_fallback": "Use the recorded before_commit and deploy backup to restore the previous release manually.",
    }
    return {
        "status": "ready_for_approval" if ready else "blocked",
        "impact": {
            "patch_type": str(patch.get("patch_type") or ""),
            "changed_files": changed_files,
            "changed_file_count": len(changed_files),
            "risk_level": risk_level,
        },
        "gates": gates,
        "pre_deploy_checks": pre_deploy_checks,
        "validation_steps": validation_steps,
        "rollback_plan": rollback_plan,
        "warnings": warnings,
        "blockers": blockers,
    }


def risk_level_from_score(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def append_pipeline_stage(pipeline: dict[str, Any], name: str, repair: dict[str, Any]) -> None:
    dry_run = safe_dict(repair.get("dry_run"))
    test_result = safe_dict(repair.get("test_result"))
    pipeline["stages"].append(
        {
            "name": name,
            "repair_id": repair.get("id"),
            "status": repair.get("status"),
            "ready": bool(
                dry_run.get("valid")
                or safe_dict(test_result.get("approval_report")).get("ready_to_approve")
                or safe_dict(test_result.get("controlled_apply")).get("ready_for_pr")
                or safe_dict(test_result.get("pull_request")).get("ready_for_review")
            ),
            "error": str(test_result.get("error") or ""),
        }
    )


def finish_ai_repair_pipeline(
    storage: Storage,
    repair: dict[str, Any],
    pipeline: dict[str, Any],
    status: str,
    stopped_at: str,
    actor: str,
    note: str,
) -> dict[str, Any]:
    pipeline["status"] = status
    pipeline["stopped_at"] = stopped_at
    result_payload = safe_dict(repair.get("test_result"))
    result_payload["pipeline"] = pipeline
    return storage.update_ai_repair_proposal_status(
        safe_int(repair.get("id")),
        str(repair.get("status") or "proposed"),
        actor=actor,
        note=note,
        test_result=result_payload,
    )


def can_auto_approve_repair(repair: dict[str, Any], policy: dict[str, Any], allowed_risks: list[str]) -> bool:
    return bool(auto_approval_decision(repair, policy, allowed_risks).get("eligible"))


def auto_approval_decision(repair: dict[str, Any], policy: dict[str, Any], allowed_risks: list[str]) -> dict[str, Any]:
    risk = str(repair.get("risk") or "medium").strip().lower()
    report = safe_dict(safe_dict(repair.get("test_result")).get("approval_report"))
    risk_assessment = safe_dict(report.get("risk_assessment"))
    assessed_level = normalize_risk(risk_assessment.get("level") or risk)
    patch = safe_dict(repair.get("patch"))
    validation = safe_dict(safe_dict(repair.get("test_result")).get("validation")) or validate_patch_dry_run(patch)
    checked_files = [str(path) for path in safe_list(validation.get("checked_files")) if str(path).strip()]
    allowed_patch_types = {str(item) for item in safe_list(policy.get("allowed_patch_types")) if str(item)}
    max_changed_files = safe_int(policy.get("max_changed_files"), safe_int(DEFAULT_AI_REPAIR_POLICY["max_changed_files"], 5))
    blockers: list[str] = []
    if not bool(policy.get("enabled", True)):
        blockers.append("AI repair policy is disabled")
    if risk not in set(allowed_risks):
        blockers.append(f"model risk {risk} is not auto-approvable")
    if assessed_level not in set(allowed_risks):
        blockers.append(f"assessed risk {assessed_level} is not auto-approvable")
    if str(patch.get("patch_type") or "") not in allowed_patch_types:
        blockers.append(f"patch type {patch.get('patch_type') or ''} is not allowed")
    if len(checked_files) > max_changed_files:
        blockers.append(f"patch changes too many files: {len(checked_files)} > {max_changed_files}")
    if not bool(report.get("ready_to_approve")):
        blockers.append("approval report is not ready")
    if not bool(str(patch.get("diff") or "").strip()):
        blockers.append("patch has no unified diff")
    blockers = unique_strings(blockers)
    return {
        "eligible": not blockers,
        "blockers": blockers,
        "model_risk": risk,
        "assessed_risk": assessed_level,
        "allowed_risks": allowed_risks,
        "patch_type": str(patch.get("patch_type") or ""),
        "changed_file_count": len(checked_files),
        "max_changed_files": max_changed_files,
        "approval_ready": bool(report.get("ready_to_approve")),
    }


def normalize_auto_approve_risks(value: list[str] | None) -> list[str]:
    risks = [str(item).strip().lower() for item in safe_list(value) if str(item).strip()]
    valid = [risk for risk in risks if risk in {"low", "medium", "high", "critical"}]
    return valid or ["low"]


def find_repair_project_by_id(config: AppConfig | None, project_id: str) -> dict[str, Any]:
    if config is None:
        return {}
    target = str(project_id or "").strip()
    if not target:
        return {}
    for project in list_projects(config):
        identifiers = {
            str(project.get("id") or "").strip(),
            str(project.get("key") or "").strip(),
            str(project.get("name") or "").strip(),
        }
        if target in identifiers:
            return project
    return {}


def normalize_drill_severity(value: Any) -> str:
    severity = str(value or "").strip().lower()
    if severity in {"warning", "critical"}:
        return severity
    return "critical"


def project_drill_next_steps(repair: dict[str, Any], run_sandbox: bool) -> list[str]:
    status = str(repair.get("status") or "")
    patch = safe_dict(repair.get("patch"))
    if status == "dry_run_failed":
        return ["review dry_run.errors before allowing sandbox or branch preparation"]
    if status == "test_failed":
        return ["review sandbox output and adjust the generated patch or test commands"]
    if not str(patch.get("diff") or "").strip():
        return ["review the manual repair guidance; no patch diff was generated"]
    if status == "test_passed":
        return ["review approval_report, then approve and prepare a controlled branch if acceptable"]
    if run_sandbox:
        return ["review sandbox_result before approval"]
    return ["run sandbox test before approval", "approve only after human review"]


def select_repair_project(
    config: AppConfig | None,
    incident: dict[str, Any],
    diagnosis: dict[str, Any] | None = None,
    request: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if config is None:
        return {}
    projects = list_projects(config)
    if not projects:
        return {}
    request_payload = safe_dict(request)
    requested = str(request_payload.get("project_id") or request_payload.get("project") or "").strip()
    if requested:
        for project in projects:
            if requested in {str(project.get("id") or ""), str(project.get("name") or "")}:
                return project
    diagnosis_context = safe_dict(safe_dict(diagnosis).get("context"))
    environment = str(
        request_payload.get("environment")
        or incident.get("environment")
        or diagnosis_context.get("environment")
        or config.app.get("environment")
        or "prod"
    )
    run_type = str(
        request_payload.get("run_type")
        or incident.get("run_type")
        or diagnosis_context.get("run_type")
        or config.app.get("run_type")
        or "normal"
    )
    for project in projects:
        if not bool(project.get("enabled", True)):
            continue
        run_types = [str(item) for item in safe_list(project.get("run_types")) if str(item)]
        if str(project.get("environment") or "") == environment and (not run_types or run_type in run_types):
            return project
    return next((project for project in projects if bool(project.get("enabled", True))), projects[0])


def resolve_repair_repo_root(
    config: AppConfig | None,
    project: dict[str, Any],
    request: dict[str, Any],
    fallback: Path | str,
) -> Path:
    raw = str(
        request.get("repo_root")
        or request.get("repository_root")
        or project.get("repo_root")
        or fallback
        or ""
    ).strip()
    if not raw:
        raw = str(fallback)
    path = Path(raw)
    if not path.is_absolute() and config is not None:
        path = config.base_dir / path
    return path


def build_repository_context(
    config: AppConfig | None,
    repair_config: dict[str, Any],
    incident: dict[str, Any],
    diagnosis: dict[str, Any],
    recommendations: list[dict],
    project: dict[str, Any],
    request: dict[str, Any],
) -> dict[str, Any]:
    settings = repository_context_settings(repair_config, request)
    if not settings["enabled"]:
        return {"enabled": False, "reason": settings.get("reason") or "disabled"}
    if config is None:
        return {"enabled": False, "reason": "config_not_available"}
    repo_root = resolve_repair_repo_root(config, project, request, config.base_dir).resolve()
    context = {
        "enabled": True,
        "repo_root": str(repo_root),
        "project_id": str(project.get("id") or ""),
        "files": [],
        "tree": [],
        "missing_files": [],
        "skipped_files": [],
        "limits": {
            "max_files": settings["max_files"],
            "max_file_chars": settings["max_file_chars"],
            "max_total_chars": settings["max_total_chars"],
            "max_file_bytes": settings["max_file_bytes"],
        },
    }
    if not repo_root.exists() or not repo_root.is_dir():
        context["enabled"] = False
        context["reason"] = "repo_root_not_found"
        return context

    candidates = repository_context_candidate_paths(repair_config, incident, diagnosis, recommendations, project, request)
    files: list[dict[str, Any]] = []
    total_chars = 0
    for relative_path in candidates:
        if len(files) >= settings["max_files"] or total_chars >= settings["max_total_chars"]:
            break
        safe_path = normalize_context_relative_path(relative_path)
        if not safe_path:
            context["skipped_files"].append({"path": str(relative_path), "reason": "unsafe_path"})
            continue
        absolute_path = (repo_root / safe_path).resolve()
        if not path_is_within(absolute_path, repo_root):
            context["skipped_files"].append({"path": safe_path, "reason": "outside_repo"})
            continue
        if not absolute_path.exists() or not absolute_path.is_file():
            context["missing_files"].append(safe_path)
            continue
        try:
            file_size = absolute_path.stat().st_size
            raw = absolute_path.read_bytes()[: settings["max_file_bytes"]]
            content = raw.decode("utf-8", errors="replace")
        except OSError as exc:
            context["skipped_files"].append({"path": safe_path, "reason": str(exc)})
            continue
        remaining = max(0, settings["max_total_chars"] - total_chars)
        if remaining <= 0:
            break
        redacted = redact_repository_content(content)
        snippet = truncate_text(redacted, min(settings["max_file_chars"], remaining))
        total_chars += len(snippet)
        files.append(
            {
                "path": safe_path,
                "chars": len(snippet),
                "bytes": file_size,
                "truncated": file_size > len(raw) or len(redacted) > len(snippet),
                "content": snippet,
            }
        )

    context["files"] = files
    context["total_chars"] = total_chars
    if not files:
        context["tree"] = repository_file_tree(repo_root, settings["max_tree_files"])
    return context


def repository_context_settings(repair_config: dict[str, Any], request: dict[str, Any]) -> dict[str, Any]:
    provider = str(repair_config.get("provider") or "rules").strip().lower()
    if provider not in MODEL_PROVIDERS:
        return {**DEFAULT_REPOSITORY_CONTEXT_SETTINGS, "enabled": False, "reason": "model_provider_disabled"}
    raw = safe_dict(repair_config.get("repository_context"))
    settings = dict(DEFAULT_REPOSITORY_CONTEXT_SETTINGS)
    for key in ("max_files", "max_file_chars", "max_total_chars", "max_tree_files", "max_file_bytes"):
        if key in raw:
            settings[key] = safe_int(raw.get(key), settings[key])
    if "enabled" in raw:
        settings["enabled"] = bool(raw.get("enabled"))
    if "include_repository_context" in request:
        settings["enabled"] = bool(request.get("include_repository_context"))
    if "repository_context_enabled" in request:
        settings["enabled"] = bool(request.get("repository_context_enabled"))
    return settings


def repository_context_candidate_paths(
    repair_config: dict[str, Any],
    incident: dict[str, Any],
    diagnosis: dict[str, Any],
    recommendations: list[dict],
    project: dict[str, Any],
    request: dict[str, Any],
) -> list[str]:
    paths: list[str] = []
    for key in ("files", "candidate_files", "repair_context_files", "context_files"):
        paths.extend(string_list(request.get(key)))
    paths.extend(string_list(project.get("repair_context_files")))
    paths.extend(string_list(safe_dict(repair_config.get("repository_context")).get("files")))
    paths.extend(string_list(safe_dict(repair_config.get("repository_context")).get("seed_files")))
    text_parts = [
        str(incident.get("title") or ""),
        str(incident.get("last_summary") or ""),
        str(incident.get("classification_category") or ""),
        str(diagnosis.get("top_category") or ""),
        json.dumps(safe_list(recommendations), ensure_ascii=False),
        str(incident.get("results_json") or ""),
    ]
    text = " ".join(text_parts).lower()
    if any(marker in text for marker in ("json_api", "json api", "synthetic", "customer service", "客服")):
        paths.extend(["ops_agent/monitors/json_api_monitor.py", "tests/test_json_api_monitor.py"])
    if any(marker in text for marker in ("http", "health", "healthz", "404", "网站", "官网")):
        paths.extend(["ops_agent/monitors/http_monitor.py", "ops_agent/monitor_targets.py", "tests/test_http_monitor.py"])
    if "log" in text or "日志" in text:
        paths.extend(["ops_agent/monitors/log_monitor.py", "tests/test_log_monitor.py"])
    if any(marker in text for marker in ("disk", "memory", "cpu", "server", "服务器")):
        paths.extend(["ops_agent/monitors/server_monitor.py", "tests/test_diagnostics.py"])
    if "classif" in text or "unknown" in text or "低置信" in text:
        paths.extend(["ops_agent/ai/classifier.py", "tests/test_classifier.py"])
    return unique_strings(paths)


def repository_file_tree(repo_root: Path, limit: int) -> list[str]:
    files: list[str] = []
    for path in repo_root.rglob("*"):
        if len(files) >= limit:
            break
        if not path.is_file():
            continue
        try:
            relative = path.relative_to(repo_root).as_posix()
        except ValueError:
            continue
        if normalize_context_relative_path(relative):
            files.append(relative)
    return files


def normalize_context_relative_path(value: Any) -> str:
    path_text = str(value or "").strip().replace("\\", "/")
    if not is_safe_patch_path(path_text):
        return ""
    parts = {part.lower() for part in Path(path_text).parts}
    if parts & REPOSITORY_CONTEXT_EXCLUDED_PARTS:
        return ""
    return path_text


def path_is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def redact_repository_content(content: str) -> str:
    redacted_lines = []
    for line in content.splitlines():
        lowered = line.lower()
        if any(marker in lowered for marker in ("api_key", "apikey", "authorization", "password", "secret", "token")):
            redacted_lines.append("[redacted sensitive line]")
        else:
            redacted_lines.append(line)
    return "\n".join(redacted_lines)


def unique_strings(values: list[Any]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def string_list(value: Any) -> list[str]:
    return [str(item) for item in safe_list(value) if str(item).strip()]


def unique_strings(values: list[Any]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def ai_repair_policy_from_config(config: AppConfig | None, project: dict[str, Any] | None = None) -> dict[str, Any]:
    if config is None:
        return normalize_ai_repair_policy({})
    repair_config = safe_dict(safe_dict(config.raw.get("ai")).get("repair"))
    policy = safe_dict(repair_config.get("policy"))
    policy.update(safe_dict(safe_dict(project).get("repair_policy")))
    return normalize_ai_repair_policy(policy)


def normalize_ai_repair_policy(value: Any) -> dict[str, Any]:
    raw = safe_dict(value)
    policy = dict(DEFAULT_AI_REPAIR_POLICY)
    for key in ("enabled", "auto_approve", "prepare_branch", "create_pr"):
        if key in raw:
            policy[key] = bool(raw.get(key))
    if "auto_approve_risks" in raw:
        policy["auto_approve_risks"] = normalize_auto_approve_risks(safe_list(raw.get("auto_approve_risks")))
    if "require_human_approval_risks" in raw:
        policy["require_human_approval_risks"] = normalize_auto_approve_risks(
            safe_list(raw.get("require_human_approval_risks"))
        )
    if "allowed_patch_types" in raw:
        values = [str(item).strip() for item in safe_list(raw.get("allowed_patch_types")) if str(item).strip()]
        policy["allowed_patch_types"] = values or list(DEFAULT_AI_REPAIR_POLICY["allowed_patch_types"])
    if "max_changed_files" in raw:
        policy["max_changed_files"] = safe_int(raw.get("max_changed_files"), 5)
    return policy


def is_safe_test_command(command: str) -> bool:
    normalized = " ".join(command.strip().split())
    return any(normalized == prefix or normalized.startswith(prefix + " ") for prefix in SAFE_TEST_COMMAND_PREFIXES)


def is_safe_deploy_command(command: str) -> bool:
    normalized = " ".join(command.strip().split())
    return any(normalized == prefix or normalized.startswith(prefix + " ") for prefix in SAFE_DEPLOY_COMMAND_PREFIXES)


def runtime_test_command(command: str) -> str:
    normalized = command.strip()
    replacements = ("python ", "python3 ", "py ")
    for prefix in replacements:
        if normalized == prefix.strip():
            return quote_shell_arg(sys.executable)
        if normalized.startswith(prefix):
            return f"{quote_shell_arg(sys.executable)} {normalized[len(prefix):]}"
    return normalized


def quote_shell_arg(value: str) -> str:
    if os.name == "nt":
        return subprocess.list2cmdline([value])
    return shlex.quote(value)


def truncate_text(value: str, max_chars: int) -> str:
    if len(value) <= max_chars:
        return value
    return value[:max_chars] + "\n...[truncated]"


def normalize_test_plan(value: Any) -> dict[str, Any]:
    if isinstance(value, list):
        commands = [str(item) for item in value if str(item).strip()]
    else:
        payload = safe_dict(value)
        commands = [str(item) for item in safe_list(payload.get("commands")) if str(item).strip()]
    if not commands:
        commands = DEFAULT_TEST_COMMANDS
    return {
        "commands": commands,
        "requires_sandbox": True,
        "run_before_merge": True,
    }


def normalize_risk(value: Any) -> str:
    risk = str(value or "medium").strip().lower()
    return risk if risk in {"low", "medium", "high", "critical"} else "medium"


def public_incident_context(incident: dict[str, Any]) -> dict[str, Any]:
    keys = [
        "id",
        "severity",
        "title",
        "last_summary",
        "classification_category",
        "classification_confidence",
        "classification_summary",
        "occurrence_count",
        "status",
        "environment",
        "run_type",
    ]
    return {key: redact_sensitive_text(incident.get(key)) for key in keys if key in incident}


def public_project_context(project: dict[str, Any]) -> dict[str, Any]:
    keys = [
        "id",
        "name",
        "environment",
        "run_types",
        "tags",
        "repo_root",
        "git_remote",
        "base_branch",
        "health_urls",
        "test_commands",
        "repair_context_files",
    ]
    return {key: redact_sensitive_text(project.get(key)) for key in keys if key in project}


def public_recommendation_context(item: dict[str, Any]) -> dict[str, Any]:
    keys = ["id", "category", "action_type", "title", "reason", "risk", "status", "source"]
    return {key: redact_sensitive_text(item.get(key)) for key in keys if key in item}


def public_action_context(item: dict[str, Any]) -> dict[str, Any]:
    keys = ["id", "action_type", "title", "risk", "status", "reason", "output", "error"]
    payload = {key: redact_sensitive_text(item.get(key)) for key in keys if key in item}
    if "params_json" in item:
        payload["params_json"] = redact_sensitive_text(item.get("params_json"))
    return payload


def redact_sensitive_text(value: Any) -> Any:
    if value is None or isinstance(value, (int, float, bool)):
        return value
    if isinstance(value, list):
        return [redact_sensitive_text(item) for item in value]
    if isinstance(value, dict):
        return {str(key): redact_sensitive_text(item) for key, item in value.items()}
    text = str(value)
    lowered = text.lower()
    if any(marker in lowered for marker in ("api_key", "apikey", "token", "password", "secret")):
        return "[redacted]"
    return text


def is_healthcheck_config_issue(summary: str, category: str) -> bool:
    lowered = summary.lower()
    return (
        category in {"route_or_healthcheck_config_mismatch", "probe_config_issue"}
        or ("healthz" in lowered and "404" in lowered)
        or ("health" in lowered and "404" in lowered)
    )


def extract_url(text: str) -> str:
    for token in text.split():
        if token.startswith("http://") or token.startswith("https://"):
            return token.strip(".,;)")
    return ""


def diff_paths(diff: str) -> list[str]:
    paths: list[str] = []
    for line in diff.splitlines():
        if line.startswith("--- a/") or line.startswith("+++ b/"):
            path = line[6:].strip()
            if path and path != "/dev/null":
                paths.append(path)
        elif line.startswith("diff --git "):
            parts = line.split()
            for part in parts[2:4]:
                if part.startswith("a/") or part.startswith("b/"):
                    paths.append(part[2:])
        elif line.startswith("+++ ") or line.startswith("--- "):
            path = line[4:].strip()
            if path.startswith("a/") or path.startswith("b/"):
                paths.append(path[2:])
    return paths


def is_safe_patch_path(value: str) -> bool:
    if patch_path_guardrail_reason(value):
        return False
    path = Path(str(value or "").strip().replace("\\", "/"))
    if path.name in ALLOWED_DIFF_FILENAMES:
        return True
    suffix = path.suffix.lower()
    return suffix in ALLOWED_DIFF_SUFFIXES


def patch_path_guardrail_reason(value: str) -> str:
    if not is_safe_relative_path(value):
        return "unsafe patch path"
    path = Path(str(value or "").strip().replace("\\", "/"))
    parts = {part.lower() for part in path.parts}
    sensitive_parts = sorted(parts & SENSITIVE_PATH_PARTS)
    if sensitive_parts:
        return f"sensitive path segment {sensitive_parts[0]}"
    name = path.name.lower()
    if name in SENSITIVE_FILENAMES:
        return "sensitive file"
    if path.suffix.lower() in SENSITIVE_FILE_SUFFIXES:
        return "sensitive file suffix"
    return ""


def is_safe_relative_path(value: str) -> bool:
    path_text = str(value or "").strip().replace("\\", "/")
    if not path_text:
        return False
    path = Path(path_text)
    if path.is_absolute():
        return False
    return ".." not in path.parts


def parse_json_object(value: str) -> dict:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def safe_dict(value: Any) -> dict:
    return dict(value) if isinstance(value, dict) else {}


def safe_list(value: Any) -> list:
    return list(value) if isinstance(value, list) else []


def safe_int(value: Any, default: int = 0) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default

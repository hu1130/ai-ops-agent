from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from ops_agent.alerts.notifier import Notifier
from ops_agent.config import AppConfig
from ops_agent.remediation.actions import ActionResult, RemediationAction
from ops_agent.remediation.executor import MUTATING_ACTIONS, execute_action
from ops_agent.remediation.verifier import VerificationResult, verify_after_action
from ops_agent.storage import Storage


APPROVABLE_STATUSES = {"pending_approval", "skipped", "failed"}


@dataclass(frozen=True)
class ApprovalExecution:
    action_id: int
    action: RemediationAction
    result: ActionResult
    verification: VerificationResult | None
    row: dict

    def to_dict(self) -> dict:
        return {
            "action_id": self.action_id,
            "action": self.action.to_dict(),
            "result": self.result.to_dict(),
            "verification": self.verification.__dict__ if self.verification else None,
            "row": self.row,
        }


def approve_action_log(
    storage: Storage,
    config: AppConfig,
    action_id: int,
    actor: str = "operator",
    notifier: Notifier | None = None,
) -> ApprovalExecution:
    row = storage.get_action_log(action_id)
    if not row:
        raise ValueError(f"action not found: #{action_id}")
    if row["status"] not in APPROVABLE_STATUSES:
        raise ValueError(f"action status cannot be approved: {row['status']}")
    expired_reason = approval_expired_reason(row)
    if expired_reason:
        storage.expire_action_log(action_id, actor, expired_reason)
        raise ValueError(expired_reason)

    action = action_from_log(row)
    result = execute_action(action, config, dry_run=False, approved=True)
    storage.update_action_log(
        action_id,
        result.status,
        result.output,
        result.error,
        approved_by=actor,
    )
    verification = verify_and_record(storage, config, action_id, action, result.status, notifier)
    updated = storage.get_action_log(action_id) or {}
    return ApprovalExecution(action_id, action, result, verification, updated)


def reject_action_log(storage: Storage, action_id: int, actor: str = "operator", note: str = "") -> dict:
    row = storage.get_action_log(action_id)
    if not row:
        raise ValueError(f"action not found: #{action_id}")
    if row["status"] != "pending_approval":
        raise ValueError(f"action status cannot be rejected: {row['status']}")
    return storage.reject_action_log(action_id, actor, note)


def approval_expiry_from_config(config: AppConfig | None) -> str:
    if config is None:
        return ""
    remediation = config.raw.get("remediation", {})
    if not isinstance(remediation, dict):
        return ""
    try:
        ttl_seconds = int(remediation.get("approval_ttl_seconds") or 0)
    except (TypeError, ValueError):
        return ""
    if ttl_seconds <= 0:
        return ""
    return (datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)).isoformat()


def approval_expired_reason(row: dict) -> str:
    expires_at = str(row.get("approval_expires_at") or "").strip()
    if not expires_at:
        return ""
    try:
        expires = datetime.fromisoformat(expires_at)
    except ValueError:
        return ""
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) <= expires:
        return ""
    return f"approval expired at {expires_at}"


def action_from_log(row: dict) -> RemediationAction:
    try:
        params = json.loads(row.get("params_json") or "{}")
    except json.JSONDecodeError:
        params = {}
    return RemediationAction(
        action_type=str(row["action_type"]),
        title=str(row["title"]),
        reason=str(row["reason"]),
        risk=str(row["risk"]),  # type: ignore[arg-type]
        params=params,
        auto_execute=True,
    )


def verify_and_record(
    storage: Storage,
    config: AppConfig,
    action_id: int,
    action: RemediationAction,
    action_status: str,
    notifier: Notifier | None = None,
) -> VerificationResult | None:
    if action_status != "executed":
        return None
    verification = verify_after_action(action, config)
    if verification.status != "verify_skipped":
        output = verification.output or verification.error
        storage.update_action_verification(action_id, verification.status, output)
        notify_verification_result(config, action, verification, notifier)
    update_related_incident_after_action(storage, action_id, action, verification)
    return verification


def update_related_incident_after_action(
    storage: Storage,
    action_id: int,
    action: RemediationAction,
    verification: VerificationResult,
) -> None:
    if action.action_type not in MUTATING_ACTIONS:
        return
    row = storage.get_action_log(action_id)
    if not row or not row.get("incident_id"):
        return
    incident_id = int(row["incident_id"])
    if verification.status == "verified_ok":
        target = "resolved"
        note = "remediation action verified"
    elif verification.status == "verified_failed":
        target = "remediating"
        note = "remediation verification failed"
    else:
        target = "verifying"
        note = "remediation action executed"
    try:
        storage.transition_incident(
            incident_id,
            target,
            actor="ops-agent",
            note=note,
            metadata={"action_id": action_id, "verification_status": verification.status},
        )
    except ValueError:
        return


def notify_verification_result(
    config: AppConfig,
    action: RemediationAction,
    verification: VerificationResult,
    notifier: Notifier | None = None,
) -> None:
    if action.action_type not in MUTATING_ACTIONS:
        return
    verification_config = dict(config.raw.get("remediation", {}).get("verification", {}))
    if not verification_config.get("notify", True):
        return
    title = "Ops Agent self-heal verified" if verification.status == "verified_ok" else "Ops Agent self-heal failed"
    text = (
        f"动作: {action.title}\n"
        f"状态: {verification.status}\n"
        f"输出: {verification.output}\n"
        f"错误: {verification.error}"
    )
    sender = notifier or Notifier(
        webhook_url=str(config.alerts.get("webhook_url", "")),
        cooldown_seconds=int(config.alerts.get("cooldown_seconds", 300)),
        email=dict(config.alerts.get("email", {})),
    )
    sender.send(title, text, dedupe_key=f"verification:{action.action_type}:{action.title}:{verification.status}")

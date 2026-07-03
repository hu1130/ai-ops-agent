from __future__ import annotations

from ops_agent.alerts.notifier import Notifier
from ops_agent.config import AppConfig
from ops_agent.remediation.actions import RemediationAction
from ops_agent.remediation.approval import approval_expiry_from_config, approve_action_log, reject_action_log
from ops_agent.storage import Storage


REQUESTABLE_STATUSES = {"suggested", "dry_run", "skipped", "failed"}
REJECTABLE_STATUSES = {"suggested", "dry_run", "pending_approval", "skipped", "failed"}


def request_recommendation_approval(
    storage: Storage,
    recommendation_id: int,
    actor: str = "operator",
    note: str = "",
    approval_expires_at: str = "",
) -> dict:
    recommendation = require_recommendation(storage, recommendation_id)
    status = str(recommendation.get("status") or "")
    action = existing_action(storage, recommendation)
    if status == "pending_approval" and action:
        return {"recommendation": recommendation, "action": action}
    if status not in REQUESTABLE_STATUSES:
        raise ValueError(f"recommendation status cannot request approval: {status}")

    action_id = int(action["id"]) if action else create_pending_action_log(
        storage,
        recommendation,
        approval_expires_at=approval_expires_at,
    )
    updated = storage.update_incident_recommendation_status(
        recommendation_id,
        "pending_approval",
        actor=actor,
        note=note,
        action_log_id=action_id,
        metadata={"action_log_id": action_id},
    )
    return {"recommendation": updated, "action": storage.get_action_log(action_id)}


def approve_recommendation(
    storage: Storage,
    config: AppConfig,
    recommendation_id: int,
    actor: str = "operator",
    note: str = "",
    notifier: Notifier | None = None,
) -> dict:
    requested = request_recommendation_approval(
        storage,
        recommendation_id,
        actor=actor,
        note=note,
        approval_expires_at=approval_expiry_from_config(config),
    )
    recommendation = requested["recommendation"]
    action_log_id = int(recommendation["action_log_id"])
    approval = approve_action_log(storage, config, action_log_id, actor=actor, notifier=notifier)
    final_status = recommendation_status_from_approval(approval.to_dict())
    updated = storage.update_incident_recommendation_status(
        recommendation_id,
        final_status,
        actor=actor,
        note=note,
        action_log_id=action_log_id,
        metadata={
            "action_log_id": action_log_id,
            "action_result": approval.result.to_dict(),
            "verification": approval.verification.__dict__ if approval.verification else None,
        },
    )
    return {"recommendation": updated, "action": approval.to_dict()}


def reject_recommendation(
    storage: Storage,
    recommendation_id: int,
    actor: str = "operator",
    note: str = "",
) -> dict:
    recommendation = require_recommendation(storage, recommendation_id)
    status = str(recommendation.get("status") or "")
    if status not in REJECTABLE_STATUSES:
        raise ValueError(f"recommendation status cannot be rejected: {status}")

    action = existing_action(storage, recommendation)
    rejected_action = None
    if action and action.get("status") == "pending_approval":
        rejected_action = reject_action_log(storage, int(action["id"]), actor=actor, note=note)
    updated = storage.update_incident_recommendation_status(
        recommendation_id,
        "rejected",
        actor=actor,
        note=note,
        action_log_id=int(action["id"]) if action else None,
        metadata={"rejected_action": rejected_action or None},
    )
    return {"recommendation": updated, "action": rejected_action}


def require_recommendation(storage: Storage, recommendation_id: int) -> dict:
    recommendation = storage.get_incident_recommendation(recommendation_id)
    if not recommendation:
        raise ValueError(f"recommendation not found: #{recommendation_id}")
    return recommendation


def existing_action(storage: Storage, recommendation: dict) -> dict | None:
    action_log_id = recommendation.get("action_log_id")
    if not action_log_id:
        return None
    return storage.get_action_log(int(action_log_id))


def create_pending_action_log(
    storage: Storage,
    recommendation: dict,
    approval_expires_at: str = "",
) -> int:
    return storage.save_action_log(
        str(recommendation.get("action_type") or ""),
        str(recommendation.get("title") or ""),
        str(recommendation.get("risk") or "low"),
        "pending_approval",
        str(recommendation.get("reason") or ""),
        dict(recommendation.get("params") or {}),
        "waiting for recommendation approval",
        "",
        environment=str(recommendation.get("environment") or "prod"),
        run_type=str(recommendation.get("run_type") or "normal"),
        trace_id=str(recommendation.get("trace_id") or ""),
        incident_id=int(recommendation["incident_id"]) if recommendation.get("incident_id") else None,
        approval_expires_at=approval_expires_at,
    )


def action_from_recommendation(recommendation: dict) -> RemediationAction:
    return RemediationAction(
        action_type=str(recommendation.get("action_type") or ""),
        title=str(recommendation.get("title") or ""),
        reason=str(recommendation.get("reason") or ""),
        risk=str(recommendation.get("risk") or "low"),  # type: ignore[arg-type]
        params=dict(recommendation.get("params") or {}),
        auto_execute=True,
    )


def recommendation_status_from_approval(payload: dict) -> str:
    verification = payload.get("verification") or {}
    verification_status = str(verification.get("status") or "")
    if verification_status and verification_status != "verify_skipped":
        return verification_status
    result = payload.get("result") or {}
    return str(result.get("status") or "approved")

from __future__ import annotations

from typing import Any

from ops_agent.config import AppConfig
from ops_agent.remediation.actions import RemediationAction, action_from_dict
from ops_agent.remediation.policy import MUTATING_ACTIONS, apply_policy_defaults, decide_action_policy
from ops_agent.storage import Storage


DEFAULT_GUARDRAILS = {
    "min_diagnosis_confidence_for_mutating": 0.8,
    "min_occurrences_for_mutating": 2,
    "diagnosis_required_for_mutating": True,
    "verification_required_for_mutating": True,
}


def evaluate_action_readiness(
    action: RemediationAction,
    config: AppConfig,
    incident: dict[str, Any] | None = None,
    diagnosis: dict[str, Any] | None = None,
) -> dict[str, Any]:
    guardrails = readiness_guardrails(config)
    decision = decide_action_policy(action, config)
    effective = apply_policy_defaults(action, config) if decision.allowed else action
    is_mutating = effective.action_type in MUTATING_ACTIONS
    diagnosis_info = diagnosis_summary(diagnosis)
    occurrence_count = max(1, safe_int((incident or {}).get("occurrence_count"), 1))
    checks: list[dict[str, Any]] = []
    blockers: list[str] = []
    warnings: list[str] = []
    score = 100

    def add_check(name: str, passed: bool, severity: str, message: str, penalty: int = 0) -> None:
        nonlocal score
        checks.append({"name": name, "passed": passed, "severity": severity, "message": message})
        if passed:
            return
        score = max(0, score - penalty)
        if severity == "blocker":
            blockers.append(message)
        elif severity == "warning":
            warnings.append(message)

    add_check(
        "policy_allowed",
        bool(decision.allowed),
        "blocker",
        decision.reason or f"no remediation policy allows {effective.action_type}",
        penalty=50,
    )

    if not decision.configured:
        legacy = legacy_allowlist_check(effective, config)
        add_check(
            "legacy_allowlist",
            legacy["allowed"],
            "blocker",
            legacy["reason"],
            penalty=35,
        )

    if is_mutating:
        diagnosis_required = bool(guardrails["diagnosis_required_for_mutating"])
        has_diagnosis = bool(diagnosis_info["top_category"])
        add_check(
            "diagnosis_present",
            has_diagnosis or not diagnosis_required,
            "blocker",
            "mutating action requires saved incident diagnosis",
            penalty=25,
        )

        min_confidence = float(guardrails["min_diagnosis_confidence_for_mutating"])
        confidence = float(diagnosis_info["top_confidence"] or 0)
        add_check(
            "diagnosis_confidence",
            (confidence >= min_confidence) or not diagnosis_required,
            "blocker",
            f"diagnosis confidence {confidence:.2f} is below required {min_confidence:.2f}",
            penalty=20,
        )

        min_occurrences = int(guardrails["min_occurrences_for_mutating"])
        add_check(
            "occurrence_count",
            occurrence_count >= min_occurrences,
            "blocker",
            f"incident occurrence_count {occurrence_count} is below required {min_occurrences}",
            penalty=15,
        )

        verification_required = bool(decision.verification_required or guardrails["verification_required_for_mutating"])
        has_verify_after = bool(safe_dict(effective.params.get("verify_after")))
        add_check(
            "verification_after_configured",
            has_verify_after or not verification_required,
            "blocker",
            "mutating action requires verify_after before execution",
            penalty=20,
        )

        next_action = str(diagnosis_info.get("next_decision") or "")
        add_check(
            "diagnosis_next_decision",
            next_action != "manual_triage",
            "blocker",
            "latest diagnosis still requires manual triage",
            penalty=20,
        )

        safe_to_auto = diagnosis_info.get("safe_to_auto_remediate")
        if safe_to_auto is False:
            add_check(
                "diagnosis_auto_remediation_signal",
                False,
                "warning",
                "diagnosis did not explicitly mark this incident safe for auto remediation",
                penalty=5,
            )

    add_check(
        "approval_required",
        not bool(decision.requires_approval),
        "warning",
        "policy requires human approval before mutating execution",
        penalty=5,
    )

    should_auto_execute = bool(effective.auto_execute or decision.auto_execute)
    auto_ready = bool(decision.allowed and not blockers and should_auto_execute and not decision.requires_approval)
    approval_ready = bool(decision.allowed and not blockers and is_mutating and decision.requires_approval)
    status = readiness_status(is_mutating, auto_ready, approval_ready, blockers, should_auto_execute)

    return {
        "action": effective.to_dict(),
        "is_mutating": is_mutating,
        "status": status,
        "score": score,
        "auto_ready": auto_ready,
        "approval_ready": approval_ready,
        "blockers": blockers,
        "warnings": warnings,
        "checks": checks,
        "policy": policy_payload(decision),
        "diagnosis": diagnosis_info,
        "requirements": {
            **guardrails,
            "occurrence_count": occurrence_count,
            "policy_configured": decision.configured,
        },
    }


def incident_self_heal_readiness(storage: Storage, config: AppConfig, incident_id: int) -> dict[str, Any]:
    incident = storage.get_incident(incident_id)
    if not incident:
        raise ValueError(f"incident not found: {incident_id}")

    diagnosis = latest_diagnosis(storage, incident_id)
    recommendations = storage.latest_incident_recommendations(incident_id)
    enriched: list[dict[str, Any]] = []
    auto_ready_count = 0
    approval_ready_count = 0
    blocked_count = 0

    for item in recommendations:
        action = action_from_dict(item)
        readiness = evaluate_action_readiness(action, config, incident=incident, diagnosis=diagnosis)
        if readiness["auto_ready"]:
            auto_ready_count += 1
        if readiness["approval_ready"]:
            approval_ready_count += 1
        if readiness["status"] == "blocked":
            blocked_count += 1
        enriched.append({**item, "readiness": readiness})

    return {
        "incident": incident_overview(incident),
        "diagnosis": diagnosis_summary(diagnosis),
        "recommendation_count": len(enriched),
        "auto_ready_count": auto_ready_count,
        "approval_ready_count": approval_ready_count,
        "blocked_count": blocked_count,
        "recommendations": enriched,
    }


def readiness_guardrails(config: AppConfig) -> dict[str, Any]:
    remediation = safe_dict(config.raw.get("remediation"))
    guardrails = safe_dict(remediation.get("guardrails"))
    merged = dict(DEFAULT_GUARDRAILS)
    for key in DEFAULT_GUARDRAILS:
        if key in guardrails:
            merged[key] = guardrails[key]
    merged["min_diagnosis_confidence_for_mutating"] = safe_float(
        merged["min_diagnosis_confidence_for_mutating"],
        DEFAULT_GUARDRAILS["min_diagnosis_confidence_for_mutating"],
    )
    merged["min_occurrences_for_mutating"] = max(
        1,
        safe_int(
            merged["min_occurrences_for_mutating"],
            DEFAULT_GUARDRAILS["min_occurrences_for_mutating"],
        ),
    )
    merged["diagnosis_required_for_mutating"] = bool(merged["diagnosis_required_for_mutating"])
    merged["verification_required_for_mutating"] = bool(merged["verification_required_for_mutating"])
    return merged


def legacy_allowlist_check(action: RemediationAction, config: AppConfig) -> dict[str, Any]:
    remediation = safe_dict(config.raw.get("remediation"))
    allowed_actions = {str(item).strip() for item in safe_list(remediation.get("allowed_actions")) if str(item).strip()}
    if allowed_actions and action.action_type not in allowed_actions:
        return {
            "allowed": False,
            "reason": f"action_type {action.action_type} is not in remediation.allowed_actions",
        }
    if action.action_type not in MUTATING_ACTIONS:
        return {"allowed": True, "reason": "read-only or diagnostic action is allowed by legacy config"}
    if not allowed_actions or action.action_type not in allowed_actions:
        return {
            "allowed": False,
            "reason": f"mutating action {action.action_type} requires remediation.allowed_actions allowlist",
        }
    if action.action_type == "restart_service":
        service = str(action.params.get("service") or "").strip()
        allowed_services = {str(item).strip() for item in safe_list(remediation.get("allowed_services"))}
        if not service:
            return {"allowed": False, "reason": "restart_service requires params.service"}
        if service not in allowed_services:
            return {"allowed": False, "reason": f"service {service} is not in remediation.allowed_services"}
    if action.action_type == "restart_docker_container":
        container = str(action.params.get("container") or "").strip()
        allowed_containers = {str(item).strip() for item in safe_list(remediation.get("allowed_containers"))}
        if not container:
            return {"allowed": False, "reason": "restart_docker_container requires params.container"}
        if container not in allowed_containers:
            return {"allowed": False, "reason": f"container {container} is not in remediation.allowed_containers"}
    return {"allowed": True, "reason": "mutating action target is allowlisted"}


def latest_diagnosis(storage: Storage, incident_id: int) -> dict[str, Any]:
    rows = storage.latest_incident_diagnoses(incident_id, limit=1)
    return rows[0] if rows else {}


def diagnosis_summary(diagnosis: dict[str, Any] | None) -> dict[str, Any]:
    data = safe_dict(diagnosis)
    payload = safe_dict(data.get("payload"))
    source = payload or data
    probable_causes = safe_list(source.get("probable_causes"))
    top = safe_dict(probable_causes[0]) if probable_causes else {}
    next_decision_raw = source.get("next_decision") if "next_decision" in source else data.get("next_decision")
    next_decision = safe_dict(next_decision_raw)
    next_action = str(next_decision.get("action") or next_decision_raw or "")
    return {
        "id": data.get("id"),
        "top_category": str(data.get("top_category") or top.get("category") or ""),
        "top_confidence": safe_float(data.get("top_confidence") if "top_confidence" in data else top.get("confidence"), 0),
        "next_decision": next_action,
        "safe_to_auto_remediate": next_decision.get("safe_to_auto_remediate"),
        "requires_human_confirmation": next_decision.get("requires_human_confirmation"),
    }


def policy_payload(decision: Any) -> dict[str, Any]:
    return {
        "configured": bool(decision.configured),
        "allowed": bool(decision.allowed),
        "policy_name": str(decision.policy_name or ""),
        "auto_execute": bool(decision.auto_execute),
        "requires_approval": bool(decision.requires_approval),
        "verification_required": bool(decision.verification_required),
        "verify_after": safe_dict(decision.verify_after),
        "reason": str(decision.reason or ""),
    }


def readiness_status(
    is_mutating: bool,
    auto_ready: bool,
    approval_ready: bool,
    blockers: list[str],
    should_auto_execute: bool,
) -> str:
    if blockers:
        return "blocked"
    if auto_ready:
        return "auto_ready"
    if approval_ready or is_mutating:
        return "approval_required"
    if should_auto_execute:
        return "auto_ready"
    return "diagnostic_ready"


def incident_overview(incident: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": incident.get("id"),
        "title": incident.get("title"),
        "severity": incident.get("severity"),
        "status": incident.get("status"),
        "environment": incident.get("environment"),
        "run_type": incident.get("run_type"),
        "trace_id": incident.get("trace_id"),
        "occurrence_count": incident.get("occurrence_count"),
        "classification_category": incident.get("classification_category"),
        "classification_confidence": incident.get("classification_confidence"),
        "last_summary": incident.get("last_summary"),
    }


def safe_dict(value: object) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def safe_list(value: object) -> list[Any]:
    return list(value) if isinstance(value, list) else []


def safe_int(value: object, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def safe_float(value: object, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default

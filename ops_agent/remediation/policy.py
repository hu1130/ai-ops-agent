from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

from ops_agent.config import AppConfig
from ops_agent.remediation.actions import RemediationAction

MUTATING_ACTIONS = {"restart_service", "restart_docker_container", "cleanup_temp_files", "rotate_large_log"}


@dataclass(frozen=True)
class PolicyDecision:
    configured: bool
    allowed: bool
    policy_name: str = ""
    auto_execute: bool = False
    requires_approval: bool = False
    verification_required: bool = False
    verify_after: dict[str, Any] | None = None
    reason: str = ""


def policy_configured(config: AppConfig) -> bool:
    return bool(remediation_policies(config))


def remediation_policies(config: AppConfig) -> list[dict[str, Any]]:
    policies = config.raw.get("remediation", {}).get("policies", [])
    if not isinstance(policies, list):
        return []
    return [item for item in policies if isinstance(item, dict)]


def decide_action_policy(action: RemediationAction, config: AppConfig) -> PolicyDecision:
    policies = remediation_policies(config)
    if not policies:
        return PolicyDecision(configured=False, allowed=True, auto_execute=action.auto_execute)

    for policy in policies:
        if str(policy.get("action_type", "")) != action.action_type:
            continue
        if not target_matches(action, policy):
            continue
        name = str(policy.get("name") or action.action_type)
        if not bool(policy.get("enabled", True)):
            return PolicyDecision(configured=True, allowed=False, policy_name=name, reason="policy disabled")
        requires_approval = bool(policy.get("requires_approval", action.action_type in MUTATING_ACTIONS))
        return PolicyDecision(
            configured=True,
            allowed=True,
            policy_name=name,
            auto_execute=bool(policy.get("auto_execute", False)),
            requires_approval=requires_approval,
            verification_required=bool(policy.get("verification_required", False)),
            verify_after=dict(policy.get("verify_after", {})) if isinstance(policy.get("verify_after"), dict) else None,
        )

    return PolicyDecision(
        configured=True,
        allowed=False,
        reason=f"no matching remediation policy for {action.action_type}",
    )


def apply_policy_defaults(action: RemediationAction, config: AppConfig) -> RemediationAction:
    decision = decide_action_policy(action, config)
    if not decision.configured:
        return action

    params = dict(action.params)
    if decision.verify_after and "verify_after" not in params:
        params["verify_after"] = decision.verify_after
    return replace(action, auto_execute=decision.allowed and decision.auto_execute, params=params)


def target_matches(action: RemediationAction, policy: dict[str, Any]) -> bool:
    targets = policy.get("targets", [])
    if not targets:
        return True
    normalized = {str(item).strip() for item in targets if str(item).strip()}
    if "*" in normalized:
        return True
    action_targets = target_values(action)
    return any(target in normalized for target in action_targets)


def target_values(action: RemediationAction) -> set[str]:
    if action.action_type == "restart_service":
        return {str(action.params.get("service", "")).strip()}
    if action.action_type == "restart_docker_container":
        return {str(action.params.get("container", "")).strip()}
    if action.action_type == "check_port":
        host = str(action.params.get("host", "")).strip()
        port = str(action.params.get("port", "")).strip()
        return {host, f"{host}:{port}" if host and port else ""}
    if action.action_type == "run_diagnostic_command":
        command = str(action.params.get("command", "")).strip()
        return {command, command.split()[0] if command else ""}
    if action.action_type == "cleanup_temp_files":
        paths = action.params.get("paths", [])
        if isinstance(paths, list):
            return {str(item).strip() for item in paths if str(item).strip()}
    return {str(action.params.get("target", "")).strip()}


def format_policy_decision(decision: PolicyDecision) -> str:
    if not decision.configured:
        return "legacy remediation config"
    if not decision.allowed:
        return f"policy denied: {decision.reason}"
    return f"policy={decision.policy_name}, auto_execute={decision.auto_execute}"

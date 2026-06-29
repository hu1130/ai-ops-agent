from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

RiskLevel = Literal["low", "medium", "high"]
ActionStatus = Literal[
    "planned",
    "pending_approval",
    "approved",
    "dry_run",
    "executed",
    "skipped",
    "failed",
    "verify_skipped",
    "verified_ok",
    "verified_failed",
]


@dataclass(frozen=True)
class RemediationAction:
    action_type: str
    title: str
    reason: str
    risk: RiskLevel = "low"
    params: dict[str, Any] = field(default_factory=dict)
    auto_execute: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_type": self.action_type,
            "title": self.title,
            "reason": self.reason,
            "risk": self.risk,
            "params": self.params,
            "auto_execute": self.auto_execute,
        }


@dataclass(frozen=True)
class ActionResult:
    action: RemediationAction
    status: ActionStatus
    output: str = ""
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action.to_dict(),
            "status": self.status,
            "output": self.output,
            "error": self.error,
        }

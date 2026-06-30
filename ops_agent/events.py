from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal
import uuid

Severity = Literal["ok", "warning", "critical"]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_trace_id() -> str:
    return uuid.uuid4().hex


@dataclass(frozen=True)
class RunContext:
    environment: str = "prod"
    run_type: str = "normal"
    trace_id: str = field(default_factory=new_trace_id)


@dataclass
class CheckResult:
    source: str
    name: str
    status: Severity
    summary: str
    details: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now_iso)
    environment: str = "prod"
    run_type: str = "normal"
    trace_id: str = ""

    @property
    def is_problem(self) -> bool:
        return self.status in {"warning", "critical"}


def apply_context(results: list[CheckResult], context: RunContext) -> list[CheckResult]:
    for result in results:
        if not result.environment or result.environment == "prod":
            result.environment = context.environment
        if not result.run_type or result.run_type == "normal":
            result.run_type = context.run_type
        if not result.trace_id:
            result.trace_id = context.trace_id
    return results

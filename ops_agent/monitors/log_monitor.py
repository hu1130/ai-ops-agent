from __future__ import annotations

from pathlib import Path
from typing import Any

from ops_agent.events import CheckResult


def run_log_checks(checks: list[dict[str, Any]], base_dir: Path) -> list[CheckResult]:
    return [run_log_check(check, base_dir) for check in checks]


def run_log_check(check: dict[str, Any], base_dir: Path) -> CheckResult:
    name = str(check.get("name") or check.get("path") or "Log check")
    path = Path(str(check.get("path", "")))
    if not path.is_absolute():
        path = base_dir / path
    tail_lines = int(check.get("tail_lines", 200))
    keywords = [str(item) for item in check.get("keywords", ["ERROR", "Exception", "Traceback"])]

    if not path.exists():
        return CheckResult(
            source="log",
            name=name,
            status="warning",
            summary=f"Log file not found: {path}",
            details={"path": str(path)},
        )

    lines = tail_file(path, tail_lines)
    matches = [line for line in lines if any(keyword.lower() in line.lower() for keyword in keywords)]
    status = "warning" if matches else "ok"
    summary = f"Found {len(matches)} suspicious log lines" if matches else "No suspicious log lines"
    return CheckResult(
        source="log",
        name=name,
        status=status,
        summary=summary,
        details={"path": str(path), "match_count": len(matches), "matches": matches[-20:]},
    )


def tail_file(path: Path, max_lines: int) -> list[str]:
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        lines = handle.readlines()
    return [line.rstrip("\n") for line in lines[-max_lines:]]

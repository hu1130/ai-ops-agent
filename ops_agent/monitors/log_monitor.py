from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
from typing import Any

from ops_agent.events import CheckResult


def run_log_checks(checks: list[dict[str, Any]], base_dir: Path) -> list[CheckResult]:
    return [run_log_check(check, base_dir) for check in checks]


def run_log_check(check: dict[str, Any], base_dir: Path) -> CheckResult:
    name = str(check.get("name") or check.get("path") or "Log check")
    if check.get("container"):
        return run_docker_log_check(check, base_dir)

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

    if check.get("only_new", False):
        lines = read_new_lines(path, base_dir)
        if not lines:
            return CheckResult(
                source="log",
                name=name,
                status="ok",
                summary="No new log lines",
                details={"path": str(path), "match_count": 0, "matches": []},
            )
        lines = lines[-tail_lines:]
    else:
        lines = tail_file(path, tail_lines)

    return build_log_result(
        "log",
        name,
        lines,
        keywords,
        {"path": str(path), **alert_policy_details(check)},
        status_on_match(check),
    )


def run_docker_log_check(check: dict[str, Any], base_dir: Path) -> CheckResult:
    name = str(check.get("name") or check.get("container") or "Docker log check")
    container = str(check.get("container", "")).strip()
    tail_lines = int(check.get("tail_lines", 200))
    keywords = [str(item) for item in check.get("keywords", ["ERROR", "Exception", "Traceback"])]
    lines, error = read_container_log_lines(
        container,
        tail_lines,
        base_dir,
        bool(check.get("only_new", False)),
        float(check.get("timeout_seconds", 5)),
    )
    if error:
        return CheckResult(
            source="log",
            name=name,
            status="warning",
            summary=f"Docker log read failed: {container}",
            details={"container": container, "error": error},
        )
    if check.get("only_new", False) and not lines:
        return CheckResult(
            source="log",
            name=name,
            status="ok",
            summary="No new docker log lines",
            details={"container": container, "match_count": 0, "matches": []},
        )
    return build_log_result(
        "log",
        name,
        lines,
        keywords,
        {"container": container, **alert_policy_details(check)},
        status_on_match(check),
    )


def build_log_result(
    source: str,
    name: str,
    lines: list[str],
    keywords: list[str],
    base_details: dict[str, Any],
    match_status: str = "warning",
) -> CheckResult:
    matches = [line for line in lines if any(keyword.lower() in line.lower() for keyword in keywords)]
    status = match_status if matches else "ok"
    summary = f"Found {len(matches)} suspicious log lines" if matches else "No suspicious log lines"
    details = dict(base_details)
    details.update({"match_count": len(matches), "matches": matches[-20:]})
    return CheckResult(
        source=source,
        name=name,
        status=status,
        summary=summary,
        details=details,
    )


def read_container_log_lines(
    container: str,
    tail_lines: int,
    base_dir: Path,
    only_new: bool,
    timeout_seconds: float,
) -> tuple[list[str], str]:
    if not container:
        return [], "container is required"

    command = ["docker", "logs", "--tail", str(max(1, tail_lines))]
    if only_new:
        state_path = base_dir / "data" / "docker_log_since.json"
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state = load_time_state(state_path)
        previous = state.get(container)
        state[container] = datetime.now(timezone.utc).isoformat()
        save_time_state(state_path, state)
        if not previous:
            return [], ""
        command.extend(["--since", previous])
    command.append(container)

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            check=False,
        )
    except Exception as exc:
        return [], str(exc)

    if completed.returncode != 0:
        return [], (completed.stderr or completed.stdout or "").strip() or f"docker logs exited {completed.returncode}"
    return (completed.stdout or "").splitlines()[-tail_lines:], ""


def status_on_match(check: dict[str, Any]) -> str:
    value = str(check.get("status_on_match", "warning")).strip().lower()
    if value in {"warning", "critical"}:
        return value
    return "warning"


def alert_policy_details(check: dict[str, Any]) -> dict[str, Any]:
    value = check.get("alert_after_failures", check.get("consecutive_failures"))
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return {}
    return {"alert_after_failures": parsed} if parsed > 0 else {}


def tail_file(path: Path, max_lines: int) -> list[str]:
    if max_lines <= 0:
        return []

    block_size = 8192
    chunks: list[bytes] = []
    line_count = 0
    with path.open("rb") as handle:
        handle.seek(0, 2)
        position = handle.tell()
        while position > 0 and line_count <= max_lines:
            read_size = min(block_size, position)
            position -= read_size
            handle.seek(position)
            chunk = handle.read(read_size)
            chunks.append(chunk)
            line_count += chunk.count(b"\n")

    data = b"".join(reversed(chunks))
    lines = data.decode("utf-8", errors="replace").splitlines()
    return lines[-max_lines:]


def read_new_lines(path: Path, base_dir: Path) -> list[str]:
    state_path = base_dir / "data" / "log_offsets.json"
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state = load_offset_state(state_path)
    key = str(path)
    size = path.stat().st_size
    previous = int(state.get(key, size))

    if previous > size:
        previous = 0

    state[key] = size
    save_offset_state(state_path, state)

    if key not in state or previous == size:
        return []

    with path.open("rb") as handle:
        handle.seek(previous)
        data = handle.read()
    return data.decode("utf-8", errors="replace").splitlines()


def load_offset_state(path: Path) -> dict[str, int]:
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return {str(key): int(value) for key, value in raw.items()}


def save_offset_state(path: Path, state: dict[str, int]) -> None:
    path.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


def load_time_state(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return {str(key): str(value) for key, value in raw.items()}


def save_time_state(path: Path, state: dict[str, str]) -> None:
    path.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")

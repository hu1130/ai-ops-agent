from __future__ import annotations

import json
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

#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify an Ops Agent production runtime")
    parser.add_argument("--config", default="/opt/ops-agent/config.json")
    parser.add_argument("--base-url", default="http://127.0.0.1:8765")
    parser.add_argument("--exercise-backup", action="store_true")
    parser.add_argument("--exercise-ai-drill", default="", metavar="PROJECT_ID")
    return parser.parse_args()


def request_json(url: str, token: str, method: str = "GET", payload: dict[str, Any] | None = None) -> dict:
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=300) as response:
            if response.status != 200:
                raise RuntimeError(f"{method} {url} returned HTTP {response.status}")
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="replace")[:2000]
        raise RuntimeError(f"{method} {url} returned HTTP {exc.code}: {error_body}") from exc


def main() -> int:
    args = parse_args()
    config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    tokens = [item for item in config.get("app", {}).get("api_tokens", []) if item.get("token")]
    reader = next((item for item in tokens if item.get("role") in {"viewer", "operator", "admin"}), None)
    operator = next((item for item in tokens if item.get("role") in {"operator", "admin"}), None)
    if not reader or ((args.exercise_backup or args.exercise_ai_drill) and not operator):
        raise SystemExit("required viewer/operator API token is not configured")

    try:
        urllib.request.urlopen(f"{args.base_url}/api/summary", timeout=10)
    except urllib.error.HTTPError as exc:
        if exc.code != 401:
            raise
    else:
        raise SystemExit("read API authentication is not enforced")

    summary = request_json(f"{args.base_url}/api/summary", reader["token"])
    discovery = request_json(f"{args.base_url}/api/discovery", reader["token"])
    backups = request_json(f"{args.base_url}/api/backups", reader["token"])
    readiness = request_json(f"{args.base_url}/api/enterprise/readiness", reader["token"])
    repair_readiness = request_json(f"{args.base_url}/api/projects/repair-readiness", reader["token"])
    discovery_summary = discovery.get("summary") or {}
    readiness_summary = readiness.get("summary") or {}
    readiness_warnings = [
        {"category": item.get("category"), "name": item.get("name"), "summary": item.get("summary")}
        for item in readiness.get("checks") or []
        if item.get("status") == "warning"
    ]
    output: dict[str, Any] = {
        "read_auth": "passed",
        "summary": {
            "current_status": summary.get("current_status"),
            "total_checks": summary.get("total_checks"),
            "latest_targets": len(summary.get("latest_targets") or []),
            "problems": [
                {
                    "source": item.get("source"),
                    "name": item.get("name"),
                    "status": item.get("status"),
                    "summary": item.get("summary"),
                }
                for item in summary.get("latest_targets") or []
                if item.get("status") in {"warning", "critical"}
            ],
        },
        "discovery": {
            "scanned": discovery_summary.get("scanned"),
            "covered": discovery_summary.get("covered"),
            "unmonitored": discovery_summary.get("unmonitored_applications"),
        },
        "backup_targets": len(backups.get("targets") or []),
        "readiness": {
            "status": readiness.get("status"),
            "score": readiness.get("score"),
            "blockers": readiness_summary.get("blockers"),
            "warnings": readiness_summary.get("warnings"),
            "warning_details": readiness_warnings,
        },
        "ai_repair_projects": [
            {
                "project_id": item.get("id"),
                "status": item.get("status"),
                "closure_status": (item.get("closure") or {}).get("status"),
                "closure_blockers": (item.get("closure") or {}).get("blockers") or [],
            }
            for item in repair_readiness.get("projects") or []
        ],
    }

    if args.exercise_backup:
        backup = request_json(
            f"{args.base_url}/api/backups/run",
            operator["token"],
            method="POST",
            payload={"target_id": "ops-agent-mysql", "actor": "production-verifier"},
        )
        if backup.get("status") != "success":
            raise SystemExit(f"MySQL backup failed: {backup.get('status')}")
        drill = request_json(
            f"{args.base_url}/api/backups/drill",
            operator["token"],
            method="POST",
            payload={"target_id": "ops-agent-mysql", "actor": "production-verifier"},
        )
        if drill.get("status") != "success":
            raise SystemExit(f"MySQL restore drill failed: {drill.get('status')}")
        output["mysql_backup"] = "success"
        output["mysql_restore_drill"] = "success"

    if args.exercise_ai_drill:
        project_id = urllib.parse.quote(args.exercise_ai_drill, safe="")
        drill = request_json(
            f"{args.base_url}/api/projects/{project_id}/ai-repair/drill",
            operator["token"],
            method="POST",
            payload={
                "actor": "production-verifier",
                "severity": "warning",
                "summary": "Controlled drill: propose a minimal test-covered fix for a simulated parser edge case.",
                "run_sandbox": True,
                "commands": ["python -m py_compile server.py"],
            },
        )
        proposal = drill.get("proposal") or {}
        sandbox = drill.get("sandbox_result") or {}
        output["ai_repair_drill"] = {
            "project_id": args.exercise_ai_drill,
            "mutates_production": drill.get("mutates_production"),
            "status": drill.get("status"),
            "model_provider": proposal.get("model_provider"),
            "dry_run_status": (drill.get("dry_run") or {}).get("status"),
            "sandbox_status": sandbox.get("status"),
        }
        if drill.get("mutates_production") is not False:
            raise SystemExit("AI repair drill safety contract failed")
        if sandbox.get("status") != "passed":
            raise SystemExit(f"AI repair sandbox drill did not pass: {sandbox.get('status') or 'not_run'}")

    print(json.dumps(output, ensure_ascii=False, indent=2))
    if output["summary"]["current_status"] in {"warning", "critical"}:
        raise SystemExit(f"production runtime is {output['summary']['current_status']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

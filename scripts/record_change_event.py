#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import urllib.request
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Record an audited Ops Agent change event")
    parser.add_argument("--config", default="/opt/ops-agent/config.json")
    parser.add_argument("--base-url", default="http://127.0.0.1:8765")
    parser.add_argument("--project-id", required=True)
    parser.add_argument("--title", required=True)
    parser.add_argument("--summary", default="")
    parser.add_argument("--change-type", default="deployment")
    parser.add_argument("--risk", default="medium")
    parser.add_argument("--actor", default="ops-agent-operator")
    parser.add_argument("--related-incident-id", type=int, default=0)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    tokens = [item for item in config.get("app", {}).get("api_tokens", []) if item.get("token")]
    operator = next((item for item in tokens if item.get("role") in {"operator", "admin"}), None)
    if not operator:
        raise SystemExit("operator API token is not configured")
    payload = {
        "project_id": args.project_id,
        "source": "operator",
        "change_type": args.change_type,
        "title": args.title,
        "summary": args.summary,
        "actor": args.actor,
        "status": "completed",
        "risk": args.risk,
        "related_incident_id": args.related_incident_id or None,
    }
    request = urllib.request.Request(
        f"{args.base_url}/api/change-events",
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": f"Bearer {operator['token']}",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        created = json.loads(response.read().decode("utf-8"))
    print(f"Change event recorded: #{created.get('id')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

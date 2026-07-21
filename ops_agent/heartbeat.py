from __future__ import annotations

import json
import os
from typing import Any
from urllib.request import Request, urlopen

from ops_agent.config import AppConfig


def heartbeat_policy(config: AppConfig) -> dict[str, Any]:
    raw = config.raw.get("heartbeat") if isinstance(config.raw.get("heartbeat"), dict) else {}
    url_env = str(raw.get("url_env") or "OPS_AGENT_HEARTBEAT_URL").strip()
    return {
        "enabled": bool(raw.get("enabled", False)),
        "url": str(raw.get("url") or os.environ.get(url_env, "")).strip(),
        "url_env": url_env,
        "method": str(raw.get("method") or "GET").strip().upper(),
        "timeout_seconds": max(1, int(raw.get("timeout_seconds") or 5)),
        "interval_seconds": max(30, int(raw.get("interval_seconds") or 60)),
    }


def send_success_heartbeat(config: AppConfig) -> dict[str, Any]:
    policy = heartbeat_policy(config)
    if not policy["enabled"]:
        return {"status": "disabled", "configured": bool(policy["url"])}
    if not policy["url"]:
        return {"status": "failed", "configured": False, "error": f"set {policy['url_env']}"}
    method = policy["method"] if policy["method"] in {"GET", "POST"} else "GET"
    body = None
    headers = {"User-Agent": "ops-agent/1.0"}
    if method == "POST":
        body = json.dumps({"status": "ok"}).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = Request(policy["url"], data=body, method=method, headers=headers)
    try:
        with urlopen(request, timeout=policy["timeout_seconds"]) as response:
            response.read(200)
            status_code = int(response.status)
        if status_code < 200 or status_code >= 300:
            return {"status": "failed", "configured": True, "status_code": status_code, "error": "non-2xx response"}
        return {"status": "sent", "configured": True, "status_code": status_code}
    except Exception as exc:
        return {"status": "failed", "configured": True, "error": str(exc)[:500]}

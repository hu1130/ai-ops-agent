from __future__ import annotations

import html
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import parse_qs, urlsplit

from ops_agent.alerts.notifier import Notifier
from ops_agent.auth import AuthResult, authenticate_token, configured_api_tokens, has_role
from ops_agent.config import AppConfig
from ops_agent.remediation.approval import approve_action_log, reject_action_log
from ops_agent.remediation.recommendations import (
    approve_recommendation,
    reject_recommendation,
    request_recommendation_approval,
)
from ops_agent.storage import Storage


ACTIONABLE_RECOMMENDATION_STATUSES = ["suggested", "pending_approval", "failed", "verified_failed", "skipped"]


def start_dashboard(
    storage: Storage,
    host: str,
    port: int,
    config: AppConfig | None = None,
    notifier: Notifier | None = None,
) -> ThreadingHTTPServer:
    api_tokens = configured_api_tokens(config)
    protect_reads = bool(config.app.get("api_auth_required_for_reads", False)) if config else False
    app_context = dict(config.app) if config else {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            path, query = split_request_path(self.path)
            if path.startswith("/api/") and protect_reads:
                auth = self.require_role(path, "viewer")
                if auth is None:
                    return
            if path == "/api/summary":
                self.send_json(storage.dashboard_summary())
                return
            if path == "/api/classifications/summary":
                self.send_json(storage.classification_summary(query_hours(query)))
                return
            if path == "/api/learning/recommendations":
                self.send_json(storage.latest_learning_recommendations(**learning_filters_from_query(query)))
                return
            if path == "/api/learning/summary":
                self.send_json(storage.learning_summary(query_limit(query, default=500, maximum=1000)))
                return
            if path == "/api/results":
                self.send_json(storage.latest_results())
                return
            if path == "/api/incidents":
                self.send_json(storage.latest_incidents())
                return
            if path == "/api/incidents/escalated":
                self.send_json(storage.latest_escalated_incidents())
                return
            incident_request = parse_incident_api_path(path)
            if incident_request:
                incident_id, action = incident_request
                if action == "":
                    incident = storage.get_incident(incident_id)
                    if not incident:
                        self.send_json({"error": "incident not found"}, status=404)
                        return
                    self.send_json(incident)
                    return
                if action == "detail":
                    detail = storage.incident_detail(incident_id)
                    if not detail:
                        self.send_json({"error": "incident not found"}, status=404)
                        return
                    self.send_json(detail)
                    return
                if action == "events":
                    self.send_json(storage.latest_incident_events(incident_id))
                    return
                if action == "recommendations":
                    self.send_json(storage.latest_incident_recommendations(incident_id))
                    return
                if action == "actions":
                    self.send_json(storage.latest_action_logs(100, incident_id=incident_id))
                    return
                if action == "failed-actions":
                    self.send_json(storage.latest_failed_action_logs(100, incident_id=incident_id))
                    return
            if path == "/api/action-logs":
                self.send_json(storage.latest_action_logs())
                return
            if path == "/api/audit-logs":
                self.send_json(storage.latest_api_audit_logs())
                return
            if path == "/api/actions/pending":
                self.send_json(storage.latest_action_logs(100, status="pending_approval"))
                return
            if path == "/api/actions/failed":
                self.send_json(storage.latest_failed_action_logs())
                return
            if path == "/api/recommendations":
                self.send_json(storage.latest_recommendations(**recommendation_filters_from_query(query)))
                return
            if path == "/api/recommendations/pending":
                self.send_json(storage.latest_recommendations(statuses=["pending_approval"]))
                return
            if path == "/api/recommendations/actionable":
                self.send_json(storage.latest_recommendations(statuses=ACTIONABLE_RECOMMENDATION_STATUSES))
                return
            recommendation_request = parse_recommendation_api_path(path)
            if recommendation_request:
                recommendation_id, action = recommendation_request
                if action == "":
                    row = storage.get_incident_recommendation(recommendation_id)
                    if not row:
                        self.send_json({"error": "recommendation not found"}, status=404)
                        return
                    self.send_json(row)
                    return
            action_request = parse_action_api_path(path)
            if action_request:
                action_id, action = action_request
                if action == "":
                    row = storage.get_action_log(action_id)
                    if not row:
                        self.send_json({"error": "action not found"}, status=404)
                        return
                    self.send_json(row)
                    return
            self.send_html(render_page(storage))

        def do_POST(self) -> None:  # noqa: N802
            path = self.path.split("?", 1)[0]
            auth = self.require_role(path, "operator")
            if auth is None:
                return

            recommendation_request = parse_recommendation_api_path(path)
            if recommendation_request:
                self.handle_recommendation_post(recommendation_request, auth)
                return

            action_request = parse_action_api_path(path)
            if action_request:
                self.handle_action_post(action_request, auth)
                return

            incident_request = parse_incident_api_path(path)
            if not incident_request:
                self.record_audit(path, 404, "not_found", "unsupported api path", auth=auth)
                self.send_json({"error": "not found"}, status=404)
                return

            incident_id, action = incident_request
            actor = "api"
            try:
                body = self.read_json_body()
                actor = self.actor_from_body(body, auth)
                to_status = status_from_incident_action(action, body)
                updated = storage.transition_incident(
                    incident_id,
                    to_status,
                    actor=actor,
                    note=str(body.get("note") or body.get("reason") or ""),
                    metadata={"api_action": action},
                )
            except ValueError as exc:
                self.record_audit(path, 400, "error", str(exc), actor=actor, auth=auth)
                self.send_json({"error": str(exc)}, status=400)
                return
            except Exception as exc:
                self.record_audit(path, 500, "error", str(exc), actor=actor, auth=auth)
                self.send_json({"error": str(exc)}, status=500)
                return
            self.record_audit(path, 200, "success", f"incident status={updated.get('status')}", actor=actor, auth=auth)
            self.send_json(updated)

        def handle_action_post(self, action_request: tuple[int, str], auth: AuthResult) -> None:
            action_id, action = action_request
            path = self.path.split("?", 1)[0]
            actor = "api"
            try:
                body = self.read_json_body()
                actor = self.actor_from_body(body, auth)
                note = str(body.get("note") or body.get("reason") or "")
                if action == "approve":
                    if config is None:
                        self.record_audit(
                            path,
                            503,
                            "error",
                            "approval execution is not configured",
                            actor=actor,
                            auth=auth,
                        )
                        self.send_json({"error": "approval execution is not configured"}, status=503)
                        return
                    result = approve_action_log(storage, config, action_id, actor=actor, notifier=notifier)
                    self.record_audit(
                        path,
                        200,
                        "success",
                        f"action status={result.result.status}",
                        actor=actor,
                        auth=auth,
                    )
                    self.send_json(result.to_dict())
                    return
                if action == "reject":
                    rejected = reject_action_log(storage, action_id, actor=actor, note=note)
                    self.record_audit(path, 200, "success", "action rejected", actor=actor, auth=auth)
                    self.send_json(rejected)
                    return
            except ValueError as exc:
                self.record_audit(path, 400, "error", str(exc), actor=actor, auth=auth)
                self.send_json({"error": str(exc)}, status=400)
                return
            except Exception as exc:
                self.record_audit(path, 500, "error", str(exc), actor=actor, auth=auth)
                self.send_json({"error": str(exc)}, status=500)
                return
            self.record_audit(
                path,
                404,
                "not_found",
                f"unsupported action operation: {action}",
                actor=actor,
                auth=auth,
            )
            self.send_json({"error": f"unsupported action operation: {action}"}, status=404)

        def handle_recommendation_post(self, recommendation_request: tuple[int, str], auth: AuthResult) -> None:
            recommendation_id, action = recommendation_request
            path = self.path.split("?", 1)[0]
            actor = "api"
            try:
                body = self.read_json_body()
                actor = self.actor_from_body(body, auth)
                note = str(body.get("note") or body.get("reason") or "")
                if action == "request-approval":
                    result = request_recommendation_approval(storage, recommendation_id, actor=actor, note=note)
                    self.record_audit(path, 200, "success", "recommendation pending approval", actor=actor, auth=auth)
                    self.send_json(result)
                    return
                if action == "approve":
                    if config is None:
                        self.record_audit(
                            path,
                            503,
                            "error",
                            "recommendation approval is not configured",
                            actor=actor,
                            auth=auth,
                        )
                        self.send_json({"error": "recommendation approval is not configured"}, status=503)
                        return
                    result = approve_recommendation(
                        storage,
                        config,
                        recommendation_id,
                        actor=actor,
                        note=note,
                        notifier=notifier,
                    )
                    self.record_audit(
                        path,
                        200,
                        "success",
                        f"recommendation status={result['recommendation'].get('status')}",
                        actor=actor,
                        auth=auth,
                    )
                    self.send_json(result)
                    return
                if action == "reject":
                    result = reject_recommendation(storage, recommendation_id, actor=actor, note=note)
                    self.record_audit(path, 200, "success", "recommendation rejected", actor=actor, auth=auth)
                    self.send_json(result)
                    return
            except ValueError as exc:
                self.record_audit(path, 400, "error", str(exc), actor=actor, auth=auth)
                self.send_json({"error": str(exc)}, status=400)
                return
            except Exception as exc:
                self.record_audit(path, 500, "error", str(exc), actor=actor, auth=auth)
                self.send_json({"error": str(exc)}, status=500)
                return
            self.record_audit(
                path,
                404,
                "not_found",
                f"unsupported recommendation operation: {action}",
                actor=actor,
                auth=auth,
            )
            self.send_json({"error": f"unsupported recommendation operation: {action}"}, status=404)

        def read_json_body(self) -> dict:
            length = int(self.headers.get("Content-Length", "0") or "0")
            if length <= 0:
                return {}
            raw = self.rfile.read(length).decode("utf-8", errors="replace")
            if not raw.strip():
                return {}
            payload = json.loads(raw)
            return payload if isinstance(payload, dict) else {}

        def require_role(self, path: str, required_role: str) -> AuthResult | None:
            auth = self.authenticate()
            if not auth.authenticated:
                message = auth.reason or "missing or invalid token"
                self.record_audit(path, 401, "unauthorized", message, auth=auth)
                self.send_auth_error(401, "unauthorized")
                return None
            if not has_role(auth.role, required_role):
                message = f"requires {required_role} role"
                self.record_audit(path, 403, "forbidden", message, auth=auth)
                self.send_auth_error(403, "forbidden")
                return None
            return auth

        def authenticate(self) -> AuthResult:
            return authenticate_token(self.provided_token(), api_tokens)

        def provided_token(self) -> str:
            provided = self.headers.get("X-Ops-Agent-Token", "").strip()
            authorization = self.headers.get("Authorization", "").strip()
            if authorization.lower().startswith("bearer "):
                provided = authorization[7:].strip()
            return provided

        def actor_from_body(self, body: dict, auth: AuthResult) -> str:
            return str(
                body.get("actor")
                or self.headers.get("X-Ops-Agent-Actor")
                or auth.token_name
                or "api"
            )

        def send_auth_error(self, status: int, message: str) -> None:
            payload = {"error": message}
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            if status == 401:
                self.send_header("WWW-Authenticate", 'Bearer realm="ops-agent"')
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def record_audit(
            self,
            path: str,
            status_code: int,
            outcome: str,
            message: str,
            actor: str = "",
            auth: AuthResult | None = None,
        ) -> None:
            operation, target_type, target_id = audit_target_from_path(path)
            audit_actor = actor or self.headers.get("X-Ops-Agent-Actor", "")
            if not audit_actor and auth and auth.authenticated:
                audit_actor = auth.token_name
            try:
                storage.record_api_audit(
                    actor=audit_actor,
                    source_ip=self.client_ip(),
                    method=self.command,
                    path=path,
                    operation=operation,
                    target_type=target_type,
                    target_id=target_id,
                    status_code=status_code,
                    outcome=outcome,
                    message=message,
                    metadata={
                        "user_agent": self.headers.get("User-Agent", ""),
                        "auth_role": auth.role if auth else "anonymous",
                        "token_name": auth.token_name if auth else "",
                        "auth_reason": auth.reason if auth else "",
                    },
                    environment=str(app_context.get("environment") or "prod"),
                    run_type="api",
                )
            except Exception:
                return

        def client_ip(self) -> str:
            forwarded_for = self.headers.get("X-Forwarded-For", "")
            if forwarded_for.strip():
                return forwarded_for.split(",", 1)[0].strip()
            return str(self.client_address[0]) if self.client_address else ""

        def send_json(self, payload: object, status: int = 200) -> None:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def send_html(self, body: str) -> None:
            data = body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, format: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer((host, port), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    actual_host, actual_port = server.server_address
    print(f"Dashboard: http://{actual_host}:{actual_port}")
    return server


def split_request_path(raw_path: str) -> tuple[str, dict[str, list[str]]]:
    parsed = urlsplit(raw_path)
    return parsed.path, parse_qs(parsed.query, keep_blank_values=False)


def recommendation_filters_from_query(query: dict[str, list[str]]) -> dict:
    return {
        "limit": query_limit(query, default=50, maximum=200),
        "incident_id": query_optional_int(query, "incident_id"),
        "statuses": query_statuses(query),
        "category": query_text(query, "category"),
        "risk": query_text(query, "risk"),
        "action_type": query_text(query, "action_type"),
        "source": query_text(query, "source"),
    }


def learning_filters_from_query(query: dict[str, list[str]]) -> dict:
    return {
        "limit": query_limit(query, default=50, maximum=200),
        "statuses": query_statuses(query),
        "category": query_text(query, "category"),
        "priority": query_text(query, "priority"),
        "trigger_type": query_text(query, "trigger_type"),
    }


def query_text(query: dict[str, list[str]], key: str) -> str:
    values = query.get(key, [])
    return str(values[0]).strip() if values else ""


def query_optional_int(query: dict[str, list[str]], key: str) -> int | None:
    text = query_text(query, key)
    if not text:
        return None
    try:
        value = int(text)
    except ValueError:
        return None
    return value if value > 0 else None


def query_limit(query: dict[str, list[str]], default: int, maximum: int) -> int:
    text = query_text(query, "limit")
    if not text:
        return default
    try:
        value = int(text)
    except ValueError:
        return default
    return min(max(value, 1), maximum)


def query_hours(query: dict[str, list[str]], default: int = 24, maximum: int = 24 * 365) -> int:
    text = query_text(query, "hours")
    if not text:
        return default
    try:
        value = int(text)
    except ValueError:
        return default
    return min(max(value, 1), maximum)


def query_statuses(query: dict[str, list[str]]) -> list[str]:
    raw_values = query.get("status", []) + query.get("statuses", [])
    statuses: list[str] = []
    for value in raw_values:
        statuses.extend(part.strip() for part in str(value).split(",") if part.strip())
    return statuses


def render_page(storage: Storage) -> str:
    summary = storage.dashboard_summary()
    incidents = storage.latest_incidents(12)
    results = storage.latest_results(60)
    latest_targets = sorted(
        summary["latest_targets"],
        key=lambda row: (status_rank(str(row.get("status"))), str(row.get("source")), str(row.get("name"))),
    )

    incident_rows = "\n".join(render_incident_row(row) for row in incidents)
    result_rows = "\n".join(render_result_row(row) for row in results)
    target_rows = "\n".join(render_target_row(row) for row in latest_targets)
    source_badges = "\n".join(
        f"<span class='badge'>{safe(source)} <strong>{count}</strong></span>"
        for source, count in sorted(summary["source_counts"].items())
    )
    status_text = {"ok": "运行正常", "warning": "存在告警", "critical": "严重异常"}.get(
        summary["current_status"], "未知"
    )

    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AI Ops Agent</title>
  <style>
    :root {{
      --ink: #17212b;
      --muted: #687385;
      --paper: #f7f8fa;
      --panel: #ffffff;
      --line: #d9e0e8;
      --ok: #157f5b;
      --warn: #a76300;
      --bad: #b42318;
      --accent: #2454d6;
      --code: #263445;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--paper);
      color: var(--ink);
      font-family: "Segoe UI", "Microsoft YaHei", Arial, sans-serif;
      font-size: 14px;
      letter-spacing: 0;
    }}
    header {{
      background: #182230;
      color: #f8fafc;
      border-bottom: 4px solid #52b788;
    }}
    .header-inner {{
      max-width: 1320px;
      margin: 0 auto;
      padding: 22px 28px;
      display: flex;
      align-items: end;
      justify-content: space-between;
      gap: 20px;
    }}
    h1, h2, h3, p {{ margin: 0; }}
    h1 {{ font-size: 24px; font-weight: 750; }}
    .subtitle {{ color: #cbd5e1; margin-top: 6px; }}
    .status-pill {{
      border: 1px solid rgba(255,255,255,.25);
      padding: 8px 12px;
      min-width: 112px;
      text-align: center;
      font-weight: 700;
      background: rgba(255,255,255,.08);
    }}
    main {{ max-width: 1320px; margin: 0 auto; padding: 24px 28px 36px; }}
    .metrics {{
      display: grid;
      grid-template-columns: repeat(5, minmax(0, 1fr));
      gap: 12px;
      margin-bottom: 18px;
    }}
    .metric {{
      background: var(--panel);
      border: 1px solid var(--line);
      padding: 14px 16px;
      min-height: 92px;
    }}
    .metric-label {{ color: var(--muted); font-size: 12px; }}
    .metric-value {{ display: block; margin-top: 10px; font-size: 28px; font-weight: 760; }}
    .metric-note {{ color: var(--muted); margin-top: 4px; font-size: 12px; }}
    .workbench {{
      display: grid;
      grid-template-columns: minmax(0, 1.15fr) minmax(360px, .85fr);
      gap: 16px;
      align-items: start;
    }}
    section {{
      background: var(--panel);
      border: 1px solid var(--line);
      margin-bottom: 16px;
    }}
    .section-head {{
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: center;
      padding: 14px 16px;
      border-bottom: 1px solid var(--line);
    }}
    h2 {{ font-size: 16px; }}
    .badges {{ display: flex; flex-wrap: wrap; gap: 8px; }}
    .badge {{
      display: inline-flex;
      gap: 6px;
      align-items: center;
      border: 1px solid var(--line);
      padding: 4px 8px;
      color: var(--muted);
      background: #fbfcfe;
      font-size: 12px;
    }}
    table {{ width: 100%; border-collapse: collapse; table-layout: fixed; }}
    th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--line); vertical-align: top; }}
    th {{ color: var(--muted); font-size: 12px; font-weight: 700; background: #f2f5f8; }}
    tr:last-child td {{ border-bottom: 0; }}
    .time {{ width: 176px; color: var(--muted); font-variant-numeric: tabular-nums; }}
    .source {{ width: 86px; }}
    .status {{ width: 88px; font-weight: 760; }}
    .summary {{ overflow-wrap: anywhere; }}
    .ok {{ color: var(--ok); }}
    .warning {{ color: var(--warn); }}
    .critical {{ color: var(--bad); }}
    .empty {{ color: var(--muted); padding: 18px 16px; }}
    details {{ border-bottom: 1px solid var(--line); }}
    details:last-child {{ border-bottom: 0; }}
    summary {{
      cursor: pointer;
      padding: 12px 16px;
      display: grid;
      grid-template-columns: 126px 156px minmax(0, 1fr);
      gap: 10px;
      align-items: center;
      list-style: none;
    }}
    summary::-webkit-details-marker {{ display: none; }}
    pre {{
      margin: 0;
      padding: 0 16px 14px;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      color: var(--code);
      font-family: Consolas, "Cascadia Mono", monospace;
      font-size: 12px;
      line-height: 1.55;
    }}
    .mobile-label {{ display: none; }}
    @media (max-width: 980px) {{
      .header-inner {{ align-items: start; flex-direction: column; }}
      .metrics {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
      .workbench {{ grid-template-columns: 1fr; }}
    }}
    @media (max-width: 640px) {{
      main, .header-inner {{ padding-left: 14px; padding-right: 14px; }}
      .metrics {{ grid-template-columns: 1fr; }}
      table, thead, tbody, tr, th, td {{ display: block; }}
      thead {{ display: none; }}
      tr {{ border-bottom: 1px solid var(--line); padding: 8px 0; }}
      td {{ border: 0; padding: 5px 12px; }}
      .time, .source, .status {{ width: auto; }}
      .mobile-label {{ display: inline; color: var(--muted); margin-right: 6px; }}
      summary {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <header>
    <div class="header-inner">
      <div>
        <h1>AI Ops Agent</h1>
        <p class="subtitle">内部运维监控工作台 · 最近 {summary["hours"]} 小时</p>
      </div>
      <div class="status-pill {safe(summary["current_status"])}">{safe(status_text)}</div>
    </div>
  </header>
  <main>
    <div class="metrics">
      {metric("总巡检", summary["total_checks"], "最近 24 小时记录")}
      {metric("正常率", f'{summary["ok_rate"]}%', "按巡检记录计算")}
      {metric("当前异常", summary["active_problem_count"], "最新状态仍异常")}
      {metric("告警事件", summary["incident_count"], "最近 24 小时")}
      {metric("严重异常", summary["critical"], "critical 记录数")}
    </div>
    <div class="workbench">
      <div>
        <section>
          <div class="section-head">
            <h2>当前监控目标</h2>
            <div class="badges">{source_badges}</div>
          </div>
          <table>
            <thead><tr><th class="status">状态</th><th class="source">来源</th><th>名称</th><th>摘要</th><th class="time">更新时间</th></tr></thead>
            <tbody>{target_rows or "<tr><td colspan='5' class='empty'>暂无巡检记录</td></tr>"}</tbody>
          </table>
        </section>
        <section>
          <div class="section-head"><h2>最近巡检</h2></div>
          <table>
            <thead><tr><th class="time">时间</th><th class="source">来源</th><th>名称</th><th class="status">状态</th><th>摘要</th></tr></thead>
            <tbody>{result_rows or "<tr><td colspan='5' class='empty'>暂无巡检记录</td></tr>"}</tbody>
          </table>
        </section>
      </div>
      <section>
        <div class="section-head"><h2>事件中心</h2></div>
        {incident_rows or "<div class='empty'>暂无告警事件</div>"}
      </section>
    </div>
  </main>
</body>
</html>"""


def metric(label: str, value: object, note: str) -> str:
    return (
        "<div class='metric'>"
        f"<div class='metric-label'>{safe(label)}</div>"
        f"<span class='metric-value'>{safe(value)}</span>"
        f"<div class='metric-note'>{safe(note)}</div>"
        "</div>"
    )


def render_target_row(row: dict) -> str:
    status = safe(row.get("status", ""))
    return (
        "<tr>"
        f"<td class='status {status}'><span class='mobile-label'>状态</span>{status}</td>"
        f"<td class='source'><span class='mobile-label'>来源</span>{safe(row.get('source', ''))}</td>"
        f"<td><span class='mobile-label'>名称</span>{safe(row.get('name', ''))}</td>"
        f"<td class='summary'><span class='mobile-label'>摘要</span>{safe(row.get('summary', ''))}</td>"
        f"<td class='time'><span class='mobile-label'>更新时间</span>{safe(row.get('created_at', ''))}</td>"
        "</tr>"
    )


def render_result_row(row: dict) -> str:
    status = safe(row.get("status", ""))
    return (
        "<tr>"
        f"<td class='time'><span class='mobile-label'>时间</span>{safe(row.get('created_at', ''))}</td>"
        f"<td class='source'><span class='mobile-label'>来源</span>{safe(row.get('source', ''))}</td>"
        f"<td><span class='mobile-label'>名称</span>{safe(row.get('name', ''))}</td>"
        f"<td class='status {status}'><span class='mobile-label'>状态</span>{status}</td>"
        f"<td class='summary'><span class='mobile-label'>摘要</span>{safe(row.get('summary', ''))}</td>"
        "</tr>"
    )


def render_incident_row(row: dict) -> str:
    severity = safe(row.get("severity", ""))
    lifecycle_status = safe(row.get("status", "open"))
    occurrence_count = int(row.get("occurrence_count") or 1)
    occurrence_label = f" x{occurrence_count}" if occurrence_count > 1 else ""
    last_seen = row.get("last_seen_at") or row.get("updated_at") or row.get("created_at", "")
    return (
        "<details>"
        "<summary>"
        f"<span class='time'>{safe(last_seen)}</span>"
        f"<span class='status {severity}'>{severity}/{lifecycle_status}{safe(occurrence_label)}</span>"
        f"<strong>{safe(row.get('title', ''))}</strong>"
        "</summary>"
        f"<pre>{safe(row.get('analysis', ''))}</pre>"
        "</details>"
    )


def status_rank(value: str) -> int:
    return {"critical": 0, "warning": 1, "ok": 2}.get(value, 3)


def parse_incident_api_path(path: str) -> tuple[int, str] | None:
    parts = [part for part in path.strip("/").split("/") if part]
    if len(parts) < 3 or parts[0] != "api" or parts[1] != "incidents":
        return None
    try:
        incident_id = int(parts[2])
    except ValueError:
        return None
    action = parts[3] if len(parts) >= 4 else ""
    return incident_id, action


def parse_action_api_path(path: str) -> tuple[int, str] | None:
    parts = [part for part in path.strip("/").split("/") if part]
    if len(parts) < 3 or parts[0] != "api" or parts[1] != "actions":
        return None
    try:
        action_id = int(parts[2])
    except ValueError:
        return None
    action = parts[3] if len(parts) >= 4 else ""
    return action_id, action


def parse_recommendation_api_path(path: str) -> tuple[int, str] | None:
    parts = [part for part in path.strip("/").split("/") if part]
    if len(parts) < 3 or parts[0] != "api" or parts[1] != "recommendations":
        return None
    try:
        recommendation_id = int(parts[2])
    except ValueError:
        return None
    action = parts[3] if len(parts) >= 4 else ""
    return recommendation_id, action


def audit_target_from_path(path: str) -> tuple[str, str, int | None]:
    recommendation_request = parse_recommendation_api_path(path)
    if recommendation_request:
        recommendation_id, action = recommendation_request
        operation = f"recommendation.{action or 'read'}"
        return operation, "recommendation", recommendation_id

    action_request = parse_action_api_path(path)
    if action_request:
        action_id, action = action_request
        operation = f"action.{action or 'read'}"
        return operation, "action", action_id

    incident_request = parse_incident_api_path(path)
    if incident_request:
        incident_id, action = incident_request
        operation = f"incident.{action or 'read'}"
        return operation, "incident", incident_id

    mapping = {
        "/api/audit-logs": ("audit.list", "audit", None),
        "/api/action-logs": ("action.list", "action", None),
        "/api/actions/failed": ("action.failed", "action", None),
        "/api/actions/pending": ("action.pending", "action", None),
        "/api/incidents": ("incident.list", "incident", None),
        "/api/incidents/escalated": ("incident.escalated", "incident", None),
        "/api/classifications/summary": ("classification.summary", "classification", None),
        "/api/learning/recommendations": ("learning.recommendation.list", "learning", None),
        "/api/learning/summary": ("learning.summary", "learning", None),
        "/api/recommendations": ("recommendation.list", "recommendation", None),
        "/api/recommendations/actionable": ("recommendation.actionable", "recommendation", None),
        "/api/recommendations/pending": ("recommendation.pending", "recommendation", None),
        "/api/summary": ("summary.read", "summary", None),
        "/api/results": ("result.list", "result", None),
    }
    return mapping.get(path, ("api.unknown", "", None))


def status_from_incident_action(action: str, body: dict) -> str:
    if action == "ack":
        return "acknowledged"
    if action in {"remediate", "remediating"}:
        return "remediating"
    if action == "verify":
        return "verifying"
    if action == "resolve":
        return "resolved"
    if action == "close":
        return "closed"
    if action == "transition":
        return str(body.get("status", ""))
    raise ValueError(f"unsupported incident action: {action}")


def safe(value: object) -> str:
    return html.escape(str(value))

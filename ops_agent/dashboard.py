from __future__ import annotations

import html
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from ops_agent.storage import Storage


def start_dashboard(storage: Storage, host: str, port: int) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            path = self.path.split("?", 1)[0]
            if path == "/api/summary":
                self.send_json(storage.dashboard_summary())
                return
            if path == "/api/results":
                self.send_json(storage.latest_results())
                return
            if path == "/api/incidents":
                self.send_json(storage.latest_incidents())
                return
            if path == "/api/action-logs":
                self.send_json(storage.latest_action_logs())
                return
            self.send_html(render_page(storage))

        def send_json(self, payload: object) -> None:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
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
      grid-template-columns: 126px 76px minmax(0, 1fr);
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
    return (
        "<details>"
        "<summary>"
        f"<span class='time'>{safe(row.get('created_at', ''))}</span>"
        f"<span class='status {severity}'>{severity}</span>"
        f"<strong>{safe(row.get('title', ''))}</strong>"
        "</summary>"
        f"<pre>{safe(row.get('analysis', ''))}</pre>"
        "</details>"
    )


def status_rank(value: str) -> int:
    return {"critical": 0, "warning": 1, "ok": 2}.get(value, 3)


def safe(value: object) -> str:
    return html.escape(str(value))

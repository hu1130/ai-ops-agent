from __future__ import annotations

import html
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from ops_agent.storage import Storage


def start_dashboard(storage: Storage, host: str, port: int) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/api/results":
                self.send_json(storage.latest_results())
                return
            if self.path == "/api/incidents":
                self.send_json(storage.latest_incidents())
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
    print(f"Dashboard: http://{host}:{port}")
    return server


def render_page(storage: Storage) -> str:
    incidents = storage.latest_incidents(10)
    results = storage.latest_results(30)
    incident_rows = "\n".join(
        f"<tr><td>{safe(row['created_at'])}</td><td>{safe(row['severity'])}</td><td>{safe(row['title'])}</td><td><pre>{safe(row['analysis'])}</pre></td></tr>"
        for row in incidents
    )
    result_rows = "\n".join(
        f"<tr><td>{safe(row['created_at'])}</td><td>{safe(row['source'])}</td><td>{safe(row['name'])}</td><td class='{safe(row['status'])}'>{safe(row['status'])}</td><td>{safe(row['summary'])}</td></tr>"
        for row in results
    )
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AI Ops Agent</title>
  <style>
    body {{ margin: 0; font-family: Arial, sans-serif; background: #f6f7f9; color: #1f2937; }}
    header {{ padding: 24px 32px; background: #111827; color: white; }}
    main {{ padding: 24px 32px; max-width: 1200px; margin: auto; }}
    section {{ margin-bottom: 28px; }}
    table {{ width: 100%; border-collapse: collapse; background: white; border: 1px solid #e5e7eb; }}
    th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid #e5e7eb; vertical-align: top; }}
    th {{ background: #eef2f7; }}
    pre {{ white-space: pre-wrap; margin: 0; font-family: Consolas, monospace; }}
    .ok {{ color: #047857; font-weight: 700; }}
    .warning {{ color: #b45309; font-weight: 700; }}
    .critical {{ color: #b91c1c; font-weight: 700; }}
  </style>
</head>
<body>
  <header>
    <h1>AI Ops Agent</h1>
    <div>内部运维监控智能体 MVP</div>
  </header>
  <main>
    <section>
      <h2>最近故障</h2>
      <table>
        <thead><tr><th>时间</th><th>级别</th><th>标题</th><th>分析</th></tr></thead>
        <tbody>{incident_rows or "<tr><td colspan='4'>暂无故障</td></tr>"}</tbody>
      </table>
    </section>
    <section>
      <h2>最近巡检</h2>
      <table>
        <thead><tr><th>时间</th><th>来源</th><th>名称</th><th>状态</th><th>摘要</th></tr></thead>
        <tbody>{result_rows or "<tr><td colspan='5'>暂无巡检记录</td></tr>"}</tbody>
      </table>
    </section>
  </main>
</body>
</html>"""


def safe(value: object) -> str:
    return html.escape(str(value))

from __future__ import annotations

import html
import json
from typing import Any


LEVEL_LABELS = {
    "monitor_only": "1 只读监控",
    "runtime_self_heal": "2 环境自愈",
    "code_suggest": "3 AI 修复建议",
    "pull_request": "4 PR 自动修复",
    "full_closure": "5 完整闭环",
}
MODE_LABELS = {"managed": "已托管", "observe_only": "只读", "ignored": "已忽略", "unbound": "待选择"}
ACTION_LABELS = {
    "run_diagnosis": "开始诊断",
    "generate_recommendations": "生成处理方案",
    "execute_recommendation": "执行已批准方案",
    "advance_ai_repair": "继续 AI 修复",
    "acknowledge_watch": "确认并继续观察",
    "manual_handoff": "交给人工处理",
}


def render_simple_page(
    summary: dict[str, Any],
    onboarding: dict[str, Any],
    inbox: dict[str, Any],
    audit_logs: list[dict[str, Any]],
    fleet: dict[str, Any] | None = None,
) -> str:
    active = safe_int(summary.get("active_problem_count"))
    current_status = str(summary.get("current_status") or "ok")
    status_class = "ok" if current_status == "ok" and active == 0 else ("danger" if current_status == "critical" else "warn")
    status_title = "系统运行正常" if active == 0 else f"有 {active} 个问题需要处理"
    target_total = len(safe_list(summary.get("latest_targets")))
    problem_rows = [item for item in safe_list(inbox.get("items")) if isinstance(item, dict)]
    candidates = [item for item in safe_list(onboarding.get("candidates")) if isinstance(item, dict)]
    projects = [item for item in safe_list(onboarding.get("projects")) if isinstance(item, dict)]
    fleet = safe_dict(fleet)
    fleet_summary = safe_dict(fleet.get("summary"))
    nodes = [item for item in safe_list(fleet.get("nodes")) if isinstance(item, dict)]
    payload = json.dumps({"onboarding": onboarding}, ensure_ascii=False).replace("</", "<\\/")

    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AI自动化运维工具</title>
  <style>
    :root {{ color-scheme: light; --ink:#18211d; --muted:#65716b; --line:#dce3df; --surface:#f5f7f6; --green:#147d52; --green-soft:#e8f5ee; --amber:#9a5a00; --amber-soft:#fff4db; --red:#b3261e; --red-soft:#fdecea; --blue:#1769aa; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; background:#fff; color:var(--ink); font:15px/1.5 Inter,"Segoe UI","Microsoft YaHei",sans-serif; letter-spacing:0; }}
    button,select,input {{ font:inherit; letter-spacing:0; }}
    button {{ cursor:pointer; }}
    .topbar {{ border-bottom:1px solid var(--line); background:#fff; }}
    .topbar-inner,.content {{ width:min(1120px,calc(100% - 32px)); margin:0 auto; }}
    .topbar-inner {{ min-height:68px; display:flex; align-items:center; justify-content:space-between; gap:16px; }}
    .brand {{ font-size:20px; font-weight:750; }}
    .live {{ display:flex; align-items:center; gap:8px; color:var(--muted); white-space:nowrap; }}
    .dot {{ width:9px; height:9px; border-radius:50%; background:var(--green); }}
    .tabs {{ border-bottom:1px solid var(--line); position:sticky; top:0; background:#fff; z-index:3; }}
    .tablist {{ width:min(1120px,calc(100% - 32px)); margin:0 auto; display:flex; gap:24px; }}
    .tab {{ border:0; border-bottom:3px solid transparent; background:transparent; padding:13px 2px 11px; color:var(--muted); }}
    .tab.active {{ color:var(--ink); border-color:var(--green); font-weight:700; }}
    .content {{ padding:28px 0 56px; }}
    .view {{ display:none; }} .view.active {{ display:block; }}
    .status {{ padding:24px; border:1px solid var(--line); border-left:5px solid var(--green); border-radius:6px; display:grid; grid-template-columns:1fr auto; gap:20px; align-items:center; }}
    .status.warn {{ border-left-color:var(--amber); background:var(--amber-soft); }} .status.danger {{ border-left-color:var(--red); background:var(--red-soft); }}
    h1,h2,h3,p {{ margin-top:0; }} h1 {{ font-size:28px; margin-bottom:6px; }} h2 {{ font-size:18px; margin:32px 0 14px; }} h3 {{ font-size:16px; margin-bottom:4px; overflow-wrap:anywhere; }}
    .muted {{ color:var(--muted); }} .metrics {{ display:flex; gap:24px; flex-wrap:wrap; }} .metric strong {{ display:block; font-size:24px; }}
    .list {{ display:grid; gap:10px; }}
    .item {{ border:1px solid var(--line); border-radius:6px; padding:16px; background:#fff; }}
    .item-head {{ display:flex; align-items:flex-start; justify-content:space-between; gap:16px; }}
    .severity {{ display:inline-flex; align-items:center; min-height:24px; padding:2px 8px; border-radius:4px; font-size:12px; font-weight:700; background:var(--amber-soft); color:var(--amber); white-space:nowrap; }}
    .severity.critical {{ color:var(--red); background:var(--red-soft); }}
    .actions {{ display:flex; gap:8px; flex-wrap:wrap; margin-top:14px; }}
    .btn {{ min-height:38px; border-radius:5px; padding:7px 13px; border:1px solid var(--line); background:#fff; color:var(--ink); }}
    .btn:hover {{ border-color:#9eaaa4; }} .btn.primary {{ background:var(--green); border-color:var(--green); color:#fff; }} .btn.danger {{ color:var(--red); }}
    .project-grid {{ display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:12px; }}
    .assets {{ margin:10px 0 0; padding:0; list-style:none; color:var(--muted); }} .assets li {{ overflow-wrap:anywhere; }}
    .project-controls {{ display:grid; grid-template-columns:minmax(180px,1fr) auto; gap:10px; align-items:end; margin-top:14px; }}
    label {{ display:grid; gap:5px; color:var(--muted); font-size:13px; }} select {{ width:100%; min-height:38px; border:1px solid var(--line); border-radius:5px; padding:6px 9px; background:#fff; color:var(--ink); }}
    .mode {{ font-size:12px; color:var(--blue); font-weight:700; white-space:nowrap; }}
    button:focus-visible,select:focus-visible {{ outline:2px solid var(--green); outline-offset:2px; }}
    details {{ margin-top:12px; color:var(--muted); }} summary {{ cursor:pointer; }}
    .audit {{ width:100%; border-collapse:collapse; }} .audit th,.audit td {{ padding:10px 8px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; }} .audit th {{ color:var(--muted); font-size:12px; }}
    .empty {{ border:1px dashed var(--line); padding:20px; color:var(--muted); border-radius:6px; }}
    .toast {{ position:fixed; right:20px; bottom:20px; max-width:min(420px,calc(100% - 40px)); padding:12px 16px; color:#fff; background:var(--ink); border-radius:6px; display:none; z-index:10; }}
    @media (max-width:720px) {{ .topbar-inner,.content,.tablist {{ width:min(100% - 24px,1120px); }} .topbar-inner {{ min-height:60px; }} .brand {{ font-size:17px; }} .status {{ grid-template-columns:1fr; padding:18px; }} h1 {{ font-size:23px; }} .project-grid {{ grid-template-columns:1fr; }} .project-controls {{ grid-template-columns:1fr; }} .audit th:nth-child(3),.audit td:nth-child(3) {{ display:none; }} }}
  </style>
</head>
<body>
  <header class="topbar"><div class="topbar-inner"><div class="brand">AI自动化运维工具</div><div class="live"><span class="dot"></span>监控运行中</div></div></header>
  <nav class="tabs" aria-label="主要页面"><div class="tablist" role="tablist">
    <button class="tab active" data-view="home" role="tab">首页</button>
    <button class="tab" data-view="servers" role="tab">服务器 <span class="muted">{len(nodes)}</span></button>
    <button class="tab" data-view="projects" role="tab">项目 <span class="muted">{len(candidates)}</span></button>
    <button class="tab" data-view="records" role="tab">记录</button>
  </div></nav>
  <main class="content">
    <section id="home" class="view active">
      <div class="status {status_class}">
        <div><h1>{escape(status_title)}</h1><div class="muted">最近 24 小时 · {target_total} 个监控项</div></div>
        <div class="metrics"><div class="metric"><strong>{escape(summary.get('ok_rate', 100))}%</strong><span class="muted">正常率</span></div><div class="metric"><strong>{safe_int(summary.get('open_incident_count'))}</strong><span class="muted">处理中</span></div></div>
      </div>
      <h2>现在需要做</h2>
      <div class="list">{render_problem_items(problem_rows)}</div>
    </section>
    <section id="servers" class="view">
      <div class="status"><div><h1>{safe_int(fleet_summary.get('online'))} 台服务器在线</h1><div class="muted">共 {safe_int(fleet_summary.get('total'))} 台 · 失联 {safe_int(fleet_summary.get('offline'))} 台 · 已停用 {safe_int(fleet_summary.get('disabled'))} 台</div></div><button class="btn" onclick="location.reload()">刷新</button></div>
      <h2>服务器</h2>
      <div class="project-grid">{render_fleet_nodes(nodes)}</div>
    </section>
    <section id="projects" class="view">
      <div class="status"><div><h1>发现 {safe_int(safe_dict(onboarding.get('summary')).get('detected_projects'))} 个项目</h1><div class="muted">已绑定 {safe_int(safe_dict(onboarding.get('summary')).get('bound_projects'))} 个 · 待选择 {safe_int(safe_dict(onboarding.get('summary')).get('unbound_projects'))} 个</div></div><button class="btn" onclick="location.reload()">重新扫描</button></div>
      <h2>服务器项目</h2>
      <div class="project-grid">{render_candidates(candidates)}</div>
      <h2>已配置能力</h2>
      <div class="list">{render_configured_projects(projects)}</div>
    </section>
    <section id="records" class="view">
      <h1>操作记录</h1>
      <div style="overflow:auto">{render_audit_logs(audit_logs)}</div>
    </section>
  </main>
  <div id="toast" class="toast" role="status"></div>
  <script id="page-data" type="application/json">{payload}</script>
  <script>
    document.querySelectorAll('.tab').forEach(button => button.addEventListener('click', () => {{
      document.querySelectorAll('.tab,.view').forEach(node => node.classList.remove('active'));
      button.classList.add('active'); document.getElementById(button.dataset.view).classList.add('active');
    }}));
    function token() {{ let value=sessionStorage.getItem('opsToken')||''; if(!value){{value=prompt('请输入管理员口令')||''; if(value)sessionStorage.setItem('opsToken',value);}} return value; }}
    function toast(message) {{ const box=document.getElementById('toast'); box.textContent=message; box.style.display='block'; setTimeout(()=>box.style.display='none',3200); }}
    async function post(url, body) {{ const headers={{'Content-Type':'application/json'}}; const value=token(); if(value)headers.Authorization='Bearer '+value; const response=await fetch(url,{{method:'POST',headers,body:JSON.stringify(body)}}); const data=await response.json(); if(!response.ok)throw new Error(data.error||'操作失败'); return data; }}
    async function bindProject(id, mode) {{ try {{ const select=document.querySelector(`[data-level="${{id}}"]`); const level=mode==='managed'?select.value:'monitor_only'; await post('/api/project-onboarding/'+encodeURIComponent(id)+'/bind',{{management_mode:mode,automation_level:level,actor:'dashboard'}}); toast('项目设置已保存'); setTimeout(()=>location.reload(),700); }} catch(error) {{ toast(error.message); }} }}
    async function incidentAction(id) {{ try {{ await post('/api/incidents/'+id+'/operator-action',{{actor:'dashboard'}}); toast('处理动作已执行'); setTimeout(()=>location.reload(),700); }} catch(error) {{ toast(error.message); }} }}
    async function nodeAction(id, action) {{ try {{ await post('/api/fleet/nodes/'+encodeURIComponent(id)+'/'+action,{{actor:'dashboard'}}); toast('服务器设置已保存'); setTimeout(()=>location.reload(),700); }} catch(error) {{ toast(error.message); }} }}
    document.querySelectorAll('[data-bind-project]').forEach(button => button.addEventListener('click', () => bindProject(button.dataset.candidateId,button.dataset.managementMode)));
    document.querySelectorAll('[data-incident-action]').forEach(button => button.addEventListener('click', () => incidentAction(button.dataset.incidentAction)));
    document.querySelectorAll('[data-node-action]').forEach(button => button.addEventListener('click', () => nodeAction(button.dataset.nodeId,button.dataset.nodeAction)));
  </script>
</body>
</html>"""


def render_problem_items(items: list[dict[str, Any]]) -> str:
    if not items:
        return '<div class="empty">当前没有需要人工处理的问题。</div>'
    rows = []
    for item in items[:12]:
        primary = safe_dict(item.get("primary_action"))
        kind = str(primary.get("kind") or "")
        action = ACTION_LABELS.get(kind, "查看并处理")
        executable = bool(primary.get("executable"))
        severity = str(item.get("severity") or "warning")
        details = safe_dict(item.get("technical"))
        rows.append(
            f'<article class="item"><div class="item-head"><div><h3>{escape(item.get("headline") or item.get("what_happened") or "监控发现异常")}</h3>'
            f'<div class="muted">{escape(item.get("what_happened") or details.get("last_summary") or "等待诊断")}</div></div>'
            f'<span class="severity {escape(severity)}">{"严重" if severity == "critical" else "注意"}</span></div>'
            f'<details><summary>技术详情</summary><p>{escape(details.get("last_summary") or "暂无")}</p></details>'
            + (
                f'<div class="actions"><button class="btn primary" data-incident-action="{safe_int(item.get("incident_id"))}">{escape(action)}</button></div>'
                if executable
                else '<div class="actions"><span class="muted">系统正在继续观察</span></div>'
            )
            + '</article>'
        )
    return "".join(rows)


def render_candidates(candidates: list[dict[str, Any]]) -> str:
    if not candidates:
        return '<div class="empty">没有发现 Docker 项目，或 Docker 当前不可用。</div>'
    rows = []
    for item in candidates:
        candidate_id = str(item.get("id") or "")
        mode = str(item.get("management_mode") or "unbound")
        current_level = str(item.get("automation_level") or "monitor_only")
        options = "".join(
            f'<option value="{escape(level)}"{" selected" if level == current_level else ""}>{escape(label)}</option>'
            for level, label in LEVEL_LABELS.items()
        )
        assets = "".join(f'<li>{escape(name)}</li>' for name in safe_list(item.get("asset_names")))
        rows.append(
            f'<article class="item"><div class="item-head"><div><h3>{escape(item.get("name") or candidate_id)}</h3><div class="muted">{escape(item.get("evidence") or "自动识别")}</div></div><span class="mode">{escape(MODE_LABELS.get(mode, mode))}</span></div>'
            f'<ul class="assets">{assets}</ul><div class="project-controls"><label>自动化级别<select data-level="{escape(candidate_id)}">{options}</select></label>'
            f'<div class="actions"><button class="btn primary" data-bind-project data-candidate-id="{escape(candidate_id)}" data-management-mode="managed">托管</button><button class="btn" data-bind-project data-candidate-id="{escape(candidate_id)}" data-management-mode="observe_only">只读</button><button class="btn danger" data-bind-project data-candidate-id="{escape(candidate_id)}" data-management-mode="ignored">忽略</button></div></div></article>'
        )
    return "".join(rows)


def render_fleet_nodes(nodes: list[dict[str, Any]]) -> str:
    if not nodes:
        return '<div class="empty">还没有接入其他服务器。</div>'
    labels = {"online": "在线", "offline": "失联", "disabled": "已停用"}
    rows = []
    for item in nodes:
        node_id = str(item.get("node_id") or "")
        status = str(item.get("status") or "offline")
        metrics = safe_dict(item.get("metrics"))
        project_count = len(safe_list(item.get("projects")))
        metric_text = " · ".join(
            value
            for value in (
                f"CPU {escape(metrics.get('cpu_percent'))}%" if metrics.get("cpu_percent") is not None else "",
                f"内存 {escape(metrics.get('memory_percent'))}%" if metrics.get("memory_percent") is not None else "",
                f"磁盘 {escape(metrics.get('disk_percent'))}%" if metrics.get("disk_percent") is not None else "",
            )
            if value
        )
        action = "enable" if status == "disabled" else "disable"
        action_label = "恢复监控" if action == "enable" else "停止监控"
        button_class = "btn primary" if action == "enable" else "btn danger"
        rows.append(
            f'<article class="item"><div class="item-head"><div><h3>{escape(item.get("name") or node_id)}</h3><div class="muted">{escape(item.get("hostname") or node_id)} · {project_count} 个项目</div></div><span class="mode">{labels.get(status, status)}</span></div>'
            f'<div class="muted">{metric_text or "等待资源数据"}</div><div class="muted">最近上报 {safe_int(item.get("heartbeat_age_seconds"))} 秒前</div>'
            f'<div class="actions"><button class="{button_class}" data-node-action="{action}" data-node-id="{escape(node_id)}">{action_label}</button></div></article>'
        )
    return "".join(rows)


def render_configured_projects(projects: list[dict[str, Any]]) -> str:
    if not projects:
        return '<div class="empty">还没有配置项目。</div>'
    rows = []
    for item in projects:
        capabilities = safe_dict(item.get("capabilities"))
        level = str(capabilities.get("automation_level") or capabilities.get("effective_level") or "monitor_only")
        blockers = safe_list(capabilities.get("blockers"))
        state = (
            "已忽略"
            if capabilities.get("management_mode") == "ignored"
            else "可用"
            if capabilities.get("ready")
            else "待补充配置"
        )
        blocker_html = "" if not blockers else f'<details><summary>缺少 {len(blockers)} 项配置</summary><p>{escape("；".join(str(value) for value in blockers))}</p></details>'
        rows.append(
            f'<article class="item"><div class="item-head"><div><h3>{escape(item.get("name") or item.get("id"))}</h3><div class="muted">{escape(LEVEL_LABELS.get(level, level))}</div></div><span class="mode">{state}</span></div>{blocker_html}</article>'
        )
    return "".join(rows)


def render_audit_logs(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return '<div class="empty">暂无操作记录。</div>'
    body = "".join(
        f'<tr><td>{escape(row.get("created_at") or row.get("timestamp") or "")}</td><td>{escape(row.get("operation") or row.get("path") or "")}</td><td>{escape(row.get("outcome") or row.get("status") or "")}</td><td>{escape(row.get("message") or "")}</td></tr>'
        for row in rows[:50]
    )
    return f'<table class="audit"><thead><tr><th>时间</th><th>操作</th><th>结果</th><th>说明</th></tr></thead><tbody>{body}</tbody></table>'


def escape(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def safe_dict(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def safe_list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, list) else []


def safe_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0

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
    identity: dict[str, Any] | None = None,
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
    identity_provided = isinstance(identity, dict) and bool(identity)
    identity = safe_dict(identity)
    auth = safe_dict(identity.get("auth"))
    users = [item for item in safe_list(identity.get("users")) if isinstance(item, dict)]
    credentials = [item for item in safe_list(identity.get("credentials")) if isinstance(item, dict)]
    fleet_enrollments = [item for item in safe_list(identity.get("fleet_enrollments")) if isinstance(item, dict)]
    is_admin = not identity_provided or str(auth.get("role") or "") in {"admin", "owner"}
    account_name = str(auth.get("display_name") or auth.get("email") or auth.get("token_name") or "管理员")
    records_tab = '<button class="tab" data-view="records" role="tab">记录</button>' if is_admin else ""
    records_section = (
        '<section id="records" class="view"><h1>操作记录</h1><div style="overflow:auto">'
        + render_audit_logs(audit_logs)
        + "</div></section>"
        if is_admin
        else ""
    )
    payload = json.dumps({"onboarding": onboarding, "identity": identity}, ensure_ascii=False).replace("</", "<\\/")

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
    button,select,input,textarea {{ font:inherit; letter-spacing:0; }}
    button {{ cursor:pointer; }}
    .topbar {{ border-bottom:1px solid var(--line); background:#fff; }}
    .topbar-inner,.content {{ width:min(1120px,calc(100% - 32px)); margin:0 auto; }}
    .topbar-inner {{ min-height:68px; display:flex; align-items:center; justify-content:space-between; gap:16px; }}
    .brand {{ font-size:20px; font-weight:750; }}
    .live {{ display:flex; align-items:center; gap:8px; color:var(--muted); white-space:nowrap; }}
    .account {{ display:flex; align-items:center; gap:10px; min-width:0; }} .account-name {{ max-width:220px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}
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
    label {{ display:grid; gap:5px; color:var(--muted); font-size:13px; }} select,input,textarea {{ width:100%; min-height:38px; border:1px solid var(--line); border-radius:5px; padding:6px 9px; background:#fff; color:var(--ink); }} textarea {{ min-height:82px; resize:vertical; }}
    .form-grid {{ display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:12px; max-width:760px; }} .form-grid .wide {{ grid-column:1/-1; }}
    .mode {{ font-size:12px; color:var(--blue); font-weight:700; white-space:nowrap; }}
    button:focus-visible,select:focus-visible {{ outline:2px solid var(--green); outline-offset:2px; }}
    details {{ margin-top:12px; color:var(--muted); }} summary {{ cursor:pointer; }}
    .audit {{ width:100%; border-collapse:collapse; }} .audit th,.audit td {{ padding:10px 8px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; }} .audit th {{ color:var(--muted); font-size:12px; }}
    .empty {{ border:1px dashed var(--line); padding:20px; color:var(--muted); border-radius:6px; }}
    .toast {{ position:fixed; right:20px; bottom:20px; max-width:min(420px,calc(100% - 40px)); padding:12px 16px; color:#fff; background:var(--ink); border-radius:6px; display:none; z-index:10; }}
    @media (max-width:720px) {{ .topbar-inner,.content,.tablist {{ width:min(100% - 24px,1120px); }} .topbar-inner {{ min-height:60px; }} .brand {{ font-size:17px; }} .account-name {{ display:none; }} .status {{ grid-template-columns:1fr; padding:18px; }} h1 {{ font-size:23px; }} .project-grid,.form-grid {{ grid-template-columns:1fr; }} .form-grid .wide {{ grid-column:auto; }} .project-controls {{ grid-template-columns:1fr; }} .audit th:nth-child(3),.audit td:nth-child(3) {{ display:none; }} }}
  </style>
</head>
<body>
  <header class="topbar"><div class="topbar-inner"><div class="brand">AI自动化运维工具</div><div class="account"><span class="live"><span class="dot"></span>监控运行中</span><span class="account-name">{escape(account_name)}</span><button class="btn" id="logout">退出</button></div></div></header>
  <nav class="tabs" aria-label="主要页面"><div class="tablist" role="tablist">
    <button class="tab active" data-view="home" role="tab">首页</button>
    <button class="tab" data-view="servers" role="tab">服务器 <span class="muted">{len(nodes)}</span></button>
    <button class="tab" data-view="projects" role="tab">项目 <span class="muted">{len(candidates)}</span></button>
    {records_tab}
    {('<button class="tab" data-view="account" role="tab">成员与密钥</button>' if is_admin else '')}
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
      {render_fleet_enrollment_section(fleet_enrollments) if is_admin else ''}
    </section>
    <section id="projects" class="view">
      <div class="status"><div><h1>发现 {safe_int(safe_dict(onboarding.get('summary')).get('detected_projects'))} 个项目</h1><div class="muted">已绑定 {safe_int(safe_dict(onboarding.get('summary')).get('bound_projects'))} 个 · 待选择 {safe_int(safe_dict(onboarding.get('summary')).get('unbound_projects'))} 个</div></div><button class="btn" onclick="location.reload()">重新扫描</button></div>
      <h2>服务器项目</h2>
      <div class="project-grid">{render_candidates(candidates, is_admin)}</div>
      <h2>已配置能力</h2>
      <div class="list">{render_configured_projects(projects, is_admin)}</div>
    </section>
    {records_section}
    {render_identity_section(users, credentials, identity.get('projects')) if is_admin else ''}
  </main>
  <div id="toast" class="toast" role="status"></div>
  <script id="page-data" type="application/json">{payload}</script>
  <script>
    document.querySelectorAll('.tab').forEach(button => button.addEventListener('click', () => {{
      document.querySelectorAll('.tab,.view').forEach(node => node.classList.remove('active'));
      button.classList.add('active'); document.getElementById(button.dataset.view).classList.add('active');
    }}));
    function token() {{ return sessionStorage.getItem('opsToken')||''; }}
    function toast(message) {{ const box=document.getElementById('toast'); box.textContent=message; box.style.display='block'; setTimeout(()=>box.style.display='none',3200); }}
    async function post(url, body) {{ const headers={{'Content-Type':'application/json'}}; const value=token(); if(value)headers.Authorization='Bearer '+value; const response=await fetch(url,{{method:'POST',headers,body:JSON.stringify(body)}}); const data=await response.json(); if(!response.ok)throw new Error(data.error||'操作失败'); return data; }}
    async function bindProject(id, mode) {{ try {{ const select=document.querySelector(`[data-level="${{id}}"]`); const level=mode==='managed'?select.value:'monitor_only'; await post('/api/project-onboarding/'+encodeURIComponent(id)+'/bind',{{management_mode:mode,automation_level:level,actor:'dashboard'}}); toast('项目设置已保存'); setTimeout(()=>location.reload(),700); }} catch(error) {{ toast(error.message); }} }}
    async function incidentAction(id) {{ try {{ await post('/api/incidents/'+id+'/operator-action',{{actor:'dashboard'}}); toast('处理动作已执行'); setTimeout(()=>location.reload(),700); }} catch(error) {{ toast(error.message); }} }}
    async function nodeAction(id, action) {{ try {{ await post('/api/fleet/nodes/'+encodeURIComponent(id)+'/'+action,{{actor:'dashboard'}}); toast('服务器设置已保存'); setTimeout(()=>location.reload(),700); }} catch(error) {{ toast(error.message); }} }}
    document.querySelectorAll('[data-bind-project]').forEach(button => button.addEventListener('click', () => bindProject(button.dataset.candidateId,button.dataset.managementMode)));
    document.querySelectorAll('[data-incident-action]').forEach(button => button.addEventListener('click', () => incidentAction(button.dataset.incidentAction)));
    document.querySelectorAll('[data-node-action]').forEach(button => button.addEventListener('click', () => nodeAction(button.dataset.nodeId,button.dataset.nodeAction)));
    document.getElementById('logout').addEventListener('click', async () => {{ await post('/api/auth/logout',{{}}); sessionStorage.removeItem('opsToken'); location.reload(); }});
    const userForm=document.getElementById('user-form'); if(userForm) userForm.addEventListener('submit',async event=>{{event.preventDefault();try{{const data=new FormData(userForm);await post('/api/users',{{email:data.get('email'),display_name:data.get('display_name'),password:data.get('password'),role:data.get('role'),project_ids:Array.from(userForm.querySelector('[name="project_ids"]').selectedOptions).map(option=>option.value)}});toast('成员已创建');setTimeout(()=>location.reload(),700);}}catch(error){{toast(error.message);}}}});
    document.querySelectorAll('[data-user-action]').forEach(button=>button.addEventListener('click',async()=>{{const enabled=button.dataset.userAction==='enable';if(!confirm(enabled?'确认启用这个成员？':'确认停用这个成员？'))return;try{{await post('/api/users/'+button.dataset.userId,{{enabled}});toast(enabled?'成员已启用':'成员已停用');setTimeout(()=>location.reload(),700);}}catch(error){{toast(error.message);}}}}));
    const credentialForm=document.getElementById('credential-form'); if(credentialForm) credentialForm.addEventListener('submit',async event=>{{event.preventDefault();try{{const data=new FormData(credentialForm);const result=await post('/api/api-credentials',{{name:data.get('name'),role:data.get('role'),project_ids:Array.from(credentialForm.querySelector('[name="project_ids"]').selectedOptions).map(option=>option.value)}});document.getElementById('new-token').textContent=result.token;document.getElementById('new-token-wrap').hidden=false;}}catch(error){{toast(error.message);}}}});
    document.querySelectorAll('[data-revoke-credential]').forEach(button=>button.addEventListener('click',async()=>{{if(!confirm('确认停用这个 API 密钥？'))return;try{{await post('/api/api-credentials/'+button.dataset.revokeCredential+'/revoke',{{}});toast('密钥已停用');setTimeout(()=>location.reload(),700);}}catch(error){{toast(error.message);}}}}));
    const enrollmentForm=document.getElementById('enrollment-form'); if(enrollmentForm) enrollmentForm.addEventListener('submit',async event=>{{event.preventDefault();try{{const data=new FormData(enrollmentForm);const result=await post('/api/fleet/enrollment-tokens',{{name:data.get('name'),node_id:data.get('node_id')}});document.getElementById('enrollment-token').textContent=result.token;document.getElementById('install-command').textContent=result.install_command||'安装脚本地址尚未配置';document.getElementById('enrollment-result').hidden=false;}}catch(error){{toast(error.message);}}}});
    document.querySelectorAll('[data-revoke-enrollment]').forEach(button=>button.addEventListener('click',async()=>{{if(!confirm('确认停用这个服务器令牌？'))return;try{{await post('/api/fleet/enrollment-tokens/'+button.dataset.revokeEnrollment+'/revoke',{{}});toast('服务器令牌已停用');setTimeout(()=>location.reload(),700);}}catch(error){{toast(error.message);}}}}));
    document.querySelectorAll('[data-project-form]').forEach(form=>form.addEventListener('submit',async event=>{{event.preventDefault();try{{const data=new FormData(form);const lines=name=>(String(data.get(name)||'').split('\\\\n').map(value=>value.trim()).filter(Boolean));await post('/api/config/projects/upsert',{{project:{{id:form.dataset.projectForm,repo_root:data.get('repo_root'),git_remote:data.get('git_remote'),base_branch:data.get('base_branch'),health_urls:lines('health_urls'),test_commands:lines('test_commands'),deploy_commands:lines('deploy_commands'),rollback_commands:lines('rollback_commands'),repair_policy:{{prepare_branch:data.get('prepare_branch')==='on',create_pr:data.get('create_pr')==='on',auto_approve:false}}}}}});toast('代码修复配置已保存');setTimeout(()=>location.reload(),700);}}catch(error){{toast(error.message);}}}}));
    document.querySelectorAll('[data-repair-drill]').forEach(button=>button.addEventListener('click',async()=>{{try{{const result=await post('/api/projects/'+encodeURIComponent(button.dataset.repairDrill)+'/ai-repair/drill',{{actor:'dashboard'}});toast(result.status==='completed'?'演练通过':'演练已完成，请查看结果');}}catch(error){{toast(error.message);}}}}));
  </script>
</body>
</html>"""


def render_login_page(status: dict[str, Any]) -> str:
    setup_required = bool(status.get("setup_required"))
    setup_form = ""
    if setup_required:
        setup_form = """
        <form id="setup-form" class="panel">
          <h1>初始化管理员</h1>
          <label>公司名称<input name="organization_name" autocomplete="organization" required></label>
          <label>姓名<input name="display_name" autocomplete="name" required></label>
          <label>邮箱<input name="email" type="email" autocomplete="username" required></label>
          <label>密码<input name="password" type="password" minlength="12" autocomplete="new-password" required></label>
          <label>安装管理员口令<input name="token" type="password" autocomplete="off"></label>
          <button class="primary" type="submit">完成初始化</button>
        </form>
        """
    else:
        setup_form = """
        <form id="login-form" class="panel">
          <h1>登录</h1>
          <label>邮箱<input name="email" type="email" autocomplete="username" required></label>
          <label>密码<input name="password" type="password" autocomplete="current-password" required></label>
          <button class="primary" type="submit">登录</button>
          <details><summary>使用管理员口令</summary><label>管理员口令<input name="token" type="password" autocomplete="off"></label><button type="button" id="token-login">口令登录</button></details>
        </form>
        """
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>登录 · AI自动化运维工具</title>
  <style>
    :root {{ color-scheme:light; --ink:#18211d; --muted:#65716b; --line:#dce3df; --green:#147d52; --red:#b3261e; }}
    * {{ box-sizing:border-box; }} body {{ margin:0; min-height:100vh; display:grid; place-items:center; padding:24px; color:var(--ink); background:#f5f7f6; font:15px/1.5 Inter,"Segoe UI","Microsoft YaHei",sans-serif; letter-spacing:0; }}
    main {{ width:min(420px,100%); }} .brand {{ font-size:20px; font-weight:750; margin-bottom:18px; }} .panel {{ display:grid; gap:14px; padding:24px; background:#fff; border:1px solid var(--line); border-radius:6px; }}
    h1 {{ font-size:24px; margin:0 0 4px; }} label {{ display:grid; gap:5px; color:var(--muted); font-size:13px; }} input,button {{ min-height:42px; border:1px solid var(--line); border-radius:5px; padding:8px 11px; background:#fff; color:var(--ink); font:inherit; letter-spacing:0; }} button {{ cursor:pointer; font-weight:700; }} button.primary {{ color:#fff; border-color:var(--green); background:var(--green); }} details {{ border-top:1px solid var(--line); padding-top:12px; }} summary {{ color:var(--muted); cursor:pointer; margin-bottom:12px; }} details label {{ margin-bottom:10px; }} #error {{ min-height:22px; color:var(--red); margin-top:12px; }}
  </style>
</head>
<body><main><div class="brand">AI自动化运维工具</div>{setup_form}<div id="error" role="alert"></div></main>
<script>
  const errorBox=document.getElementById('error');
  async function submit(url,body,token=''){{const headers={{'Content-Type':'application/json'}};if(token)headers.Authorization='Bearer '+token;const response=await fetch(url,{{method:'POST',headers,body:JSON.stringify(body)}});const data=await response.json();if(!response.ok)throw new Error(data.error||'操作失败');location.reload();}}
  const setup=document.getElementById('setup-form'); if(setup) setup.addEventListener('submit',async event=>{{event.preventDefault();errorBox.textContent='';const data=new FormData(setup);try{{await submit('/api/auth/bootstrap',{{organization_name:data.get('organization_name'),display_name:data.get('display_name'),email:data.get('email'),password:data.get('password')}},data.get('token'));}}catch(error){{errorBox.textContent=error.message;}}}});
  const login=document.getElementById('login-form'); if(login) login.addEventListener('submit',async event=>{{event.preventDefault();errorBox.textContent='';const data=new FormData(login);try{{await submit('/api/auth/login',{{email:data.get('email'),password:data.get('password')}});}}catch(error){{errorBox.textContent=error.message;}}}});
  const tokenButton=document.getElementById('token-login'); if(tokenButton) tokenButton.addEventListener('click',async()=>{{errorBox.textContent='';try{{await submit('/api/auth/login',{{token:new FormData(login).get('token')}});}}catch(error){{errorBox.textContent=error.message;}}}});
</script></body></html>"""


def render_identity_section(users: list[dict[str, Any]], credentials: list[dict[str, Any]], projects: object) -> str:
    project_rows = [row for row in safe_list(projects) if isinstance(row, dict) and bool(row.get("enabled", True))]
    options = "".join(
        f'<option value="{escape(row.get("id"))}">{escape(row.get("name") or row.get("id"))}</option>'
        for row in project_rows
    )
    user_row_items = []
    for row in users:
        enabled = bool(row.get("enabled"))
        action = "disable" if enabled else "enable"
        action_label = "停用" if enabled else "启用"
        user_row_items.append(
            f'<tr><td>{escape(row.get("display_name") or row.get("email"))}</td><td>{escape(row.get("role"))}</td>'
            f'<td>{escape(", ".join(safe_list(row.get("project_ids"))) or "公司级")}</td>'
            f'<td>{"启用" if enabled else "停用"} <button class="btn" data-user-action="{action}" '
            f'data-user-id="{safe_int(row.get("id"))}">{action_label}</button></td></tr>'
        )
    user_rows = "".join(user_row_items) or '<tr><td colspan="4">暂无成员</td></tr>'
    credential_row_items = []
    for row in credentials:
        action = "已停用" if row.get("revoked_at") else (
            f'<button class="btn danger" data-revoke-credential="{safe_int(row.get("id"))}">停用</button>'
        )
        credential_row_items.append(
            f'<tr><td>{escape(row.get("name"))}</td><td>{escape(row.get("token_prefix"))}...</td>'
            f'<td>{escape(row.get("role"))}</td><td>{action}</td></tr>'
        )
    credential_rows = "".join(credential_row_items) or '<tr><td colspan="4">暂无 API 密钥</td></tr>'
    return f"""
    <section id="account" class="view">
      <h1>成员与密钥</h1>
      <h2>成员</h2>
      <div style="overflow:auto"><table class="audit"><thead><tr><th>成员</th><th>角色</th><th>项目</th><th>状态</th></tr></thead><tbody>{user_rows}</tbody></table></div>
      <h2>添加成员</h2>
      <form id="user-form" class="form-grid">
        <label>姓名<input name="display_name" required></label><label>邮箱<input name="email" type="email" required></label>
        <label>初始密码<input name="password" type="password" minlength="12" required></label><label>角色<select name="role"><option value="viewer">只读</option><option value="operator">运维人员</option><option value="admin">管理员</option></select></label>
        <label class="wide">可管理项目<select name="project_ids" multiple size="{max(2, min(len(project_rows), 5))}">{options}</select></label>
        <div><button class="btn primary" type="submit">添加成员</button></div>
      </form>
      <h2>API 密钥</h2>
      <div style="overflow:auto"><table class="audit"><thead><tr><th>名称</th><th>前缀</th><th>角色</th><th>状态</th></tr></thead><tbody>{credential_rows}</tbody></table></div>
      <h2>创建 API 密钥</h2>
      <form id="credential-form" class="form-grid">
        <label>名称<input name="name" required></label><label>角色<select name="role"><option value="viewer">只读</option><option value="operator">运维人员</option><option value="admin">管理员</option></select></label>
        <label class="wide">授权项目<select name="project_ids" multiple size="{max(2, min(len(project_rows), 5))}">{options}</select></label>
        <div><button class="btn primary" type="submit">创建密钥</button></div>
      </form>
      <div id="new-token-wrap" class="item" hidden><h3>新密钥</h3><code id="new-token" style="overflow-wrap:anywhere"></code></div>
    </section>"""


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


def render_candidates(candidates: list[dict[str, Any]], can_manage: bool = True) -> str:
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
        controls = (
            f'<div class="project-controls"><label>自动化级别<select data-level="{escape(candidate_id)}">{options}</select></label>'
            f'<div class="actions"><button class="btn primary" data-bind-project data-candidate-id="{escape(candidate_id)}" data-management-mode="managed">托管</button><button class="btn" data-bind-project data-candidate-id="{escape(candidate_id)}" data-management-mode="observe_only">只读</button><button class="btn danger" data-bind-project data-candidate-id="{escape(candidate_id)}" data-management-mode="ignored">忽略</button></div></div>'
            if can_manage
            else ""
        )
        rows.append(
            f'<article class="item"><div class="item-head"><div><h3>{escape(item.get("name") or candidate_id)}</h3><div class="muted">{escape(item.get("evidence") or "自动识别")}</div></div><span class="mode">{escape(MODE_LABELS.get(mode, mode))}</span></div>'
            f'<ul class="assets">{assets}</ul>{controls}</article>'
        )
    return "".join(rows)


def render_fleet_enrollment_section(rows: list[dict[str, Any]]) -> str:
    body_items = []
    for row in rows:
        state = "已停用" if row.get("revoked_at") else "可用"
        action = "" if row.get("revoked_at") else (
            f'<button class="btn danger" data-revoke-enrollment="{safe_int(row.get("id"))}">停用</button>'
        )
        body_items.append(
            f'<tr><td>{escape(row.get("name"))}</td><td>{escape(row.get("node_id") or "任意节点")}</td>'
            f'<td>{escape(state)}</td><td>{action}</td></tr>'
        )
    body = "".join(body_items) or '<tr><td colspan="4">暂无安装令牌</td></tr>'
    return f"""
      <h2>接入新服务器</h2>
      <form id="enrollment-form" class="form-grid">
        <label>服务器名称<input name="name" required></label>
        <label>节点编号<input name="node_id" pattern="[A-Za-z0-9][A-Za-z0-9._-]{{0,63}}" required></label>
        <div><button class="btn primary" type="submit">生成安装令牌</button></div>
      </form>
      <div id="enrollment-result" class="item" hidden><h3>安装令牌</h3><code id="enrollment-token" style="overflow-wrap:anywhere"></code><h3 style="margin-top:14px">安装命令</h3><code id="install-command" style="overflow-wrap:anywhere"></code></div>
      <div style="overflow:auto;margin-top:18px"><table class="audit"><thead><tr><th>名称</th><th>节点</th><th>状态</th><th>操作</th></tr></thead><tbody>{body}</tbody></table></div>
    """


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
        version_text = f"版本 {escape(item.get('agent_version') or '未知')}"
        if item.get("upgrade_required"):
            version_text += f"，需要升级到 {escape(item.get('required_agent_version'))}"
        rows.append(
            f'<article class="item"><div class="item-head"><div><h3>{escape(item.get("name") or node_id)}</h3><div class="muted">{escape(item.get("hostname") or node_id)} · {project_count} 个项目</div></div><span class="mode">{labels.get(status, status)}</span></div>'
            f'<div class="muted">{metric_text or "等待资源数据"}</div><div class="muted">{version_text} · 最近上报 {safe_int(item.get("heartbeat_age_seconds"))} 秒前</div>'
            f'<div class="actions"><button class="{button_class}" data-node-action="{action}" data-node-id="{escape(node_id)}">{action_label}</button></div></article>'
        )
    return "".join(rows)


def render_configured_projects(projects: list[dict[str, Any]], can_manage: bool = True) -> str:
    if not projects:
        return '<div class="empty">还没有配置项目。</div>'
    rows = []
    for item in projects:
        capabilities = safe_dict(item.get("capabilities"))
        repair_readiness = safe_dict(item.get("repair_readiness"))
        closure = safe_dict(repair_readiness.get("closure"))
        level = str(capabilities.get("automation_level") or capabilities.get("effective_level") or "monitor_only")
        blockers = [
            *safe_list(capabilities.get("blockers")),
            *safe_list(repair_readiness.get("blockers")),
            *safe_list(closure.get("blockers")),
        ]
        state = (
            "已忽略"
            if capabilities.get("management_mode") == "ignored"
            else "修复闭环已就绪"
            if closure.get("status") == "ready"
            else "监控已就绪"
            if capabilities.get("ready") and repair_readiness.get("status") != "blocked"
            else "待补充配置"
        )
        blocker_html = "" if not blockers else f'<details><summary>缺少 {len(blockers)} 项配置</summary><p>{escape("；".join(str(value) for value in blockers))}</p></details>'
        repair_form = render_project_repair_form(item) if can_manage else ""
        rows.append(
            f'<article class="item"><div class="item-head"><div><h3>{escape(item.get("name") or item.get("id"))}</h3><div class="muted">{escape(LEVEL_LABELS.get(level, level))}</div></div><span class="mode">{state}</span></div>{blocker_html}</article>'
            if not repair_form
            else f'<article class="item"><div class="item-head"><div><h3>{escape(item.get("name") or item.get("id"))}</h3><div class="muted">{escape(LEVEL_LABELS.get(level, level))}</div></div><span class="mode">{state}</span></div>{blocker_html}{repair_form}</article>'
        )
    return "".join(rows)


def render_project_repair_form(item: dict[str, Any]) -> str:
    project_id = str(item.get("id") or "")
    policy = safe_dict(item.get("repair_policy"))
    checked_branch = " checked" if bool(policy.get("prepare_branch")) else ""
    checked_pr = " checked" if bool(policy.get("create_pr")) else ""

    def lines(name: str) -> str:
        return escape("\n".join(str(value) for value in safe_list(item.get(name))))

    return f"""
      <details><summary>代码修复配置</summary>
        <form class="form-grid" data-project-form="{escape(project_id)}">
          <label class="wide">代码目录<input name="repo_root" value="{escape(item.get('repo_root'))}" required></label>
          <label>Git 远程<input name="git_remote" value="{escape(item.get('git_remote') or 'origin')}" required></label>
          <label>基础分支<input name="base_branch" value="{escape(item.get('base_branch') or 'main')}" required></label>
          <label class="wide">健康验证地址<textarea name="health_urls">{lines('health_urls')}</textarea></label>
          <label class="wide">测试命令<textarea name="test_commands">{lines('test_commands')}</textarea></label>
          <label class="wide">部署命令<textarea name="deploy_commands">{lines('deploy_commands')}</textarea></label>
          <label class="wide">回滚命令<textarea name="rollback_commands">{lines('rollback_commands')}</textarea></label>
          <label><span>创建修复分支</span><input name="prepare_branch" type="checkbox"{checked_branch}></label>
          <label><span>创建 Pull Request</span><input name="create_pr" type="checkbox"{checked_pr}></label>
          <div class="actions wide"><button class="btn primary" type="submit">保存配置</button><button class="btn" type="button" data-repair-drill="{escape(project_id)}">运行安全演练</button></div>
        </form>
      </details>"""


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

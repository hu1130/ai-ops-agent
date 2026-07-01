# AI Ops Agent MVP

一个给公司内部先用起来的轻量 AI 运维监控智能体。当前目标是先把产品上线后的常见问题看住，并逐步演进成企业级运维平台。

已支持：

- 定时检查官网、API、健康接口是否正常
- 真实调用 AI 客服接口，监控回复是否成功、是否过慢
- 采集本机 CPU、内存、磁盘等基础指标
- 扫描应用日志、Docker 日志里的新增错误
- 出现异常时生成规则/AI 分析
- 报警邮件附带处理建议、服务器资源、Docker 状态和相关日志
- 连续失败后再报警，恢复后发送恢复通知
- 每日发送巡检日报
- 使用 SQLite 保存巡检和事件记录
- 给巡检、事件、处置动作打上环境、运行类型和 trace_id 标记
- 按生产/测试数据分别执行保留和自动清理
- 提供本地 Web 面板查看健康概览、当前监控目标、事件中心和最近巡检

## 快速开始

可选：如果希望采集更完整的 CPU 和内存指标，可以先安装：

```powershell
python -m pip install -r .\requirements-optional.txt
```

复制配置文件：

```powershell
Copy-Item .\config.example.json .\config.json
```

修改 `config.json` 里的监控目标、日志路径、邮件或 webhook 配置。

启动：

```powershell
python .\ops_agent\main.py --config .\config.json
```

打开面板：

```text
http://127.0.0.1:8765
```

面板包含：

- 最近 24 小时巡检总数、正常率、当前异常和告警事件数
- 当前每个监控目标的最新状态
- 事件中心，可展开查看报警分析和诊断内容
- 最近巡检记录

## Docker 日志监控

推荐按容器名配置 Docker 日志，不要写死 `/var/lib/docker/containers/...` 里的容器 ID 路径。容器重建后 ID 会变，容器名通常保持稳定。

```json
"log_checks": [
  {
    "name": "AI customer service API docker log",
    "container": "ai-customer-service-api-1",
    "tail_lines": 120,
    "only_new": true,
    "keywords": ["ERROR", "Exception", "Traceback", "timeout", "failed", "CRITICAL"]
  }
]
```

普通文件日志仍然可以继续用 `path`：

```json
{
  "name": "Application log",
  "path": "/opt/app/logs/server.log",
  "tail_lines": 120,
  "only_new": true
}
```

只跑一次巡检：

```powershell
python .\ops_agent\main.py --config .\config.json --once
```

## 一键诊断

手动打印当前服务器诊断快照：

```powershell
python -m ops_agent.cli --config .\config.json diagnose
```

校验配置是否有明显错误：

```powershell
python -m ops_agent.cli --config .\config.json validate-config
```

## 报警诊断

当监控项连续失败并真正触发报警时，邮件会自动附带：

- 下一步处理建议
- 主机、系统、磁盘、负载、内存快照
- `docker ps` 和 `docker stats` 摘要
- 相关日志最近片段
- 建议执行的排查命令

可在 `alerts.diagnostics` 中调整：

```json
{
  "enabled": true,
  "include_logs": true,
  "include_docker": true,
  "max_log_lines": 60,
  "max_log_chars": 6000,
  "command_timeout_seconds": 5
}
```

## 自动处置后端

当前已支持自动处置引擎的安全骨架：

- 根据异常自动生成处置计划
- 默认 `suggest` 模式，只建议和 dry-run，不直接修改系统
- 支持端口检查、进程检查、只读诊断命令
- 重启服务、重启容器、清理临时文件、轮转日志已建模，但默认需要人工确认
- 重启服务和重启容器必须通过白名单或策略中心授权后才能执行
- 所有动作都会写入 `action_logs` 审计日志

生成处置计划：

```powershell
python -m ops_agent.cli --config .\config.json remediation-plan --source json_api --name "AI 客服" --status warning --summary "Slow response" --url https://example.com/v1/chat
```

试运行一个动作：

```powershell
python -m ops_agent.cli --config .\config.json run-action --type check_port --host 127.0.0.1 --port 8765
```

真正执行安全动作时加 `--execute`。会修改系统状态的动作当前仍只做计划，不会直接执行：

```powershell
python -m ops_agent.cli --config .\config.json run-action --type check_port --host 127.0.0.1 --port 8765 --execute
```

查看动作审计日志：

```powershell
python -m ops_agent.cli --config .\config.json action-logs
```

## 自愈 Playbook

`remediation.playbooks` 用来把常见故障处理流程配置成剧本。Playbook 只负责编排动作，不绕过策略中心；最终能否自动执行、是否需要人工确认、是否必须执行后验证，仍由 `remediation.policies` 决定。

Playbook 支持按以下条件匹配异常：
- `sources`: 例如 `http`、`json_api`、`server`、`log`
- `statuses`: `warning` 或 `critical`
- `name_contains`、`summary_contains`、`url_contains`、`path_contains`

执行闭环字段：
- `stage`: 步骤阶段，支持 `diagnose`、`remediate`、`verify`、`rollback`
- `on_failure`: 步骤失败后的处理，支持 `continue`、`halt`、`escalate`、`rollback`
- `rollback_steps`: 当步骤设置 `on_failure=rollback` 时执行的回滚/补救诊断步骤

步骤里的 `params`、`title`、`reason` 支持占位符：
- `{{source}}`、`{{name}}`、`{{status}}`、`{{summary}}`
- `{{url}}`、`{{host}}`、`{{port}}`、`{{path}}`
- `{{details.xxx}}`

示例：
```json
{
  "name": "web availability triage",
  "enabled": true,
  "on_failure": "halt",
  "match": {
    "sources": ["http", "json_api"],
    "statuses": ["warning", "critical"]
  },
  "steps": [
    {
      "id": "check_target_port",
      "stage": "diagnose",
      "on_failure": "halt",
      "action_type": "check_port",
      "title": "检查目标端口 {{host}}:{{port}}",
      "reason": "{{source}}/{{name}} 访问异常，先确认目标端口是否可连通。",
      "params": {
        "host": "{{host}}",
        "port": "{{port}}",
        "timeout_seconds": 3
      },
      "auto_execute": true
    }
  ]
}
```

失败处理含义：
- `continue`: 当前步骤失败也继续后续步骤
- `halt`: 当前步骤失败后跳过同一 Playbook 的后续步骤，并写入 `skipped` 审计
- `escalate`: 当前步骤失败后发送升级告警，并将关联事件推进到 `remediating`
- `rollback`: 当前步骤失败后执行 `rollback_steps`，再跳过同一 Playbook 的后续步骤

调度器执行成功后如果动作里带有 `verify_after`，会自动做执行后验证，并把结果写回 `action_logs.verify_status`。

## 自愈策略中心

`remediation.policies` 用来明确控制每一种自愈动作的边界。配置了策略后，执行器会优先按策略判断；没有配置策略时，才兼容旧的 `allowed_actions`、`allowed_services` 和 `allowed_containers`。

策略可以控制：
- `action_type`: 动作类型，例如 `check_port`、`run_diagnostic_command`、`restart_service`
- `targets`: 允许作用的目标，支持 `*`，也支持 `host:port`、服务名、容器名、诊断命令首词
- `enabled`: 是否启用这条策略
- `auto_execute`: 计划生成后是否允许自动执行
- `requires_approval`: 是否必须人工确认
- `verification_required`: 修改系统状态后是否必须配置验证
- `verify_after`: 执行成功后请求的健康检查地址

示例：
```json
{
  "name": "ops-agent service restart",
  "action_type": "restart_service",
  "enabled": true,
  "targets": ["ops-agent"],
  "auto_execute": false,
  "requires_approval": true,
  "verification_required": true,
  "verify_after": {
    "type": "http",
    "url": "http://127.0.0.1:8765/api/summary",
    "expected_status": 200,
    "wait_seconds": 5,
    "retries": 3
  }
}
```

建议规则：读操作可以放宽；重启、清理、变更类动作必须明确目标、不能使用 `*`、必须人工确认，并配置执行后验证。

需要人工确认的动作会先生成一个动作 ID：

```powershell
python -m ops_agent.cli --config .\config.json run-action --type restart_service --service ops-agent
```

确认执行时必须显式带上动作 ID 和 `--execute`：

```powershell
python -m ops_agent.cli --config .\config.json approve-action --id 1 --by owner --execute
```

没有配置 `remediation.policies` 时，只有在 `remediation.allowed_services` 或 `remediation.allowed_containers` 白名单中的服务/容器才会被真正重启。配置策略后，以策略中心的 `targets` 为准。

执行后验证可以在创建动作时指定健康接口：

```powershell
python -m ops_agent.cli --config .\config.json run-action --type restart_docker_container --container ai-customer-service-api-1 --verify-url https://agent.setdx.com/health --verify-wait-seconds 30 --verify-retries 3
```

确认执行后，系统会在动作成功时自动请求该健康接口：

- 返回预期状态码：审计状态变为 `verified_ok`
- 仍然失败：审计状态变为 `verified_failed`
- 没有配置验证：保持执行结果，并记录 `verify_skipped`

真正的重启类动作验证完成后，会按告警配置发送自愈结果通知。

## 事件闭环

告警事件不再只是静态记录。`incidents` 会保存当前生命周期状态，`incident_events` 会保存每次状态变化审计。

同一环境、同一运行类型、同一监控目标的重复异常会归并到已有 active 事件，不会反复创建新事件或重复发送同一类告警。归并字段：

- `fingerprint`: 事件指纹
- `occurrence_count`: 已归并的异常出现次数
- `first_seen_at`: 首次出现时间
- `last_seen_at`: 最近出现时间
- `last_summary`: 最近一次异常摘要

恢复闭环不只依赖进程内存。服务重启后，如果数据库里还有 active 事件，调度器会用事件指纹匹配当前健康结果；只有该事件关联的所有监控目标都在本轮恢复正常时，才会自动转为 `resolved` 并发送恢复通知。

当前状态：

- `open`: 新告警已创建
- `acknowledged`: 已人工确认
- `remediating`: 已进入处置过程
- `verifying`: 已执行变更，等待验证
- `resolved`: 监控已恢复
- `closed`: 事件已关闭归档

查看事件列表：

```powershell
python -m ops_agent.cli --config .\config.json incidents
```

查看事件流转历史：

```powershell
python -m ops_agent.cli --config .\config.json incident-events --id 1
```

查看某个事件关联的处置动作：

```powershell
python -m ops_agent.cli --config .\config.json action-logs --incident-id 1
```

人工确认事件：

```powershell
python -m ops_agent.cli --config .\config.json incident-transition --id 1 --status acknowledged --actor owner --note "开始处理"
```

关闭事件：

```powershell
python -m ops_agent.cli --config .\config.json incident-transition --id 1 --status closed --actor owner --note "已复盘归档"
```

本地 API 也支持事件流转：

```text
GET  /api/incidents
GET  /api/incidents/1
GET  /api/incidents/1/events
GET  /api/incidents/1/actions
POST /api/incidents/1/ack
POST /api/incidents/1/resolve
POST /api/incidents/1/close
POST /api/incidents/1/transition
```

API 鉴权：

```json
{
  "app": {
    "api_tokens": [
      {
        "name": "readonly-dashboard",
        "role": "viewer",
        "token": "replace-with-viewer-token"
      },
      {
        "name": "ops-console",
        "role": "operator",
        "token": "replace-with-operator-token"
      }
    ],
    "api_auth_required_for_reads": false
  }
}
```

角色说明：

- `viewer`: 可访问读接口；如果 `api_auth_required_for_reads=false`，读接口仍可不带 token。
- `operator`: 可执行事件流转、动作确认和拒绝。
- `admin`: 拥有 operator 权限，保留给后续用户和系统管理能力。

旧配置 `app.api_token` 继续兼容，会被视为 `admin` token。配置 token 后，所有 `POST` 接口至少需要 `operator` 权限：

```text
Authorization: Bearer replace-with-operator-token
```

也可以使用请求头 `X-Ops-Agent-Token`。如果把 `api_auth_required_for_reads` 设为 `true`，`GET /api/*` 读接口也会要求 token。

动作审批队列 API：

```text
GET  /api/action-logs
GET  /api/audit-logs
GET  /api/actions/pending
GET  /api/actions/1
POST /api/actions/1/approve
POST /api/actions/1/reject
```

确认动作：
```json
{
  "actor": "owner"
}
```

拒绝动作：
```json
{
  "actor": "owner",
  "note": "先人工排查，不执行重启"
}
```

`approve` 会真正执行该动作，并写回执行结果、审批人和执行后验证状态。`reject` 不会执行动作，只会把动作状态更新为 `rejected`，并写入拒绝人和原因。

操作审计：

```powershell
python -m ops_agent.cli --config .\config.json audit-logs
```

所有 `POST /api/*` 写接口都会记录到 `api_audit_logs`，包括成功、失败和未授权请求。记录字段包括操作者、来源 IP、HTTP 方法、路径、操作名、目标对象、状态码和结果摘要。

`POST /api/incidents/1/transition` 的 JSON 示例：

```json
{
  "status": "acknowledged",
  "actor": "owner",
  "note": "开始处理"
}
```

手动执行动作时可以绑定事件：

```powershell
python -m ops_agent.cli --config .\config.json run-action --type check_port --host 127.0.0.1 --port 8765 --incident-id 1
```

## 环境和测试数据标记

所有巡检、告警事件和处置动作都会写入以下上下文字段：

- `environment`: 默认 `prod`
- `run_type`: 定时巡检默认 `normal`
- `trace_id`: 每轮巡检自动生成，用于串联同一轮产生的巡检、事件和动作日志

推荐在生产配置中保持：

```json
"app": {
  "environment": "prod",
  "run_type": "normal",
  "cli_run_type": "manual"
}
```

如果要跑测试环境，可以单独配置：

```json
"app": {
  "environment": "test",
  "run_type": "manual_test",
  "cli_run_type": "manual_test"
}
```

这样测试数据和生产数据不会混在一起，后续查询、清理、权限隔离和前端筛选都会更清楚。

## 数据保留和自动清理

长期运行时，巡检记录会持续写入 SQLite。可以用 `retention` 配置自动清理过期数据：

```json
"retention": {
  "enabled": true,
  "check_results_days": 30,
  "problem_results_days": 90,
  "incidents_days": 90,
  "action_logs_days": 90,
  "test_results_days": 7,
  "test_incidents_days": 7,
  "test_action_logs_days": 7,
  "test_environments": ["test"],
  "test_run_types": ["manual_test", "synthetic_test"],
  "cleanup_hour": 3,
  "vacuum": false
}
```

默认策略：

- 正常巡检记录保留 30 天
- warning/critical 巡检记录保留 90 天
- 告警事件保留 90 天
- 处置动作审计保留 90 天
- `environment=test` 或 `run_type=manual_test/synthetic_test` 的测试数据保留 7 天
- 每天 03:00 自动执行一次

手动预览将删除多少数据：

```powershell
python -m ops_agent.cli --config .\config.json retention-cleanup
```

真正执行清理：

```powershell
python -m ops_agent.cli --config .\config.json retention-cleanup --execute
```

## 可选 AI 分析

默认没有配置模型时，会使用内置规则分析。需要接入 OpenAI 兼容接口时设置环境变量：

```powershell
$env:OPENAI_API_KEY="你的 key"
$env:OPENAI_BASE_URL="https://api.openai.com/v1"
$env:OPENAI_MODEL="gpt-4.1-mini"
```

也可以在 `config.json` 中关闭 AI：

```json
"ai": {
  "enabled": false
}
```

## Webhook 和邮件告警

支持普通 JSON webhook。飞书、企业微信、钉钉可以通过机器人 webhook 接入。

也支持 SMTP 邮件告警，QQ 邮箱需要使用 SMTP 授权码，不要使用登录密码。真实密码和授权码不要提交到 Git 仓库。

## 目录

```text
ops-agent/
  config.example.json
  ops_agent/
    main.py
    scheduler.py
    config.py
    storage.py
    dashboard.py
    diagnostics/
    remediation/
    monitors/
    ai/
    alerts/
  docs/
  tests/
```

## 后续迭代方向

第一阶段先让它能“看、分析、提醒、辅助排查”。后续会继续加：

- Web 管理后台
- 多项目、多服务器管理
- 事件中心和处理记录
- 多告警渠道
- 登录、权限和审计日志
- 私有化部署包
- 人工确认后的低风险自动修复动作

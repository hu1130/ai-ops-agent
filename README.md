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
- 将异常分类、置信度、证据链和下一步动作结构化保存到事件表
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

## HTTP 备用诊断

HTTP 监控默认会做备用诊断。主检查地址失败时，系统会自动访问同域名备用入口，区分“业务真的不可用”和“健康检查地址不存在但站点可访问”。默认备用入口是 `/`、`/login`、`/signin`，也可以用 `fallback_urls` 为单个项目覆盖。

示例：

```json
{
  "name": "Website health",
  "url": "https://example.com/healthz",
  "expected_status": 200,
  "fallback_urls": ["/login", "/"],
  "fallback_expected_statuses": [200, 204, 301, 302, 401, 403],
  "fallback_success_status": "warning"
}
```

如果 `/healthz`、`/health`、`/api/status` 等主探针返回 404/405/401/403，但备用入口正常，结果会带上 `classification`，例如 `primary_route_missing_fallback_reachable` 或 `primary_auth_required_fallback_reachable`，不会再简单判断为整站宕机。生产环境如果希望这种情况完全不触发故障事件，可以把 `fallback_success_status` 设为 `ok`；如果希望提醒你补健康检查接口，设为 `warning`。

注意：主探针返回 5xx 时不会因为首页能打开就降级。5xx 通常代表应用或依赖真的异常，仍然按 critical 处理。

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

## 通用异常分类引擎

新事件会先进入通用分类器，不再按单个项目写死判断逻辑。分类器会输出异常类型、置信度、证据链和下一步动作。

当前内置分类：

```text
probe_config_issue      监控探针或配置问题
service_unavailable     服务不可用
dependency_failure      依赖故障
performance_degraded    性能下降
container_unhealthy     容器健康异常
log_error_spike         日志错误增加
synthetic_quality_fail  合成测试质量失败
resource_pressure       服务器资源压力
unknown                 未知异常
```

分类器会做多信号关联。例如：

- 主健康接口 404，但同域名首页 200：更可能是 `probe_config_issue`
- HTTP 5xx：仍按 `service_unavailable` 处理
- HTTP/API 异常同时出现日志错误：提升为真实服务故障判断
- 资源压力和业务探针异常同时出现：优先怀疑资源或依赖引发故障
- AI/业务合成测试返回异常结构、兜底话术或空字段：归为 `synthetic_quality_fail`

分类结果会写入 `incidents` 表，字段包括：

- `classification_category`
- `classification_confidence`
- `classification_summary`
- `classification_evidence_json`
- `classification_next_steps_json`

后端提供分类统计接口：

```text
GET /api/classifications/summary?hours=24
```

返回最近 N 小时事件总数、已分类数量、按分类/状态/严重级别聚合、示例事件，以及需要继续优化规则的候选分类。这个接口后续可以直接给前端图表、周报和学习优化任务使用。

## 学习优化任务

系统会定期读取最近事件，自动生成“规则优化建议”，并写入 `learning_recommendations` 表。它不会直接修改代码，而是把需要优化的信号沉淀成可审查队列。

当前会识别：

- `unknown_classification`: 事件没有稳定分类或仍是 `unknown`/`unclassified`
- `low_confidence`: 分类置信度低于阈值
- `frequent_unresolved`: 同一个 active 事件累计出现次数过高
- `frequent_open_category`: 同一分类下有多个未解决事件

配置示例：

```json
"learning": {
  "enabled": true,
  "interval_seconds": 21600,
  "lookback_hours": 72,
  "confidence_threshold": 0.65,
  "frequent_occurrence_threshold": 10,
  "frequent_open_category_threshold": 3,
  "notify": false
}
```

查看学习建议：

```text
GET /api/learning/recommendations
GET /api/learning/recommendations?status=open&priority=high
GET /api/learning/summary
GET /api/learning/recommendations/1
POST /api/learning/recommendations/1/accept
POST /api/learning/recommendations/1/dismiss
POST /api/learning/recommendations/1/apply
POST /api/learning/recommendations/1/propose-config
GET /api/learning/config-patches
GET /api/learning/config-patches/1
POST /api/learning/config-patches/1/validate
POST /api/learning/config-patches/1/approve
POST /api/learning/config-patches/1/reject
POST /api/learning/config-patches/1/apply
```

## 变更关联中心

系统会把发布、配置修改、人工操作和 AI 修复部署统一写入 `change_events` 表。事件诊断时会自动关联最近 24 小时内同环境、同运行类型、同项目或直接绑定的变更，用来判断“是不是最近改动引起的问题”。

接口：
```text
GET /api/change-events
GET /api/change-events?project_id=ops-agent&change_type=deployment
POST /api/change-events
GET /api/incidents/1/changes
GET /api/incidents/1/timeline?hours=24
GET /api/incidents/1/detail
```

事件详情会返回 `timeline`，单独时间线接口也可以直接读取。时间线会把同一事件相关的巡检结果、事件状态变更、诊断、推荐动作、执行动作、通知记录和关联变更按时间排序，便于判断问题是否由最近部署、配置修改或 AI 修复引起。

写入示例：
```json
{
  "title": "Deploy website release",
  "source": "deploy",
  "change_type": "deployment",
  "project_id": "website",
  "environment": "prod",
  "run_type": "normal",
  "commit_sha": "abc123",
  "actor": "operator"
}
```

AI 修复部署和回滚会自动写入变更事件，并关联 `related_incident_id` 和 `related_ai_repair_id`。这一步不会直接修改业务代码，只负责沉淀变更上下文，供误报压降、根因诊断和后续大模型修复策略使用。

以下后端操作会自动写入变更事件：
- 配置中心应用配置、恢复配置、DeepSeek/AI 修复策略/自动触发策略更新
- 项目配置新增、更新、删除
- 监控目标新增、更新、启用、停用、删除
- 学习建议标记为已应用
- 学习配置补丁应用到 `config.json`
- AI 修复部署和自动回滚

变更事件只保存脱敏摘要、目标 ID、备份路径、操作结果和关联事件 ID，不保存完整敏感配置。

Learning recommendation review flow:
- `accept` keeps the suggestion in an accepted state and stores a generated optimization draft.
- `dismiss` closes a noisy or expected suggestion without applying changes.
- `apply` marks the suggestion as applied after the rule/playbook change has been made and reviewed.
- `propose-config` converts an accepted draft into a reviewable JSON config patch.
- `validate` previews the patch and runs full config validation without writing the file.
- Config patches must be approved before `apply` writes to `config.json`. `apply` also runs the same validation again, creates a timestamped backup, and records the result in `learning_config_patches`.

The system does not silently rewrite production code from learning suggestions. It stores a reviewable draft first, records actor/time/note, and writes each POST operation into `api_audit_logs`.

配置驱动分类规则示例：
```json
"classification_rules": [
  {
    "name": "learned slow ai response",
    "enabled": true,
    "category": "performance_degraded",
    "confidence": 0.8,
    "summary": "Configured rule matched a repeated slow AI response.",
    "match": {
      "sources": ["json_api"],
      "statuses": ["warning", "critical"],
      "summary_contains": ["slow", "response"]
    },
    "next_steps": ["Check API latency, model provider latency, database connection pool, and recent deployments."]
  }
]
```

建议字段包括 `priority`、`trigger_type`、`category`、`reason`、`recommended_action`、`evidence`、`incident_ids` 和 `metrics`。后续可以把这些建议接到前端、周报，或者人工确认后再生成分类器规则/Playbook 改动。

Playbook 可以用 `match.categories` 绑定分类结果：

```json
{
  "name": "probe config triage",
  "match": {
    "categories": ["probe_config_issue"]
  },
  "steps": [
    {
      "action_type": "run_diagnostic_command",
      "title": "验证监控探针 {{url}}",
      "reason": "{{source}}/{{name}} 分类为 {{category}}，先确认探针配置。",
      "params": {
        "command": "curl -I -L --max-time 10 {{url}}"
      }
    }
  ]
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
- `last_notification_at`: 最近一次对该事件发出通知的时间
- `escalated_at`: 最近一次升级时间
- `escalation_level`: 当前升级级别

持续异常不会每轮都打扰。默认只在首次创建事件时通知，之后同一事件继续异常时，每隔 `alerts.repeat_notification_interval_seconds` 秒最多发送一次持续异常提醒。

升级策略不要求新通知渠道。没有飞书、短信或电话时，会继续使用当前邮件/webhook，只是标题改为 `[升级] ...`，并把升级记录写入 `incident_events`。默认规则：

- 同一 active 事件持续 30 分钟未恢复，升级提醒
- `critical` 事件累计出现 10 次，升级提醒
- 自动处置动作失败，升级提醒
- 每个事件同一级别只升级一次，避免重复打扰

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
GET  /api/incidents/escalated
GET  /api/incidents/1
GET  /api/incidents/1/detail
GET  /api/incidents/1/events
GET  /api/incidents/1/recommendations
GET  /api/incidents/1/actions
GET  /api/incidents/1/failed-actions
GET  /api/incidents/1/playbook-matches
POST /api/incidents/1/assign
POST /api/incidents/1/unassign
POST /api/incidents/1/priority
POST /api/incidents/1/comment
POST /api/incidents/1/false-positive
POST /api/incidents/1/playbook-recommendations
GET  /api/playbooks
GET  /api/playbooks/detail?name=web%20triage
GET  /api/monitor-targets
GET  /api/monitor-targets/http/0
POST /api/monitor-targets/http
POST /api/monitor-targets/http/0/update
POST /api/monitor-targets/http/0/enable
POST /api/monitor-targets/http/0/disable
POST /api/monitor-targets/http/0/delete
POST /api/monitor-targets/server/update
GET  /api/notification-logs
GET  /api/classifications/summary?hours=24
GET  /api/learning/recommendations
GET  /api/learning/recommendations/1
POST /api/learning/recommendations/1/accept
POST /api/learning/recommendations/1/dismiss
POST /api/learning/recommendations/1/apply
POST /api/learning/recommendations/1/propose-config
GET  /api/learning/config-patches
GET  /api/learning/config-patches/1
POST /api/learning/config-patches/1/validate
POST /api/learning/config-patches/1/approve
POST /api/learning/config-patches/1/reject
POST /api/learning/config-patches/1/apply
GET  /api/learning/summary
GET  /api/recommendations
GET  /api/recommendations/pending
GET  /api/recommendations/actionable
GET  /api/recommendations/1
POST /api/recommendations/1/request-approval
POST /api/recommendations/1/approve
POST /api/recommendations/1/reject
POST /api/incidents/1/ack
POST /api/incidents/1/resolve
POST /api/incidents/1/close
POST /api/incidents/1/transition
```

`GET /api/incidents/1/detail` 会一次返回事件本体、事件流、评论、结构化处置建议、关联动作、失败动作、通知日志和摘要字段，方便后续前端直接展示处理闭环和升级原因。结构化建议也可以通过 `GET /api/incidents/1/recommendations` 单独读取，字段包括动作类型、风险、是否需要人工确认、是否需要执行后验证、当前状态、参数和策略/playbook 元信息。

事件列表支持筛选：`status`、`assignee`、`priority`、`severity`、`false_positive`、`limit`。例如：`GET /api/incidents?assignee=alice&priority=high&false_positive=false`。`assign`/`priority`/`comment`/`false-positive` 会写入事件审计；误报标记会把事件关闭，并保留误报原因。

Playbook Center API：`GET /api/playbooks` 返回当前配置里的自愈剧本清单和步骤摘要；`GET /api/incidents/1/playbook-matches` 会按事件里的巡检结果预览匹配剧本和策略允许/拒绝的动作；`POST /api/incidents/1/playbook-recommendations` 会把允许的动作追加写入事件推荐队列，重复调用会去重，不会覆盖已有审批记录。真正执行仍然走 `/api/recommendations/1/request-approval`、`approve`、`reject`。

推荐项状态机通过 `POST /api/recommendations/1/*` 操作：`request-approval` 会创建并绑定待确认动作；`approve` 会复用动作审批执行链路，写回执行和验证结果；`reject` 会拒绝推荐项及其待确认动作。

推荐项列表支持筛选参数：`status`/`statuses`、`incident_id`、`category`、`risk`、`action_type`、`source`、`limit`。例如：`GET /api/recommendations?status=suggested,pending_approval&risk=medium`。`/pending` 只返回待审批建议，`/actionable` 返回仍需要处理的建议队列。

审批安全配置：`remediation.approval_ttl_seconds` 可以设置待审批动作有效期。例如设置为 `3600` 后，通过 CLI 或 API 创建的 `pending_approval` 动作会写入 `action_logs.approval_expires_at`；超过时间再审批时，系统会把动作标记为 `skipped`，`decision=expired`，并拒绝执行。

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
GET  /api/notification-logs
GET  /api/audit-logs
GET  /api/ops/metrics?hours=24
GET  /api/ops/report?hours=24
GET  /api/actions/pending
GET  /api/actions/failed
GET  /api/actions/1
POST /api/actions/1/approve
POST /api/actions/1/reject
GET  /api/config
GET  /api/config/backups
POST /api/config/validate
POST /api/config/backup
POST /api/config/apply
POST /api/config/restore
GET  /api/config/projects
POST /api/config/projects/upsert
POST /api/config/projects/delete
GET  /api/projects/repair-readiness
GET  /api/config/ai-repair-policy
POST /api/config/ai-repair-policy
GET  /api/config/ai-repair-auto-trigger
POST /api/config/ai-repair-auto-trigger
POST /api/config/deepseek
GET  /api/ai-repairs
GET  /api/ai-repairs/approval-queue
POST /api/ai-repairs/approval-queue/notify
GET  /api/ai-repairs/1
POST /api/ai-repairs/1/advance
POST /api/projects/prod/ai-repair/drill
POST /api/incidents/1/ai-repair/propose
POST /api/incidents/1/ai-repair/run-pipeline
POST /api/ai-repairs/1/run-pipeline
POST /api/ai-repairs/1/sandbox-test
POST /api/ai-repairs/1/approve
POST /api/ai-repairs/1/prepare-branch
POST /api/ai-repairs/1/create-pr
POST /api/ai-repairs/1/deploy-merged
```

`POST /api/ai-repairs/{id}/deploy-merged` runs the merged PR deployment, health verification, and automatic rollback on deployment or verification failure. Optional JSON fields: `commands`, `verify_urls`, `rollback_commands`, `rollback_verify_urls`.

`POST /api/ai-repairs/{id}/sandbox-test` records `test_result.guardrails` and folds guardrail blockers into `approval_report.blockers`. Approval is blocked when a model patch targets sensitive paths such as `.env`, `.ssh`, private key files, uses path traversal, changes more files than policy allows, or requests non-whitelisted test commands.

Sandbox approval reports also include `approval_report.risk_assessment` with `score`, `level`, `factors`, `changed_file_count`, and `recommended_next_action`. Auto-approval now uses both the model-reported risk and this assessed risk, so a low-risk model proposal can still be blocked when the actual patch blast radius or validation result raises the assessed risk.

Sandbox approval reports also include `approval_report.execution_plan`, a machine-readable change plan with `impact`, required gates, pre-deploy checks, validation steps, and rollback strategy. Pull request bodies include the same execution and rollback plan so reviewers can see how the AI repair should be verified and reverted before merge.

`GET /api/ai-repairs/approval-queue` returns the human approval queue for AI repair proposals. Each item includes `queue_state`, blockers, warnings, safe next action, and booleans such as `can_approve`, `can_prepare_branch`, `can_create_pr`, and `can_deploy`. Optional query fields: `status`, `include_done`, `risk`, `model_provider`, `limit`.

`POST /api/ai-repairs/approval-queue/notify` sends the current approval queue through the configured notifier and records a notification log. Optional JSON fields: `states` (default `["ready_for_approval"]`), `include_done`, `limit`, `actor`.

`POST /api/ai-repairs/{id}/advance` executes the queue item safe next action from `next_action`: dry-run, sandbox-test, approve, prepare-branch, create-pr, or deploy-merged. It uses project repo/test configuration from the proposal context when available and refuses actions that do not match the current queue state unless `force` is true.

`POST /api/projects/{project_id}/ai-repair/drill` creates a safe synthetic incident for a configured project, asks the repair model for a proposal, and runs patch dry-run validation. It records the result for review but does not mutate production, approve, prepare a branch, open a PR, or deploy. Optional JSON fields: `summary`, `severity`, `run_sandbox`, `commands`, `force`. If readiness is blocked, the API returns `409` unless `force` is true.

`POST /api/incidents/{id}/ai-repair/run-pipeline` and `POST /api/ai-repairs/{id}/run-pipeline` run the backend AI repair pipeline: proposal, dry-run, sandbox test, optional auto-approval, optional branch preparation, and optional PR creation. It stops at human approval by default. Optional JSON fields: `commands`, `auto_approve`, `auto_approve_risks`, `prepare_branch`, `create_pr`, `remote`, `base`, `draft`.

Incident-based pipeline runs are project-aware. The agent selects the project by `project_id` from the request, or by the incident `environment` and `run_type`. Project `repo_root`, `test_commands`, `git_remote`, `base_branch`, and `repair_policy` override global defaults for that run.

AI repair auto-trigger can be enabled under `ai.repair.auto_trigger`. When enabled, new incidents are matched against severity, category, source, environment, run type, and classifier confidence before the scheduler creates a repair proposal. The scheduler never mutates production through this path; it creates a proposal, optionally runs dry-run validation, records an incident event, and can notify only the newly created queue item.

Use `GET /api/config/ai-repair-auto-trigger` to inspect the effective policy. Use `POST /api/config/ai-repair-auto-trigger` to update it through the config center with backup, validation, and audit logging. The request body can be either the policy object or `{ "auto_trigger": { ... }, "reason": "..." }`.

```json
{
  "ai": {
    "repair": {
      "auto_trigger": {
        "enabled": true,
        "severities": ["critical"],
        "categories": ["service_unavailable", "performance_degraded", "synthetic_quality_fail"],
        "min_classification_confidence": 0.65,
        "run_dry_run": true,
        "notify": true,
        "notify_states": ["needs_sandbox", "ready_for_approval", "blocked", "review_only"]
      }
    }
  }
}
```

`GET /api/projects/repair-readiness` reports whether each project is ready for AI repair: repository path availability, safe test commands, configured model key, loaded context files, skipped/missing files, and effective repair policy. Use this before allowing DeepSeek to generate patches for a real business project.

Model repair proposals can include bounded repository context so DeepSeek/OpenAI-compatible models can generate concrete reviewable diffs instead of guessing. Configure it globally under `ai.repair.repository_context`, and optionally add project-level `repair_context_files`:

```json
{
  "projects": [
    {
      "id": "prod",
      "repo_root": "/opt/your-project",
      "repair_context_files": ["src/app.py", "tests/test_app.py"]
    }
  ],
  "ai": {
    "repair": {
      "repository_context": {
        "enabled": true,
        "max_files": 8,
        "max_file_chars": 4000,
        "max_total_chars": 16000
      }
    }
  }
}
```

The repository context reader skips sensitive paths such as `.env`, `.ssh`, `.git`, private key files, and common build/cache directories. Lines containing key, token, password, authorization, or secret markers are redacted before sending to the model.

DeepSeek repair model can be enabled through:

```json
{
  "api_key_env": "DEEPSEEK_API_KEY",
  "model": "deepseek-v4-flash"
}
```

Send it to `POST /api/config/deepseek`. The API key should stay in the server environment variable, not in `config.json`.

Config center behavior:

- `GET /api/config` returns the active config with secrets redacted.
- `POST /api/config/validate` validates a full candidate config without writing it.
- `POST /api/config/backup` creates a manual backup beside `config.json`.
- `POST /api/config/apply` validates, backs up, then replaces `config.json`.
- `POST /api/config/restore` restores from a generated backup file name, validates it first, then backs up the current file before rollback.

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

企业级指标接口：`GET /api/ops/metrics?hours=24` 返回可用率、事件、动作、通知、分类和 MTTR 等结构化指标；`GET /api/ops/report?hours=24` 在同一份指标基础上增加 `executive_summary` 和 `scorecard`，方便后续前端报表、日报或管理驾驶舱直接展示。

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
  "auto_close_resolved_incidents": true,
  "auto_close_resolved_after_days": 7,
  "test_auto_close_resolved_after_days": 1,
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
- 已恢复事件默认 7 天后自动转为 `closed` 归档，测试环境默认 1 天后归档
- `environment=test` 或 `run_type=manual_test/synthetic_test` 的测试数据保留 7 天
- 每天 03:00 自动执行一次

注意：自动归档只改变事件生命周期状态，不删除记录；真正删除仍由 `incidents_days`、`test_incidents_days` 等保留天数控制。

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

告警降噪配置：

```json
"alerts": {
  "cooldown_seconds": 300,
  "consecutive_failures": 2,
  "recovery_enabled": true,
  "repeat_notification_enabled": true,
  "repeat_notification_interval_seconds": 3600,
  "escalation_enabled": true,
  "escalation_after_seconds": 1800,
  "escalation_critical_occurrences": 10,
  "default_channels": [],
  "routes": [
    {
      "name": "critical-email",
      "enabled": true,
      "match": {"severities": ["critical"]},
      "channels": ["email"]
    }
  ],
  "silence_windows": [
    {
      "name": "night-warning-silence",
      "enabled": false,
      "start": "00:00",
      "end": "08:00",
      "timezone": "+08:00",
      "match": {"severities": ["warning"]}
    }
  ]
}
```

- `cooldown_seconds`: 通知器层面的同类消息冷却时间
- `consecutive_failures`: 连续失败多少次才创建告警事件
- `repeat_notification_interval_seconds`: 同一 active 事件持续异常时，至少间隔多久再次提醒
- `escalation_after_seconds`: 同一 active 事件持续多久未恢复后升级
- `escalation_critical_occurrences`: `critical` 事件累计出现多少次后升级
- `routes`: 按 source、status、severity、category、name、environment、run_type 等条件给告警打路由标签，并生成独立去重 key
- `default_channels`: 没有命中 routes 时使用的默认通知通道；为空时保持旧行为
- `silence_windows`: 在指定时间段内压制匹配告警的通知，但事件仍会落库，供统计和学习优化使用

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

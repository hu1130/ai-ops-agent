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

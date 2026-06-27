# AI Ops Agent 企业版技术架构

## 1. 当前架构

当前内部 MVP 是单进程 Agent：

```text
ops-agent
  ├─ HTTP/API 监控
  ├─ JSON 业务探针
  ├─ 服务器指标监控
  ├─ 日志监控
  ├─ SQLite 存储
  ├─ 邮件告警
  └─ 本机 Web 面板
```

部署方式：

```text
systemd -> /opt/ops-agent -> Python 程序 -> SQLite
```

当前优点：

- 简单
- 稳定
- 易部署
- 适合内部使用

当前限制：

- 单服务器
- 配置靠 JSON 文件
- 面板只适合本机查看
- 诊断能力还弱
- 不适合多用户和多租户

## 2. 企业级目标架构

企业版建议演进为 Agent + Server + Web Console：

```text
┌────────────────────┐
│ Web Console         │
│ 配置 / 告警 / 报表   │
└─────────┬──────────┘
          │
┌─────────▼──────────┐
│ Ops Server          │
│ API / 规则 / 事件    │
│ AI 诊断 / 权限 / 审计 │
└─────────┬──────────┘
          │
 ┌────────▼────────┐
 │                 │
 │   Ops Agents    │
 │                 │
 └─────┬─────┬─────┘
       │     │
  Server A  Server B
  项目/日志  容器/数据库
```

## 3. 组件职责

### 3.1 Ops Agent

部署在客户服务器或内网机器上。

职责：

- 执行监控探针
- 读取本机日志
- 采集资源指标
- 查询 Docker 状态
- 执行低风险诊断命令
- 上报结果到 Ops Server
- 在离线模式下本地告警

Agent 原则：

- 轻量
- 低权限优先
- 不影响业务服务
- 可独立运行
- 配置可远程下发

### 3.2 Ops Server

企业版核心服务。

职责：

- 管理项目和服务器
- 接收 Agent 上报
- 存储监控结果
- 执行告警规则
- 生成事件
- 调用 AI 诊断
- 管理用户和权限
- 提供 API 给 Web Console

### 3.3 Web Console

给用户使用的管理后台。

功能：

- 登录
- 仪表盘
- 项目管理
- 服务器管理
- 监控配置
- 告警规则
- 事件中心
- 诊断报告
- 报表
- 系统设置

## 4. 数据流

### 4.1 正常监控流程

```text
Agent 执行探针
  ↓
生成 CheckResult
  ↓
写本地缓存
  ↓
上报 Ops Server
  ↓
Server 存储
  ↓
规则引擎判断
  ↓
Web Console 展示
```

### 4.2 告警流程

```text
CheckResult 异常
  ↓
连续失败计数
  ↓
达到阈值
  ↓
创建 Incident
  ↓
收集诊断上下文
  ↓
AI/规则生成建议
  ↓
发送邮件/飞书/企业微信
  ↓
事件中心记录
```

### 4.3 恢复流程

```text
异常项恢复 OK
  ↓
关闭 Incident
  ↓
记录恢复时间
  ↓
计算持续时长
  ↓
发送恢复通知
```

## 5. 数据模型草案

### 5.1 project

```text
id
name
description
owner_id
environment
created_at
updated_at
```

### 5.2 server

```text
id
project_id
name
host
private_ip
os
agent_version
last_seen_at
status
```

### 5.3 monitor

```text
id
project_id
server_id
type
name
config_json
interval_seconds
enabled
created_at
updated_at
```

### 5.4 check_result

```text
id
monitor_id
server_id
status
summary
latency_ms
details_json
created_at
```

### 5.5 incident

```text
id
project_id
monitor_id
severity
status
title
analysis
started_at
resolved_at
duration_seconds
created_at
updated_at
```

### 5.6 notification_channel

```text
id
project_id
type
name
config_json_encrypted
enabled
created_at
updated_at
```

### 5.7 audit_log

```text
id
user_id
action
resource_type
resource_id
details_json
created_at
```

## 6. 技术选型建议

### 6.1 Agent

当前继续使用：

```text
Python
SQLite
systemd
标准库优先
```

后续增强：

```text
psutil
docker SDK
httpx
pydantic
```

### 6.2 Server

建议：

```text
Python FastAPI
PostgreSQL
Redis
SQLAlchemy / SQLModel
Alembic
```

### 6.3 Web Console

建议：

```text
Next.js
React
Tailwind CSS
shadcn/ui
ECharts / Recharts
```

### 6.4 部署

内部版：

```text
systemd + SQLite
```

企业私有化：

```text
Docker Compose
PostgreSQL
Redis
Nginx
```

大型客户：

```text
Kubernetes
PostgreSQL 高可用
对象存储
消息队列
```

## 7. 安全设计

### 7.1 密钥管理

- 本地配置文件不进 Git
- Server 端加密保存告警渠道密钥
- Agent 使用短期 token 注册
- 支持密钥轮换

### 7.2 权限控制

角色：

- Owner
- Admin
- Operator
- Developer
- Viewer

权限：

- 查看
- 配置
- 处理事件
- 执行自动化动作
- 管理成员

### 7.3 自动化动作安全

动作分级：

```text
L1 只读诊断
L2 低风险操作
L3 高风险操作
```

要求：

- L1 可自动执行
- L2 可配置自动执行
- L3 必须人工确认
- 所有动作写审计日志

## 8. V0.2 技术任务拆分

### 8.1 故障邮件增强

新增模块：

```text
ops_agent/diagnostics/
  collector.py
  suggestions.py
```

输出内容：

- 最近日志
- 资源快照
- Docker 状态
- 建议命令

### 8.2 一键诊断命令

CLI：

```bash
python -m ops_agent.cli diagnose
python -m ops_agent.cli validate-config
```

### 8.3 配置校验

检查：

- URL 是否合法
- 日志路径是否存在
- 邮件配置是否完整
- 阈值是否合理
- interval 是否合理

### 8.4 面板增强

短期：

- 保持本机监听
- 增加最近 24 小时统计
- 增加最近事件列表

中期：

- 登录认证
- 反向代理访问
- HTTPS

## 9. 迁移策略

不要推倒重来。

建议顺序：

1. 继续增强当前 Agent。
2. 把诊断能力模块化。
3. 把配置模型结构化。
4. 引入 Server 原型。
5. Agent 同时支持本地模式和上报模式。
6. 最后做 Web Console。

这样当前内部监控不会中断，也能逐步演进到企业版。


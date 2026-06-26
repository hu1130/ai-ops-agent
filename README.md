# AI Ops Agent MVP

一个给公司内部先用起来的轻量 AI 运维监控智能体。第一版目标是：

- 定时检查网站/API 是否正常
- 采集本机 CPU/内存/磁盘等基础指标
- 扫描错误日志
- 出现异常时生成 AI/规则分析
- 发送 webhook 告警
- 用 SQLite 保存巡检和事件记录
- 提供一个简单 Web 面板查看状态

## 快速开始

可选：如果你希望采集 CPU 和内存指标，可以先安装：

```powershell
python -m pip install -r .\requirements-optional.txt
```

1. 复制配置文件：

```powershell
Copy-Item .\config.example.json .\config.json
```

2. 修改 `config.json` 里的监控目标、日志路径和 webhook。

3. 启动：

```powershell
python .\ops_agent\main.py --config .\config.json
```

4. 打开面板：

```text
http://127.0.0.1:8765
```

只跑一次巡检：

```powershell
python .\ops_agent\main.py --config .\config.json --once
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

## Webhook 告警

支持普通 JSON webhook。飞书、企业微信、钉钉都可以先用机器人 webhook 接入。

如果暂时没有 webhook，留空即可，告警会写入数据库和控制台。

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
    monitors/
    ai/
    alerts/
  tests/
```

## 后续迭代建议

第一阶段先让它能“看、分析、提醒”。后续可以继续加：

- 多项目管理
- 登录和权限
- 前端管理后台
- Prometheus/Grafana 接入
- 人工确认后的自动修复动作
- 多租户和审计日志

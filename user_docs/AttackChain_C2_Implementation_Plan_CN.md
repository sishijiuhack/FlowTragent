# FlowTragent 攻击链还原与 C2 识别实施计划

## 1. 目标

将 FlowTragent 从“PCAP -> CVE 候选 -> 报告”的检索型 MVP，升级为“流量驱动的攻击链还原与应急响应分析系统”。

目标能力：

- 还原攻击时间线。
- 识别攻击入口。
- 识别攻击流程和攻击阶段。
- 识别攻击手法和候选 CVE。
- 聚合来源 IP、目标资产、User-Agent、URI 等来源证据。
- 识别疑似 C2 / beacon 通信。
- 输出包含攻击链、C2 分析、来源分析、影响判断和处置建议的报告。

## 2. 架构定位

```text
FlowTragent = 应急响应主系统 / 攻击链还原系统
NOVA-F = 漏洞流量相似检索与 CVE 候选召回模块
Agent = 多源证据推理与报告生成模块
Parser = PCAP / HTTP / 日志解析模块
C2 Detector = 回连与信标行为检测模块
```

NOVA-F 不直接给最终结论，只提供候选证据：

- 相似训练样本。
- 候选 CVE。
- 相似度分数。
- 近邻 payload。
- 标签分布。
- 后续可扩展 blocklist / rerank / 空标签抑制信息。

最终判断由 FlowTragent 综合完成。

## 3. 新增模块

计划新增：

```text
src/event/
  models.py

src/correlation/
  timeline.py
  attack_chain.py
  c2_detector.py
  source_tracker.py
```

职责：

- `event/models.py`：统一事件、证据、攻击阶段、C2 发现的数据结构。
- `correlation/timeline.py`：按时间排序并生成 timeline items。
- `correlation/attack_chain.py`：基于规则识别扫描、漏洞利用、命令执行、载荷下载、WebShell、横向移动等阶段。
- `correlation/c2_detector.py`：基于五元组、时间间隔、请求频率、HTTP 特征识别疑似 C2。
- `correlation/source_tracker.py`：聚合来源 IP、入口 URI、User-Agent、目标资产等来源信息。

## 4. 核心数据模型

### 4.1 NetworkEvent

字段：

- `event_id`
- `timestamp`
- `src_ip`
- `src_port`
- `dst_ip`
- `dst_port`
- `protocol`
- `payload_clean`
- `summary`

### 4.2 HttpEvent

在 `NetworkEvent` 基础上增加：

- `method`
- `uri`
- `host`
- `user_agent`
- `headers`
- `body`
- `status_code`

### 4.3 RetrievalEvidence

字段：

- `event_id`
- `candidate_cve`
- `score`
- `rank`
- `neighbor_id`
- `neighbor_payload`
- `neighbor_labels`
- `engine`

### 4.4 AttackStage

字段：

- `stage`
- `technique`
- `confidence`
- `start_time`
- `end_time`
- `source_ip`
- `target_ip`
- `evidence_ids`
- `reasoning`

### 4.5 C2Finding

字段：

- `c2_type`
- `confidence`
- `src_ip`
- `dst_ip`
- `dst_port`
- `first_seen`
- `last_seen`
- `request_count`
- `beacon_interval`
- `jitter`
- `evidence_ids`
- `indicators`

## 5. 攻击阶段识别规则

### 5.1 Reconnaissance / 扫描探测

特征：

- 同一源 IP 短时间访问大量 URI。
- 大量 404 / 403 / 400。
- 常见扫描路径：`/.env`、`/wp-login.php`、`/phpinfo.php`、`/cgi-bin/`。
- User-Agent 包含 `curl`、`python-requests`、`Go-http-client`、`nuclei`、`masscan`。

### 5.2 Exploitation / 漏洞利用

特征：

- NOVA-F 返回高相似度 CVE 候选。
- payload 包含漏洞利用特征。
- URI、参数、请求方法与候选 CVE 攻击方式一致。

示例：

- Log4Shell：`${jndi:`、`ldap://`、`rmi://`
- 路径穿越：`../`、`%2e%2e`、`/etc/passwd`
- SQL 注入：`union select`、`sleep(`、`or 1=1`
- RCE：`cmd=`、`exec=`、`bash -c`、`powershell`

### 5.3 Command Execution / 命令执行

特征：

- `whoami`
- `id`
- `uname`
- `ipconfig`
- `ifconfig`
- `cmd.exe`
- `powershell`

### 5.4 Payload Delivery / 载荷下载

特征：

- `wget`
- `curl`
- `certutil`
- 下载 `.sh`、`.exe`、`.dll`、`.jsp`、`.php`、`.aspx`

### 5.5 WebShell / 后门交互

特征：

- 上传脚本文件。
- `multipart/form-data` 携带脚本内容。
- 后续对异常路径反复 POST。
- 参数名包含 `cmd`、`pass`、`shell`、`exec`、`action`。

### 5.6 Lateral Movement / 横向移动

特征：

- 被攻击主机继续访问内网其他 IP。
- SMB/RDP/WinRM/SSH/Redis/MySQL 等端口连接。
- 内网端口扫描行为。

### 5.7 Exfiltration / 数据外传

特征：

- 大 POST body。
- 持续外连上传。
- 访问云存储、paste、webhook、未知外部 IP。
- DNS 查询异常多。

## 6. C2 识别策略

第一阶段采用规则 + 统计方法。

### 6.1 HTTP Beacon

特征：

- 同一 `src_ip -> dst_ip:dst_port` 多次连接。
- 时间间隔稳定。
- 请求路径或 User-Agent 稳定。
- 小请求 / 小响应。
- GET 拉取任务、POST 上报结果。

### 6.2 DNS C2

后续扩展：

- 高频 TXT 查询。
- 长子域名。
- 高熵域名。
- 大量 NXDOMAIN。

### 6.3 TCP C2

特征：

- 长连接。
- 周期性小包。
- 非常规端口。
- 内网主机主动连接外部 IP。

## 7. 报告结构升级

报告新增章节：

```text
Executive Summary
Key Findings
Attack Timeline
Attack Chain
CVE Retrieval Evidence
C2 Analysis
Source Analysis
Impact Assessment
Recommendations
```

其中：

- `Attack Timeline` 按时间排序展示关键事件。
- `Attack Chain` 展示阶段、手法、置信度、证据 ID。
- `C2 Analysis` 展示疑似 C2 endpoint、周期、抖动、证据。
- `Source Analysis` 展示源 IP、入口 URI、User-Agent、目标资产。

## 8. 实施阶段

### Phase 1：结构化事件与基础时间线

任务：

- 新增事件数据模型。
- 改造 PCAP parser，输出 `HttpEvent`。
- 保留 CSV 输出兼容 NOVA-F。
- 新增 timeline builder。
- 报告输出基础时间线。

验收：

- `tests/test_pipeline.py` 仍通过。
- 报告中出现 Attack Timeline。

### Phase 2：攻击阶段识别

任务：

- 新增 attack chain analyzer。
- 识别扫描、漏洞利用、命令执行、载荷下载、WebShell。
- 将 NOVA-F CVE 候选作为 exploitation 证据。

验收：

- Log4Shell demo PCAP 能输出 Exploitation 阶段。
- 报告中出现 Attack Chain。

### Phase 3：C2 / Beacon 检测

任务：

- 新增 C2 detector。
- 按五元组聚合事件。
- 计算请求间隔中位数和 jitter。
- 输出疑似 HTTP beacon。

验收：

- 构造周期请求测试数据时能识别 Suspicious HTTP Beacon。
- 报告中出现 C2 Analysis。

### Phase 4：来源分析和影响判断

任务：

- 聚合源 IP、目标 IP、入口 URI、User-Agent。
- 输出 source summary。
- 初步判断是否有成功利用证据。

验收：

- 报告中出现 Source Analysis 和 Impact Assessment。

### Phase 5：Agent 二次研判

任务：

- 将 timeline、attack stages、C2 findings、retrieval evidence 输入 Agent。
- Agent 输出更稳定的 summary 和建议。
- Ollama 可选增强。

验收：

- 无 Ollama 时规则报告完整。
- 有 Ollama 时 Agent Summary 更具体。

## 9. 当前优先实现

先实现 Phase 1 到 Phase 3 的最小闭环：

```text
PCAP -> HttpEvent -> NOVA-F candidates -> Timeline -> Attack Chain -> C2 Analysis -> Report
```

暂不做：

- 复杂威胁情报归因。
- 攻击团伙识别。
- 主机侧取证。
- 自动处置。

这些需要更多数据源，不适合在当前阶段承诺。


# FlowTragent API 中文说明

本文面向使用者说明 FlowTragent Web/API 的主要入口。若配置了 `FLOWTRAGENT_TOKEN`，上传、下载、删除、导出、图谱和告警页面等敏感接口需要提供 token；未配置时，本地开发请求默认放行。

## 认证方式

支持以下方式传递 token：

```text
X-FlowTragent-Token: <FLOWTRAGENT_TOKEN>
Authorization: Bearer <FLOWTRAGENT_TOKEN>
?token=<FLOWTRAGENT_TOKEN>
flowtragent_token=<FLOWTRAGENT_TOKEN>
```

## 健康检查

```http
GET /health
```

返回 Web 服务、关键目录、NOVA index、live alert DB 和 worker 状态。该接口不要求 token，便于监控和反向代理探活。

## Prometheus 指标

```http
GET /metrics
```

返回 Prometheus text format，包含处理过的 PCAP 数量、告警数量、深度分析次数、限流次数、live 队列长度、报告数量、alert DB 大小和 NOVA index ready 状态等指标。

## Payload 分析

```http
POST /analyze-payload
```

表单字段：

| 字段 | 说明 |
| --- | --- |
| `payload` | 待分析 HTTP payload |
| `flowtragent_token` | 可选认证 token |

成功后生成 JSON/Markdown 报告，并跳转到报告列表或详情页。

## PCAP 分析

```http
POST /analyze-pcap
```

表单字段：

| 字段 | 说明 |
| --- | --- |
| `pcap_file` | `.pcap` 或 `.pcapng` 文件 |
| `access_log` | 可选访问日志 |
| `flowtragent_token` | 可选认证 token |

服务会校验扩展名与 PCAP magic header，避免把任意文件当作流量输入处理。

## 报告与图谱

```http
GET /reports/<filename>
GET /graph-svg/<filename>
GET /export-reports.zip
POST /delete-report/<filename>
```

报告接口用于下载或查看 Markdown/JSON 报告；图谱接口把 Mermaid/DOT 关系渲染为 SVG；导出接口打包当前报告；删除接口移除指定报告文件。

## 告警页面

```http
GET /alerts
```

展示 live analyzer 写入的 SQLite 告警，包括状态、风险分数、severity、fingerprint、发生次数、首次/最近出现时间和关联报告。

## 安全边界

API 不承诺自动定责、自动处置或 APT 归因。检索命中与攻击 marker 只能增强相关性，最终结论仍必须服从证据分级和 impact verdict。

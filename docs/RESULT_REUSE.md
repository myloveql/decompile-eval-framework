# 生成结果复用、只评估与子集报告

本文说明如何复用已经生成的反编译代码，尤其是费用较高的闭源模型结果。框架 0.6 起将
生成、候选代码、评估证据和指标计算分开缓存。

## 1. 四层数据生命周期

```text
模型输入 + 模型配置
        │
        ▼
Generation（模型原始输出）
        │  generation_key
        ▼
Candidate（后处理后实际参与评估的代码）
        │  candidate_key
        ▼
EvaluationEvidence（编译、链接和测试证据）
        │  evaluation_key
        ▼
Metric / Report（指标值与聚合报告）
```

各层缓存键的边界如下。

### generation_key

包含：

- 反编译器能够看到的 `DecompileRequest`；
- 后端类型、模型、提示词和推理参数；
- 后端版本和 `required_inputs`。

不包含：

- `selection_manifest`、`limit` 和数据集筛选条件；
- 编译器、测试协议和执行器配置；
- 指标列表。

因此，全量运行切换成固定子集不会导致模型重新推理。`batch_size` 和
`plugin_config.max_concurrency` 只是调度参数，也不进入 generation key。API Key、API Key
环境变量名、token、password 和 secret 等凭据字段完全排除，不写入缓存记录，也不会因从
明文密钥切换到环境变量而导致缓存失配。

### candidate_key

包含 `generation_key` 和后处理配置。修改 Markdown 围栏提取、目标函数重命名等后处理时，
会从已有模型输出重新生成候选代码，不调用模型。

### evaluation_key

包含：

- 数据集样本内容哈希；
- 候选代码哈希；
- 数据集评估配置和评估协议版本；
- 编译、执行器和资源限制配置。

它明确排除 `selection_manifest`、`limit`、语言和优化等级筛选字段。只改变样本集合不会重新
执行编译测试；改变测试夹具、协议、编译设置或候选代码才会重新评估。

### Metric

指标配置不进入前三层缓存键。每次运行都会根据已缓存的 EvaluationEvidence 重新调用 Metric。
传统 Metric 继续实现：

```python
def evaluate(self, sample, evidence):
    ...
```

需要读取候选代码的新 Metric 可以声明可选上下文：

```python
def evaluate(self, sample, evidence, *, context=None):
    code = context.candidate_code
    digest = context.candidate_sha256
    return my_score(code, evidence)
```

`context` 还包含 artifact 路径以及 generation、candidate、evaluation 三层 key。旧 Metric 无须修改。

## 2. 新运行的自动复用

正常命令不变：

```bash
python -m decomp_eval run \
  --config configs/my-model.yaml \
  --run-dir runs/my-model-full
```

只要后续配置的 `output.cache` 指向同一目录，框架会分别检查三层缓存。例如把全量配置改成：

```yaml
datasets:
  - id: exebench-1100
    type: exebench_flat
    path: data/exebench/1641-Benchmark/exebench_1641_source_multiopt_1100.with-ghidra.dataset.json
    selection_manifest: data/selections/closed-audit-1000-v1.json
```

不会使相同样本的 generation key 变化。

每条 `results.jsonl` 记录包含：

```text
generation_key / generation_cache_hit
candidate_key  / candidate_cache_hit
evaluation_key / evaluation_cache_hit
sample_content_hash / candidate_sha256
```

可以据此审计每一层是否发生了实际计算。

如果希望先集中生成、以后再安排编译测试，可以只运行生成阶段：

```bash
python -m decomp_eval generate \
  --config configs/my-model.yaml \
  --run-dir runs/my-model-generation
```

该命令生成 `generations.jsonl` 和 `generation_summary.json`，保存 generation/candidate 两层缓存，
不执行参考源码预检、候选编译、链接、测试或 Metric。之后对相同缓存执行 `evaluate` 即可。

## 3. 导入历史运行

0.6 以前的运行已经在 `runs/.../artifacts/` 中保存了 `request.json`、`raw_output.txt`、
`candidate.c` 和 `evaluation.json`。使用 `import-run` 将其登记到分层缓存：

```bash
python -m decomp_eval import-run \
  --run-dir runs/kimi-k2.6-full \
  --config configs/kimi-k2.6-original.yaml
```

推荐提供产生该 run 的原始配置。命令会从配置的 `output.cache` 自动确定缓存目录，并额外读取
数据集以导入 `evaluation.json`。这样后续只新增指标时，模型推理和原有编译测试都不用重跑。

如果原始配置已经遗失，仍可只导入 generation 和 candidate：

```bash
python -m decomp_eval import-run \
  --run-dir runs/kimi-k2.6-full \
  --cache-dir /absolute/path/to/.cache/decomp-eval
```

此时后续不会调用模型，但第一次新评估会重新编译和测试候选代码。

`import-run` 同时支持只有 `generations.jsonl` 的 generate-only 运行，因此尚未进入评估阶段的
模型输出也可以迁移到同一分层缓存。

导入报告字段：

- `imported`：成功导入的模型输出与候选代码数；
- `evaluations_imported`：同时导入的评估证据数；
- `skipped` 和 `skipped_records`：缺失 request、candidate 或后端配置的记录。

导入不会删除或修改原始 run。相同 generation key 如果对应不同输出会报冲突，避免随机生成结果
被静默覆盖。需要同时保留两次随机输出时，应给实验使用不同后端版本标识或不同缓存目录。

历史版本的 `request.json` 可能尚未写入 `binary`、`pseudocode` 或 `compile_context` 等可选字段。
导入时会将“字段缺失”规范化为 `null`，使其与当前请求结构得到相同 generation key。

## 4. 安全的“只评估”模式

导入后，在新 YAML 中使用同一后端配置、相同数据集 ID，并可添加固定子集清单：

```yaml
datasets:
  - id: exebench-1100
    # 其他数据集字段保持一致
    selection_manifest: data/selections/closed-audit-1000-v1.json

decompilers:
  - id: closed-llm-assembly
    # 模型、提示词、required_inputs 和生成参数保持与历史运行一致
```

然后使用 `evaluate`，不要使用普通 `run`：

```bash
python -m decomp_eval evaluate \
  --config configs/kimi-k2.6-audit-1000.yaml \
  --run-dir runs/kimi-k2.6-audit-1000
```

`evaluate` 在开始前检查所有选中样本的 generation cache。只要缺少一条就整体终止，并列出缺失
样本；它绝不会退回 API 或本地模型生成。这是闭源模型复用时的安全边界。

仍可以断点续跑：

```bash
python -m decomp_eval evaluate \
  --config configs/kimi-k2.6-audit-1000.yaml \
  --run-dir runs/kimi-k2.6-audit-1000 \
  --resume
```

## 5. 新增指标时如何运行

只修改 YAML 的 `metrics`：

```yaml
metrics:
  - recompilable
  - behavioral_pass
  - type: my_metrics:CandidateQualityMetric
```

再运行新的 evaluate-only 目录：

```bash
python -m decomp_eval evaluate \
  --config configs/kimi-k2.6-new-metrics.yaml \
  --run-dir runs/kimi-k2.6-new-metrics
```

行为取决于指标需求：

| 变化 | 模型生成 | 后处理 | 编译/测试 | 指标计算 |
|---|---:|---:|---:|---:|
| 只改变指标 | 复用 | 复用 | 复用 | 重新计算 |
| 改变分组或聚合 | 复用 | 复用 | 复用 | 重新聚合 |
| 改变后处理 | 复用 | 重做 | 重做 | 重新计算 |
| 改变测试协议/编译设置 | 复用 | 复用 | 重做 | 重新计算 |
| 改变模型/提示词/输入视图 | 重做 | 重做 | 重做 | 重新计算 |

新 Metric 如果只读取 candidate 和已有 evidence，不会触发编译测试。新 Metric 如果需要新的动态
证据，应通过新的 EvaluationProtocol 或修改协议版本产生；evaluation key 变化后只重跑评估层。

## 6. 从全量结果直接派生子集报告

如果生成、评估协议和指标都不变，只想得到完整运行在固定子集上的统计，不必重新执行任何代码：

```bash
python -m decomp_eval derive-subset \
  --source-run runs/llm4decompile-full \
  --selection-manifest data/selections/closed-audit-1000-v1.json \
  --output-run runs/llm4decompile-audit-1000-derived
```

该命令：

- 校验 selection manifest 自身哈希；
- 检查源 run 是否包含清单中的全部样本；
- 筛选 `results.jsonl`；
- 重新生成 `summary.json` 和 `summary.csv`；
- 在新 manifest 中记录源 run 和 `selection_hash`。

派生 run 不复制大型 artifact，记录仍指向源 artifact。不要删除源 run。若改变了协议、测试或指标，
应使用 `evaluate`，而不是 `derive-subset`。

## 7. Kimi-K2.6 推荐操作顺序

```bash
# 1. 导入已经完成的全量结果和评估证据
python -m decomp_eval import-run \
  --run-dir runs/kimi-k2.6-full \
  --config configs/kimi-k2.6-original.yaml

# 2. 创建并固定至少 1000 条的 selection manifest（只需创建一次）
python -m decomp_eval create-selection-manifest \
  --config configs/build-selection-1000.yaml \
  --output data/selections/closed-audit-1000-v1.json

# 3. 安全地在固定子集上重新评估或计算新指标
python -m decomp_eval evaluate \
  --config configs/kimi-k2.6-audit-1000.yaml \
  --run-dir runs/kimi-k2.6-audit-1000
```

在第 3 步看到任何 `generation cache entries` 缺失错误时，先检查导入报告和两份 YAML 的后端
生成配置是否一致。不要改用 `run` 绕过检查，否则缺失样本会重新调用 API。

## 8. 全量闭源实验尚未完成时切换到固定子集

这一场景适用于：Kimi 等闭源模型的全量运行耗时过长，已经完成了一部分 API 调用，现在希望
停止全量实验，改为完成一个可复现的固定子集，同时保留以后恢复全量运行的能力。

推荐流程：

```text
安全停止全量运行
    ↓
导入已经完成的历史记录
    ↓
为新配置绑定 selection manifest
    ↓
generate 只补齐子集中缺失的生成结果
    ↓
evaluate 完成评估
```

### 8.1 在记录边界停止当前运行

最好等待终端刚输出一条完整记录，例如：

```text
[1234] dataset/backend/sample: pass
```

然后按 `Ctrl+C`。Runner 每完成一条记录就写入并刷新 `results.jsonl`，此前已经打印的记录通常
已经完整保存。正在执行的批次可能仍有尚未落盘的 API 请求，因此在一条输出刚完成后停止可以
尽量减少已付费但未保存的响应。

不要删除、清理或复用原来的 run 目录。也不要将新的子集 YAML 与原来的全量 run 目录组合使用
`--resume`，因为两者的配置哈希和统计分母不同。

### 8.2 导入当前已经完成的部分

使用启动全量实验时的原始 YAML：

```bash
python -m decomp_eval import-run \
  --run-dir runs/kimi-full \
  --config configs/kimi-full.yaml
```

全量实验不需要已经完成。`import-run` 只导入当前 `results.jsonl` 中完整存在的记录，并保持原始
run 不变。检查命令输出：

```json
{
  "imported": 800,
  "evaluations_imported": 800,
  "skipped": 0
}
```

正式继续前应检查 `skipped_records`；理想情况下 `skipped` 为 0。提供原始 YAML 后，命令还会
导入已有 `evaluation.json`，所以相同评估设置下连编译和测试证据也可以复用。

### 8.3 从原始 YAML 创建子集 YAML

复制原始配置：

```bash
cp configs/kimi-full.yaml configs/kimi-audit-1000.yaml
```

在数据集段删除 `limit`，添加同一份 selection manifest，并保持数据集 `id` 不变：

```yaml
datasets:
  - id: exebench-1100
    type: exebench_flat
    path: data/exebench/1641-Benchmark/exebench_1641_source_multiopt_1100.with-ghidra.dataset.json
    selection_manifest: data/selections/closed-audit-1000-v1.json
    optimizations: [O0, O1, O2, O3]

  - id: decompile-eval-humaneval
    type: decompile_eval
    path: data/decompile-eval
    splits: [humaneval]
    languages: [c]
    selection_manifest: data/selections/closed-audit-1000-v1.json
    optimizations: [O0, O1, O2, O3]
```

Kimi 后端应保持以下生成身份不变：

- backend `id`、模型名称和 provider；
- 输入类型、提示词和 thinking 配置；
- temperature、max tokens 等生成参数；
- API 协议及其他会影响模型输出的配置。

`batch_size` 和 `max_concurrency` 是纯调度参数，可以调整。新旧配置的 `output.cache` 必须
解析到同一个目录，否则新配置无法发现刚刚导入的缓存。

### 8.4 只补齐子集缺失的模型输出

执行 generation-only：

```bash
python -m decomp_eval generate \
  --config configs/kimi-audit-1000.yaml \
  --run-dir runs/kimi-audit-1000-generation
```

已导入的子集样本会命中 generation cache，不调用 Kimi；只有 selection manifest 中尚未生成的
样本才会产生新 API 请求。该阶段不运行参考源码预检、编译、链接、测试或 Metric。

完成后检查 `generation_summary.json`：

```json
{
  "total": 1000,
  "decompile_success": 998,
  "candidate_available": 998,
  "generation_cache_hits": 720
}
```

此例表示720条复用了全量运行结果，其余约280条才需要新生成。

终端中的 `[generation N] ...: pass` 只表示生成成功，并不表示缓存命中。是否复用必须查看
`generations.jsonl` 的 `generation_cache_hit` 和 `candidate_cache_hit`，或者查看最终的
`generation_summary.json`。真正的缓存命中通常应很快连续输出。

### 8.5 安全执行子集评估

```bash
python -m decomp_eval evaluate \
  --config configs/kimi-audit-1000.yaml \
  --run-dir runs/kimi-audit-1000-evaluation
```

`evaluate` 会在开始前检查1000条样本的 generation cache。只要缺少一条就整体终止，不会退回
API。历史导入的 EvaluationEvidence 会直接复用；新生成或评估设置变化的样本才会重新编译测试。

### 8.6 以后恢复原来的全量运行

子集实验不会修改原来的全量 run。需要时仍可使用原始配置恢复：

```bash
python -m decomp_eval run \
  --config configs/kimi-full.yaml \
  --run-dir runs/kimi-full \
  --resume
```

必须使用原始全量 YAML 和原始 run 目录，不能使用子集配置续跑全量目录。

### 8.7 API 失败和空输出的处理边界

历史记录中的 `closed_llm_empty_output`、API 异常或其他生成失败默认也会导入 generation cache。
这是为了忠实保存原实验结果，并防止 `evaluate` 意外重新调用付费 API。因此，`generate` 默认
不会自动重试已经导入的失败记录。

如果需要把供应商临时不稳定造成的失败视为“尚未生成”，应使用专门的失败缓存失效或导入过滤
机制。不要仅通过随意修改模型、提示词或推理配置强制重试，因为这会改变 generation key，使
原本成功的样本也无法复用。在正式加入按失败原因重试的命令前，应先统计失败类型并保留原始
run 作为审计证据。

## 9. 复现与归档建议

正式实验至少保留：

- 原始运行的 `manifest.json`、`results.jsonl` 和完整 `artifacts/`；
- selection manifest 及其 `selection_hash`；
- 使用的 YAML（去除密钥）；
- 分层缓存，或可重新执行的 `import-run` 输入；
- 框架版本和 Git commit。

`runs/` 已被 Git 忽略，但它是实验原始证据，不应作为普通中间文件清理。

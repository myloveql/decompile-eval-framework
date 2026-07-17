# 闭源模型多模型、多输入评估矩阵

本文说明如何在同一固定子集上统一运行多个闭源模型，并分别比较汇编输入和 Ghidra 伪代码
输入。推荐实验矩阵为：

```text
selection manifest
  × 数据集（ExeBench / HumanEval / MBPP）
  × 输入模式（assembly / pseudocode）
  × 闭源模型（Kimi / GLM / 后续模型）
```

每个“模型 × 输入模式”对应独立 `DecompilerBackend`，最终报告使用 `backend_id` 区分实验条件。

## 1. 当前矩阵

本地配置为 `configs/closed-llm-matrix-audit-1000.yaml`，当前启用：

| backend_id | 模型 | 输入 |
|---|---|---|
| `closed-llm-assembly` | Kimi-K2.6 | 汇编 |
| `kimi-k2.6-pseudocode` | Kimi-K2.6 | Ghidra 伪代码 |
| `glm-5.1-assembly` | AutoDL GLM-5.1 | 汇编 |
| `glm-5.1-pseudocode` | AutoDL GLM-5.1 | Ghidra 伪代码 |

`closed-llm-assembly` 保留历史 backend ID 和配置版本，用于复用已经生成的 Kimi 汇编结果。
实验完成并归档前不要随意重命名。

## 2. 双输入固定子集

矩阵使用 `data/selections/closed-audit-1000-dual-input-v1.json`：

| 数据集 | 数量 |
|---|---:|
| ExeBench | 400 |
| HumanEval | 200 |
| MBPP | 400 |
| 总计 | 1000 |

O0、O1、O2、O3 各250条。全部1000条同时具有汇编和伪代码视图。原清单中一条 MBPP
记录缺少伪代码，因此将该源函数的 O0–O3 四个版本整体替换为另一个视图完整的函数组。

正式比较汇编与伪代码时应使用两种输入的交集清单，否则 `pseudocode_missing` 会进入固定分母，
测到的是“模型能力 + 数据缺失”，而不是纯输入模式差异。

## 3. 数据集与输入模式

DatasetAdapter 同时声明两种视图：

```yaml
datasets:
  - id: exebench-1100
    type: exebench_flat
    selection_manifest: code/decompile-eval-framework/data/selections/closed-audit-1000-dual-input-v1.json
    assembly_view: objdump_att_instruction_only
    pseudocode_view: ghidra

  - id: decompile-eval-humaneval
    type: decompile_eval
    splits: [humaneval]
    selection_manifest: code/decompile-eval-framework/data/selections/closed-audit-1000-dual-input-v1.json
    assembly_view: asm
    pseudocode_view: ghidra_pseudo
```

Backend 的 `required_inputs` 决定模型实际看到哪个字段：

```yaml
required_inputs: [assembly]
```

或：

```yaml
required_inputs: [pseudocode]
```

参考源码、测试代码和 oracle 不会进入 `DecompileRequest`。

## 4. 同一模型的两个输入 backend

```yaml
x-kimi-plugin: &kimi_plugin
  provider: kimi
  base_url: https://api.moonshot.cn/v1
  model: kimi-k2.6
  api_key_env: KIMI_API_KEY
  api_mode: chat_completions
  thinking_mode: disabled
  max_output_tokens: 4096
  max_concurrency: 2

decompilers:
  - id: closed-llm-assembly
    type: python
    plugin: plugins.openai_compatible_backend:OpenAICompatibleBackend
    required_inputs: [assembly]
    plugin_config: *kimi_plugin

  - id: kimi-k2.6-pseudocode
    type: python
    plugin: plugins.openai_compatible_backend:OpenAICompatibleBackend
    required_inputs: [pseudocode]
    plugin_config: *kimi_plugin
```

两个 backend 应使用相同模型参数，唯一实验变量是输入视图。不要使用不同 system prompt、
temperature 或输出长度，否则不能解释为纯输入消融。

## 5. AutoDL GLM-5.1

```yaml
plugin_config: &glm_plugin
  provider: zhipu
  base_url: https://www.autodl.art/api/v1
  model: glm-5.1
  api_key_env: AUTODL_API_KEY
  api_mode: chat_completions
  thinking_mode: disabled
  thinking_protocol: thinking_type
  max_output_tokens: 4096
  max_concurrency: 2
```

`provider: zhipu` 用于选择 GLM 的 `thinking: {type: ...}` 协议，HTTP 地址仍然是 AutoDL。
如果代理拒绝 thinking 参数，改为 `thinking_mode: auto`。`auto` 表示不发送 thinking 参数，
不等于关闭思考。详见 [`THINKING_MODE.md`](THINKING_MODE.md)。

## 6. 添加新模型

每个新模型增加两个 backend，并使用独立 plugin anchor：

```yaml
  - id: model-c-assembly
    type: python
    plugin: plugins.openai_compatible_backend:OpenAICompatibleBackend
    version: provider-c:model-c
    required_inputs: [assembly]
    batch_size: 4
    plugin_config: &model_c_plugin
      provider: provider-c
      base_url: https://provider-c.example/v1
      model: model-c
      api_key_env: MODEL_C_API_KEY
      api_mode: chat_completions
      thinking_mode: auto
      max_output_tokens: 4096
      timeout: 120
      max_retries: 3
      max_concurrency: 2

  - id: model-c-pseudocode
    type: python
    plugin: plugins.openai_compatible_backend:OpenAICompatibleBackend
    version: provider-c:model-c
    required_inputs: [pseudocode]
    batch_size: 4
    plugin_config: *model_c_plugin
```

必须使用唯一 `backend_id`。同一模型的两个 backend 共享模型参数，只改变 `required_inputs`。

## 7. 导入历史结果

```bash
python -m decomp_eval import-run \
  --run-dir runs/kimi-decompile \
  --config configs/closed-llm-kimi-smoke.yaml

python -m decomp_eval import-run \
  --run-dir runs/kimi-audit-1000-generation \
  --config configs/kimi-audit-1000.yaml
```

`import-run` 支持 `results.jsonl` 和 `generations.jsonl`。凭据字段、`batch_size` 和
`max_concurrency` 不进入 generation key，因此可以迁移到环境变量或调整纯调度参数而不破坏
历史生成复用。

## 8. 一条命令生成整个矩阵

```bash
export KIMI_API_KEY="..."
export AUTODL_API_KEY="..."

python -m decomp_eval generate \
  --config configs/closed-llm-matrix-audit-1000.yaml \
  --run-dir runs/closed-llm-matrix-audit-1000-generation
```

当前任务规模为：

```text
1000条 × 2种输入 × 2个模型 = 4000个模型/样本组合
```

已有 Kimi 汇编结果会命中缓存。Kimi 伪代码和 GLM 两种输入需要新的 API 调用。

Runner 当前按 backend 顺序执行完整1000条，不同 backend 之间不并发；单个 backend 内部由
`max_concurrency` 控制并发。一条命令便于统一管理和断点续跑，但不会同时占满多个供应商。

断点恢复：

```bash
python -m decomp_eval generate \
  --config configs/closed-llm-matrix-audit-1000.yaml \
  --run-dir runs/closed-llm-matrix-audit-1000-generation \
  --resume
```

## 9. 统一评估

```bash
python -m decomp_eval evaluate \
  --config configs/closed-llm-matrix-audit-1000.yaml \
  --run-dir runs/closed-llm-matrix-audit-1000-evaluation
```

`evaluate` 不允许调用模型；任何 generation cache 缺失都会在开始阶段终止。生成完成后可以进行
新指标、重新编译或新测试协议实验，不产生新的闭源 API 调用。

一条 shell 命令连续执行两阶段：

```bash
python -m decomp_eval generate \
  --config configs/closed-llm-matrix-audit-1000.yaml \
  --run-dir runs/closed-matrix-generation \
&& python -m decomp_eval evaluate \
  --config configs/closed-llm-matrix-audit-1000.yaml \
  --run-dir runs/closed-matrix-evaluation
```

## 10. 报告解释

建议至少报告以下比较：

| 比较 | 研究问题 |
|---|---|
| Kimi 汇编 vs Kimi 伪代码 | 伪代码是否比汇编更适合作为输入 |
| GLM 汇编 vs GLM 伪代码 | 输入收益能否跨模型保持 |
| Kimi 汇编 vs GLM 汇编 | 不同闭源模型的汇编反编译能力 |
| Kimi 伪代码 vs GLM 伪代码 | 不同模型的伪代码修复能力 |

主要指标是 `recompilable` 和 `behavioral_pass`。除总体结果外，还应分别报告三个数据集和
O0–O3，避免总体平均掩盖数据集或优化等级差异。

## 11. 安全与运行建议

- YAML 只保存 `api_key_env`，不要保存明文密钥；
- 发送到对话、终端日志或 Git 的真实密钥应立即轮换；
- 正式1000条前用 smoke 配置验证每家 API 的模型名、Base URL 和 thinking 参数；
- 使用 `tmux` 运行长任务，并依靠 `--resume` 恢复；
- `pass` 表示生成成功，不表示缓存命中，应查看 `generation_cache_hit`；
- 不要删除源 run，它们是历史导入和实验审计证据。

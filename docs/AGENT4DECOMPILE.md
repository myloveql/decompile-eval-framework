# Agent4Decompile 后端

本框架通过 `plugins.agent4decompile_backend:Agent4DecompileBackend` 接入
Agent4Decompile。适配器支持已有伪代码修复、单传统反编译器和多传统反编译器共识；
最终可重新编译率与行为通过率仍由数据集绑定的 EvaluationProtocol 计算。

## 公平性边界

普通后端只开放 L1/L2：

- L1：将公开的 `compile_context.prelude` 与候选函数组合，执行语法检查；
- L2：使用数据集声明的编译器、参数和当前 O0/O1/O2/O3，将候选编译为对象文件；
- L3：不向后端传递正式测试、期望输出、参考源码或 ExeBench wrapper。

`constraint_level` 只能设置成 `1` 或 `2`。设置成 `3` 会直接失败，而不是静默降级。
Agent4Decompile 原项目支持将 ExeBench 正式测试反馈给 LLM，但这种结果属于
benchmark-oracle-assisted 实验，不能与静态反编译器放在同一公平主表中，所以当前通用
Backend 不提供该入口。

内部 L1/L2 只负责给 Agent 生成反馈。正式 `recompilable`、`behavioral_pass` 和新增指标
始终由框架在候选生成完成后独立计算。

## 提示词对齐保证

适配器没有复制、翻译或重新编写 Agent4Decompile 的提示词。运行时从 `agent4_root` 导入：

```python
src.refinement.refiner.MCGDRefiner
```

并直接使用：

- `MCGDRefiner.SYSTEM_PROMPT`；
- `MCGDRefiner._build_prompt()`；
- `MCGDRefiner._extract_code()`；
- `src.refinement.refiner.preprocess_decompiled_code()`；
- `MCGDRefiner.refine()` 的原始迭代控制流程。

OpenAI-compatible 模式发送的消息结构也与原始 `_call_llm()` 一致：

```python
[
    {"role": "system", "content": MCGDRefiner.SYSTEM_PROMPT},
    {"role": "user", "content": MCGDRefiner._build_prompt(...)},
]
```

因此 Agent4Decompile 原项目修改提示词后，下次运行会自动使用新提示词。后端会计算
`Agent4Decompile/src/**/*.py` 的 SHA-256，并把摘要写入后端版本和生成缓存键；外部算法源码
变化后不会误用旧提示词生成的缓存。

需要注意：L1/L2 编译反馈会反映数据集真实编译上下文，可能与原项目整程序 `gcc -o`
的报错文本不同。这是单函数评估必须做的语义适配；提示词模板、状态组织、当前代码位置
和任务指令仍来自原实现。

每个样本都会保存 `agent4_system_prompt.txt`、`iteration_NN_prompt.txt` 和
`iteration_NN_response.txt`，可以审计实际发送的完整内容。

## 安装与目录

建议在 Linux/WSL 中运行：

```bash
cd /mnt/f/LLM_Decompile/code/decompile-eval-framework
pip install -e '.[api]'
```

Agent4Decompile 作为外部算法目录加载，不复制进本仓库：

```text
code/
├── decompile-eval-framework/
└── Agent4Decompile/
```

伪代码模式只需要 Agent4Decompile 源码、GCC 和模型 API SDK。二进制模式还需要：

- `binary_single + ghidra`：Ghidra headless；
- `binary_single + angr`：安装 angr；
- `binary_single + retdec`：RetDec CLI；
- `binary_consensus`：建议同时准备 Ghidra、angr 和 RetDec。

Agent4Decompile 当前没有 Python 安装包元数据，所以通过 `agent4_root` 动态导入。如果同一
进程已经导入另一个顶层 `src` 包，适配器会失败并报告路径，不会误用其他代码。

## 推荐模式：伪代码 + L1/L2

复制示例为本地配置：

```bash
cp configs/agent4decompile-pseudocode-l2-smoke.yaml.example \
   configs/agent4decompile-pseudocode-l2-smoke.yaml
```

关键配置：

```yaml
datasets:
  - type: decompile_eval
    pseudocode_view: ghidra_pseudo
    languages: [c]

decompilers:
  - id: agent4decompile-ghidra-l2
    type: python
    plugin: plugins.agent4decompile_backend:Agent4DecompileBackend
    required_inputs: [pseudocode, compile_context]
    batch_size: 1
    plugin_config:
      agent4_root: ../Agent4Decompile
      mode: pseudocode_refine
      constraint_level: 2
      max_iterations: 5
      architecture: x86_64
      allowed_languages: [c]
      compile_optimization: same
```

`required_inputs` 必须包含 `pseudocode` 和不含测试的 `compile_context`。ExeBench 使用保存
Ghidra 结果的数据文件时通常设置 `pseudocode_view: ghidra`；decompile-eval 可以使用
`ghidra_pseudo` 或 `ida_pseudo`。第一版只支持 C，数据集应设置 `languages: [c]`。

## 模型配置

### OpenAI-compatible API

```yaml
llm:
  provider: openai_compatible
  base_url: https://api.example.com/v1
  api_key_env: AGENT4DECOMPILE_API_KEY
  model: model-name
  temperature: 0.2
  max_tokens: 8000
  timeout: 300
  max_retries: 5
  retry_backoff: 2
  thinking_mode: auto
```

```bash
export AGENT4DECOMPILE_API_KEY='...'
```

也支持在本地 `.yaml` 中直接设置 `api_key`，但不要提交到 Git。示例配置只能写
`api_key_env`。`temperature: 0.2` 和 `max_tokens: 8000` 是 Agent4Decompile 原始默认值，
为了复现实验不建议改变。

### 思考模式

`thinking_mode: auto` 不发送额外 thinking 字段。显式控制时可以设置：

```yaml
thinking_mode: disabled
thinking_protocol: enable_thinking
```

支持：

- `thinking_type`：发送 `thinking: {type: enabled|disabled}`；
- `enable_thinking`：发送布尔 `enable_thinking`；
- `custom`：仅使用 `extra_body`；
- `auto`：模型名包含 `kimi` 时选择 `thinking_type`，否则选择 `enable_thinking`。

思考参数改变推理行为，但不改变 Agent4Decompile 的 system/user 提示词文本。

### 原生 Provider

也可以让 Agent4Decompile 原始 `_call_llm()` 直接调用：

```yaml
llm:
  provider: deepseek   # 或 openai、anthropic
  model: deepseek-chat
```

此时密钥和 base URL 遵循 Agent4Decompile 原实现，例如 DeepSeek 使用
`DEEPSEEK_API_KEY`。原生模式不经过框架的 OpenAI-compatible 重试层。

## 二进制模式

单传统反编译器示例为 `configs/agent4decompile-binary-single-smoke.yaml.example`：

```yaml
required_inputs: [binary, compile_context]
plugin_config:
  mode: binary_single
  traditional_decompiler: ghidra
  ghidra_path: /path/to/ghidra_11.0.3_PUBLIC
```

`traditional_decompiler` 可选 `ghidra`、`angr`、`retdec`。

多反编译器示例为 `configs/agent4decompile-binary-consensus-smoke.yaml.example`：

```yaml
required_inputs: [binary, compile_context]
plugin_config:
  mode: binary_consensus
  ghidra_path: /path/to/ghidra_11.0.3_PUBLIC
  retdec_path: /path/to/retdec
```

二进制模式优先用于 ExeBench。decompile-eval 当前不提供二进制输入，应使用伪代码模式。

## 运行

```bash
python -m decomp_eval validate-config \
  --config configs/agent4decompile-pseudocode-l2-smoke.yaml

python -m decomp_eval validate-dataset \
  --config configs/agent4decompile-pseudocode-l2-smoke.yaml

python -m decomp_eval run \
  --config configs/agent4decompile-pseudocode-l2-smoke.yaml \
  --run-dir runs/agent4decompile-smoke
```

生成结果进入框架分层缓存。以后更换指标或重新评估可以复用候选 C，不需要再次调用模型。
`runs/` 不需要删除，也不应作为清理缓存的方式。

## 样本产物

```text
agent4_initial.c                 初始伪代码或传统反编译结果
agent4_preprocessed.c            原始 preprocess_decompiled_code 输出
agent4_system_prompt.txt         原始 SYSTEM_PROMPT
iteration_NN_prompt.txt          原始 _build_prompt 输出
iteration_NN_response.txt        模型原始响应
iteration_NN_candidate.c         原始 _extract_code 输出
constraint_NN_syntax.c           加入公开 prelude 的语法检查单元
constraint_NN_compilation.c      加入公开 prelude 的对象编译单元
constraint_NN.json               命令、返回码和编译日志
agent4_final_candidate.c         交给正式评估协议的候选代码
agent4_metadata.json             模式、迭代历史和审计字段
```

审计字段固定包含：

```json
{
  "prompt_policy": "runtime_import_from_agent4decompile",
  "oracle_assisted": false,
  "request_has_private_tests": false
}
```

## 当前限制

- 只支持 C；
- 不支持正式测试反馈 L3；
- 没有批量推理，建议 `batch_size: 1`；
- 二进制模式沿用 Agent4Decompile 的整文件输出，复杂二进制可能包含多个函数；
- 后端会自动将外部 `src/**/*.py` 的内容哈希写入版本；仍建议在实验记录中注明上游版本来源。

建议用不同 backend id 区分输入和算法能力：

```text
agent4decompile-ghidra-pseudo-l2
agent4decompile-ida-pseudo-l2
agent4decompile-binary-ghidra-l2
agent4decompile-binary-consensus-l2
```

# Agent4Decompile 后端

本框架通过 `plugins.agent4decompile_backend:Agent4DecompileBackend` 接入
Agent4Decompile。适配器支持已有伪代码修复、单传统反编译器和多传统反编译器共识；
最终可重新编译率与行为通过率仍由数据集绑定的 EvaluationProtocol 计算。

## L1/L2 公平模式与 L3 oracle-assisted 模式

默认的公平后端使用 L1/L2：

- L1：将公开的 `compile_context.prelude` 与候选函数组合，执行语法检查；
- L2：使用数据集声明的编译器、参数和当前 O0/O1/O2/O3，将候选编译为对象文件；
- L3：使用 ExeBench JSON-I/O 或 Decompile-Eval 聚合测试程序执行候选，并将失败状态反馈给下一轮 LLM。

`constraint_level` 支持 `1`、`2`、`3`。L3 必须同时显式配置
`allow_oracle_assisted: true`，并在 `required_inputs` 中加入 `oracle_context`；缺少任一项都会
直接失败，不会静默降级。`oracle_context` 只有被后端显式请求时才会从 CanonicalSample
复制到 DecompileRequest，普通 L1/L2 后端仍然看不到正式测试。

L3 是 benchmark-oracle-assisted 实验，不能与只使用静态输入的反编译器放在同一公平主表。
无论是否启用 L3，正式 `recompilable`、`behavioral_pass` 和新增指标仍由框架在候选生成完成后
独立计算；L3 内部执行结果只用于 Agent 迭代反馈。

当前 L3 支持 `exebench_json_io` 和 `decompile_eval_exitcode`。前者复用 Agent4Decompile
原生执行器并反馈 expected/actual；后者由适配层运行聚合测试程序，只反馈状态和退出码。

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

## 伪代码 + L1/L2/L3（oracle-assisted）

### ExeBench JSON-I/O L3

```bash
cp configs/agent4decompile-pseudocode-l3-smoke.yaml.example \
   configs/agent4decompile-pseudocode-l3-smoke.yaml
```

关键配置：

```yaml
datasets:
  - type: exebench_flat
    pseudocode_view: ghidra
    include_path: third_party/exebench/exebench
    evaluation_protocol:
      type: exebench_json_io

decompilers:
  - id: agent4decompile-ghidra-pseudo-l3-oracle-assisted
    required_inputs: [pseudocode, compile_context, oracle_context]
    plugin_config:
      mode: pseudocode_refine
      constraint_level: 3
      allow_oracle_assisted: true
```

ExeBench adapter 提供的 `oracle_context` 仅包含 L3 所需内容：`io_pairs`、
`executable_wrapper`、依赖声明、目标函数签名和 ExeBench include 路径，不包含参考函数源码。
Agent4Decompile 原生 `evaluate_execution_exebench()` 负责构建 wrapper、执行正式 I/O，并把失败
用例的期望值和实际值写入原生 L3 feedback。该 feedback 会出现在
`iteration_NN_prompt.txt` 中。

L1/L2 仍使用框架的 `compile_context`；L3 则保持 Agent4Decompile 原生语义，将当前候选代码
交给其 `gcc -S` 和 ExeBench wrapper 流程。因而只依赖框架自动附加 prelude、但自身不完整的
候选可能通过 L2、随后在 L3 收到原生编译或链接错误反馈。

开启 L3 后，`request.json` 和 `agent4_metadata.json` 属于含 benchmark oracle 的敏感审计产物；
其中前者会保存传入后端的 wrapper、输入和期望输出。发布运行产物前应按实验披露策略处理。

### Decompile-Eval exit-code L3

复制 Decompile-Eval 示例：

```bash
cp configs/agent4decompile-pseudocode-l3-decompile-eval-smoke.yaml.example \
   configs/agent4decompile-pseudocode-l3-decompile-eval-smoke.yaml
```

关键配置与 ExeBench 相同，但数据集协议为：

```yaml
datasets:
  - type: decompile_eval
    pseudocode_view: ghidra_pseudo
    evaluation_protocol:
      type: decompile_eval_exitcode

decompilers:
  - required_inputs: [pseudocode, compile_context, oracle_context]
    plugin_config:
      constraint_level: 3
      allow_oracle_assisted: true
```

Decompile-Eval adapter 将测试程序放入 `oracle_context`，L3 按正式协议拼接并执行：

```text
func_dep + candidate + test → compile → link → run
```

反馈策略固定为 `exitcode_only`：LLM 只会看到组合编译失败、链接失败、超时、通过或具体退出码；
不会在 L3 message 中看到测试源码、断言内容、编译器详细诊断、stdout 或 stderr。完整测试源码和
命令日志仍保存在本地 `request.json`、`constraint_NN_l3_test.c/.cpp` 与
`constraint_NN.json`，因此这些运行产物仍然属于含 oracle 的敏感产物。

Decompile-Eval 是单个聚合测试程序，不能像 ExeBench 一样提供逐用例 expected/actual；这里的
L3 反馈粒度因此更低，但迭代停止条件仍是组合程序成功编译、链接并以退出码 0 结束。

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

L3 的通过状态和执行详情也写入 `constraint_NN.json`。审计字段固定包含：

```json
{
  "prompt_policy": "runtime_import_from_agent4decompile",
  "oracle_assisted": true,
  "request_has_private_tests": true,
  "oracle_protocol": "decompile_eval_exitcode"
}
```

L1/L2 运行的这两个布尔值均为 `false`。

## 当前限制

- 只支持 C；
- Decompile-Eval L3 仅提供聚合测试程序状态/退出码，不提供逐用例 expected/actual；
- 没有批量推理，建议 `batch_size: 1`；
- 二进制模式沿用 Agent4Decompile 的整文件输出，复杂二进制可能包含多个函数；
- 后端会自动将外部 `src/**/*.py` 的内容哈希写入版本；仍建议在实验记录中注明上游版本来源。

建议用不同 backend id 区分输入和算法能力：

```text
agent4decompile-ghidra-pseudo-l2
agent4decompile-ida-pseudo-l2
agent4decompile-binary-ghidra-l2
agent4decompile-binary-consensus-l2
agent4decompile-ghidra-pseudo-l3-oracle-assisted
agent4decompile-ghidra-pseudo-l3-decompile-eval-oracle-assisted
```

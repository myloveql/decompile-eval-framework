# 闭源 LLM 后端接入指南

框架通过 `plugins/openai_compatible_backend.py` 提供闭源模型插件，使用 OpenAI Python SDK
调用 OpenAI API 或实现了 OpenAI-compatible API 的其他闭源模型服务。插件只会收到
`required_inputs` 声明的公开字段，
不会收到参考源代码、测试代码、预期输出或其他评估答案。

## 1. 安装依赖

在 Linux/WSL 的框架目录中执行：

```bash
pip install -e '.[api,test]'
```

## 2. 配置 API 密钥

推荐把密钥放在环境变量中，不要提交到 YAML：

```bash
export OPENAI_API_KEY='your-api-key'
```

YAML 中只记录环境变量名：

```yaml
api_key_env: OPENAI_API_KEY
```

后端也支持以下写法，但不建议在版本库中保存明文密钥：

```yaml
api_key: env:MY_LLM_API_KEY
# 或 api_key: ${MY_LLM_API_KEY}
# 或 api_key: sk-...   # 能运行，manifest 会脱敏，但仍会留在 YAML 中
```

框架不会自动读取 `.env`。如果使用 `.env`，请先由 shell 或你自己的启动脚本导出变量。

## 3. OpenAI 官方 API 配置

```yaml
decompilers:
  - id: my-closed-model
    type: python
    plugin: plugins.openai_compatible_backend:OpenAICompatibleBackend
    version: openai:your-model-name
    required_inputs: [assembly]
    batch_size: 4
    plugin_config:
      provider: openai
      model: your-model-name
      api_key_env: OPENAI_API_KEY
      api_mode: responses
      temperature: 0
      max_output_tokens: 4096
      timeout: 120
      max_retries: 3
      empty_output_retries: 2
      empty_output_backoff_seconds: 1
      empty_output_backoff_max_seconds: 8
      max_concurrency: 2
```

`responses` 使用 SDK 的 Responses API。若具体模型或兼容服务只支持 Chat Completions，改为：

```yaml
plugin_config:
  api_mode: chat_completions
```

## 4. 其他 OpenAI-compatible 提供商

提供商名称用于标记实验来源；实际服务地址由 `base_url` 指定：

```yaml
decompilers:
  - id: vendor-model
    type: python
    plugin: plugins.openai_compatible_backend:OpenAICompatibleBackend
    version: vendor-name:vendor-model-name
    required_inputs: [assembly]
    plugin_config:
      provider: vendor-name
      base_url: https://api.vendor.example/v1
      model: vendor-model-name
      api_key_env: VENDOR_API_KEY
      api_mode: chat_completions
```

非 `openai` 提供商必须配置 `base_url`。框架不内置任何第三方地址，避免把供应商名称和
可能变化的端点错误绑定。若服务需要额外的兼容参数，可使用：

```yaml
plugin_config:
  extra_body:
    top_k: 20
```

## 5. 选择模型输入

`required_inputs` 决定模型实际能看到什么：

```yaml
required_inputs: [assembly]              # 直接从汇编反编译
required_inputs: [pseudocode]            # 优化数据集中的 Ghidra 伪代码
required_inputs: [assembly, pseudocode]  # 同时提供两种视图
```

使用 `pseudocode` 时，数据集还必须选择伪代码视图。例如 ExeBench：

```yaml
datasets:
  - id: exebench-1100
    type: exebench_flat
    path: data/exebench/1641-Benchmark/exebench_1641_source_multiopt_1100.with-ghidra.dataset.json
    assembly_view: objdump_att_instruction_only
    pseudocode_view: ghidra
    evaluation_protocol:
      type: exebench_json_io
```

如果所选样本没有要求的视图，该样本会记录为 `assembly_missing` 或
`pseudocode_missing`，并进入固定评估分母。

## 6. 自定义提示词

默认 system prompt 要求模型输出完整、可编译且保留目标函数签名的 C/C++。可以覆盖：

```yaml
plugin_config:
  system_prompt: |
    You are a binary decompiler. Return only complete compilable C source code.

  user_prompt_template: |
    Recover function {function_name} as {language}.
    Optimization: {optimization}
    Assembly syntax: {assembly_syntax}
    Assembly:
    {assembly}
```

支持的占位符：

- `{dataset_id}`、`{split}`、`{sample_id}`、`{source_group_id}`
- `{function_name}`、`{language}`、`{optimization}`
- `{assembly}`、`{assembly_syntax}`、`{assembly_view}`
- `{pseudocode}`、`{pseudocode_view}`、`{pseudocode_producer}`

自定义模板只能引用公开请求字段。模板中引用未知占位符会产生明确错误，不会静默替换。

## 7. 响应提取规则

后端会保存模型原始响应，然后按以下顺序提取实际参与编译的候选代码：

1. 选择最长的 `c`、`cpp`、`c++`、`cc` 或 `cxx` Markdown 代码围栏；
2. 没有 C/C++ 围栏时，选择最长的任意代码围栏；
3. 没有围栏时，使用完整响应文本。

因此模型可以偶尔输出解释文字，但 `candidate.c` 只包含提取出的代码。产物包括：

```text
raw_output.txt         模型完整原始文本
candidate.c            实际编译和测试的候选代码
model_prompt.txt       实际发送的 user prompt（不含 API 密钥）
response_metadata.json 提供商、模型、请求 ID、token 用量、结束原因和提取方式
postprocess.json        后续显式代码处理记录
```

API 密钥不会写入这些文件。`manifest.json` 中名为 `api_key`、`token`、`password` 或
`secret` 的配置字段也会被替换为 `<redacted>`。

## 8. 并发、重试和成本控制

`batch_size` 决定 Runner 一次交给后端多少个样本；`max_concurrency` 决定这一批中最多同时
发出多少个 API 请求。网络重试与空响应重试是两层独立机制：

```yaml
batch_size: 8
plugin_config:
  max_concurrency: 2
  max_retries: 3                  # SDK：连接错误、429、部分 5xx
  empty_output_retries: 2         # HTTP 成功但响应文本为空
  empty_output_backoff_seconds: 1 # 指数退避：1、2、4……秒
  empty_output_backoff_max_seconds: 8
```

建议第一次使用 `limit: 1`、`batch_size: 1`、`max_concurrency: 1`。确认提示词、输入视图和
候选代码正确后，再逐渐扩大。每次空响应尝试的请求 ID、状态、token 用量、结果和退避时间
都会写入 `response_metadata.json`。重试预算耗尽后才记录 `closed_llm_empty_output`，且仍然
进入评估分母。

## 9. 运行步骤

复制示例并修改模型名：

```bash
cp configs/closed-llm-pseudocode-example.yaml configs/my-closed-llm.yaml
```

然后执行：

```bash
python -m decomp_eval validate-config --config configs/my-closed-llm.yaml

python -m decomp_eval validate-dataset \
  --config configs/my-closed-llm.yaml \
  --run-dir runs/my-closed-llm-preflight

python -m decomp_eval run \
  --config configs/my-closed-llm.yaml \
  --run-dir runs/my-closed-llm
```

中断后使用完全相同的配置恢复：

```bash
python -m decomp_eval run \
  --config configs/my-closed-llm.yaml \
  --run-dir runs/my-closed-llm \
  --resume
```

## 10. 常见问题

- `API key environment variable ... is not set`：当前 shell 没有导出 YAML 指定的变量。
- `base_url is required`：使用了非 `openai` provider，但没有配置兼容 API 地址。
- `closed_llm_auth_error`：密钥无效、无权限或模型不可访问。
- `closed_llm_rate_limit`：降低 `max_concurrency`，并检查供应商配额。
- `closed_llm_timeout`：提高 `timeout`，或减少输入与 `max_output_tokens`。
- `closed_llm_empty_output`：API 成功返回但没有可用文本。
- 编译失败：依次检查 `raw_output.txt`、`candidate.c`、`postprocess.json` 和评估编译日志。

对同一模型做正式比较时，应固定 provider、model、API 模式、提示词、输入视图、生成参数和
框架版本；这些配置都会参与缓存键计算。

# DeGPT 后端使用指南

框架通过 `plugins/degpt_backend.py` 接入 DeGPT（NDSS 2024，*Optimizing Decompiler Output with LLM*）。DeGPT 是**反编译伪代码优化器**：它接收 Ghidra/IDA 风格 C 伪代码，依次由 referee 判断优化方向、由 advisor 执行结构简化/注释补充/变量重命名，并输出优化后的 C 文本。

> DeGPT 的目标是改善伪代码的可读性，而不是恢复完整编译环境。因此本框架仍用 recompilable 和 behavioral_pass 做统一执行级评测，但不应把较低的编译率直接等同于其可读性优化能力低。

## 1. 隔离与兼容性

集成遵循不影响现有框架的原则：

- 新增独立插件、配置和文档；不修改现有 backend、数据集或评估协议。
- 重依赖只在 DeGPT backend 初始化时导入；未安装依赖不会影响其他 backend。
- upstream DeGPT 被最小化包化：`degpt` 现在可作为正规 Python package 导入，移除了其 `sys.path` 注入。
- DeGPT 原先每个 LLM 调用都注册 atexit handler、向当前目录写 `chat_log.json`；backend 会设置 `DEGPT_DISABLE_ATEXIT_LOG=1` 禁用该副作用。
- DeGPT 的 LLM 配置通过环境变量注入，不会重写 `code/DeGPT/degpt/config.ini`。

## 2. 安装

DeGPT 的 `cinspector` 依赖其自带的 Linux `tree-sitter.so`，需要固定 tree-sitter ABI：

```bash
pip install -e '.[degpt]'
```

该 extra 等效于安装：

- `openai>=1.28`
- `tiktoken>=0.2`
- `python-levenshtein>=0.21`
- `cinspector==0.0.1`
- `tree-sitter==0.21.0`

先在 Linux/WSL 进行依赖自检：

```bash
python -c "from cinspector.interfaces import CCode; print(len(CCode('int f(){return 0;}').get_by_type_name('function_definition')))"
```

预期输出 `1`。不要使用 `tree-sitter>=0.22`：其 `Language` API 与 cinspector 0.0.1 不兼容。

## 3. 配置

复制本地 smoke 配置：

```bash
cp configs/degpt-pseudocode-smoke.yaml.example \
   configs/degpt-pseudocode-smoke.yaml
```

设置 API Key：

```bash
export DEGPT_API_KEY='your-key'
```

关键配置：

```yaml
decompilers:
  - id: degpt-ghidra-pseudocode
    type: python
    plugin: plugins.degpt_backend:DeGPTBackend
    required_inputs: [pseudocode]
    plugin_config:
      degpt_root: ../DeGPT
      model: gpt-4o
      base_url: https://api.openai.com/v1/
      api_key_env: DEGPT_API_KEY
      temperature: 0.2
```

| 字段 | 含义 |
|---|---|
| `degpt_root` | 上游 DeGPT repository 根目录，必须包含 `degpt/role.py`。 |
| `model` | OpenAI-compatible chat model 名称。 |
| `base_url` | OpenAI-compatible endpoint。 |
| `api_key_env` | API key 环境变量名称，默认为 `DEGPT_API_KEY`。 |
| `temperature` | 覆盖 upstream 默认值 0.2。 |

不要把真实 API key 写进 yaml 或 `config.ini`。

## 4. 运行

先验证配置：

```bash
python -m decomp_eval validate-config \
  --config configs/degpt-pseudocode-smoke.yaml
```

再运行：

```bash
python -m decomp_eval run \
  --config configs/degpt-pseudocode-smoke.yaml
```

配置要求 `pseudocode_view: ghidra_pseudo`，因此仅能用于提供该视图的数据集。

## 5. 调用流程与 artifact

对每个函数，DeGPT 执行：

1. **Referee**：一次 LLM 调用，决定是否执行简化、注释和变量命名优化；
2. **Advisor**：对每种被选中的优化分别调用一次 LLM；
3. **Operator**：采用 advisor 输出。上游 SemanticComparison 校验逻辑已注释，因此不会作为语义 oracle；
4. **统一评估**：生成结果仍交由数据集绑定的编译/行为协议评估。

一次样本通常消耗 **1–4 次** LLM 调用，没有自反思迭代。

每个 artifact 目录包含：

| 文件 | 内容 |
|---|---|
| `degpt_input.c` | 输入伪代码 |
| `degpt_result.json` | upstream 完整 workflow、方向及每轮 response |
| `degpt_final.c` | DeGPT 的候选输出 |
| `degpt_metadata.json` | 模型、温度、方向、失败信息和 backend version |

失败 reason：

- `degpt_missing_pseudocode`：数据集未提供非空伪代码；
- `degpt_pipeline_failed`：依赖、LLM 或 upstream pipeline 异常；
- `degpt_empty_output`：DeGPT 未返回候选代码。

## 6. 上游兼容性改动

为将 upstream 作为库调用，`code/DeGPT/degpt/` 有以下最小改动：

- 新增 `__init__.py`；
- `role.py` 的 `util`/`chat` 裸 import 改为相对 import；
- 删除仅为裸 import 服务的 `sys.path.append`；
- Windows 上 `run_timer` 降级为直接调用（SIGALRM 不可用）；
- `chat.py` 支持 `DEGPT_MODEL`、`DEGPT_API_KEY`、`DEGPT_API_BASE`、`DEGPT_TEMPERATURE` 环境变量覆盖；
- atexit 日志由 `DEGPT_DISABLE_ATEXIT_LOG=1` 禁用；
- 修复 upstream `get_optimized_from_dic` 在 referee 未选择全部三类优化时的 KeyError。

`mssc.py` 保持 upstream 原样。它只被注释掉的语义校验路径引用，当前 backend 不加载该模块，因此不会把其旧版 `cinspector.analysis` 兼容问题带入默认 DeGPT 流程。

这些改动均隔离在 DeGPT 独立仓库中；框架的公共模型、现有 backend、协议和现有配置均未修改。

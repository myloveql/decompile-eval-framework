# Decompile Eval Framework

一个面向传统反编译器和 LLM 反编译器的可扩展评估框架。框架从数据集读取汇编，将公开字段交给反编译后端，再把生成的 C/C++ 放回数据集原有测试夹具中编译、链接和执行。

当前内置支持：

- 数据集：ExeBench flat JSON、Decompile-Bench-Eval（HumanEval、MBPP）；
- 反编译器：Python 插件、外部命令、预生成 C/C++、Ghidra Headless；
- 指标：可重新编译率 `recompilable`、全部测试通过率 `behavioral_pass`；
- 后处理：Markdown 代码围栏提取、显式函数名修复；
- 多数据集 × 多后端评估矩阵、参考源码预检、缓存和断点续跑；
- 按数据集、后端、split、语言和 O0/O1/O2/O3 汇总结果。

> 仓库只包含评估框架，不包含大型数据集、模型权重和运行结果。请将它们放在本地目录中，并在 YAML 配置里填写路径。

## 工作流程

```text
DatasetAdapter
  -> CanonicalSample
  -> DecompileRequest（不含参考源码与测试答案）
  -> DecompilerBackend
  -> Postprocessor
  -> EvaluationProtocol（由数据集绑定）
  -> EvaluationEvidence
  -> Metric / Report
```

参考源码、测试代码和 oracle 保存在 `CanonicalSample.private_payload` 中，不会传给反编译器。模型只能看到汇编、函数名、语言、优化等级和数据集声明的公开元信息。

## 环境要求

- Python 3.10 或更高版本；
- Linux 或 WSL；
- GCC 和 G++（候选代码会被真实编译、链接和执行）；
- Decompile-Bench-Eval 的默认 C++ 配置链接 OpenSSL crypto，需要提供 `libcrypto` 开发库；
- 使用 `decompile-eval` Arrow 数据时需要 Hugging Face `datasets`，已包含在基础依赖中；
- 使用内置 LLM4Decompile 后端时需要 PyTorch、Transformers 和可选 CUDA 环境。

## 安装

```bash
git clone https://github.com/myloveql/decompile-eval-framework.git
cd decompile-eval-framework

python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e '.[test]'
```

Ubuntu/WSL 可安装系统依赖：

```bash
sudo apt-get install build-essential libssl-dev
```

LLM4Decompile 用户安装额外依赖：

```bash
pip install -e '.[llm4decompile,test]'
```

使用 vLLM 推理引擎：

```bash
pip install -e '.[vllm,test]'
```

检查安装：

```bash
decomp-eval list-plugins
decomp-eval validate-config --config configs/example.yaml
pytest -q
```

## 准备数据

推荐的本地布局如下，目录均已加入 `.gitignore`：

```text
decompile-eval-framework/
├── datasets/
│   ├── exebench-1641/
│   │   └── exebench_1641_source_multiopt_1100.dataset.json
│   └── decompile-eval/
│       ├── humaneval/
│       └── mbpp/
├── models/
│   └── llm4decompile-1.3b-v1.6/
└── runs/
```

### ExeBench 1100

适配器读取单个 flat JSON。每条记录需要包含源代码、评估夹具、优化等级和所选汇编视图。本项目构建的数据集同时提供：

- `objdump_att_instruction_only`：干净 AT&T 指令视图，推荐给 LLM4Decompile；
- `objdump_intel_instruction_only`：干净 Intel 指令视图；
- `objdump_intel_with_relocations`：带机器码和重定位信息的审计视图；
- GCC 目标函数及 translation-unit 汇编。

两个 instruction-only 视图均来自真实对象文件的 objdump，去除了地址、机器码和文件头，并把 PC32/PLT32 重定位合并成符号操作数。

ExeBench 的 wrapper 还需要其 C++ 头文件。通过数据集配置的 `include_path` 指向对应 include 根目录。

### Decompile-Bench-Eval

将 Hugging Face `save_to_disk`/Arrow 数据放到配置路径下。第一版启用 `humaneval` 和 `mbpp`，有意排除没有测试夹具的 `github` split。

可选择：

- `asm`：GNU objdump AT&T；
- `ida_asm`：IDA Intel；
- `ghidra_asm`：Ghidra Intel 风格。

## 最小配置

复制 `configs/example.yaml`，只启用你实际拥有的数据集和后端：

```yaml
workspace_root: ..

datasets:
  - id: exebench-1100
    type: exebench_flat
    path: datasets/exebench-1641/exebench_1641_source_multiopt_1100.dataset.json
    include_path: datasets/exebench-include
    assembly_view: objdump_att_instruction_only
    evaluation_protocol:
      type: exebench_json_io
    optimizations: [O0, O1, O2, O3]
    timeout: 30

decompilers:
  - id: existing-results
    type: precomputed
    version: "1"
    path: precomputed/my-decompiler
    pattern: "{sample_id}.c"

postprocessors: [markdown_fence]
metrics: [recompilable, behavioral_pass]

executor:
  type: local
  require_linux: true
  memory_mb: 2048
  max_file_mb: 64

preflight:
  mode: strict

output:
  root: runs
  cache: .cache/decomp-eval
```

`workspace_root` 相对于配置文件所在目录解析。上例配置位于 `configs/`，因此 `..` 表示仓库根目录。

## 运行评估

先验证配置，再验证参考源码：

```bash
decomp-eval validate-config --config configs/my-eval.yaml
decomp-eval validate-dataset --config configs/my-eval.yaml \
  --run-dir runs/reference-preflight
```

正式运行：

```bash
decomp-eval run --config configs/my-eval.yaml --run-dir runs/my-run
```

断点续跑：

```bash
decomp-eval run --config configs/my-eval.yaml \
  --run-dir runs/my-run --resume
```

重新生成汇总报告：

```bash
decomp-eval report --run-dir runs/my-run
```

正式实验建议保持：

```yaml
preflight:
  mode: strict
```

这样任何参考源码编译、链接或测试失败都会在模型评估前终止，防止无效测试夹具被计入反编译器失败。

## 输出文件

每次运行生成：

```text
runs/my-run/
├── manifest.json       # 配置、环境、版本和内容哈希
├── results.jsonl       # 每个样本的完整状态
├── summary.json        # 机器可读汇总
├── summary.csv         # 表格汇总
└── artifacts/
    └── .../
        ├── request.json
        ├── assembly.s
        ├── raw_output.txt
        ├── candidate.c
        └── compile/test logs
```

指标定义：

- `recompilable`：候选代码成功编译为对象文件并成功链接测试夹具；
- `behavioral_pass`：该样本全部测试用例通过；
- 反编译失败、空输出、编译失败、链接失败、崩溃、超时和输出不匹配都进入固定分母；
- 单个样本只有所有测试全部通过，才计为行为成功。

每条结果同时记录 `protocol_id`、`protocol_version`、能力集合和协议描述。报告默认按协议隔离；不同测试粒度或比较器的结果不会被合并。指标只有在协议声明所需能力时才进入分母，但模型反编译失败和后续阶段失败仍计入固定分母。

## 接入 Ghidra

内置 `ghidra` 后端可将数据集原始二进制统一转换为固定伪代码视图；`pseudocode` 后端可直接评估该视图，Python/LLM 后端也可声明只读取伪代码并进行修复。配置、数据写回、模型修复方式和失败原因见 [Ghidra 接入指南](docs/GHIDRA.md)。

## 接入 LLM4Decompile

内置插件位于 `plugins/llm4decompile_backend.py`，默认使用官方提示形式：

```text
# This is the assembly code:
{assembly}
# What is the source code?
```

配置示例：

```yaml
decompilers:
  - id: llm4decompile-1.3b-v1.6
    type: python
    version: "llm4decompile-1.3b-v1.6"
    plugin: plugins.llm4decompile_backend:LLM4DecompileBackend
    batch_size: 1
    plugin_config:
      model_path: models/llm4decompile-1.3b-v1.6
      device: cuda
      max_input_tokens: 14000
      max_new_tokens: 2048
      do_sample: false
```

ExeBench 建议使用 `objdump_att_instruction_only`，因为它更接近 LLM4Decompile 的训练和官方评估输入分布。
插件支持 `engine: transformers` 和 `engine: vllm` 两种推理路径；vLLM 的批处理、张量并行、
显存与 token 配置见 [LLM4Decompile vLLM 指南](docs/LLM4DECOMPILE_VLLM.md)。

也可以独立测试一个请求：

```bash
python plugins/llm4decompile_backend.py \
  --model-path models/llm4decompile-1.3b-v1.6 \
  --dataset datasets/exebench-1641/exebench_1641_source_multiopt_1100.dataset.json \
  --assembly-view objdump_att_instruction_only \
  --optimization O0 \
  --sample-index 0
```

## 扩展框架

新增能力不需要修改 Runner：

- Python 反编译器：实现 `decompile(request, artifact_dir)`，通过 `module:object` 加载；
- 外部工具：使用 command 后端和 `{assembly_file}`、`{output_file}` 等占位符；
- 离线结果：使用 precomputed 后端；
- 新数据集：实现 `DatasetAdapter`；
- 新评估方式：实现 `EvaluationProtocol`，并由数据集配置显式绑定；
- 新指标：实现 `Metric`；
- 新后处理：实现 `Postprocessor`。

完整接口、`DecompileRequest` 字段、批量推理、传统反编译器、LLM、数据集和指标教程见 [扩展指南](docs/EXTENDING.md)。ExeBench 汇编重建和验证见 [ExeBench 工具说明](docs/EXEBENCH_TOOLS.md)。

## 仓库结构

```text
src/decomp_eval/          核心框架
plugins/                  可选 Python/LLM 后端
configs/                  示例配置
examples/                 外部命令示例
tools/exebench/           ExeBench 构建与验证工具
tests/                    单元及端到端 fixture 测试
docs/EXTENDING.md         详细扩展教程
```

## 安全说明

候选 C/C++ 属于不可信代码。当前本地执行器提供超时和资源限制，但不是强隔离沙箱。不要在包含密钥或重要数据的宿主环境中运行不可信模型输出；高风险评估应使用一次性虚拟机或后续 Docker 执行器。

## 闭源 LLM API

`plugins/openai_compatible_backend.py` 可通过 OpenAI Python SDK 调用 OpenAI 或任意
OpenAI-compatible 模型服务，并分别保存模型原始响应与提取后的候选 C/C++。
配置、安全、提示词、伪代码优化和运行方法见 [闭源 LLM 后端接入指南](docs/CLOSED_LLM.md)。

## License

[MIT](LICENSE)

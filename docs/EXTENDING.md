# 反编译评估框架扩展指南

本文介绍如何为 `decomp-eval` 接入新的传统反编译器、LLM 反编译器、预生成结果、数据集、评估指标和代码后处理器。

框架的基本流程如下：

```text
DatasetAdapter
  -> CanonicalSample
  -> DecompilerBackend
  -> Postprocessor
  -> EvaluationProtocol
  -> EvaluationEvidence
  -> Metric
  -> Report
```

ExeBench 可使用 `objdump_att_instruction_only` 或 `objdump_intel_instruction_only`。其中
LLM4Decompile 推荐使用 AT&T 视图。两者都来自真实对象文件的 objdump 输出；Intel 视图来自
`objdump_intel_with_relocations`，只保留函数/控制流标签、指令助记符、操作数和合并后的
全局/外部符号。原始地址、机器码字节、文件头与独立重定位记录被删除，但原始视图仍保留在
数据集中，可用于审计或重新生成清洗视图。

核心接口位于：

- `src/decomp_eval/interfaces.py`
- `src/decomp_eval/models.py`
- `src/decomp_eval/protocols/`
- `configs/example.yaml`

## 1. 准备运行环境

正式评估需要 Linux 或 WSL，因为候选 C/C++ 代码会被真实编译、链接并执行。

```bash
cd decompile-eval-framework

python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[test]'
```

验证安装：

```bash
python -m decomp_eval list-plugins
python -m decomp_eval validate-config --config configs/example.yaml
```

内置插件包括：

```text
datasets:
  exebench_flat
  decompile_eval

backends:
  command
  precomputed
  python

metrics:
  recompilable
  behavioral_pass

postprocessors:
  markdown_fence
  rename_target
```

## 2. 接入命令行反编译器

如果反编译器可以通过命令调用，优先使用 `command` 后端。

### 2.1 输入输出约定

框架会为每个样本创建：

```text
assembly.s        输入汇编
request.json      公开的样本信息
backend_output.c  默认候选代码输出文件
```

命令行工具需要完成以下操作：

1. 读取 `assembly.s`。
2. 生成目标函数的 C/C++ 代码。
3. 将代码写入 `backend_output.c`，或打印到标准输出。
4. 成功时返回退出码 `0`。

配置示例：

```yaml
decompilers:
  - id: my-traditional-decompiler
    type: command
    version: "1.0"

    command:
      - /opt/my-decompiler/bin/decompile
      - --assembly
      - "{assembly_file}"
      - --function
      - "{function_name}"
      - --language
      - "{language}"
      - --output
      - "{output_file}"

    output_mode: file
    timeout: 300
```

如果工具直接将 C 代码打印到标准输出：

```yaml
output_mode: stdout
```

### 2.2 命令占位符

| 占位符 | 含义 |
|---|---|
| `{assembly_file}` | 汇编文件绝对路径 |
| `{output_file}` | 候选代码输出路径 |
| `{request_file}` | 公开请求 JSON 路径 |
| `{sample_id}` | 样本 ID |
| `{function_name}` | 目标函数名 |
| `{optimization}` | O0/O1/O2/O3 |
| `{language}` | c/cpp |
| `{artifact_dir}` | 当前样本产物目录 |

### 2.3 公开请求格式

`request.json` 示例：

```json
{
  "dataset_id": "exebench-1100",
  "split": "benchmark",
  "sample_id": "sample-id",
  "source_group_id": "source-group-id",
  "function_name": "target_function",
  "language": "c",
  "optimization": "O2",
  "assembly": {
    "text": "...",
    "syntax": "intel",
    "view": "objdump_intel_with_relocations"
  },
  "metadata": {
    "signature": ["int", "int *"]
  }
}
```

公开请求不会包含参考源代码、测试、wrapper、预期输出或行为 oracle。

## 3. 接入本地 LLM 或 API 模型

需要模型常驻、GPU 复用、批量推理或 API 调用时，使用 `python` 后端。

### 3.1 创建 Python 插件

例如创建：

```text
my_decompiler/
├── __init__.py
└── backend.py
```

`backend.py`：

```python
from pathlib import Path

from decomp_eval.models import DecompileRequest, DecompileResult


class MyLLMDecompiler:
    version = "my-model-v1"

    def __init__(self, config):
        self.model_path = config["model_path"]
        self.temperature = config.get("temperature", 0.0)
        self.model = self.load_model(self.model_path)

    def load_model(self, model_path):
        # 替换为实际模型加载逻辑
        return None

    def prepare(self, requests):
        # 可选：模型预热
        pass

    def build_prompt(self, request: DecompileRequest) -> str:
        return f"""
You are given the assembly of a function.

Function name: {request.function_name}
Language: {request.language}
Optimization: {request.optimization}
Assembly syntax: {request.assembly.syntax}

Assembly:
{request.assembly.text}

Return only a compilable function implementation.
"""

    def decompile(self, request: DecompileRequest, artifact_dir: Path):
        prompt = self.build_prompt(request)
        response = self.model_generate(prompt)

        return DecompileResult(
            success=bool(response.strip()),
            raw_output=response,
            code=response,
            reason=None if response.strip() else "empty_model_output",
            backend_version=self.version,
        )

    def model_generate(self, prompt):
        # 替换为实际模型调用
        raise NotImplementedError

    def close(self):
        # 可选：释放模型、连接和 GPU 资源
        pass
```

插件的 `decompile` 可以返回：

- C/C++ 代码字符串；
- `DecompileResult`；
- 可用于构造 `DecompileResult` 的字典。

字典示例：

```python
return {
    "success": True,
    "raw_output": response,
    "code": response,
    "elapsed_seconds": 1.25,
    "backend_version": self.version,
}
```

### 3.2 批量推理

LLM 后端建议实现 `decompile_many`：

```python
def decompile_many(self, requests, artifact_dirs):
    prompts = [self.build_prompt(request) for request in requests]
    responses = self.model.generate_batch(prompts)

    return [
        DecompileResult(
            success=bool(response.strip()),
            raw_output=response,
            code=response,
            reason=None if response.strip() else "empty_model_output",
            backend_version=self.version,
        )
        for response in responses
    ]
```

配置：

```yaml
decompilers:
  - id: my-local-llm
    type: python
    version: "my-model-v1"
    plugin: my_decompiler.backend:MyLLMDecompiler

    plugin_config:
      model_path: models/my-model
      temperature: 0.0

    batch_size: 8
```

如果插件没有实现 `decompile_many`，框架会自动逐样本调用 `decompile`。

### 3.3 让插件可以被导入

推荐把插件安装为 Python 包：

```bash
pip install -e /path/to/my_decompiler
```

也可以使用 `PYTHONPATH`：

```bash
export PYTHONPATH=/path/to/plugin/root:$PYTHONPATH
```

验证导入：

```bash
python -c "from my_decompiler.backend import MyLLMDecompiler; print(MyLLMDecompiler.version)"
```

## 4. 使用预生成反编译结果

Ghidra、IDA、RetDec 等工具已经生成 `.c` 文件时，使用 `precomputed` 后端。

### 4.1 按文件名读取

```yaml
decompilers:
  - id: ghidra
    type: precomputed
    version: "11.0"
    path: experiments/ghidra
    pattern: "{sample_id}.c"
```

`sample_id` 会被文件名安全化。例如：

```text
exebench:real:foo:O2
```

将变为：

```text
exebench_real_foo_O2.c
```

也可以组合其他字段：

```yaml
pattern: "{split}/{function_name}_{optimization}.c"
```

### 4.2 使用 JSONL manifest

```yaml
decompilers:
  - id: ghidra
    type: precomputed
    version: "11.0"
    path: experiments/ghidra
    manifest: experiments/ghidra/results.jsonl
```

manifest 可以直接保存代码：

```json
{"sample_id":"sample-1","code":"int foo(void) { return 1; }"}
{"sample_id":"sample-2","code":"int bar(int x) { return x + 1; }"}
```

也可以引用代码文件：

```json
{"sample_id":"sample-1","path":"generated/sample-1.c"}
{"sample_id":"sample-2","path":"generated/sample-2.c"}
```

相对文件路径以该后端的 `path` 为根目录。

## 5. 配置代码后处理

后处理发生在反编译完成之后、候选代码编译之前。原始输出和处理后的代码都会被保留。

### 5.1 提取 Markdown 代码块

```yaml
postprocessors:
  - markdown_fence
```

该处理器会从聊天模型回答中选取最长的 C/C++ 代码块。

### 5.2 显式重命名目标函数

传统反编译器可能输出：

```c
int FUN_00101230(int x)
{
    return x + 1;
}
```

而测试夹具调用原始函数名时，可以显式启用：

```yaml
postprocessors:
  - markdown_fence

  - type: rename_target
    pattern: '\bFUN_[0-9A-Fa-f]+\b'
```

处理记录保存在：

```text
artifacts/.../postprocess.json
```

不建议默认启用大量自动修复，否则会混淆模型能力和人工修复能力。

## 6. 扩展新数据集

新数据集适配器只负责数据读取、规范化和私有载荷，并声明默认评估协议：

1. 将原始记录转换为 `CanonicalSample`；
2. 将参考源码、fixture 和 oracle 放入 `private_payload`；
3. 通过 `default_protocol` 声明默认协议。编译和测试逻辑属于独立的 `EvaluationProtocol`。

### 6.1 最小适配器

```python
from pathlib import Path

from decomp_eval.models import (
    AssemblyInput,
    CanonicalSample,
    EvaluationEvidence,
    ValidationResult,
)
from decomp_eval.util import sha256_json


class MyDatasetAdapter:
    plugin_name = "my_dataset"
    default_protocol = "my_package.protocol:MyEvaluationProtocol"

    def __init__(self, config, *, base_dir: Path):
        self.dataset_id = config["id"]
        path = Path(config["path"])
        self.path = path if path.is_absolute() else (base_dir / path).resolve()
        self.timeout = int(config.get("timeout", 30))
        self.assembly_view = config.get("assembly_view", "asm")
        self.evaluation_protocol = None  # 框架在创建适配器后完成绑定

    def iter_samples(self):
        for row in self.load_records(self.path):
            yield CanonicalSample(
                dataset_id=self.dataset_id,
                split=row["split"],
                sample_id=row["sample_id"],
                source_group_id=row["source_group_id"],
                function_name=row["function_name"],
                language=row.get("language", "c"),
                optimization=row.get("optimization", "O0"),
                assembly=AssemblyInput(
                    text=row[self.assembly_view],
                    syntax=row.get("assembly_syntax", "intel"),
                    view=self.assembly_view,
                ),
                content_hash=sha256_json(row),

                # metadata 会传递给反编译器，只能放公开信息。
                metadata={
                    "signature": row.get("signature"),
                },

                # private_payload 不会传递给反编译器。
                private_payload={
                    "reference_source": row["source"],
                    "dependencies": row.get("dependencies", ""),
                    "tests": row["tests"],
                },
            )

    def load_records(self, path):
        raise NotImplementedError
```

安全要求：

- `metadata` 只能包含允许下游反编译器看到的信息；
- 源码、测试、预期输出和 wrapper 必须放在 `private_payload`；
- `content_hash` 应覆盖所有会影响反编译或评估的原始字段；
- `sample_id` 在同一数据集内必须唯一。

### 6.2 实现评估协议和参考源码预检

```python
from decomp_eval.models import ProtocolDescriptor, ValidationResult
from decomp_eval.protocols.base import BaseEvaluationProtocol


class MyEvaluationProtocol(BaseEvaluationProtocol):
    descriptor = ProtocolDescriptor(
        protocol_id="my_exitcode_protocol",
        version="1",
        description="Compile one test program and require exit code zero.",
        capabilities=("candidate_compile", "fixture_link", "behavioral_test"),
        compile_unit="candidate_dependencies_and_test",
        test_granularity="single_test_program",
        comparator="process_exit_code_zero",
    )

    def validate_reference(self, sample, executor, workdir):
        source = sample.private_payload["reference_source"]

        evidence = self.evaluate_candidate(sample, source, executor, workdir)

        return ValidationResult(
            sample_id=sample.sample_id,
            valid=evidence.recompilable and evidence.behavioral_pass,
            evidence=evidence,
        )
```

参考源码和模型生成代码必须调用同一个协议的 `evaluate_candidate`。协议的 ID、版本、能力和语义会进入缓存、manifest、逐样本结果及报告分组。

### 6.3 候选代码评估

下面是单文件 C 测试的简化实现。将该方法加入上面的 `MyEvaluationProtocol`：

```python
import time

def evaluate_candidate(self, sample, code, executor, workdir):
    started = time.perf_counter()
    workdir.mkdir(parents=True, exist_ok=True)

    dependencies = sample.private_payload["dependencies"]
    tests = sample.private_payload["tests"]

    source_path = workdir / "candidate.c"
    object_path = workdir / "candidate.o"
    executable_path = workdir / "candidate.x"

    source_path.write_text(
        dependencies + "\n" + code + "\n" + tests,
        encoding="utf-8",
    )

    compile_result = executor.run(
        [
            "gcc",
            f"-{sample.optimization}",
            "-std=gnu11",
            "-c",
            str(source_path),
            "-o",
            str(object_path),
        ],
        cwd=workdir,
        timeout=self.adapter.timeout,
    )

    if compile_result.timed_out:
        return self.evidence(reason="compile_timeout")

    if compile_result.returncode != 0:
        return self.evidence(
            reason="compile_error",
            logs={"compile_stderr": compile_result.stderr},
        )

    link_result = executor.run(
        [
            "gcc",
            str(object_path),
            "-o",
            str(executable_path),
            "-lm",
        ],
        cwd=workdir,
        timeout=self.adapter.timeout,
    )

    if link_result.timed_out:
        return self.evidence(
            compile_pass=True,
            reason="link_timeout",
        )

    if link_result.returncode != 0:
        return self.evidence(
            compile_pass=True,
            reason="link_error",
            logs={"link_stderr": link_result.stderr},
        )

    run_result = executor.run(
        [str(executable_path)],
        cwd=workdir,
        timeout=self.adapter.timeout,
    )

    passed = not run_result.timed_out and run_result.returncode == 0

    return self.evidence(
        compile_pass=True,
        link_pass=True,
        behavioral_pass=passed,
        reason=None if passed else "test_failed",
        tests_total=1,
        tests_passed=int(passed),
        elapsed_seconds=time.perf_counter() - started,
        logs={
            "test_stdout": run_result.stdout,
            "test_stderr": run_result.stderr,
        },
    )
```

### 6.4 注册数据集

```yaml
datasets:
  - id: my-benchmark
    type: my_package.dataset:MyDatasetAdapter
    path: data/my-benchmark
    assembly_view: asm
    evaluation_protocol:
      type: my_package.protocol:MyEvaluationProtocol
    timeout: 30
```

使用 `module:object` 后不需要修改核心 Runner 或内置插件注册表。

### 6.5 协议能力、版本与报告隔离

协议必须使用稳定的 `protocol_id` 和显式 `version`。任何会改变成功语义的修改，例如比较器、编译单元、测试粒度或分母政策，都应提升协议版本。

内置能力包括：

```text
candidate_compile       能判断候选编译是否成功
fixture_link            能判断候选与测试夹具是否链接成功
behavioral_test         能给出样本级全测试通过状态
per_case_test           能逐测试样例计数
aggregate_test_program  只能观察整个测试程序
structured_output       测试产生结构化输出
strict_json_compare     使用严格递归 JSON 比较
```

指标通过 `required_capabilities` 声明适用条件。不支持的指标返回 `None`，不会进入该指标分母；反编译、编译或测试失败仍具有协议能力，因此会以 `False` 进入固定分母。

`results.jsonl` 保存：

```text
protocol_id
protocol_version
protocol_capabilities
protocol_descriptor
```

`summary.json` 默认按协议 ID 和版本隔离。即使两个协议都产生 `behavioral_pass`，框架也不会将 JSON I/O 比较和进程退出码测试合并为同一总体结果。

协议配置及描述符会进入缓存键。改变协议参数后不会误用旧结果。0.2 之前没有协议身份的运行目录不能使用 `--resume` 继续执行。

## 7. 扩展评估指标

指标根据统一的 `EvaluationEvidence` 计算。常用字段包括：

```python
evidence.compile_pass
evidence.link_pass
evidence.behavioral_pass
evidence.reason
evidence.tests_total
evidence.tests_passed
evidence.elapsed_seconds
evidence.logs
evidence.protocol_id
evidence.protocol_version
evidence.capabilities
evidence.stages
evidence.details
```

### 7.1 布尔指标

```python
class NoTimeoutMetric:
    name = "no_timeout"

    def evaluate(self, sample, evidence):
        return evidence.reason not in {
            "compile_timeout",
            "link_timeout",
            "test_timeout",
        }

    def aggregate(self, values):
        eligible = [bool(value) for value in values if value is not None]
        passed = sum(eligible)

        return {
            "eligible": len(eligible),
            "passed": passed,
            "rate": passed / len(eligible) if eligible else 0.0,
        }
```

配置：

```yaml
metrics:
  - recompilable
  - behavioral_pass
  - type: my_package.metrics:NoTimeoutMetric
```

### 7.2 数值指标

```python
class TestCasePassRateMetric:
    name = "test_case_pass_rate"

    def evaluate(self, sample, evidence):
        if evidence.tests_total == 0:
            return None
        return evidence.tests_passed / evidence.tests_total

    def aggregate(self, values):
        eligible = [float(value) for value in values if value is not None]
        return {
            "eligible": len(eligible),
            "mean": sum(eligible) / len(eligible) if eligible else None,
        }
```

严格行为指标仍然遵循：只有该样本的全部测试都通过，`behavioral_pass` 才为真。部分测试通过率只能作为辅助指标。

## 8. 扩展代码后处理器

```python
class RemoveExplanationPostprocessor:
    name = "remove_explanation"

    def process(self, code, sample, config):
        marker = config.get("marker", "Explanation:")
        if marker not in code:
            return code, None

        cleaned = code.split(marker, 1)[0]
        return cleaned, {
            "processor": self.name,
            "marker": marker,
        }
```

配置：

```yaml
postprocessors:
  - markdown_fence

  - type: my_package.postprocess:RemoveExplanationPostprocessor
    marker: "Explanation:"
```

处理器必须返回：

```python
(
    processed_code,
    action_record_or_none,
)
```

## 9. 多数据集、多反编译器配置

```yaml
workspace_root: ..

datasets:
  - id: exebench-1100
    type: exebench_flat
    path: datasets/exebench-1641/exebench_1641_source_multiopt_1100.dataset.json
    assembly_view: objdump_att_instruction_only
    optimizations: [O0, O1, O2, O3]

  - id: decompile-eval
    type: decompile_eval
    path: datasets/decompile-eval
    splits: [humaneval, mbpp]
    assembly_view: asm
    optimizations: [O0, O1, O2, O3]

decompilers:
  - id: my-llm
    type: python
    plugin: my_package.backend:MyLLMDecompiler
    plugin_config:
      model_path: models/my-model
    batch_size: 8

  - id: ghidra
    type: precomputed
    path: experiments/ghidra
    pattern: "{sample_id}.c"

  - id: retdec
    type: command
    command:
      - /opt/retdec/decompile
      - "{assembly_file}"
      - -o
      - "{output_file}"

postprocessors:
  - markdown_fence

metrics:
  - recompilable
  - behavioral_pass

executor:
  type: local
  require_linux: true
  memory_mb: 4096
  max_file_mb: 128

preflight:
  mode: strict

output:
  root: experiments/decompile_eval
  cache: experiments/decompile_eval/cache
```

一次运行将评估所有选定的“数据集 × 反编译器 × 样本”组合。

## 10. 推荐运行流程

### 10.1 验证配置

```bash
python -m decomp_eval validate-config --config configs/my-evaluation.yaml
```

### 10.2 验证参考源码

```bash
python -m decomp_eval validate-dataset \
  --config configs/my-evaluation.yaml \
  --run-dir runs/preflight
```

正式评估建议始终使用：

```yaml
preflight:
  mode: strict
```

任何参考源码不能编译、链接或通过全部测试时，正式评估会停止。

### 10.3 小规模冒烟测试

在数据集配置中临时加入：

```yaml
limit: 10
optimizations: [O0]
```

运行：

```bash
python -m decomp_eval run \
  --config configs/my-evaluation.yaml \
  --run-dir runs/smoke
```

### 10.4 全量评估

删除 `limit` 后运行：

```bash
python -m decomp_eval run \
  --config configs/my-evaluation.yaml \
  --run-dir runs/full-run
```

### 10.5 断点恢复

```bash
python -m decomp_eval run \
  --config configs/my-evaluation.yaml \
  --run-dir runs/full-run \
  --resume
```

`--resume` 要求当前配置哈希与首次运行一致，防止不同实验配置混入同一个结果目录。

### 10.6 重新生成报告

```bash
python -m decomp_eval report \
  --run-dir runs/full-run
```

## 11. 输出目录

```text
full-run/
├── manifest.json
├── preflight.json
├── results.jsonl
├── summary.json
├── summary.csv
└── artifacts/
    └── dataset/
        └── decompiler/
            └── sample/
                ├── assembly.s
                ├── request.json
                ├── raw_output.txt
                ├── candidate.c
                ├── decompiler.log
                ├── postprocess.json
                ├── evaluation.json
                └── evaluation/
```

关键文件：

- `manifest.json`：配置快照、环境、版本和评估口径；
- `preflight.json`：参考源码验证结果；
- `raw_output.txt`：反编译器原始输出；
- `candidate.c`：实际参与评估的后处理代码；
- `evaluation.json`：编译、链接和测试证据；
- `results.jsonl`：逐样本扁平结果；
- `summary.json`：分组统计；
- `summary.csv`：适合 Pandas、Excel 和绘图工具。

## 12. 常见失败原因

| reason | 含义 |
|---|---|
| `assembly_missing` | 指定汇编字段为空 |
| `decompile_timeout` | 反编译器超时 |
| `decompile_command_error` | 命令行工具非零退出 |
| `decompile_output_missing` | 命令没有产生输出文件 |
| `decompile_empty_output` | 反编译结果为空 |
| `decompiler_exception` | Python 插件发生异常 |
| `precomputed_output_missing` | 找不到预生成代码 |
| `compile_error` | 候选代码不能生成对象文件 |
| `compile_timeout` | 编译超时 |
| `link_error` | 候选对象不能与测试夹具链接 |
| `link_timeout` | 链接超时 |
| `runtime_error` | 测试程序崩溃或异常退出 |
| `test_timeout` | 测试执行超时 |
| `test_failed` | 断言失败或测试程序非零退出 |
| `output_mismatch` | ExeBench 输出与 oracle 不一致 |
| `invalid_output` | 测试输出文件无法读取或解析 |

推荐排查顺序：

1. 查看 `request.json`，确认函数名、语言、优化等级和汇编视图；
2. 查看 `raw_output.txt`，确认反编译器原始输出；
3. 对比 `candidate.c` 和 `postprocess.json`；
4. 查看 `evaluation.json` 中的编译、链接和运行日志；
5. 进入该样本的 `evaluation/` 目录手工复现命令。

## 13. 正式实验建议

1. 不要把参考源码、测试答案或 oracle 放进 `metadata`。
2. 函数名修复等操作必须显式配置并完整留痕。
3. 参考源码和候选代码必须经过同一条评估链路。
4. 固定数据集版本、汇编视图、提示词、模型版本、后处理和编译参数。
5. 不要使用不同配置续跑同一个运行目录。
6. 反编译失败、空输出和编译失败必须保留在固定分母中。
7. 正式发布结果时同时保存 `manifest.json`、`results.jsonl` 和汇总报告。
8. 先运行小规模冒烟测试，再执行完整评估矩阵。

## 14. 实战：接入仓库中的 LLM4Decompile

本节以仓库已有模型为例：

```text
models/llm4decompile-1.3b-v1.6
```

该模型是 `LlamaForCausalLM` 架构，约 1.3B 参数，配置使用 `transformers 4.51.3`、`bfloat16` 和最大 16384 token 上下文。

### 14.1 准备推理环境

在 Linux/WSL 中进入框架目录：

```bash
cd decompile-eval-framework

python3 -m venv .venv
source .venv/bin/activate

pip install -e '.[test]'
pip install "transformers==4.51.3" accelerate safetensors
```

PyTorch 需要根据本机 CUDA 环境安装。先检查：

```bash
nvidia-smi
```

安装匹配的 PyTorch 后验证：

```bash
python - <<'PY'
import torch

print("torch:", torch.__version__)
print("cuda available:", torch.cuda.is_available())

if torch.cuda.is_available():
    print("gpu:", torch.cuda.get_device_name(0))
    print("bf16:", torch.cuda.is_bf16_supported())
PY
```

模型权重约 2.7 GB，但推理还需要输入张量和 KV cache。建议至少 8 GB 显存，处理长汇编时建议 12 GB 以上。

### 14.2 创建模型插件

创建：

```text
code/decompile-eval-framework/
└── plugins/
    ├── __init__.py
    └── llm4decompile_backend.py
```

`plugins/__init__.py` 可以为空。

在 `plugins/llm4decompile_backend.py` 中写入：

```python
from __future__ import annotations

import time
from pathlib import Path

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

from decomp_eval.models import DecompileRequest, DecompileResult


class LLM4DecompileBackend:
    version = "llm4decompile-1.3b-v1.6"

    def __init__(self, config):
        self.model_path = Path(config["model_path"]).expanduser().resolve()
        self.device = config.get(
            "device",
            "cuda" if torch.cuda.is_available() else "cpu",
        )
        self.max_new_tokens = int(config.get("max_new_tokens", 2048))
        self.max_input_tokens = int(config.get("max_input_tokens", 14000))
        self.do_sample = bool(config.get("do_sample", False))
        self.temperature = float(config.get("temperature", 0.0))
        self.top_p = float(config.get("top_p", 1.0))

        self.tokenizer = AutoTokenizer.from_pretrained(
            self.model_path,
            trust_remote_code=False,
        )
        self.tokenizer.padding_side = "left"

        if self.tokenizer.pad_token_id is None:
            self.tokenizer.pad_token_id = self.tokenizer.eos_token_id

        dtype = self._choose_dtype()

        print(
            f"Loading {self.model_path} "
            f"on {self.device} with {dtype}"
        )

        self.model = AutoModelForCausalLM.from_pretrained(
            self.model_path,
            torch_dtype=dtype,
            trust_remote_code=False,
        )
        self.model.to(self.device)
        self.model.eval()
        self.model.config.use_cache = True

    def _choose_dtype(self):
        if self.device == "cpu":
            return torch.float32

        if (
            self.device.startswith("cuda")
            and torch.cuda.is_bf16_supported()
        ):
            return torch.bfloat16

        return torch.float16

    def prepare(self, requests):
        """可选的模型预热。"""
        if not requests:
            return

        warmup_prompt = (
            "# This is the assembly code:\n"
            "test:\n"
            "  xor eax, eax\n"
            "  ret\n"
            "# What is the source code?\n"
        )

        inputs = self.tokenizer(
            warmup_prompt,
            return_tensors="pt",
        ).to(self.device)

        with torch.inference_mode():
            self.model.generate(
                **inputs,
                max_new_tokens=8,
                do_sample=False,
                pad_token_id=self.tokenizer.pad_token_id,
                eos_token_id=self.tokenizer.eos_token_id,
            )

    def build_prompt(self, request: DecompileRequest) -> str:
        # 与 LLM4Decompile 训练数据中的提示形式保持一致。
        return (
            "# This is the assembly code:\n"
            f"{request.assembly.text.strip()}\n"
            "# What is the source code?\n"
        )

    def _generation_kwargs(self):
        values = {
            "max_new_tokens": self.max_new_tokens,
            "do_sample": self.do_sample,
            "pad_token_id": self.tokenizer.pad_token_id,
            "eos_token_id": self.tokenizer.eos_token_id,
        }

        if self.do_sample:
            values.update(
                {
                    "temperature": self.temperature,
                    "top_p": self.top_p,
                }
            )

        return values

    def decompile(
        self,
        request: DecompileRequest,
        artifact_dir: Path,
    ) -> DecompileResult:
        started = time.perf_counter()

        try:
            prompt = self.build_prompt(request)
            inputs = self.tokenizer(
                prompt,
                return_tensors="pt",
                truncation=True,
                max_length=self.max_input_tokens,
            ).to(self.device)

            input_width = inputs["input_ids"].shape[1]

            with torch.inference_mode():
                output = self.model.generate(
                    **inputs,
                    **self._generation_kwargs(),
                )

            generated_tokens = output[0, input_width:]
            code = self.tokenizer.decode(
                generated_tokens,
                skip_special_tokens=True,
            ).strip()

            return DecompileResult(
                success=bool(code),
                raw_output=code,
                code=code,
                reason=None if code else "empty_model_output",
                elapsed_seconds=time.perf_counter() - started,
                backend_version=self.version,
            )

        except torch.cuda.OutOfMemoryError as error:
            torch.cuda.empty_cache()
            return DecompileResult(
                success=False,
                reason="cuda_out_of_memory",
                log=repr(error),
                elapsed_seconds=time.perf_counter() - started,
                backend_version=self.version,
            )

        except Exception as error:
            return DecompileResult(
                success=False,
                reason="model_inference_error",
                log=repr(error),
                elapsed_seconds=time.perf_counter() - started,
                backend_version=self.version,
            )

    def decompile_many(self, requests, artifact_dirs):
        """批量推理；返回结果数量必须与请求数量完全一致。"""
        if not requests:
            return []

        started = time.perf_counter()
        prompts = [self.build_prompt(request) for request in requests]

        try:
            inputs = self.tokenizer(
                prompts,
                return_tensors="pt",
                padding=True,
                truncation=True,
                max_length=self.max_input_tokens,
            ).to(self.device)

            input_width = inputs["input_ids"].shape[1]

            with torch.inference_mode():
                outputs = self.model.generate(
                    **inputs,
                    **self._generation_kwargs(),
                )

            elapsed = time.perf_counter() - started
            per_sample_elapsed = elapsed / len(requests)
            results = []

            for output in outputs:
                generated_tokens = output[input_width:]
                code = self.tokenizer.decode(
                    generated_tokens,
                    skip_special_tokens=True,
                ).strip()

                results.append(
                    DecompileResult(
                        success=bool(code),
                        raw_output=code,
                        code=code,
                        reason=None if code else "empty_model_output",
                        elapsed_seconds=per_sample_elapsed,
                        backend_version=self.version,
                    )
                )

            return results

        except torch.cuda.OutOfMemoryError as error:
            torch.cuda.empty_cache()
            return [
                DecompileResult(
                    success=False,
                    reason="cuda_out_of_memory",
                    log=repr(error),
                    backend_version=self.version,
                )
                for _ in requests
            ]

        except Exception as error:
            return [
                DecompileResult(
                    success=False,
                    reason="model_batch_inference_error",
                    log=repr(error),
                    backend_version=self.version,
                )
                for _ in requests
            ]

    def close(self):
        del self.model

        if torch.cuda.is_available():
            torch.cuda.empty_cache()
```

### 14.3 创建小规模配置

创建 `configs/llm4decompile-smoke.yaml`：

```yaml
workspace_root: ..

datasets:
  - id: exebench-1100
    type: exebench_flat
    path: datasets/exebench-1641/exebench_1641_source_multiopt_1100.dataset.json
    assembly_view: objdump_att_instruction_only
    optimizations: [O0]
    limit: 10
    timeout: 30

decompilers:
  - id: llm4decompile-1.3b-v1.6
    type: python
    version: "llm4decompile-1.3b-v1.6"
    plugin: plugins.llm4decompile_backend:LLM4DecompileBackend

    plugin_config:
      # plugin_config 的路径不会被框架自动转换，建议使用 WSL 绝对路径。
      model_path: models/llm4decompile-1.3b-v1.6
      device: cuda
      max_input_tokens: 14000
      max_new_tokens: 2048
      do_sample: false
      temperature: 0.0
      top_p: 1.0

    # 第一次从 1 开始，确认显存占用后再提高。
    batch_size: 1

postprocessors:
  - markdown_fence

metrics:
  - recompilable
  - behavioral_pass

executor:
  type: local
  require_linux: true
  memory_mb: 4096
  max_file_mb: 128

preflight:
  mode: strict

output:
  root: experiments/decompile_eval
  cache: experiments/decompile_eval/cache
```

验证插件能被导入：

```bash
cd decompile-eval-framework

python - <<'PY'
from plugins.llm4decompile_backend import LLM4DecompileBackend

print(LLM4DecompileBackend.version)
PY
```

### 14.4 运行 smoke test

检查配置：

```bash
python -m decomp_eval validate-config \
  --config configs/llm4decompile-smoke.yaml
```

验证 10 条参考源码：

```bash
python -m decomp_eval validate-dataset \
  --config configs/llm4decompile-smoke.yaml \
  --run-dir runs/llm4decompile-smoke
```

运行 LLM 反编译与评估：

```bash
python -m decomp_eval run \
  --config configs/llm4decompile-smoke.yaml \
  --run-dir runs/llm4decompile-smoke
```

中断后恢复：

```bash
python -m decomp_eval run \
  --config configs/llm4decompile-smoke.yaml \
  --run-dir runs/llm4decompile-smoke \
  --resume
```

### 14.5 检查模型结果

单个样本位于：

```text
experiments/decompile_eval/llm4decompile-smoke/
└── artifacts/
    └── exebench-1100/
        └── llm4decompile-1.3b-v1.6/
            └── sample-id/
```

按以下顺序检查：

1. `assembly.s`：模型输入汇编；
2. `request.json`：公开函数信息和优化等级；
3. `raw_output.txt`：模型原始输出；
4. `candidate.c`：实际参与评估的代码；
5. `postprocess.json`：代码围栏提取等处理记录；
6. `evaluation.json`：编译、链接和测试日志。

常见模型输出问题包括：

- 输出自然语言解释；
- 代码不完整；
- 函数名与 `request.function_name` 不一致；
- 输出 `_DWORD`、`__int64` 等未定义的 IDA 类型；
- 输出整个程序而不是目标函数；
- 生成代码能编译，但行为测试失败。

### 14.6 调整显存和批量大小

从以下配置开始：

```yaml
batch_size: 1
max_input_tokens: 12000
max_new_tokens: 1536
```

显存稳定后依次尝试 `batch_size: 2` 和 `batch_size: 4`。由于不同汇编长度不同，批量 padding 后的显存取决于当前批次中最长样本。

出现 `cuda_out_of_memory` 时按以下顺序处理：

1. 减小 `batch_size`；
2. 减小 `max_input_tokens`；
3. 减小 `max_new_tokens`；
4. 确认 GPU 使用 `float16` 或 `bfloat16`；
5. 后续可扩展按输入 token 长度分桶的批处理策略。

### 14.7 扩展到 O0–O3 全量评估

smoke test 正常后，将数据集配置改为：

```yaml
datasets:
  - id: exebench-1100
    type: exebench_flat
    path: datasets/exebench-1641/exebench_1641_source_multiopt_1100.dataset.json
    assembly_view: objdump_att_instruction_only
    optimizations: [O0, O1, O2, O3]
    timeout: 30
```

删除 `limit: 10`，并使用新的运行目录：

```bash
python -m decomp_eval run \
  --config configs/llm4decompile-full.yaml \
  --run-dir runs/llm4decompile-full
```

不要将全量配置续跑到 smoke 目录，因为配置和评估分母已经变化。

### 14.8 接入 decompile-eval

增加：

```yaml
datasets:
  - id: decompile-eval
    type: decompile_eval
    path: datasets/decompile-eval
    splits: [humaneval, mbpp]
    assembly_view: asm
    optimizations: [O0, O1, O2, O3]
    limit: 10
    timeout: 30
```

`github` split 没有测试，因此第一版不使用。`asm` 通常更接近 LLM4Decompile 的训练输入形式。

也可以单独评估 `ida_asm`，但不同汇编视图必须放在不同运行目录中，报告中也必须明确标注汇编视图。

### 14.9 替换为远程 LLM API

远程 API 仍然实现相同接口，只需要替换模型加载和生成部分：

```python
import os

from decomp_eval.models import DecompileResult


class RemoteLLMDecompiler:
    version = "remote-model-version"

    def __init__(self, config):
        self.base_url = config["base_url"]
        self.model = config["model"]
        self.api_key = os.environ[config.get("api_key_env", "LLM_API_KEY")]

    def build_prompt(self, request):
        return (
            "# This is the assembly code:\n"
            f"{request.assembly.text.strip()}\n"
            "# What is the source code?\n"
        )

    def decompile(self, request, artifact_dir):
        prompt = self.build_prompt(request)
        response = self.call_api(prompt)

        return DecompileResult(
            success=bool(response.strip()),
            raw_output=response,
            code=response,
            reason=None if response.strip() else "empty_model_output",
            backend_version=self.version,
        )
```

API 密钥不要写入 YAML：

```bash
export LLM_API_KEY="..."
```

配置中只记录环境变量名：

```yaml
plugin_config:
  base_url: https://your-server/v1
  model: your-model
  api_key_env: LLM_API_KEY
```

### 14.10 推荐实验顺序

1. 单条 O0，确认模型加载和生成；
2. 10 条 O0，确认后处理、编译和测试；
3. 10 条 O0–O3，确认分组统计；
4. 100 条，观察显存、生成长度和失败分布；
5. ExeBench 全量 1100；
6. decompile-eval HumanEval/MBPP 小规模；
7. decompile-eval 全量；
8. 固定模型、prompt、汇编视图和生成参数后进行正式比较。

第一次实验建议保持：

```yaml
do_sample: false
temperature: 0.0
batch_size: 1

preflight:
  mode: strict
```

这样结果最容易复现和排查。

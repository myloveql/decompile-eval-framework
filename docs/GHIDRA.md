# 接入 Ghidra Headless

推荐先用内置 `ghidra` 后端把二进制统一转换为固定伪代码，并把结果写入数据集。正式实验再读取数据集中的同一份伪代码：既可以直接评估 Ghidra，也可以交给模型修复后评估。生成过程不会使用参考源码、测试代码或测试答案。

## 推荐的数据流

```text
原始 ELF ──一次性 Ghidra Headless──> samples[].decompilation.ghidra.code
                                      ├── pseudocode 后端直接评估
                                      └── Python/LLM 后端修复后评估
```

固定伪代码避免 Ghidra 版本、分析参数和运行环境的变化混入不同模型之间的比较。

## 写入数据集

```bash
python tools/exebench/add_ghidra_pseudocode.py \
  --dataset /mnt/f/LLM_Decompile/data/exebench/1641-Benchmark/exebench_1641_source_multiopt_1100.dataset.json \
  --output /mnt/f/LLM_Decompile/data/exebench/1641-Benchmark/exebench_1641_source_multiopt_1100.with-ghidra.dataset.json \
  --workspace-root /mnt/f/LLM_Decompile \
  --ghidra-path code/LLM4Decompile/ghidra/ghidra_11.0.3_PUBLIC \
  --workers 2 \
  --batch-size 20 \
  --resume
```

工具支持断点续跑和原子写入。建议先输出到新文件，验证 1100 条全部存在后再将其作为正式数据集。每条记录新增：

```json
{
  "decompilation": {
    "ghidra": {
      "code": "...",
      "sha256": "...",
      "producer": "ghidra",
      "version": "11.0.3",
      "function_name": "target",
      "input_kind": "target-object",
      "input_binary_sha256": "..."
    }
  }
}
```

默认的 `target-object` 视图使用与汇编数据相同的优化等级，将目标函数外部化后编译为 ELF relocatable object。不能直接统一使用数据集原有 executable：O1–O3 中静态目标函数可能被内联并从符号表消失。记录中的 object SHA-256、优化等级和 Ghidra 版本可用于追溯生成过程。仅用于诊断时可指定 `--binary-view dataset-binary`。

## 输入边界

不同反编译器需要的输入不同：

- LLM/Python/command 后端默认声明 `assembly` 输入；
- Ghidra 后端声明 `binary` 输入；
- ExeBench 1100 的每条记录包含 ELF 路径和 SHA-256，因此可直接使用；
- 当前 Decompile-Bench-Eval Arrow 数据没有原始二进制，使用 Ghidra 时会记录 `binary_missing`。

框架不会从参考源码重新编译二进制。这样可以避免把 oracle 信息泄漏给反编译器，也避免评估对象与数据集原始二进制不一致。

## 直接评估固定 Ghidra 伪代码

使用 `configs/ghidra-pseudocode-exebench-smoke.yaml`。数据集必须声明伪代码视图：

```yaml
datasets:
  - id: exebench-1100
    type: exebench_flat
    path: data/exebench/1641-Benchmark/exebench_1641_source_multiopt_1100.with-ghidra.dataset.json
    pseudocode_view: ghidra

decompilers:
  - id: ghidra-11.0.3-fixed-pseudocode
    type: pseudocode
    version: "11.0.3"
```

此时后端只收到 `pseudocode`，不会收到汇编或二进制。

## 使用模型修复 Ghidra 伪代码

Python 后端显式声明输入：

```yaml
decompilers:
  - id: my-ghidra-refiner
    type: python
    version: "1"
    required_inputs: [pseudocode]
    plugin: my_package.ghidra_refiner:GhidraRefiner
```

插件从以下字段构造模型提示：

```python
def decompile(self, request, artifact_dir):
    ghidra_code = request.pseudocode.text
    prompt = (
        "Repair this Ghidra pseudocode into recompilable, behaviorally equivalent C.\n"
        + ghidra_code
    )
    return self.model_generate(prompt)
```

当 `required_inputs: [pseudocode]` 时，Runner 会清空 `request.assembly.text` 并令 `request.binary` 为 `null`，防止模型意外获得额外输入。也可以显式配置 `[assembly, pseudocode]` 做多视图实验，但报告会记录该后端的完整输入集合。

## Decompile-Eval 中已有的伪代码

Decompile-Eval 本身包含 `ida_pseudo` 和 `ghidra_pseudo`。无需重新运行 Ghidra，只需在数据集配置中选择：

```yaml
datasets:
  - id: decompile-eval
    type: decompile_eval
    path: data/decompile-eval
    splits: [humaneval, mbpp]
    pseudocode_view: ghidra_pseudo
```

然后复用同一个 `type: pseudocode` 直接评估，或复用 `required_inputs: [pseudocode]` 的模型修复后端。可运行示例为 `configs/ghidra-pseudocode-decompile-eval-smoke.yaml`。

## 在线 Ghidra 后端（数据构建与诊断）

可复制 `configs/ghidra-exebench-smoke.yaml`。关键部分如下：

```yaml
decompilers:
  - id: ghidra-11.0.3
    type: ghidra
    ghidra_path: code/LLM4Decompile/ghidra/ghidra_11.0.3_PUBLIC
    timeout: 300
    analysis_timeout: 120
    verify_binary_hash: true

postprocessors: [markdown_fence, ghidra_compat_types]
```

字段含义：

- `ghidra_path`：Ghidra 安装根目录，也可直接指向 `support/analyzeHeadless`；
- `timeout`：单个样本整个 Headless 进程的最长运行秒数；
- `analysis_timeout`：Ghidra 单文件分析及目标函数反编译的超时秒数；
- `verify_binary_hash`：若数据集提供 SHA-256，是否在导入前验证，默认开启；
- `script_path`：可选，自定义 Headless Java 脚本；默认使用框架内置的 `DecompileFunction.java`。

Ghidra 会输出 `undefined1/2/4/8/16` 等宽度类型，它们不是标准 C 类型。示例显式启用 `ghidra_compat_types`，仅为实际出现的这些类型增加等宽 typedef，不修改控制流、表达式或函数名。该操作会完整写入 `postprocess.json`；若要统计完全原始 Ghidra 输出的可编译率，可从配置中删除它。

路径均相对于 `workspace_root` 解析。示例配置位于本项目的 `configs/`，其 `workspace_root: ../../..` 指向当前工作区 `LLM_Decompile` 根目录，因此在 Windows 和 `/mnt/f/...` 的 WSL 工作区中都不需要写死盘符。

## 运行在线后端

Ghidra 11.0.3 需要可用的 Java 17。正式评估仍建议在 Linux/WSL 中运行，因为候选 C 的编译、链接和测试链路以 Linux 为基准。

```bash
python -m decomp_eval validate-config \
  --config configs/ghidra-exebench-smoke.yaml

python -m decomp_eval run \
  --config configs/ghidra-exebench-smoke.yaml \
  --run-dir runs/ghidra-exebench-smoke
```

在线后端适合检查安装和重新生成伪代码。正式固定伪代码实验应使用 `type: pseudocode`。确认单样本跑通后，可删除 `limit: 1`，并把优化等级改为：

```yaml
optimizations: [O0, O1, O2, O3]
```

## 每个样本的产物

除框架通用文件外，Ghidra 后端还保存：

- `input_binary`：实际导入 Ghidra 的二进制副本；
- `backend_output.c`：Ghidra 原始目标函数输出；
- `ghidra.stdout.log`、`ghidra.stderr.log`：Headless 日志；
- `candidate.c`：后处理后送入数据集评估协议的代码；
- `evaluation/`：编译、链接和测试证据。

`manifest.json` 和每条 `results.jsonl` 记录都会写入 `backend_required_inputs: [binary]`，便于区分汇编输入与二进制输入的实验结果。

## 常见失败原因

- `binary_missing`：数据集没有提供二进制字段；
- `binary_not_found`：记录中的路径无法解析或文件已移动；
- `binary_hash_mismatch`：文件内容与数据集 SHA-256 不一致；
- `ghidra_headless_error`：Ghidra/Java/导入/脚本执行失败，查看两个 Ghidra 日志；
- `decompile_output_missing`：目标函数没有找到或脚本没有产出文件；
- `compile_error` / `link_error`：Ghidra 输出含有未声明类型、错误签名或外部符号，后续评估未通过；
- `test_output_mismatch`：候选代码可编译链接，但行为与测试 oracle 不一致。

Ghidra 能成功生成伪 C 不代表该代码可直接重新编译。框架会分别保留“反编译成功”“可重新编译”和“全部测试通过”三个层次的结果。

# 接入 Ghidra Headless

内置 `ghidra` 后端直接读取数据集提供的可执行二进制，在 Ghidra Headless 中完成分析，并只导出指定目标函数的反编译 C 代码。它不会使用参考源码、测试代码或测试答案。

## 输入边界

不同反编译器需要的输入不同：

- LLM/Python/command 后端默认声明 `assembly` 输入；
- Ghidra 后端声明 `binary` 输入；
- ExeBench 1100 的每条记录包含 ELF 路径和 SHA-256，因此可直接使用；
- 当前 Decompile-Bench-Eval Arrow 数据没有原始二进制，使用 Ghidra 时会记录 `binary_missing`。

框架不会从参考源码重新编译二进制。这样可以避免把 oracle 信息泄漏给反编译器，也避免评估对象与数据集原始二进制不一致。

## 配置

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

## 运行

Ghidra 11.0.3 需要可用的 Java 17。正式评估仍建议在 Linux/WSL 中运行，因为候选 C 的编译、链接和测试链路以 Linux 为基准。

```bash
python -m decomp_eval validate-config \
  --config configs/ghidra-exebench-smoke.yaml

python -m decomp_eval run \
  --config configs/ghidra-exebench-smoke.yaml \
  --run-dir runs/ghidra-exebench-smoke
```

确认单样本跑通后，删除 `limit: 1`，并把优化等级改为：

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

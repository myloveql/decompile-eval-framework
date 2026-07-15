# ExeBench 数据集维护工具

`tools/exebench/` 中的脚本用于复现和审计 ExeBench flat-1100 的汇编字段。它们不是运行框架的必需依赖，且不会下载数据集。

所有命令都应在已经安装本项目的 Linux/WSL 环境中执行：

```bash
pip install -e .
```

## 文件说明

- `objdump_instruction_view.py`：解析 objdump，生成带符号重定位的 Intel/AT&T 干净指令序列；
- `rebuild_flat_assembly.py`：从每条记录的自包含源码重新编译对象文件并重建 GCC/Intel 汇编字段；
- `add_att_instruction_view.py`：为已有 flat 数据集增加 `objdump_att_instruction_only`；
- `add_ghidra_pseudocode.py`：从原始 ELF 生成固定 Ghidra 伪代码视图，支持并发、断点续跑和原子写入；
- `validate_assembly_behavior.py`：重新汇编、链接 wrapper 并执行全部 I/O；
- `validate_flat_dataset.py`：检查结构、哈希、报告、二进制和 1100 条完整性。

## 增加 AT&T 视图

建议输出到新文件，检查通过后再替换正式数据集：

```bash
python tools/exebench/add_att_instruction_view.py \
  --dataset datasets/exebench-1641/exebench_1641_source_multiopt_1100.dataset.json \
  --output datasets/exebench-1641/exebench_1641_source_multiopt_1100.with-att.dataset.json \
  --workers 8
```

脚本使用：

```bash
objdump -dr --no-show-raw-insn --disassemble=<function> candidate.o
```

它会移除地址和头信息、生成稳定的内部跳转标签、将 PC32/PLT32 重定位合并回操作数，并为每条文本保存 SHA-256。

## 重建 Intel 汇编字段

```bash
python tools/exebench/rebuild_flat_assembly.py \
  --dataset datasets/exebench-1641/exebench_1641_source_multiopt_1100.dataset.json \
  --output datasets/exebench-1641/exebench_1641_source_multiopt_1100.rebuilt.dataset.json \
  --workers 8
```

重建会使原行为验证失效。在将文件作为最终结果发布前，必须重新执行行为验证。

## 行为验证

```bash
python tools/exebench/validate_assembly_behavior.py \
  --dataset datasets/exebench-1641/exebench_1641_source_multiopt_1100.dataset.json \
  --include-path datasets/exebench-include \
  --output runs/validation/assembly_behavior1100.json \
  --workers 12 \
  --update-dataset
```

这里验证的是保存的完整 GCC ASM，而 instruction-only 字段是同一对象代码的文本视图。行为通过意味着在数据集全部 I/O 上一致，不代表形式化等价。

## 完整结构验证

```bash
python tools/exebench/validate_flat_dataset.py \
  --dataset datasets/exebench-1641/exebench_1641_source_multiopt_1100.dataset.json \
  --source-report runs/validation/source_multiopt_valid1100.json \
  --assembly-report runs/validation/assembly_behavior1100.json \
  --asset-root /path/to/original/workspace
```

`--asset-root` 用于解析 JSON 中保存的 `binary.path`。如果发布可迁移数据集，应同步规范化这些路径，或在新的适配器中显式映射二进制根目录。

# SK²Decompile 后端使用指南

框架通过 `plugins/sk2decompile_backend.py` 提供完整的两阶段后端：

```text
IDA 伪代码
  → 官方规范化与 clang-format
  → sk2decompile-struct
  → Skeleton 中间代码
  → sk2decompile-ident
  → 最终 C 代码
  → 恢复数据集目标函数名
  → 数据集绑定的编译与行为评估
```

后端不会接收参考源码、测试代码或期望输出，只接收 `required_inputs: [pseudocode]`
公开的伪代码和普通样本元信息。编译与行为测试仍由各数据集自己的评估协议完成。

## 安装

在 Linux/WSL 的框架目录中执行：

```bash
pip install -e '.[sk2decompile,vllm,test]'
sudo apt-get install clang-format
```

官方发布模型为：

- `LLM4Binary/sk2decompile-struct-6.7b`
- `LLM4Binary/sk2decompile-ident-6.7b`

模型配置既可以使用 Hugging Face ID，也可以使用已经下载好的 WSL 本地绝对路径。

## 快速运行

示例 `configs/sk2decompile-decompile-eval-smoke.yaml` 分别选择 HumanEval、MBPP 中的 C 语言、
IDA 伪代码和前 5 个样本：

```bash
python -m decomp_eval validate-config \
  --config configs/sk2decompile-decompile-eval-smoke.yaml

python -m decomp_eval run \
  --config configs/sk2decompile-decompile-eval-smoke.yaml \
  --run-dir runs/sk2decompile-smoke
```

第一次使用远程模型 ID 会下载两套模型权重。建议先把 `limit` 设为 `1`，确认模型、显存和
`clang-format` 均正常。

## 核心配置

```yaml
datasets:
  - id: decompile-eval
    type: decompile_eval
    path: data/decompile-eval
    splits: [humaneval, mbpp]
    pseudocode_view: ida_pseudo
    languages: [c]
    evaluation_protocol:
      type: decompile_eval_exitcode

decompilers:
  - id: sk2decompile-ida
    type: python
    plugin: plugins.sk2decompile_backend:SK2DecompileBackend
    required_inputs: [pseudocode]
    batch_size: 8
    plugin_config:
      struct_model_path: LLM4Binary/sk2decompile-struct-6.7b
      ident_model_path: LLM4Binary/sk2decompile-ident-6.7b
      engine: vllm
      preprocess: true
      rename_target: true
```

必须使用 `required_inputs: [pseudocode]`。如果误写为 `assembly`，后端不会收到伪代码。

## 两阶段模型与显存

默认使用顺序驻留策略：

1. 只选择尚未完成、没有结果缓存且伪代码存在的样本。
2. 加载 struct 模型，分批生成所有 Skeleton。
3. 释放 struct 模型与 CUDA 缓存。
4. 加载 ident 模型，按 Runner 批次生成最终代码。

两套 6.7B 权重不需要同时驻留 GPU。常用配置：

```yaml
plugin_config:
  tensor_parallel_size: 1
  max_num_seqs: 8
  stage_batch_size: 8
  gpu_memory_utilization: 0.8
  max_model_len: 32768
  max_new_tokens: 4096
```

显存不足时，先把 `stage_batch_size` 和 `max_num_seqs` 降为 `1`。后端也支持 Transformers：

```yaml
plugin_config:
  engine: transformers
  device: cuda
  stage_batch_size: 1
```

Transformers 更适合调试；正式批量评估推荐 vLLM。

## 伪代码预处理

`preprocess: true` 会复现官方预处理的主要步骤：

1. 删除块注释和行注释。
2. 十六进制常量转十进制并保留整数后缀。
3. 删除 `__fastcall` 等 IDA 调用约定关键字。
4. 将 `_DWORD`、`_BYTE`、`__int64` 等替换为标准类型。
5. 使用 Google 风格 `clang-format` 格式化并删除空行。

原始数据集不会被修改。官方数据准备脚本还会删除有效代码行数不在 `(3, 300)` 范围内的
记录。统一评估默认关闭这种过滤：

```yaml
enforce_official_filter: false
```

这可以保持固定分母。如果开启过滤，未通过的记录也不会消失，而会明确记为
`sk2_preprocess_failed`。输入已经规范化时可以设置 `preprocess: false`。

## 官方提示格式

第一阶段虽然输入伪代码，但官方脚本仍使用：

```text
# This is the assembly code:
<normalized pseudocode>
# What is the source code?
```

第二阶段为：

```text
# This is the normalized code:
<struct output>
# What is the source code?
```

后端严格保留这两个模板，不额外套用聊天模板。

## 函数名恢复

官方推理会把 ident 模型生成的函数名替换成数据集目标函数名。框架通过显式配置复现：

```yaml
rename_target: true
```

替换覆盖函数定义和递归调用，并记录原函数名及替换次数。关闭后，测试夹具可能因找不到目标符号
而链接失败。

## 样本产物

每个样本除通用文件外还会保存：

```text
sk2_pseudocode_normalized.c  第一阶段实际输入
sk2_struct_prompt.txt        第一阶段提示
sk2_struct_output.c          Skeleton 输出
sk2_ident_prompt.txt         第二阶段提示
sk2_ident_output.c           ident 原始输出
sk2_final_output.c           函数名恢复后的代码
sk2_metadata.json            模型、视图、预处理和重命名审计信息
```

这些文件会进入框架缓存。断点续跑和结果缓存命中不会重新执行已经完成的两阶段推理。

## 数据集选择

官方模型针对 Linux x64、C 语言和 IDA 伪代码训练。decompile-eval 推荐：

```yaml
pseudocode_view: ida_pseudo
languages: [c]
```

ExeBench 1100 当前只有 Ghidra 伪代码。虽然可以选择 `pseudocode_view: ghidra`，但这属于跨
反编译器泛化实验，不应与 IDA 条件下的结果直接合并汇报。

## 失败原因

- `pseudocode_missing`：没有所选伪代码视图。
- `sk2_preprocess_failed`：语言、输入、clang-format 或官方过滤失败。
- `sk2_struct_inference_error`：struct 批量推理异常。
- `sk2_empty_struct_output`：struct 返回空结果。
- `sk2_ident_inference_error`：ident 批量推理异常。
- `sk2_empty_ident_output`：ident 返回空结果。

所有失败都会进入所选样本固定分母。

参考：

- [SK²Decompile struct 模型](https://huggingface.co/LLM4Binary/sk2decompile-struct-6.7b)
- [SK²Decompile ident 模型](https://huggingface.co/LLM4Binary/sk2decompile-ident-6.7b)

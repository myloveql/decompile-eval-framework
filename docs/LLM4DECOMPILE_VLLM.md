# LLM4Decompile vLLM 推理指南

`plugins/llm4decompile_backend.py` 同时支持 Transformers 与 vLLM。两种引擎使用完全相同的
LLM4Decompile 提示词、`DecompileRequest` 输入边界、候选代码评估协议和报告格式，因此可以在
不改变数据集及指标的情况下比较吞吐量和评估结果。

## 1. 安装

vLLM 需要 Linux/WSL、兼容的 NVIDIA 驱动和 CUDA 环境：

```bash
pip install -e '.[vllm,test]'
```

检查环境：

```bash
python -c "import vllm; print(vllm.__version__)"
nvidia-smi
```

本框架已针对当前环境中的 vLLM 0.7.2 接口进行验证，依赖范围为 `vllm>=0.7,<1`。

## 2. 最小配置

复制 `configs/llm4decompile-vllm-smoke.yaml`，至少确认模型路径和 GPU 数量：

```yaml
decompilers:
  - id: llm4decompile-1.3b-v1.6-vllm
    type: python
    version: llm4decompile-1.3b-v1.6:vllm
    plugin: plugins.llm4decompile_backend:LLM4DecompileBackend
    required_inputs: [assembly]

    # Runner 一次提交给插件的样本数，也是单次 LLM.generate 的 prompt 数。
    batch_size: 8

    plugin_config:
      model_path: models/llm4decompile-1.3b-v1.6
      engine: vllm

      tensor_parallel_size: 1
      max_num_seqs: 8
      gpu_memory_utilization: 0.82
      max_model_len: 16384

      max_input_tokens: 14000
      max_new_tokens: 2048
      do_sample: false
      temperature: 0
      seed: 0
      use_tqdm: false
```

## 3. 与参考脚本的参数对应

| 参考脚本参数 | 插件配置 | 含义 |
|---|---|---|
| `--gpus` | `tensor_parallel_size` | 单个模型实例使用的 GPU 数量 |
| `--max_num_seqs` | `max_num_seqs` | vLLM 引擎内部同时调度的最大序列数 |
| `--gpu_memory_utilization` | `gpu_memory_utilization` | 每张 GPU 可供 vLLM 使用的显存比例 |
| `--max_total_tokens` | `max_model_len` | 模型允许的最大总上下文长度 |
| `--max_new_tokens` | `max_new_tokens` | 每个样本最多生成的 token 数 |
| `--temperature` | `temperature` | 采样温度 |

框架额外使用顶层 `batch_size` 控制一次从 Runner 送入 `LLM.generate` 的 prompt 数量。它与
`max_num_seqs` 不完全相同：前者是应用层批次，后者是 vLLM 调度器上限。通常可以先设置为相同值。

## 4. Token 预算

必须满足：

```text
max_model_len > max_new_tokens
```

插件传给 vLLM 的最大 prompt token 数自动计算为：

```text
min(max_input_tokens, max_model_len - max_new_tokens)
```

例如：

```yaml
max_model_len: 16384
max_input_tokens: 14000
max_new_tokens: 2048
```

实际 prompt 上限为 14000。若设置 `max_input_tokens: 16000`，实际会限制为 14336，避免
prompt 与生成预算之和超过 vLLM 的上下文限制。

## 5. 确定性与采样

正式评估推荐：

```yaml
do_sample: false
temperature: 0
seed: 0
```

当 `do_sample: false` 时，插件会强制使用：

```text
temperature = 0
top_p = 1
top_k = -1
```

即使配置中误写了非零 `temperature`，也不会意外变成随机采样。需要采样时显式配置：

```yaml
do_sample: true
temperature: 0.8
top_p: 0.95
top_k: 50
repetition_penalty: 1.0
seed: 0
```

## 6. 多 GPU

四张 GPU 上做张量并行：

```yaml
plugin_config:
  engine: vllm
  tensor_parallel_size: 4
  gpu_memory_utilization: 0.82
```

启动前限制可见 GPU：

```bash
export CUDA_VISIBLE_DEVICES=0,1,2,3
```

`tensor_parallel_size` 不应大于可见 GPU 数量。对于 1.3B 模型，单卡通常已经可以容纳；多卡
张量并行不一定更快，建议先比较单卡吞吐。

## 7. 运行

验证配置：

```bash
python -m decomp_eval validate-config \
  --config configs/llm4decompile-vllm-smoke.yaml
```

运行 10 条 O0 smoke test：

```bash
python -m decomp_eval run \
  --config configs/llm4decompile-vllm-smoke.yaml \
  --run-dir runs/llm4decompile-vllm-smoke
```

也可以独立运行单条请求：

```bash
python plugins/llm4decompile_backend.py \
  --engine vllm \
  --model-path models/llm4decompile-1.3b-v1.6 \
  --dataset datasets/exebench-1641/exebench_1641_source_multiopt_1100.dataset.json \
  --tensor-parallel-size 1 \
  --max-model-len 16384 \
  --max-input-tokens 14000 \
  --max-new-tokens 2048
```

## 8. 输出与失败

vLLM 返回的第一个候选文本写入 `DecompileResult.raw_output` 和 `code`，随后仍经过框架统一的
Markdown 围栏提取、编译、链接与行为测试。结果顺序与输入请求顺序保持一致。
运行结束时插件会释放模型、销毁 vLLM model-parallel/distributed 环境并清理 CUDA 缓存。

主要失败原因：

- `empty_model_output`：vLLM 成功执行但模型文本为空；
- `cuda_out_of_memory`：GPU 显存不足；
- `vllm_inference_error`：vLLM 初始化后的批量生成失败；
- `decompiler_exception`：模型初始化或插件准备阶段抛出异常。

显存不足时依次降低：

1. `batch_size`；
2. `max_num_seqs`；
3. `max_model_len`；
4. `gpu_memory_utilization`；
5. `max_new_tokens`。

初始化失败还可以通过 `vllm_kwargs` 传递当前 vLLM 版本支持的高级参数：

```yaml
plugin_config:
  engine: vllm
  vllm_kwargs:
    enforce_eager: true
```

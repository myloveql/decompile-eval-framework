# SCCDec 后端使用指南

框架通过 `plugins/sccdec_backend.py` 接入 SCCDec。后端使用 OpenAI-compatible API 调用
FAE 模型，并支持论文中的 Self-Constructed Context（SCC）二阶段推理。

## 1. 实现范围

后端提供两种模式：

- `mode: fae`：只执行一次汇编到 C 推理；
- `mode: scc`：先生成第一版 C，将其重新编译和反汇编，构造一组临时的“汇编 → 第一版 C”
  上下文，再对原始汇编执行第二次推理。

如果第一版 C 不能重新编译、目标符号不能反汇编，或者第二次推理失败，后端按照 SCCDec
参考实现回退到第一版 C。该样本随后仍由数据集绑定的正式评估协议编译和测试，回退不等于测试通过。

当前默认只允许 C。SCCDec 官方模型和公开评估数据没有覆盖框架中的 C++、MBPP 和 ExeBench，
这些组合即使技术上能够运行，也应作为扩展实验单独报告。

## 2. 安装与启动模型

安装 API 依赖：

```bash
pip install -e '.[api,test]'
```

按照 SCCDec 官方方式启动基础模型和 LoRA：

```bash
vllm serve LLM4Binary/llm4decompile-6.7b-v1.5 \
  --port 8000 \
  --tensor-parallel-size 1 \
  --enable-lora \
  --lora-modules sccdec=ylfeng/sccdec-lora
```

这里的 `sccdec` 是服务端 LoRA 名称，也应作为配置中的 `model`。

本地 vLLM 通常不会校验 API Key。插件在环境变量未设置时使用非敏感占位值。如果服务端要求
鉴权，可设置：

```bash
export SCCDEC_API_KEY='your-key'
```

不要把真实 Key 写进准备提交的 `.yaml.example`。插件也允许本地 `.yaml` 使用 `api_key`，但不推荐。

## 3. 创建本地配置

复制示例；`.yaml` 是本地配置，不应提交：

```bash
cp configs/sccdec-decompile-eval-smoke.yaml.example \
   configs/sccdec-decompile-eval-smoke.yaml
```

核心配置如下：

```yaml
decompilers:
  - id: sccdec
    type: python
    plugin: plugins.sccdec_backend:SCCDecBackend
    required_inputs: [assembly, compile_context]
    batch_size: 4
    plugin_config:
      base_url: http://127.0.0.1:8000/v1
      model: sccdec
      mode: scc
      one_shot: false
      recompile_optimization: same
      max_concurrency: 4
```

`required_inputs` 中的 `compile_context` 是数据集提供的安全重编译上下文，仅包含：

- 编译器和编译参数；
- 公开头文件、类型定义和依赖声明；
- 链接第一版候选代码需要的公开依赖。

它不包含参考函数源码、测试程序、测试输入、期望输出或断言。该上下文只用于把第一版候选 C
重新编译成 SCC 示例，不会拼进模型的原始目标提示词。

## 4. 运行

先验证配置与参考数据：

```bash
python -m decomp_eval validate-config \
  --config configs/sccdec-decompile-eval-smoke.yaml

python -m decomp_eval validate-dataset \
  --config configs/sccdec-decompile-eval-smoke.yaml
```

运行评估：

```bash
python -m decomp_eval run \
  --config configs/sccdec-decompile-eval-smoke.yaml \
  --run-dir runs/sccdec-smoke
```

断点续跑：

```bash
python -m decomp_eval run \
  --config configs/sccdec-decompile-eval-smoke.yaml \
  --run-dir runs/sccdec-smoke \
  --resume
```

## 5. 配置项

| 配置 | 默认值 | 说明 |
|---|---:|---|
| `base_url` | `http://127.0.0.1:8000/v1` | OpenAI-compatible 服务地址 |
| `model` | `sccdec` | 模型或 LoRA 服务名称 |
| `mode` | `scc` | `fae` 或 `scc` |
| `one_shot` | `false` | 第一阶段前加入官方固定质数函数示例 |
| `recompile_optimization` | `same` | SCC 重编译跟随样本优化等级；也可固定为 `O0`–`O3` |
| `max_tokens` | `1024` | 每次模型生成上限 |
| `temperature` | `0` | 推理温度 |
| `max_retries` | `3` | 空输出或 API 异常的最大尝试次数 |
| `retry_backoff` | `1` | 指数退避初始秒数 |
| `compile_timeout` | `30` | 第一版候选重编译及 objdump 超时 |
| `max_concurrency` | `1` | 同一批次并行处理的样本数 |
| `objdump` | `objdump` | GNU objdump 命令或绝对路径 |
| `extra_body` | `{}` | 供应商或 vLLM 的附加请求字段 |

开启 `one_shot` 后，插件在 `prepare()` 中按本次数据的优化等级生成固定示例汇编，因此运行环境
必须能够调用 GCC 和 GNU objdump。

## 6. 样本产物

每个样本目录可能包含：

```text
sccdec_first_messages.json   第一阶段消息
sccdec_first_raw.txt         第一阶段原始响应
sccdec_first_candidate.c     第一版候选 C
sccdec_self_context.s        第一版 C 重新编译后的汇编
sccdec_second_messages.json  SCC 第二阶段完整消息
sccdec_second_raw.txt        第二阶段原始响应
sccdec_final_candidate.c     SCC 最终候选 C
sccdec_metadata.json         重试、编译、回退和最终阶段记录
```

正式的 `candidate.c`、编译日志、测试日志和指标仍由框架 Runner 与数据集评估协议统一生成。

## 7. 数据集建议

### decompile-eval HumanEval

推荐配置：

```yaml
splits: [humaneval]
assembly_view: asm
languages: [c]
```

这是当前最接近 SCCDec 官方评估的数据组合。框架 HumanEval C 有 656 条，即 164 个函数的
O0–O3 版本。不过框架中的汇编和 SCCDec 项目自带 JSON 并非逐字符一致，因此结果属于统一框架
口径，不应直接宣称复现论文表格。

### MBPP

可以选择 `languages: [c]` 运行，但属于模型分布外扩展评估。

### ExeBench

建议使用：

```yaml
assembly_view: objdump_att_instruction_only
languages: [c]
```

ExeBench 适配器会向 SCC 重编译阶段提供经过清洗的公开依赖。目标模型并未在 ExeBench 上公布
官方结果，因此报告时应与 HumanEval 官方近似口径分开。

## 8. 结果解释

`sccdec_metadata.json` 中：

- `scc_applied: true`：第一版 C 成功重编译，第二阶段成功产生最终代码；
- `scc_applied: false`：最终使用第一版 C；
- `fallback_reason: compile_error`：第一版 C 无法构造 SCC 上下文；
- `fallback_reason: second_inference_failed`：第二次 API 推理失败或返回空代码。

无论是否应用 SCC，最终候选都进入固定评估分母。只有正式数据集协议完成编译、链接并通过全部
测试，才计为 `behavioral_pass`。

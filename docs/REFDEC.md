# ReF-Dec 后端使用指南

框架通过 `plugins/refdec_backend.py` 接入 ReF-Dec（*ReF Decompile: Relabeling and Function Call Enhanced Decompile*）。该方法以标注后的 x86-64 AT&T 汇编为输入，使用模型的 function calling 能力查询 `.rodata` 数据，并生成完整 C 函数。

## 1. 隔离性

集成仅新增：

- `plugins/refdec_backend.py`
- `src/decomp_eval/datasets/refdec.py`
- `configs/refdec-decompile-eval-smoke.yaml` 及其 example
- 本文档
- `pyproject.toml` 中的 `refdec` optional extra

数据集注册只在 `BUILTIN_DATASETS` 追加 `refdec` 条目；未改动现有 backend、协议、数据类或现有配置。ReF-Dec 复用既有 `decompile_eval_exitcode` 协议。

## 2. 数据集

Adapter 读取 upstream 文件：

```text
code/ReF-Dec/data/decompile-eval-gcc-rodata.json
```

该 JSON 含 656 个 HumanEval GCC 反编译样本，每个样本已有：

- `asm_labeled`：将跳转和 RIP-relative 数据引用改为 `L*` / `D*` 标签的汇编；
- `address_mapping`：标签到 ELF 地址的映射；
- `rodata_addr` / `rodata_data`：`.rodata` 段基址和十六进制字节；
- `c_func` / `c_test`：参考函数与 assert 风格测试。

因此 benchmark 不需要针对这份数据集重新运行 `objdump`、`format_asm` 或 ELF `.rodata` 提取。Adapter 将 rodata 元数据存入既有的 `request.metadata["refdec_rodata"]`，不修改公共数据类。

## 3. 安装和部署

安装 API 依赖：

```bash
pip install -e '.[refdec]'
```

按官方方式启动模型：

```bash
vllm serve ylfeng/ReF-Decompile --port 8000 \
  --enable-auto-tool-choice \
  --tool-call-parser mistral
```

模型通过 OpenAI-compatible `/v1/chat/completions` endpoint 访问。若本地 vLLM 不要求鉴权，backend 使用 `not-required` 占位 key；若服务端要求鉴权：

```bash
export REFDEC_API_KEY='your-key'
```

## 4. 配置和运行

```bash
cp configs/refdec-decompile-eval-smoke.yaml.example \
   configs/refdec-decompile-eval-smoke.yaml

python -m decomp_eval validate-config \
  --config configs/refdec-decompile-eval-smoke.yaml

python -m decomp_eval validate-dataset \
  --config configs/refdec-decompile-eval-smoke.yaml

python -m decomp_eval run \
  --config configs/refdec-decompile-eval-smoke.yaml
```

关键 backend 配置：

```yaml
plugin_config:
  base_url: http://127.0.0.1:8000/v1
  model: ylfeng/ReF-Decompile
  api_key_env: REFDEC_API_KEY
  enable_tool: true
  temperature: 0.0
  max_tokens: 2048
  timeout: 300
```

`enable_tool: true` 是保真复刻默认值。关闭后 backend 不传 tools schema，可用于诊断工具调用对性能的贡献。

## 5. Tool calling 流程

1. backend 将 `asm_labeled` 发送给模型；
2. 模型可调用 `parse_data(data_label, data_type)`；
3. backend 从样本自带 `.rodata` 中按模型指定类型读取 `D*` 标签，并返回 tool result；
4. backend 执行一次 follow-up completion，提取 C markdown fence；
5. 既有 `decompile_eval_exitcode` 协议编译并执行候选代码。

为与 upstream `eval.py` 对齐，工具调用最多两轮：第一轮 + 一次带 tool result 的 follow-up。读取支持 `i8/u8/i16/u16/i32/u32/i64/u64/f32/f64/byte/word/dword/qword` 以及固定长度数组。

上游的 `float` / `double` 到 `f32` / `f64` 映射使用了比较运算符而非赋值。adapter 直接接受 ReF-Dec 原生类型集合，避免继承该 bug。

## 6. Artifact 与失败原因

每个样本产生：

| 文件 | 内容 |
|---|---|
| `refdec_prompt.txt` | 第一轮汇编 prompt |
| `refdec_response.txt` | 最终模型文本 |
| `refdec_metadata.json` | 模型、代码提取策略、tool calls 和结果 |

失败分类：

- `refdec_missing_assembly`：样本没有 labeled assembly；
- `refdec_empty_output`：模型没有输出候选代码；
- `refdec_pipeline_failed`：endpoint、tool-call JSON 或处理流程错误。

## 7. 评测边界

ReF-Dec 数据集与现有 decompile-eval HumanEval 样本同源但不完全相同：它额外提供了 `.rodata`、标注汇编和官方评测格式。因此应以独立 dataset id `refdec` 报告结果，避免与现有 HumanEval selection manifest 混合或直接合并统计。

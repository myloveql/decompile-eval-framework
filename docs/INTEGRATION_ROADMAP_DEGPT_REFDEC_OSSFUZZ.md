# 集成路线图：DeGPT + ReF-Dec + OSS-Fuzz

> **文档性质**：三合一集成方案（已批准实施）
> **框架定位**：长期维护的反编译评测 benchmark 工具（非一次性实验）。所有设计优先考虑接口稳定性、可扩展性、配置统一性。
> **核心约束**：**不影响现有框架**——新增文件为主，注册文件只追加，不删现有项；所有重依赖延迟导入，缺依赖只让该 backend 不可用。
> **产出粒度**：三合一总方案。按 M1 → M2 → M3 → M4 顺序实现，每步可独立验收。
> **调研依据**：已完成对现有 backend 接口契约、DeGPT 源码、ReF-Dec eval.py/demo.py、DecompileBench evaluate_cer/rsr.py 的逐行核查。
> **制定日期**：2026-07-20

---

## 目录

- [0. 背景与动机](#0-背景与动机)
- [1. 不影响现有框架的红线](#1-不影响现有框架的红线)
- [2. 共同遵守的集成规范](#2-共同遵守的集成规范)
- [3. DeGPT Backend（NDSS 2024）](#3-degpt-backendndss-2024)
- [4. ReF-Dec Backend（保真复刻）](#4-ref-dec-backend保真复刻)
- [5. OSS-Fuzz 数据集（完整 CER，分两阶段）](#5-oss-fuzz-数据集完整-cer分两阶段)
- [6. 实现顺序与里程碑](#6-实现顺序与里程碑)
- [7. 待实现时确认的开放问题](#7-待实现时确认的开放问题)
- [附录 A：调研证据索引](#附录-a调研证据索引)

---

## 0. 背景与动机

### 0.1 为什么做这件事

剔除 FidelityGPT 后（详见 `runs/fidelitygpt-full/PAPER_VS_IMPLEMENTATION_AUDIT.md` 的归因分析——其方法论设计边界与执行级评测不可通约），框架需要补位并扩展：

1. **DeGPT**：FidelityGPT 的主要对比基线（NDSS 2024），同代、同范式（LLM 优化伪代码），但本框架从未在执行级评测下测过它。
2. **ReF-Dec**（arxiv 2502.12221）：原生报 Re-executability Rate 的方法，与本框架执行级评测范式天然对齐。
3. **OSS-Fuzz**：真实开源项目函数（libpng/libxml2/openssl 等），拉开与算法题数据集（HumanEval/MBPP）的距离。

### 0.2 框架现状盘点

**已集成 backend（7 个）**：`agent4decompile`、`agent4decompile-improved`、`llm4decompile`、`sccdec`、`sk2decompile`、`binoracle`、`fidelitygpt`（剔除中）

**`code/` 下有源码但未集成的方法**：
- DeGPT（`code/DeGPT/`，纯 LLM 多轮调用）
- ReF-Dec（`code/ReF-Dec/`，已训练模型 + vLLM serve）

**数据维度缺口**：现有 selection manifest 只有 ExeBench/HumanEval/MBPP；`code/DecompileBench-main/` 里的 OSS-Fuzz 数据集尚未接入。

---

## 1. 不影响现有框架的红线

> 这是本方案的最高约束，所有实现细节都必须服从。

| # | 红线 | 如何保证 |
|---|---|---|
| 1 | **新增文件为主** | 三个 backend/dataset/protocol 全部是新文件；DeGPT 包重构在 `code/DeGPT/`（独立仓库，不在框架 `src/` 下） |
| 2 | **注册文件只追加** | `src/decomp_eval/{datasets,protocols}/__init__.py` 只在 `BUILTIN_*` 字典里追加新条目，**不删现有项、不改现有顺序** |
| 3 | **`pyproject.toml` 只追加** | 在 `[project.optional-dependencies]` 追加 `degpt`/`refdec`/`ossfuzz` 三个 extras，**不动现有 extras 和核心依赖** |
| 4 | **不动现有 backend/协议/runs/configs** | 现有 7 个 backend、2 个协议、所有 runs、所有 configs 一律不碰 |
| 5 | **重依赖延迟导入** | 所有重依赖（cinspector/openai/libclang/keystone 等）在 backend `__init__` 或 `prepare` 里 `try/except ImportError` → `RuntimeError("install with: pip install -e '.[xxx]'")`，缺依赖只让该 backend 不可用，不影响框架启动和其他 backend |
| 6 | **新协议/数据集独立注册** | `ossfuzz_rsr`/`ossfuzz_cer`/`refdec`/`ossfuzz` 都是新 id，不与现有 `decompile_eval_exitcode`/`exebench_json_io` 冲突 |
| 7 | **不改公共数据类** | `src/decomp_eval/models.py` 不改；如需扩展字段透传（ReF-Dec 的 rodata 元数据），优先用现有 `metadata` 字段，不改 dataclass 定义 |
| 8 | **DeGPT 重构隔离** | DeGPT 包重构改动都在 `code/DeGPT/degpt/` 内（独立 git repo），框架只通过 `plugins/degpt_backend.py` import 它，不污染框架 `src/` |

---

## 2. 共同遵守的集成规范

> 基于 `PythonPluginBackend`（`src/decomp_eval/backends/python_plugin.py`）和现存 7 个 backend 的实际契约确定。所有新 backend 必须满足。

### 2.1 类与方法签名

| 项 | 规范 | 依据 |
|---|---|---|
| 类定义 | `class XBackend:` （不强制继承基类，由 PythonPluginBackend 包装） | `python_plugin.py:16` |
| `__init__` | `def __init__(self, config: dict, **_):` 接收 yaml 的 `plugin_config` | `python_plugin.py:17` |
| 必须 | `def decompile(self, request: DecompileRequest, artifact_dir: Path) -> DecompileResult:` | `python_plugin.py:30-45` |
| 可选 | `prepare(self, requests) -> None`、`close(self) -> None`、`decompile_many(...)` | `python_plugin.py:21-59` |

### 2.2 数据类（来自 `src/decomp_eval/models.py`，不改）

```python
from decomp_eval.models import DecompileRequest, DecompileResult
from plugins.openai_compatible_backend import extract_candidate_code  # 复用代码提取
```

**`DecompileRequest`** 关键字段（`models.py:96-113`）：
- `assembly: AssemblyInput` — 总是存在（`text`/`syntax`/`view`）
- `pseudocode: PseudocodeInput | None` — 仅当 `required_inputs` 含 `pseudocode`
- `oracle_context: OracleContext | None` — 仅当 `required_inputs` 含 `oracle_context`
- `metadata: dict` — 公开元信息（backend 可读，**ReF-Dec rodata 元数据走这里**）
- `language`/`optimization`/`function_name` 等

**输入过滤机制**（`models.py:69-93`）：backend 能拿到什么**完全由 `required_inputs` 决定**。runner 在 `public_request` 里清空白名单外字段。

**`DecompileResult`**（`models.py:116-124`）：
```python
@dataclass
class DecompileResult:
    success: bool
    raw_output: str = ""
    code: str = ""              # 实际参与编译评估的候选代码
    reason: str | None = None   # 失败分类；成功时 None
    log: str = ""
    elapsed_seconds: float = 0.0
    backend_version: str = "unknown"
```

### 2.3 强制惯例

| 项 | 规范 |
|---|---|
| **失败处理** | 返回 `DecompileResult(success=False, reason="<prefix>_<category>", ...)`，**不抛异常**（runner 会兜底成 `decompiler_exception`，但应自己分类） |
| **artifact 落盘** | `artifact_dir.mkdir(parents=True, exist_ok=True)`；往里写 `<prefix>_*` 诊断文件（prompt/response/metadata.json） |
| **依赖管理** | `pyproject.toml` 加 `[project.optional-dependencies]` 新 extra；重依赖**延迟导入** + `try/except ImportError` → 友好 `RuntimeError("install with: pip install -e '.[xxx]'")` |
| **API key** | 用 `api_key_env: MY_VAR`，绝不硬编码 yaml；参考 `openai_compatible_backend.py:157-181` 的 `_resolve_api_key` |
| **version 指纹** | 把所有影响输出的因素（源码 sha256 + 模型 + 参数）拼进 `self.version`，进生成缓存键 |
| **配置成对** | yaml 写 `.yaml` + `.yaml.example` 两份（仓库惯例） |
| **文档** | `docs/<BACKEND>.md` 一篇 |

### 2.4 YAML 配置模板（最小新 backend）

```yaml
workspace_root: ../../..

datasets:
  - id: <dataset>
    type: <dataset_type>
    path: data/<path>
    selection_manifest: data/selections/<manifest>.json
    assembly_view: asm
    pseudocode_view: ghidra_pseudo      # 按需
    evaluation_protocol:
      type: decompile_eval_exitcode      # 或 exebench_json_io / 新协议
    languages: [c]
    optimizations: [O0, O1, O2, O3]
    limit: 10                            # smoke 用 limit，正式用 selection_manifest
    timeout: 30

decompilers:
  - id: <my-backend>-v1
    type: python
    plugin: plugins.my_backend:MyBackend
    version: my-backend-v1
    required_inputs: [assembly]          # 或 [pseudocode] / [binary, assembly, pseudocode]
    batch_size: 1
    plugin_config:
      model: <model-name>
      base_url: <url>
      api_key_env: MY_BACKEND_API_KEY
      temperature: 0.0

postprocessors: [markdown_fence]
metrics: [recompilable, behavioral_pass]

executor:
  type: local
  require_linux: true
  memory_mb: 4096
  max_file_mb: 64

preflight:
  mode: strict

output:
  root: runs
  cache: .cache/decomp-eval
```

### 2.5 `required_inputs` 合法值

`assembly` / `binary` / `pseudocode` / `compile_context` / `oracle_context`（`runner.py:434-449` 校验）。声明不准确会导致样本被跳过（产生 `<input>_missing` 失败结果）。

---

## 3. DeGPT Backend（NDSS 2024）

### 3.1 定位

FidelityGPT 的主要对比基线，填补剔除 FidelityGPT 后的位置。同代、同范式（LLM 优化伪代码）、但本框架从没在执行级评测下测过它。

- **输入**：伪代码（Ghidra/IDA 风格 C 函数）
- **`required_inputs`**：`["pseudocode"]`
- **输出**：优化后的 C 代码
- **LLM 调用预算**：每样本 1（referee）+ 0~3（advisor）= 1~4 次，无迭代循环

### 3.2 DeGPT 包重构（关键工程项）

> 决策：**重构为正规包**（而非 sys.path 注入）。理由：长期维护、可 rebase、import 干净。
> **隔离性**：所有改动都在 `code/DeGPT/degpt/` 内（独立 git repo），框架 `src/` 不受影响。

DeGPT 源码当前问题：裸 import、Unix-only signal、atexit 副作用、硬编码 config.ini。

**改动清单（最小侵入，可 rebase）**：

| # | 文件:行 | 原状 | 改动 |
|---|---|---|---|
| 1 | `degpt/__init__.py` | 不存在 | 新建（空文件，标记为包） |
| 2 | `degpt/role.py:25` | `from util import ...` | `from .util import ...` |
| 3 | `degpt/role.py:26` | `from mssc import ...` | `from .mssc import ...` |
| 4 | `degpt/role.py:27` | `from chat import ...` | `from .chat import ...` |
| 5 | `degpt/role.py:22-23` | `sys.path.append(DIR)` | 删除（相对 import 后不再需要） |
| 6 | `degpt/mssc.py:14-15` | `sys.path.append(...)` | 删除 |
| 7 | `degpt/chat.py:43` | `atexit.register(self.log_history)` | 加开关：`if os.environ.get("DEGPT_DISABLE_ATEXIT_LOG") != "1": atexit.register(...)` |
| 8 | `degpt/role.py:36-53` | `run_timer` 用 `signal.SIGALRM` | `platform.system() == "Windows"` 守卫，Windows 降级为 passthrough（当前是死代码，防御性处理） |
| 9 | `degpt/mssc.py:18-30` | 同上 | 同上 |

**仅 `role.py` 有 3 处裸 import**（已确认：chat.py/mssc.py/util.py/prompt.py 均无 intra-package 裸 import）。

**config.ini 策略**：
- 保留 `degpt/config.ini`（基于 `__file__` 定位，`chat.py:13-14`，跨平台安全）
- backend 在 `prepare` 时根据 yaml 配置**重写** config.ini 的 `[LLM]` 节（model/api_key/api_base），让框架统一管理凭证
- 重写逻辑加文件锁防并发

**不动的部分**：
- `mssc.py`（SemanticComparison）：当前代码路径是死代码（`Operator.operate` 的 SemanticComparison 调用被 `role.py:280-287` 注释），保留 import 但不启用，与上游一致
- `prompt.py`：独立编辑器脚本，不被 role.py 引用，顶层有 `print`+`assert` 副作用，**绝不 import**

### 3.3 DeGPT 调用流程（参考）

```
输入：单个 C 函数（伪代码字符串）
    ↓
[Referee] 1 次 LLM 调用 → 判断需要哪几类优化（simplify/comment/rename）
    ↓
[Advisor] 每类 1 次 LLM 调用 → 生成优化建议（最多 3 次）
    ↓
[Operator] 当前是 pass-through（mssc 验证被注释）
    ↓
输出：dic['output'] = 优化后 C 代码
```

**入口**：`RoleModel(decompile_code=code).work(end_at='DONE')` 返回 dict，`dic['output']` 是最终代码。绕过 CLI（`single_run`/`OUTPUT_DIR`/argparse）。

### 3.4 Backend 实现 `plugins/degpt_backend.py`

```python
class DeGPTBackend:
    version = "degpt-adapter-v1"
    required_inputs = ["pseudocode"]

    def __init__(self, config):
        # 校验 degpt_root、expected_commit
        # 计算源码 sha256 → version 指纹
        # 解析 chat config（model/base_url/api_key_env/temperature）

    def prepare(self, requests):
        # 延迟 import degpt.role.RoleModel（触发 cinspector 依赖检查）
        # 重写 degpt/config.ini [LLM] 节
        # 设环境变量 DEGPT_DISABLE_ATEXIT_LOG=1

    def decompile(self, request, artifact_dir):
        # 1. artifact_dir.mkdir(parents=True, exist_ok=True)
        # 2. code = request.pseudocode.text
        # 3. 写 degpt_input.c
        # 4. try:
        #        model = RoleModel(decompile_code=code)
        #        dic = model.work(end_at='DONE')
        #    except Exception as e:
        #        return DecompileResult(success=False, reason="degpt_pipeline_failed",
        #                               log=repr(e), backend_version=self.version)
        # 5. candidate = dic.get('output', '')
        # 6. 写 degpt_final.c、degpt_metadata.json
        #    （含 sorted_directions / advisor_responses / 各阶段 raw LLM 输出）
        # 7. if not candidate.strip():
        #        return DecompileResult(success=False, reason="degpt_empty_output", ...)
        # 8. return DecompileResult(success=True, raw_output=str(dic),
        #                           code=candidate, backend_version=self.version)

    def close(self):
        pass  # 无持久资源
```

### 3.5 依赖与文件清单

| 文件 | 动作 |
|---|---|
| `code/DeGPT/degpt/__init__.py` | 新建（DeGPT 仓库内） |
| `code/DeGPT/degpt/role.py` | 改 3 处 import + 删 sys.path + run_timer 守卫（DeGPT 仓库内） |
| `code/DeGPT/degpt/mssc.py` | 删 sys.path + run_timer 守卫（DeGPT 仓库内） |
| `code/DeGPT/degpt/chat.py` | atexit 开关（DeGPT 仓库内） |
| `plugins/degpt_backend.py` | 新建（框架内） |
| `configs/degpt-pseudocode-smoke.yaml` + `.example` | 新建 |
| `docs/DEGPT.md` | 新建 |

**`pyproject.toml` 新增 extra**（只追加）：
```toml
degpt = [
    "openai>=1.28",
    "tiktoken>=0.2",
    "python-levenshtein",
    "cinspector @ git+https://github.com/PeiweiHu/cinspector",
]
```

**最大风险**：`cinspector`（依赖 tree-sitter + tree-sitter-c 的 C AST 库，非 PyPI 主流）。

**⚠️ 验收前置任务**：在目标环境（Linux/WSL，因为 `executor.require_linux=true`）先验证 `from cinspector.interfaces import CCode` 能 import 成功，再写 backend。若失败需 fallback 到 sys.path 注入方案（见 §7 开放问题 2）。

### 3.6 验收标准

- [ ] `python -m decomp_eval run configs/degpt-pseudocode-smoke.yaml` 在 5~10 样本上跑通
- [ ] artifact 目录有 `degpt_input.c`、`degpt_final.c`、`degpt_metadata.json`
- [ ] 不在 cwd 产生 `chat_log.json`（验证 atexit 开关生效）
- [ ] recompilable 率有合理数字（预期类似 FidelityGPT 量级，因为同样是伪代码优化、不补头文件——这本身是 DeGPT 的设计边界）
- [ ] **现有 backend 不受影响**（跑一个现有 config 确认未回归）

---

## 4. ReF-Dec Backend（保真复刻）

### 4.1 定位

原生报 Re-executability Rate 的方法（arxiv 2502.12221），与本框架执行级评测天然对齐。

- **输入**：汇编（x86-64 AT&T）
- **`required_inputs`**：`["assembly"]`（+ rodata 元数据走 `metadata` 字段）
- **评测协议**：**直接复用现有 `decompile_eval_exitcode`**，不写新协议
- **集成深度**：**档位 2（保真复刻）**——实现 tool-call 两段式循环 + rodata 数据段解析

### 4.2 关键利好：数据集自带预处理产物

调研发现 ReF-Dec 的 `data/decompile-eval-gcc-rodata.json`（656 条）**预计算好了**：
- `asm_labeled`（标准化汇编，地址已替换成 L0/D0 标签）
- `address_mapping`（label → 地址 + bias）
- `rodata_data`（hex 字符串）
- `rodata_addr`（.rodata 段地址）

**因此可以完全省掉 `format_asm` + `objdump` + `extract_function_rodata`**（这几个只在 demo.py 处理新二进制时需要）。backend 只需实现 tool-call 两段式循环 + rodata 解析。

### 4.3 模型部署

用户需先：
```bash
vllm serve ylfeng/ReF-Decompile --port 8000 \
    --enable-auto-tool-choice --tool-call-parser mistral
```

- **模型**：Mistral 系 LoRA merged 权重（预计 7B，单卡 ~14-16GB fp16）
- **OpenAI 兼容**：是，暴露 `/v1/chat/completions`
- **tool-call parser**：`mistral`（适配 Mistral 官方 chat template 的 tool-call 文法）
- **显存**：需先 `huggingface-cli download ylfeng/ReF-Decompile` 确认 config.json 的确切参数量

backend 通过 OpenAI 兼容 endpoint 调用，`base_url` 在 yaml 配置。`docs/REFDEC.md` 写清部署 checklist。

### 4.4 tool-call 两段式循环（参考 `eval.py:234-365`）

```
输入：asm_labeled（带 D0/L0 标签的汇编）
    ↓
[第一轮] client.chat.completions.create(messages, tools=TOOLS)
    ↓
分支：response.tool_calls 非空？
    ├─ 是 → 循环处理每个 tool_call:
    │       parse_data(data_label, data_type)
    │         → read_data(rodata_data, address_mapping, label, dtype)
    │         → render_rodata（格式化回填值）
    │       拼 tool result message
    │   [第二轮] client.chat.completions.create(messages + tool_results, tools=TOOLS)
    │   → 取最终 content
    └─ 否 → 直接取第一轮 content
    ↓
输出：从 markdown 围栏提取 C 代码
```

**固定 2 轮**（第一轮 + 一个 follow-up），无重试机制。

### 4.5 Backend 实现 `plugins/refdec_backend.py`

```python
class ReFDecBackend:
    version = "refdec-adapter-v1"
    required_inputs = ["assembly"]

    def __init__(self, config):
        # 校验 base_url/model/api_key_env
        # 解析 enable_tool（默认 True）、temperature、max_tokens、timeout、max_retries

    def prepare(self, requests):
        # 延迟 from openai import OpenAI
        # 准备 client

    def decompile(self, request, artifact_dir):
        # 1. asm_labeled, address_mapping, rodata_addr, rodata_data =
        #       从 request.metadata["refdec_rodata"] 取（见 §4.6）
        # 2. messages = [{"role":"user",
        #                 "content":"What is the c source code of the assembly code below:\n\n" + asm_labeled}]
        # 3. 第一轮: resp = client.chat.completions.create(
        #        messages, tools=TOOLS if enable_tool else None, ...)
        # 4. if resp.choices[0].message.tool_calls:
        #        for tc in tool_calls:
        #            parse arguments (data_label, data_type)
        #            result = read_data(rodata_data, address_mapping, label, dtype)
        #            messages.append(tool_result_message)
        #        第二轮: resp = client.chat.completions.create(messages + tool_results, ...)
        # 5. candidate, policy = extract_candidate_code(resp.choices[0].message.content)
        # 6. 写 refdec_prompt.txt、refdec_response.txt、refdec_metadata.json
        #    （含 tool_calls 记录、每个 read_data 的结果）
        # 7. return DecompileResult(success=True, raw_output=..., code=candidate,
        #                           backend_version=self.version)
```

**复刻的常量**（从 ReF-Dec 搬进 backend 作为模块级常量）：
- `TOOLS`（`parse_data` 函数 schema，`eval.py:30-53`）
- `STRUCT_MAPPING`（i8/u8/.../qword → struct 格式符 + 字节数，`eval.py:173-188`）
- `read_data`、`render_rodata` 纯函数（`eval.py:191-209`）

### 4.6 数据集 adapter `src/decomp_eval/datasets/refdec.py`

ReF-Dec 数据集与 `decompile-eval` 同源（HumanEval GCC + rodata 增强）。新增 adapter：

```
读 data/decompile-eval-gcc-rodata.json（656 条）
    ↓
产出 CanonicalSample:
  - assembly.text = asm_labeled（模型训练分布）
  - metadata["refdec_rodata"] = {address_mapping, rodata_addr, rodata_data}
    （工具服务端数据，走标准 metadata 字段，不给模型看）
  - OracleContext = {c_func, c_test}（走 decompile_eval_exitcode）
    ↓
注册到 BUILTIN_DATASETS，type: refdec（追加，不删现有）
```

**契约方案**：rodata 元数据走 `request.metadata["refdec_rodata"]`（标准字段，`repr=True`，backend 可读）。**不改 dataclass 定义**。

### 4.7 上游 bug 标注（实现时修正）

| 位置 | bug | 修正 |
|---|---|---|
| `eval.py:289` | `parsed_data_type == "f32"` 是比较而非赋值 | float/double 类型实际不会替换成 f32/f64，改为 `=` |
| `eval.py:542-546` | `--enable-tool` 用 `action="store_true"` + `default=True`，命令行无法关闭 | backend 的 `enable_tool` 用 yaml 配置覆盖 |
| `demo.py:462` | 同 `eval.py:289` 的 float/double bug | 同上 |

### 4.8 依赖与文件清单

| 文件 | 动作 |
|---|---|
| `plugins/refdec_backend.py` | 新建（含 TOOLS/STRUCT_MAPPING/read_data/render_rodata + tool-call 循环） |
| `src/decomp_eval/datasets/refdec.py` | 新建 |
| `src/decomp_eval/datasets/__init__.py` | **追加**注册 `refdec`（不删现有） |
| `configs/refdec-decompile-eval-smoke.yaml` + `.example` | 新建 |
| `docs/REFDEC.md` | 新建（含 vllm serve 部署说明） |

**`pyproject.toml` 新增 extra**（只追加）：
```toml
refdec = ["openai>=1.70"]   # 轻，rodata 解析只用 stdlib struct
```

**最大风险**：用户侧 vLLM 部署（显存 + mistral tool-call parser 兼容性）。

### 4.9 验收标准

- [ ] vLLM serve 起来后，smoke 5~10 样本跑通
- [ ] tool_calls 在 metadata.json 里有记录（验证 tool calling 生效）
- [ ] recompilable/behavioral_pass 数字与论文趋势一致（ReF-Dec 应明显优于 LLM4Decompile-End ~48%）
- [ ] enable_tool=False 时走 fallback 路径不崩
- [ ] **现有 backend 不受影响**

---

## 5. OSS-Fuzz 数据集（完整 CER，分两阶段）

### 5.1 定位

真实开源项目函数（libpng/libxml2/openssl 等），代表"野外"复杂度，拉开与算法题数据集的距离。

- **性质**：**数据集 + 协议**（不引入新 backend）
- **所有现有 backend**（Agent4Decompile/LLM4Decompile/sccdec/DeGPT/ReFDec）都能在 OSS-Fuzz 上跑
- **这是"数据集维度扩展"而非"方法扩展"**
- **分两阶段**：先 RSR（轻、可独立验收），后 CER（重、需 OSS-Fuzz 项目 build）

### 5.2 指标映射

| DecompileBench 指标 | 含义 | 本框架对应 | 映射关系 |
|---|---|---|---|
| **RSR** (Re-compilable Success Rate) | 反编译 C 代码能否编成 .so | `recompilable` | **一一对应**，可直接复用 |
| **CER** (Coverage Equivalence Rate) | fuzzer 语料驱动下，与 ground truth 的逐行覆盖率是否一致 | `behavioral_pass` | **不能直接映射**（粒度/oracle/工具链都不同），需新协议 |

### 5.3 数据集 adapter `src/decomp_eval/datasets/ossfuzz.py`

读 DecompileBench 构建产物（`$dataset_path/eval` + `compiled_ds` HF arrow + `binary/task-*.so`）：

```
样本粒度：一条样本 = 一个函数（来自真实 OSS-Fuzz C/C++ 项目）
字段：
  - project（如 file/libprotobuf-mutator）
  - file（函数名，作为文件 stem）
  - func（函数源码）
  - include（前置宏/结构体定义/prologue）
  - addr（函数在 .so 里的地址）
  - opt（O0/O1/O2/O3/Os）
  - path（指向 binary/task-*.so）

产出 CanonicalSample:
  - assembly = 对 .so 跑 objdump（或读数据集预存的 asm）
  - compile_context.prelude = include 字段
  - private_payload = {func, path, addr, project, fuzzer, corpus_path}
  - language 从 project.yaml 推断（c/c++）
```

**数据来源门槛**：用户需先按 DecompileBench README 跑 `compile_ossfuzz.py`：
1. clone oss-fuzz repo + checkout 指定 commit
2. apply 3 个 patch（`oss-fuzz-patch/01-detailed-llvm-cov.diff` 等）
3. `python infra/helper.py build_image base-builder/base-runner`
4. 跑 `compile_ossfuzz.py` 产出 task-*.so

`docs/OSSFUZZ.md` 写清前置准备 checklist。

**Oracle 充分性**：
- 有原函数源码 → 可做参考预检 / readability
- **没有 assert-style 单元测试** → 行为正确性靠 fuzzer 语料 + llvm-cov 覆盖率差异（CER）
- RSR 易复现，CER 必须依赖 fuzzer 二进制 + 语料库

### 5.4 阶段 1：RSR 协议（轻量，先做）

新协议 `src/decomp_eval/protocols/ossfuzz_rsr.py`，对应 DecompileBench 的 RSR（`evaluate_rsr.py`）：

```
evaluate_candidate(code, sample, executor, workdir):
  1. fixer = importlib.import_module("fix." + compiler)  # 每个反编译器专属修正
  2. fixed_code = fixer.fix(code, function_name)          # 修常见语法问题
  3. static_code = make_function_static(fixed_code)       # libclang 改 static 避免符号冲突
  4. injected = inject_template(static_code)              # TEMPLATE: mmap 0xbabe0000 写函数指针
  5. clang -shared -fPIC -fcoverage-mapping ... → libfunction.so
  6. 成功判定：clang returncode == 0
```

**能力声明**（`ProtocolDescriptor`）：
```python
capabilities = ("candidate_compile", "shared_object_compile")
compile_unit = "candidate_only"
test_granularity = "compile_only"
comparator = "clang_compile_success"
protocol_id = "ossfuzz_rsr"
version = "1"
```

**Docker 依赖**：仅需 `gcr.io/oss-fuzz-base/base-builder`（含 clang + libclang）。轻量。

**`fix/` 模块**：从 DecompileBench 搬 `fix/{compiler}.py`，作为 protocol 内部步骤（独立目录，不动框架现有 postprocessor）。

**最小依赖**：clang + libclang（`LIBCLANG_PATH`）+ fix 模块 + TEMPLATE。**不需要** ld.so/libfunction.so 预编译版/fuzzer/corpus/llvm-cov。

### 5.5 阶段 2：CER 协议（重量，后做）

新协议 `src/decomp_eval/protocols/ossfuzz_cer.py`，对应 DecompileBench 的 CER（`evaluate_cer.py`）：

```
evaluate_candidate(code, sample, executor, workdir):
  前置：base_libfunction.so（ground truth 编译）+ target_libfunction.so（反编译器输出编译）

  对每个 fuzzer:
    1. patch_fuzzer: 用 keystone 把 fuzzer 入口改成 jmp 0xbabe0000（跳到替换后的函数）
    2. 跑 base: LD_PRELOAD=ld.so ./patched_fuzzer -runs=0 -seed=... /corpus/...
       → llvm-profdata merge + llvm-cov show → base.txt（逐行覆盖率）
    3. 跑 target: 同上，链接 target_libfunction.so → target.txt
    4. 逐行 diff：所有行覆盖率集合一致 → 该 fuzzer pass

  成功判定：所有 fuzzer 都 pass
```

**Docker 依赖**（重）：
- `gcr.io/oss-fuzz/{project}` 每个 target 项目镜像（含 fuzzer + corpus）
- `ld.so`（LD_PRELOAD 修复 PLT 重定位）
- `keystone-engine`（patch_fuzzer 用）
- `llvm-profdata` + `llvm-cov`

**patched llvm-cov 的处理**：
- 调研发现当前 DecompileBench 代码里 patched llvm-cov 的挂载**被注释掉了**（`extract_functions.py:436`）
- 实际用容器自带官方 llvm-cov，set-based diff 能容忍格式差异
- **方案：先用官方 llvm-cov，diff 噪声大时再挂载 patched 版**

**ld.so/libfunction.so**：用 DecompileBench 仓库预编译版（`ld.so`/`libfunction.so`/`ld.c`/`dummy.c`），docs 说明如何重新编译。

**最小可评测单元**：CER 本质依赖运行 fuzzer binary，而 fuzzer 是 OSS-Fuzz 项目特定的，无法脱离项目镜像运行。CER 的最小依赖实际上是"整个 OSS-Fuzz 项目 build pipeline"。

### 5.6 Backend 侧（零工作）

OSS-Fuzz 是**数据集 + 协议**，不引入新 backend。所有现有 backend 都能在 OSS-Fuzz 数据集上跑，用 RSR 或 CER 协议评测。

### 5.7 依赖与文件清单

| 文件 | 动作 | 阶段 |
|---|---|---|
| `src/decomp_eval/datasets/ossfuzz.py` | 新建 | 1 |
| `src/decomp_eval/datasets/__init__.py` | **追加**注册 `ossfuzz` | 1 |
| `src/decomp_eval/protocols/ossfuzz_rsr.py` | 新建 | 1 |
| `src/decomp_eval/protocols/__init__.py` | **追加**注册 `ossfuzz_rsr` | 1 |
| `fix/`（从 DecompileBench 搬，独立目录） | 新建 | 1 |
| `configs/ossfuzz-rsr-smoke.yaml` + `.example` | 新建 | 1 |
| `docs/OSSFUZZ.md`（含 oss-fuzz build 前置说明） | 新建 | 1 |
| `src/decomp_eval/protocols/ossfuzz_cer.py` | 新建 | 2 |
| `src/decomp_eval/protocols/__init__.py` | **追加**注册 `ossfuzz_cer` | 2 |
| `configs/ossfuzz-cer-smoke.yaml` + `.example` | 新建 | 2 |
| `third_party/ossfuzz/{ld.so, libfunction.so, ld.c, dummy.c}` | 搬入 | 2 |

**`pyproject.toml` 新增 extra**（只追加）：
```toml
ossfuzz = [
    "libclang",              # make_function_static
    "keystone-engine",       # patch_fuzzer（CER 用）
    "pyelftools>=0.31",      # ELF 解析
]
# Docker 作为运行时依赖，文档化（非 pip 可装）
```

### 5.8 验收标准

**RSR（阶段 1）**：
- [ ] 在 5~10 个预 build 的 OSS-Fuzz 样本上，反编译器输出能跑通 clang 编译判定
- [ ] 多个 backend 在 OSS-Fuzz 数据集上有差异化结果（证明数据集有区分度）
- [ ] **现有 backend/协议不受影响**

**CER（阶段 2）**：
- [ ] 在 1 个完整 build 的 OSS-Fuzz 项目（如 `file`）上，base/target 覆盖率 diff 能产出
- [ ] CER 数字与 DecompileBench 论文趋势一致

---

## 6. 实现顺序与里程碑

| 里程碑 | 内容 | 前置依赖 | 验收 |
|---|---|---|---|
| **M1** | DeGPT 包重构 + backend | 验证 cinspector 可 import（Linux/WSL） | smoke 跑通 |
| **M2** | ReF-Dec backend + 数据集 adapter | 用户起 vLLM serve | smoke 跑通 + tool_calls 记录 |
| **M3** | OSS-Fuzz 数据集 + RSR 协议 | 用户预 build oss-fuzz base-builder | RSR smoke 跑通 |
| **M4** | OSS-Fuzz CER 协议 | 用户预 build 至少 1 个 oss-fuzz 项目镜像 | CER smoke 跑通 |

**每阶段独立交付，互不阻塞**。M1/M2 纯软件（无 Docker），M3/M4 需用户侧 oss-fuzz build（docs 提供 checklist）。

**推荐执行顺序**：M1 → M2 → M3 → M4。每个里程碑完成后汇报验收结果再进入下一个。

### 每个里程碑的回归检查（强制）

每完成一个里程碑，必须验证**现有框架未受影响**：
1. 跑一个现有 backend 的 smoke（如 `llm4decompile-smoke.yaml`）确认未回归
2. `python -m decomp_eval list-plugins`（或等价命令）确认现有 backend 仍可枚举
3. 确认 `pyproject.toml` 改动只是追加（git diff 检查）

---

## 7. 待实现时确认的开放问题

> 这些问题不阻塞方案批准，实现相应里程碑时验证。

1. **ReF-Dec rodata 元数据透传**：`request.metadata` 是否被 runner 允许传自定义字段给 backend。实现 M2 时先测 `models.py:69-93` 的 `public_request` 白名单行为——`metadata` 是标准字段应可透传，若不行 fallback 到 `compile_context.prelude` 编码。

2. **DeGPT `cinspector` 在 Linux 上的可用性**：M1 前置验证任务。若 `from cinspector.interfaces import CCode` 失败，fallback 到 sys.path 注入方案（保留裸 import，backend 用 `sys.path.insert` + `import role`，不重构 DeGPT）。

3. **OSS-Fuzz patched llvm-cov 必要性**：先用官方版跑 CER，diff 噪声大再挂载 patched 版（`extract_functions.py:436` 的注释行）。

4. **ReF-Dec 数据集与现有 decompile-eval 重叠**：ReF-Dec 的 656 条来自 HumanEval GCC，可能与现有 HumanEval 样本重叠——是否需要去重或标记为独立数据集（`type: refdec` 独立注册已避免 id 冲突，但样本内容重叠需在分析时注意）。

5. **DeGPT config.ini 并发重写**：多进程跑 DeGPT 时 config.ini 重写需文件锁（`fcntl` Linux-only），或改用环境变量注入（monkeypatch `chat.load_config`）。

---

## 附录 A：调研证据索引

### DeGPT
- 主流程：`code/DeGPT/degpt/role.py:463-595`（RoleModel.work）
- 裸 import：`role.py:25-27`（仅此 3 处）
- sys.path 注入：`role.py:22-23`、`mssc.py:14-15`
- config.ini 定位：`chat.py:13-14`（基于 `__file__`）
- atexit 副作用：`chat.py:43, 62-73`
- run_timer（SIGALRM）：`role.py:36-53`、`mssc.py:18-30`（死代码）
- mssc 死代码：`role.py:280-287`（SemanticComparison 调用被注释）
- LLM 调用：`chat.py:75-106`（openai SDK，temperature=0.2 硬编码，无 retry/timeout）

### ReF-Dec
- 模型部署：`code/ReF-Dec/README.md:11`
- tool-call 循环：`eval/eval.py:234-365`（固定 2 轮）
- TOOLS 定义：`eval.py:30-53`
- STRUCT_MAPPING/read_data/render_rodata：`eval.py:129-209`
- 数据集字段：`data/decompile-eval-gcc-rodata.json`（656 条，自带 asm_labeled/address_mapping/rodata_data）
- float/double bug：`eval.py:289`、`demo.py:462`
- enable_tool 开关：`eval.py:268, 344`（tools=None 时不发 schema）

### OSS-Fuzz / DecompileBench
- 数据集构建：`code/DecompileBench-main/compile_ossfuzz.py:101-224`
- RSR 编译判定：`evaluate_rsr.py:204-292`
- TEMPLATE（mmap 跳板）：`evaluate_rsr.py:150-183`
- make_function_static：`evaluate_rsr.py:101-139`
- CER fuzzer patch + 覆盖率比对：`evaluate_cer.py:33-43, 166-281`
- patched llvm-cov 挂载被注释：`extract_functions.py:436`
- 三个预编译产物：`DecompileBench-main/{libfunction.so, ld.so, llvm-cov}` + `ld.c`, `dummy.c`
- ld.so 用途（LD_PRELOAD 修复 PLT）：`ld.c:159-190`
- config：`DecompileBench-main/config.yaml`

### 本框架接入点
- 协议注册：`src/decomp_eval/protocols/__init__.py:5-6`（只追加）
- 数据集注册：`src/decomp_eval/datasets/__init__.py:5-6`（只追加）
- `decompile_eval_exitcode` 协议（ReF-Dec 复用）：`src/decomp_eval/protocols/decompile_eval.py:11-72`
- DecompileEval adapter（ReF-Dec 近亲）：`src/decomp_eval/datasets/decompile_eval.py:16-113`
- Backend 接口：`src/decomp_eval/interfaces.py:41-54`
- `PythonPluginBackend` 包装层：`src/decomp_eval/backends/python_plugin.py:11-59`
- 数据类：`src/decomp_eval/models.py:8-194`（不改）
- `extract_candidate_code`：`plugins/openai_compatible_backend.py:23-38`（复用）
- extras 声明：`pyproject.toml:12-20`（只追加）
- 扩展指南（权威）：`docs/EXTENDING.md`

---

*本方案基于对现有 backend 接口契约、DeGPT 源码、ReF-Dec eval.py/demo.py、DecompileBench evaluate_cer/rsr.py 的逐行核查制定。核心约束：**不影响现有框架**——所有改动以新增为主，注册文件只追加，重依赖延迟导入隔离。按 M1→M2→M3→M4 顺序实施，每个里程碑含回归检查。*

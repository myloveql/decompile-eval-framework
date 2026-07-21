# BinOracle 后端

BinOracle 通过框架的 Python Backend 接入。框架仍负责样本选择、生成缓存、候选后处理、
参考预检和正式隐藏测试；BinOracle 只使用显式公开的二进制、汇编和初始伪代码。

当前版本为 `binoracle-backend-v3-phase3a`。它保留了
`binoracle-backend-v1-sprint1` 的已知契约Runner，并开始实施自动契约自举协议。V1已经完成
`binOracle_v1.md` 最后一节定义的近期Sprint：

1. ELF 符号、重定位、全局和依赖事实；
2. x86-64 SysV 已知契约 ABI trampoline；
3. 原始 `target.o` Runner、guard page、崩溃和超时隔离；
4. `InputCase → Observation` JSON 协议。

本 Sprint 不编译候选、不进行原始/候选差分、不调用 LLM，也不会修改数据集提供的候选 C。

## 五种模式

### `static_passthrough`

静态基线：

- 验证 ELF64、x86-64 和 ET_REL；
- 提取完整 ELF 事实；
- 从公开汇编生成保守静态契约；
- 对 `void_or_unknown` 禁止比较 RAX；
- 将初始 Ghidra C 原样交给框架正式评估。

后端 ID 建议使用：

```text
binoracle-static-mvp1
```

### `dynamic_audit`

已知契约 Runner 验证模式：

- 从显式 `contract_manifest` 读取人工 fixture 契约和 InputCase；
- 构建 `original_runner.x`；
- 每个 InputCase fork 一个隔离子进程；
- 调用原始 `target.o` 中的目标函数；
- 观察返回状态、参数对象、简单全局、崩溃、超时和 guard-page 故障；
- 候选代码仍保持不变。

后端 ID 建议使用：

```text
binoracle-dynamic-audit-v1-sprint1
```

已知契约可能来自人工签名，因此该模式当前用于验证动态 Oracle 本身，不能作为“自动契约恢复”
方法与其他反编译器公平比较。后续完成 Top-k 自动契约恢复后，应使用新的 backend ID。

此外，`contract_probe`生成并动态评分自动契约，`contract_audit`执行确定性审计与
Harness冻结，`differential`使用冻结Harness进行原始/候选双轨执行。`dynamic_repair`
尚未实现；配置该模式会明确失败。

## 支持边界

动态模式当前支持：

- Linux/WSL x86-64；
- ELF64 ET_REL；
- C 和 System V AMD64 ABI；
- RDI、RSI、RDX 最多三个整数或一级指针参数；
- 单个指针对象，总大小不超过 16 KiB；
- `void`、整数或指向已知对象的指针返回；
- 最多 32 个可导出简单全局，每个最多观察 256 字节；
- `memcpy`、`memset`、`malloc` 等白名单 libc；
- 每样本最多 1000 次执行。

不支持：

- Windows 原生执行、非 x86-64 或非 ET_REL；
- XMM/浮点、按值结构体、二级指针、复杂别名、变参和 C++；
- 未知外部项目依赖；
- 自定义全局初值；
- 多对象输入；
- 候选编译、差分、Top-k 动态契约和 LLM 修复；
- 完整安全沙箱和网络命名空间隔离。

不支持的样本使用 `binoracle_unsupported_*` 失败分类，并在 `binoracle_metadata.json` 写入
`unsupported_reason`，不会进入错误 Harness。

## 安装

在 Linux/WSL 中：

```bash
pip install -e '.[binoracle]'
```

还需要：

```bash
gcc --version
```

`pyelftools` 是 BinOracle 的可选依赖：静态单元测试保留最小 ELF64 fallback parser，
`dynamic_audit` 启动时则强制要求安装 `pyelftools`。

## 数据准备

先将保存的完整翻译单元汇编构建成 ELF ET_REL：

```bash
python tools/exebench/build_binoracle_objects.py \
  --input ../../data/exebench/1641-Benchmark/exebench_1641_source_multiopt_1100.with-ghidra.dataset.json \
  --output ../../data/exebench/1641-Benchmark/exebench_1641_binoracle.with-ghidra.dataset.json \
  --object-root ../../data/exebench/1641-Benchmark/binoracle-objects
```

正式构建应使用 Linux/WSL 中与参考数据一致的 GCC。构建器会验证输出为 ET_REL。

数据集必须隐藏参考签名：

```yaml
expose_signature_metadata: false
```

后端只允许：

```yaml
required_inputs: [binary, assembly, pseudocode]
```

禁止加入 `compile_context` 或 `oracle_context`。

## 已知契约清单

复制示例：

```bash
cp configs/binoracle-known-contracts.json.example \
   configs/binoracle-known-contracts.json
```

清单可以按 `sample_id` 定义：

```json
{
  "schema_version": 1,
  "samples": {
    "dataset:sample:O0": {
      "contract": {
        "contract_id": "K1",
        "arguments": [
          {"slot": "RDI", "kind": "pointer", "object_ref": "obj0"},
          {"slot": "RSI", "kind": "integer"}
        ],
        "return": {"kind": "void", "observable": false},
        "objects": [
          {"object_id": "obj0", "argument_slot": "RDI", "min_size": 64}
        ]
      },
      "inputs": []
    }
  }
}
```

也可以用顶层 `functions` 按函数名匹配。`inputs` 为空时生成一个确定性的全零最小输入。

指针可以指向对象：

```json
"RDI": {"object_ref": "obj0"}
```

也可以显式为空：

```json
"RDI": {"null": true}
```

对象支持左右贴边，用于识别不同越界方向：

```json
{
  "size": 64,
  "bytes_hex": "...恰好 64 字节...",
  "placement": "right"
}
```

## 动态配置

复制：

```bash
cp configs/binoracle-dynamic-audit-smoke.yaml.example \
   configs/binoracle-dynamic-audit-smoke.yaml
```

核心配置：

```yaml
decompilers:
  - id: binoracle-dynamic-audit-v1-sprint1
    type: python
    plugin: plugins.binoracle_backend:BinOracleBackend
    required_inputs: [binary, assembly, pseudocode]
    batch_size: 1
    plugin_config:
      mode: dynamic_audit
      strict_privacy: true
      require_relocatable: true
      abi: sysv-x86_64
      contract_manifest: configs/binoracle-known-contracts.json
      runner_compiler: gcc
      runner_execution_timeout_ms: 100
      max_executions: 1000
```

`batch_size: 1` 是当前建议值，便于控制编译器和子进程资源。

## Runner 结构

运行时位于：

```text
plugins/binoracle/runtime/
├── abi_trampoline.S
├── binoracle_runtime.h
├── guard_memory.c
├── observation.c
├── runner_main.c
└── CMakeLists.txt
```

链接关系：

```text
runtime + generated target_binding.c + target.o → original_runner.x
```

汇编 trampoline 根据 `CallFrame` 加载 RDI、RSI、RDX、RCX、R8、R9，保持 SysV 栈对齐，
间接调用目标并保存 RAX/RDX。

每个 InputCase 都在独立 fork 子进程中运行。子进程设置 CPU、地址空间、文件大小和进程数
限制；父进程执行毫秒级超时并在超时时 SIGKILL 子进程。目标 stdout/stderr 被重定向，不能
破坏 Runner JSON。

参数对象通过 `mmap + mprotect` 放置在两个 `PROT_NONE` guard page 之间。左右贴边能分别捕获
负偏移和正向越界。报告只保存 `obj0_left_guard`、`obj0_right_guard` 和相对偏移，不保存
ASLR 绝对地址。

## Observation 语义

正常返回：

```json
{
  "schema_version": 1,
  "contract_id": "K1",
  "status": "returned",
  "signal": null,
  "return": {"valid": false, "reason": "void_or_unknown"},
  "objects": {
    "obj0": {
      "size": 64,
      "before_sha256": "...",
      "after_sha256": "...",
      "changed_ranges": [[8, 12]],
      "after_bytes_hex": "..."
    }
  },
  "globals": {},
  "elapsed_us": 17
}
```

`void` 或未知返回始终忽略原始 RAX，避免寄存器残值产生假差异。指针返回只有落在已知对象
中时才规范化为 `object + offset`；其他指针标记为 `not_comparable`。

故障示例：

```json
{
  "status": "signal",
  "signal": "SIGSEGV",
  "fault_address_class": "obj0_right_guard",
  "object": "obj0",
  "relative_offset": 68
}
```

## 审计产物

每个样本包含：

```text
binoracle_public_request.json
binoracle_initial.c
binoracle_final.c
binoracle_metadata.json
binoracle/
├── binary_facts.json
├── symbols.json
├── relocations.json
├── dependencies.json
├── contract_candidates.json
├── selected_contract.json
├── observation_policy.json
├── harness_manifest.json
├── target_binding.c
├── runner_build.json
├── original_runner.x
├── generated_inputs.jsonl
├── original_observations.jsonl
├── probe_history.jsonl
├── candidate_observations.jsonl
├── differences.jsonl
└── dynamic_summary.json
```

当前 `candidate_observations.jsonl` 和 `differences.jsonl` 有意为空，避免把未实现的差分伪装成
实验结果。

## 运行

```bash
python -m decomp_eval validate-config \
  --config configs/binoracle-dynamic-audit-smoke.yaml

python -m decomp_eval validate-dataset \
  --config configs/binoracle-dynamic-audit-smoke.yaml \
  --run-dir runs/binoracle-reference-preflight

python -m decomp_eval run \
  --config configs/binoracle-dynamic-audit-smoke.yaml \
  --run-dir runs/binoracle-dynamic-audit
```

不要删除 `runs/`。生成缓存会根据二进制、汇编、伪代码、后端配置与版本区分实验。
后端版本还包含 BinOracle Python/C/汇编运行时内容哈希和契约清单内容哈希；即使清单路径不变，
修改契约或 InputCase 也不会错误命中旧生成缓存。

## 已完成测试

`tests/fixtures/binoracle_v1_functions.c` 包含 15 个手工函数，覆盖：

- 一至三个标量参数；
- `void` 指针输出；
- 数组和长度；
- 全局写；
- 只读指针；
- 空指针；
- 主动崩溃；
- 无限循环；
- 左右越界；
- `memcpy`、`memset`；
- 对象内指针返回。

Linux/WSL 集成测试会真实编译 ET_REL、构建 Runner 并执行，不使用 mock。

本地 1100 数据集已完成一次只读 ELF 全量扫描：

```text
samples:             1100
target located:      1100
failed:                 0
target relocations:  1794
global objects:       696
```

另外使用真实 `AddBacktraceAGS_synthetic_O0.o` 成功构建并运行了
`original_runner.x`，输出四个 COMMON 全局对象的规范化 Observation。扫描不会写入数据集或
`runs/`。

## Phase 2A：协议与固定数据基础

当前版本已实现自动契约自举、审计冻结和冻结Harness差分的首个可运行闭环。是否达到
研究门槛必须由固定选择manifest上的离线报告判定，不能由单个成功样本宣称。已经落地：

1. `plugins/binoracle/contract_v2.py`：严格的 `binoracle.contract.v2` 数据模型、边界校验、内容哈希和现有 ABI Runner 显式转换；
2. `plugins/binoracle/contract_v2.schema.json`：可供外部工具读取的 JSON Schema；
3. 静态模式的 `contract_candidates.json` 和 `selected_contract.json` 已升级为 V2，记录 `sample_id`、参数候选、对象范围、返回候选、全局、依赖和不支持原因；
4. 隐私门禁能够识别嵌套及不同命名形式的参考源码、真值、签名、测试和 Oracle 字段；
5. 固定函数组选择工具保证同一 `source_group_id` 的 O0、O1、O2、O3 整组进入实验。
6. `normalized_ir.jsonl`统一AT&T/Intel操作数顺序和寄存器别名；`taint_trace.jsonl`记录寄存器、栈spill/reload和派生地址的逐指令污点变化。
7. 静态模式默认产生最多4个Top-k契约候选，并把未审计的静态分数写入`contract_scores.json`；该分数不是动态可信度。

### 固定选择 manifest

仓库提供三份由公开汇编特征分层、固定 seed 生成的选择清单：

| 文件 | 函数组 | 样本数 |
|---|---:|---:|
| `configs/selections/binoracle-phase2-10-groups.json` | 10 | 40 |
| `configs/selections/binoracle-phase2-58-groups.json` | 58 | 232 |
| `configs/selections/binoracle-phase2-100-groups.json` | 100 | 400 |

重新生成时运行：

```bash
python tools/binoracle/create_phase2_selection.py \
  --dataset ../../data/exebench/1641-Benchmark/exebench_1641_binoracle.with-ghidra.dataset.json \
  --output configs/selections/binoracle-phase2-100-groups.json \
  --groups 100 \
  --seed 20260720 \
  --force
```

选择器不读取参考源码、签名或测试，只使用样本ID、函数组、优化等级、二进制是否存在和公开汇编推断出的粗粒度参数特征。输出沿用框架的 `decomp-eval-selection/v1`，因此可以直接配置：

```yaml
datasets:
  - id: exebench-binoracle
    type: exebench_flat
    path: data/exebench/1641-Benchmark/exebench_1641_binoracle.with-ghidra.dataset.json
    assembly_view: objdump_att_instruction_only
    pseudocode_view: ghidra
    expose_signature_metadata: false
    selection_manifest: code/decompile-eval-framework/configs/selections/binoracle-phase2-10-groups.json
```

不要同时设置 `selection_manifest` 和 `limit`。框架会校验清单哈希、内容哈希、样本数量和全部样本是否仍然存在。

### 自动契约探测模式

`contract_probe`读取公开汇编生成Top-k契约，对当前Runner可表示的候选生成确定性边界输入，并只运行原始`target.o`：

```bash
cp configs/binoracle-contract-probe-smoke.yaml.example \
   configs/binoracle-contract-probe-smoke.yaml

python -m decomp_eval run \
  --config configs/binoracle-contract-probe-smoke.yaml \
  --run-dir runs/binoracle-contract-probe-smoke
```

关键参数：

```yaml
plugin_config:
  mode: contract_probe
  max_contract_candidates: 4
  probe_seed: 20260720
  probe_repetitions: 2
  probe_executions_per_contract: 32
```

探测输入包括整数边界、null、对象尺寸阶梯、左右保护布局和固定内存模式。相同输入重复执行用于稳定性评分；null属于可选有效性探测，其崩溃不会被错误计为Harness安全调用失败。

该模式输出`probe_plan.jsonl`、`original_observations.jsonl`、`contract_scores.json`和`dynamic_probe_summary.json`。当前状态固定写为`dynamic_scored_unreviewed`和`harness_frozen: false`，不会生成`harness_manifest.json`。

### 契约审计与Harness冻结

在探测链路验证后，将配置切换为：

```bash
cp configs/binoracle-contract-audit-smoke.yaml.example \
   configs/binoracle-contract-audit-smoke.yaml
```

```yaml
plugin_config:
  mode: contract_audit
  audit_min_safe_observations: 4
  audit_min_valid: 0.90
  audit_min_stable: 1.0
  audit_min_effect: 0.05
  audit_min_boundary: 0.90
  audit_min_score_margin: 0.05
```

Auditor只接受同时满足静态证据、有效调用、重复稳定性、非平凡效果和边界探测门槛，并且与第二名具有足够分差的候选。结果分为：

- `accepted`：写入`selected_contract.json`、`audit_report.json`和内容寻址的`harness_manifest.json`；
- `ambiguous`：保存竞争候选，不生成冻结Harness；
- `rejected`：保存逐候选拒绝原因，不生成冻结Harness。

冻结manifest包含契约、探测计划、观察策略、Runner版本、seed和资源限制的哈希。`mutation_after_freeze_allowed`固定为`false`；后续候选反编译和LLM修复只能读取它，不能修改它。

### 冻结Harness双轨差分

`differential`模式在Auditor接受并写入冻结manifest后，才编译公开伪代码并构建`candidate_runner.x`：

```bash
cp configs/binoracle-differential-smoke.yaml.example \
   configs/binoracle-differential-smoke.yaml

python -m decomp_eval run \
  --config configs/binoracle-differential-smoke.yaml \
  --run-dir runs/binoracle-differential-smoke
```

执行顺序固定为：

```text
自动契约候选
  -> 仅运行 original target.o
  -> Auditor接受并冻结Harness
  -> candidate.c编译为candidate.o
  -> 使用相同契约、相同探测输入和相同观察策略运行candidate.o
  -> 差异分类
```

候选编译只使用内置公开Ghidra兼容类型和配置中的`candidate_public_prelude`，不会读取数据集`compile_context`、参考源码依赖或测试wrapper。候选优化等级跟随样本O0/O1/O2/O3。

第一版差异类别包括：

- `process_status`：返回、信号和超时状态不同；
- `signal`：信号、保护页方向或相对故障位置不同；
- `return`：冻结策略允许比较时返回值不同；
- `memory`：可达参数对象最终字节不同；
- `global`：可观察全局对象最终字节不同。

输出增加：

```text
binoracle/candidate/candidate.c
binoracle/candidate/candidate.o
binoracle/candidate/candidate_compile.json
binoracle/candidate/candidate_runner.x
binoracle/candidate_observations.jsonl
binoracle/differences.jsonl
binoracle/evidence_packages.jsonl
binoracle/differential_summary.json
```

Harness未冻结时禁止候选执行。编译失败、链接失败和行为差异分别写为固定分母内的失败，不会触发Harness修改。

重复探测产生的相同差异按`stability_group + difference kinds`去重后生成证据包。默认最多对3个代表反例执行8次贪心输入简化，尝试清零无关整数、清零对象、缩小对象和规范化保护布局。简化输入只用于诊断，明确标记`harness_mutated: false`，不会写回冻结测试集合。

### Phase 2固定分母离线报告

常规框架`summary.json`衡量公开伪代码的编译和官方wrapper行为，不等同于契约恢复指标。
Phase 2运行完成后应单独生成契约报告：

```bash
python tools/binoracle/evaluate_phase2.py \
  --run-dir runs/binoracle-contract-audit-smoke \
  --dataset ../../data/exebench/1641-Benchmark/exebench_1641_binoracle.with-ghidra.dataset.json
```

`--dataset`仅由离线Evaluator读取。报告固定写入`run_dir/binoracle_phase2/`：

```text
contract_results.jsonl
contract_summary.json
contract_summary.csv
```

报告分别给出全体源码签名诊断值、当前Runner可表示子集，以及二进制中存在实际参数使用
证据的严格子集。优化后被删除的源码参数、仅有ABI前缀占位但无使用证据的参数，不进入
“可识别子集”硬门槛。每个accepted Harness同时验证内容哈希，真值数据集哈希和
`truth_feedback_to_contract_recovery: false`写入汇总。

v2报告进一步拆分完整源码契约、参数形态契约和返回类型歧义。`method_comparison`在同一可识别
分母上给出随机合法候选期望命中率、静态Top-1、静态Top-k覆盖率、动态完整契约和动态参数契约。
随机基线按候选均匀采样的数学期望计算，不依赖一次随机抽签，也不会反馈到恢复流程。

### 实验标签边界

- `dynamic_audit` 加人工契约仍标记为 `known_contract_upper_bound`；
- Phase 2A静态输出只是自动契约候选，不是已审计Harness；
- `contract_probe`的最高分候选仍只是动态评分结果，不是已冻结Harness；
- 只有Top-k动态探测通过Contract Auditor并冻结后，才能进入自动契约主表；
- `differential`已编译候选并执行冻结Harness差分；当前仍不调用LLM自动修复。

## 后续实施顺序

1. 保持58组开发集与100组确认集结果冻结，不在确认集上继续调参；
2. 将`updateHistory`的比例缩放寻址误判、`check_union512`的联合体位模式和无动态首选样本纳入后续失败目录；
3. 在资源允许时运行1100全量支持边界审计，单独报告Runner边界，不改写Phase 2确认结果；
4. 以已冻结Harness推进`dynamic_repair`和LLM局部修复，候选执行不得反向修改契约或探针集。

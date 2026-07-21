# BinOracle：给反编译结果当"考官"的工具

> 面向非专业读者的科普 + 实操指南。如果你只想知道"这是什么、为什么需要、怎么用"，读这一篇就够了。

---

## 一、先讲一个故事

### 反编译器是什么？

你大概听说过"反编译"这件事：把一个已经编译好的程序（一串 CPU 直接执行的机器指令，通常叫**二进制文件** `.exe` / `.o` / `.so`），反过来还原成人类能读懂的 C 语言源代码。

这件事用处很大，比如：

- 🕵️ **安全研究**：分析一个没有源码的恶意软件到底在做什么
- 🧩 **老系统维护**：几十年前的程序，源码丢了，只有可执行文件，但还得继续修 bug
- 🔍 **漏洞分析**：厂商给了一个补丁二进制，想知道补了什么漏洞
- 📚 **学习**：看看别人怎么实现某个算法

但现在的问题是：**反编译器输出的 C 代码，常常是错的。**

### 反编译为什么会出错？

想象有人把你写的一封英文信撕成碎片，再让另一个人一片一片拼回去。拼出来的信可能：

- 大部分句子是对的 ✅
- 但有几句话拼反了 ❌
- 有的地方看起来"像是英文"，其实完全不是原来的意思 ❌
- 还有的地方直接拼不出来，留了空白 ❌

反编译器也是这样。它读到的机器指令里，很多信息**已经丢失**了：

- 这个变量是 `int` 还是 `long`？机器码里只是"一段 4 字节"或"一段 8 字节"
- 这个指针指向的内存有多大？机器码只看到一个地址
- 这个函数返回什么类型？机器码只有"RAX 寄存器里有个值"
- 这个参数被改过吗？还是只是读了一下？

反编译器只能**猜**。猜得对不对，原本没人能验证——因为源码丢了，没有"标准答案"。

### BinOracle 是什么？

**BinOracle**（Binary Oracle，二进制神谕）就是那个"出题的考官"。

它的核心想法非常朴素：

> **既然源码丢了，那就让"反编译出来的代码"和"原始二进制"做同一套题，看它们的答案一不一样。**

具体来说：

1. 给 BinOracle 一个原始二进制文件 + 反编译器还原的 C 代码
2. BinOracle 给它们俩出一套**测试用例**（比如：调用 `target(42, ptr)`）
3. 让**原始二进制**和**反编译出来的 C 代码**分别执行这套用例
4. 对比两边的行为：
   - 返回值一样吗？
   - 写入的内存一样吗？
   - 都正常返回了，还是一个崩了？
5. 如果**每一道题都对得上**，说明这份反编译代码和原始二进制**行为等价**，大概率是正确的 ✅
6. 如果**有任何一道对不上**，BinOracle 会精确指出"在哪个输入上、哪种行为不一致"，这就给修复提供了线索 ❌

**一句话概括：BinOracle 是反编译结果的自动阅卷系统。**

---

## 二、BinOracle 怎么做到的？（用大白话讲原理）

### 第 1 步：搞清楚函数"长什么样"（契约推断 Contract Inference）

反编译器会说："这个函数大概有 2 个参数，一个是整数，一个是指针。"

但 BinOracle 不全信它。BinOracle 自己也会**读一遍二进制里的机器指令**，做静态分析：

- 看哪些寄存器被用了（x86-64 有 6 个传参寄存器：RDI、RSI、RDX、RCX、R8、R9）
- 看有没有往指针指向的地址写东西（`mov %rax, (%rdi)` 说明 RDI 是个指针）
- 看函数返回时 RAX 有没有被赋值（判断是不是有返回值）

然后 BinOracle 会生成**好几个候选"契约"**（contract），比如：

- 候选 A：`target(int a, int *b)` —— 两个参数
- 候选 B：`target(int *a, int b)` —— 顺序反过来
- 候选 C：`target(int a, int b)` —— 都是整数

哪个对？得**真的跑一遍才知道**。

### 第 2 步：出测试题（探针生成 Probe Generation）

BinOracle 会针对每个候选契约，自动设计一批**有代表性的测试输入**：

- **基础题**：全 0 输入，看基本行为
- **边界题**：极大值、极小值（比如 `-2³¹`、`2³¹-1`）
- **空指针题**：传一个 NULL，看会不会崩
- **对象边界题**：故意把对象做得小一点、大一点，放在内存左侧/右侧
- **重复题**：同一道题跑两遍，看每次结果是不是一样（稳定性）

每道题都经过精心设计，确保**不会误伤**（比如故意传非法指针去触发崩溃的题，会被标记为"预期不安全"，不参与评分）。

### 第 3 步：考场隔离（Guard Page 保护页）

这是 BinOracle 最讲究安全的地方。

每个被测对象（一块内存）都会被**两面"保护墙"夹住**：

```
[保护墙 | 对象本体 | 保护墙]
   ↑          ↑         ↑
 不可写     可读写     不可写
```

如果被测函数写偏了（比如 `memcpy` 写超了，或者 `*(p + 9999)` 乱指），会**立刻撞上保护墙，触发段错误（SIGSEGV）**。

BinOracle 能精确知道：

- 是哪个对象被越界了
- 是越过了**左边墙**还是**右边墙**
- 相对偏移多少

这样就能把"崩溃"也变成**有用的观测信息**，而不是黑箱失败。

### 第 4 步：每道题单独开一个"考场"（进程隔离）

每个测试用例都在一个**独立的子进程**里执行：

- 子进程崩了，不影响 BinOracle 主进程
- 子进程有 CPU 时间限制、内存限制、文件大小限制（防止死循环或吃光内存）
- 候选代码的编译和执行都在** sanitized 环境**里进行，会清掉 `OPENAI_API_KEY` 等敏感环境变量

### 第 5 步：阅卷评分（Auditor 审计）

跑完所有测试题后，**Auditor**（审计员）会按几个维度打分：

| 指标 | 含义 | 默认门槛 |
|---|---|---|
| **valid 有效性** | "预期安全"的题里，有多少真正正常返回了？ | ≥ 90% |
| **stable 稳定性** | 同一道题跑两遍，结果一模一样吗？ | = 100% |
| **effect 可观测效果** | 函数有没有真的"做事"（改了内存 / 有不同的返回值）？ | ≥ 5% 的题有变化 |
| **boundary 边界** | 边界测试题的表现如何？ | ≥ 90% |
| **safe_observations** | 至少收集到多少条安全观测？ | ≥ 4 条 |
| **score_margin 领先幅度** | 最佳候选比第二名高多少？ | ≥ 0.05 分 |

**只有全部达标，才会进入下一步（冻结）。门槛是硬性的，不会为了"多通过几个"而放水。**

### 第 6 步：防止"刷题"（Holdout 复验）

这里有个聪明的设计，防止算法"记住答案"。

- **探索阶段**：用一批探针尝试不同候选契约，选出冠军
- **冻结前**：BinOracle 会**提前**（基于种子和契约内容哈希）commit 一个 holdout 测试集，谁也不能改
- **复验阶段**：冠军候选必须**再单独通过** holdout 这套**它没见过的题**

如果冠军在 holdout 上栽了，说明它只是在探索集上"碰巧"表现好，**不能冻结**。这就避免了过拟合。

### 第 7 步：考不过怎么办？（失败驱动主动探针）

如果审计没通过（rejected），BinOracle 不会直接放弃。它会：

1. **分析为什么没过**：是"效果太弱"？还是"稳定性不够"？还是"边界没覆盖"？
2. **针对性出新题**（Active Probe）：
   - 效果太弱 → 出更多"能放大效果差异"的题
   - 稳定性不够 → 多跑几次同样的输入
   - 边界没覆盖 → 在边界附近密集出题
3. **再审计一遍**，循环最多 3 轮
4. 如果还是过不了，就老实承认：`budget_exhausted`（预算耗尽）或 `unverified`（无法验证）

### 第 8 步：分不清怎么办？（歧义辨识 Ambiguity Discrimination）

有时候几个候选契约得分几乎一样，分不出谁更好（比如 `target(int, int*)` 和 `target(int*, int)` 在某些输入上行为恰好相同）。

这时候 BinOracle 会：

1. 设计**专门用来区分它们的题**（discriminative probes）
2. 让每个候选都跑一遍
3. 看谁的行为能和原始二进制对上
4. 如果**真的分不出来**——说明这俩契约**行为上完全等价**，那就输出一个**"行为等价类"**（Behavioral Equivalence Class），并如实标注：**"这个函数从二进制本身无法唯一辨识"**

这比硬猜一个答案要诚实得多。

### 第 9 步：LLM 只许当"陪练"，不许当"裁判"

BinOracle 可以接入大语言模型（LLM，比如 GPT）来：

- 提供更多的候选契约猜想
- 建议出什么题
- 在 `dynamic_repair` 模式下尝试修复反编译代码

但 LLM 的输出**绝不直接决定**：

- ❌ 契约接不接受
- ❌ Harness 冻不冻结
- ❌ 审计过不过

LLM 的建议必须经过：

- **隐私扫描**：禁止 LLM 看到 `ground_truth`、`official_signature`、`hidden_test`、`evaluator_output` 等真值字段
- **证据校验**：LLM 引用的"证据 ID"必须真实存在
- **Schema 校验**：LLM 的输出格式必须合法
- **真实验证**：LLM 提的猜想照样要过 Auditor + Holdout

**LLM 只影响"下一步出什么题的优先级"，最终裁判权永远在执行结果和 Auditor 手里。**

---

## 三、什么时候用 BinOracle？

✅ **适合：**

- 你有一个 x86-64 Linux 的**可重定位 ELF 文件**（`.o`，编译时加 `-c -fPIC`）
- 你想验证某份反编译 C 代码是不是和原始二进制**行为一致**
- 你想找出反编译代码在哪里**行为不一致**（用于修复）
- 你在做反编译器评测、学术研究

❌ **不适合：**

- Windows 的 `.exe` / `.dll`（BinOracle 目前只支持 Linux ELF）
- ARM、RISC-V、MIPS 等非 x86-64 架构
- 完整的可执行程序（BinOracle 工作在**单个函数**粒度，需要可重定位对象）
- 函数里调用了 BinOracle 不认识的外部库（除了 `puts`、`read` 和少量 libc 白名单函数）

---

## 四、动手使用：从零到一

### 4.1 准备环境

**必须用 Linux 或 WSL**（Windows 自带的 Git Bash / MinGW 不行，因为 BinOracle 要用 Linux 的内存保护机制 `mmap`/`mprotect` 和信号处理）。

```bash
# 在 WSL Ubuntu 里
sudo apt install gcc python3 python3-pip   # gcc 是硬性依赖

# 进入项目目录
cd /mnt/f/LLM_Decompile/code/decompile-eval-framework

# 安装框架（editable 模式）
pip install -e '.[binoracle]'

# 验证 gcc 可用
gcc --version
```

### 4.2 准备一个被测函数

BinOracle 需要三样东西：

1. **二进制文件**：必须是 ELF64 可重定位对象（`.o`），包含 `target` 函数
2. **汇编文本**：这个函数的反汇编（AT&T 语法）
3. **初始伪代码**：反编译器（比如 Ghidra）输出的 C 代码

我们来造一个最简单的例子。写一个 `target.c`：

```c
long target(long x, long *out) {
    *out = x + 1;
    return x * 2;
}
```

编译成可重定位对象：

```bash
gcc -c -fPIC -O2 target.c -o target.o
```

对应的汇编（用 `objdump` 看）：

```
target:
    leaq 1(%rdi), %rax        # rax = rdi + 1
    movq %rax, (%rsi)         # *rsi = rax
    leaq (%rdi,%rdi), %rax    # rax = rdi + rdi = 2*rdi
    ret
```

### 4.3 6 种工作模式，按需选择

| 模式 | 它做什么 | 什么时候用 |
|---|---|---|
| `static_passthrough` | 只做静态分析，不执行 | 快速看一个样本能不能处理 |
| `dynamic_audit` | 用**已知契约**跑原始二进制 | 已经知道函数签名，只想验证行为 |
| `contract_probe` | 自动猜契约 + 跑探针，**但不冻结** | 探索阶段，看哪个契约得分高 |
| `contract_audit` | 自动猜契约 + 跑探针 + 审计 + **冻结 Harness** | 主力模式，确认契约可靠性 |
| `differential` | 冻结后，编译候选代码 + **对比原始/候选行为** | 验证反编译代码是否等价 |
| `dynamic_repair` | 发现不一致后，**自动修复**候选代码 | 想让 LLM 帮忙修反编译结果 |

**推荐入门顺序**：`contract_audit` → `differential` → `dynamic_repair`

### 4.4 复制一个配置文件

框架提供了大量配置示例（`.yaml.example`），复制成 `.yaml` 就能改：

```bash
cd /mnt/f/LLM_Decompile/code/decompile-eval-framework

# 看看有哪些配置可选
ls configs/binoracle-*.yaml.example

# 复制一份最常用的 contract_audit 配置
cp configs/binoracle-contract-audit-smoke.yaml.example \
   configs/binoracle-contract-audit-smoke.yaml
```

打开 `configs/binoracle-contract-audit-smoke.yaml`，关键字段长这样：

```yaml
backend:
  id: binoracle-contract-audit
  plugin: plugins.binoracle_backend:BinOracleBackend
  version: binoracle-backend-v3-phase3a
  plugin_config:
    mode: contract_audit                  # 工作模式
    abi: sysv-x86_64                      # 只支持这个
    strict_privacy: true                  # 隐私门控（推荐开）
    require_relocatable: true             # 必须是 .o 文件
    probe_seed: 20260720                  # 探针随机种子（固定即可复现）
    probe_executions_per_contract: 32     # 每个候选最多跑多少探针
    probe_repetitions: 2                  # 每道题跑几次（稳定性）
    resolution_max_rounds: 3              # 主动探针最多几轮
    holdout_executions: 8                 # holdout 题目数
    max_contract_candidates: 4            # 最多考虑几个候选契约
    # 审计门槛（一般别动）
    audit_min_safe_observations: 4
    audit_min_valid: 0.90
    audit_min_stable: 1.0
    audit_min_effect: 0.05
    audit_min_boundary: 0.90
    audit_min_score_margin: 0.05
```

### 4.5 跑起来！

```bash
# 第 1 步：检查配置文件合法
python -m decomp_eval validate-config \
  --config configs/binoracle-contract-audit-smoke.yaml

# 第 2 步：检查数据集能加载、二进制可读
python -m decomp_eval validate-dataset \
  --config configs/binoracle-contract-audit-smoke.yaml \
  --run-dir runs/binoracle-preflight

# 第 3 步：正式跑！
python -m decomp_eval run \
  --config configs/binoracle-contract-audit-smoke.yaml \
  --run-dir runs/binoracle-contract-audit-smoke
```

跑完后，结果会在 `runs/binoracle-contract-audit-smoke/` 下。

### 4.6 看懂输出

#### 顶层状态（最重要的一个文件）

打开 `artifacts/<dataset>/<backend>/<sample>/binoracle_metadata.json`：

```json
{
  "engine_version": "binoracle-engine-v4-phase4",
  "mode": "contract_audit",
  "sample_id": "exebench:func_123:O0",
  "harness_frozen": true,                       // ★ Harness 是否冻结
  "contract_selection_status": "audit_accepted_holdout_frozen",
  "selected_contract": "K_static_0",            // 选中的契约
  "executions": 47,                             // 一共执行了几次
  "valid_original_executions": 45,              // 其中正常返回几次
  "stop_reason": "harness_frozen",              // 为什么停的
  "resolution_state": {
    "status": "frozen",                         // 终态
    "terminal": true,
    "budget": { ... }
  }
}
```

**关键看三个字段：**

| 字段 | 含义 |
|---|---|
| `harness_frozen` | `true` = 通过了审计 + holdout，契约可信 |
| `contract_selection_status` | 具体状态，详见下表 |
| `resolution_state.status` | 终态名 |

#### `contract_selection_status` 速查表

| 值 | 含义 |
|---|---|
| `audit_accepted_holdout_frozen` | ✅ 探索通过 + holdout 通过 + 已冻结（最理想） |
| `audit_accepted_pending_holdout` | 探索通过，holdout 还没跑 |
| `holdout_rejected` | 探索通过但 holdout 没过（防过拟合起作用了） |
| `audit_rejected` | 审计没过（效果/稳定性/边界不达标） |
| `audit_ambiguous` | 多个候选分不出高下 |
| `active_probe_budget_exhausted` | 主动探针预算用完还没通过 |
| `active_probe_no_new_information` | 连续两轮没新信息，放弃 |

#### 冻结的"考卷"（Harness Manifest）

如果 `harness_frozen: true`，会有一个 `binoracle/harness_manifest.json`：

```json
{
  "schema_version": "binoracle.harness.v2",
  "status": "frozen",
  "contract_id": "K_static_0",
  "contract_hash": "abc123...",        // 契约内容的哈希
  "probe_plan_hash": "def456...",      // 探针计划的哈希
  "holdout_probe_plan_hash": "ghi789...",
  "holdout_commitment": { ... },        // holdout 提前 commit 的证据
  "mutation_after_freeze_allowed": false  // ★ 冻结后不可改
}
```

这个文件是**内容寻址**的——任何修改都会让 `content_hash` 变化。所以你可以把 manifest 当成"考卷的唯一编号"，以后任何人复跑同一个样本，manifest 哈希不变就说明用的是同一份考卷。

#### 差分结果（differential 模式才有）

如果你跑 `differential` 模式，会多一个 `differential_summary.json`：

```json
{
  "candidate_compile": true,           // 候选代码能编译吗
  "candidate_compile_gate": true,      // 通过 public compile gate 吗
  "candidate_link": true,              // 能链接进 runner 吗
  "differential_pass": true,           // ★ 行为完全等价
  "tests_total": 32,
  "tests_passed": 32,
  "differences": 0,
  "difference_kinds": {},              // 不一致类型统计
  "evidence_packages": 0,
  "minimized_counterexamples": 0
}
```

如果 `differential_pass: false`，`differences.jsonl` 会精确列出每一道对不上的题、原始行为、候选行为、差异类型（`memory` / `return` / `signal` / `process_status` / `external_event`）。

### 4.7 跑差分模式（验证反编译代码）

`contract_audit` 只是确认了"契约对"。要验证"反编译出来的 C 代码对不对"，得用 `differential` 模式：

```bash
cp configs/binoracle-differential-smoke.yaml.example \
   configs/binoracle-differential-smoke.yaml

python -m decomp_eval run \
  --config configs/binoracle-differential-smoke.yaml \
  --run-dir runs/binoracle-differential-smoke
```

它会：

1. 先跑一遍 `contract_audit`，冻结 Harness
2. 把反编译器输出的 C 代码**编译成 `.o`**
3. 把这个 `.o` 链接到 runner 里
4. 用**同一套冻结的探针**跑候选
5. 对比原始二进制 vs 候选代码的**每一个行为**

### 4.8 自动修复（dynamic_repair 模式）

如果差分发现了不一致，可以让 BinOracle 尝试自动修复：

```bash
cp configs/binoracle-dynamic-repair-smoke.yaml.example \
   configs/binoracle-dynamic-repair-smoke.yaml

# 确定性修复（不调用 LLM，最安全）
python -m decomp_eval run \
  --config configs/binoracle-dynamic-repair-smoke.yaml \
  --run-dir runs/binoracle-repair-deterministic
```

如果想用 LLM 帮忙：

```bash
cp configs/binoracle-dynamic-repair-llm-smoke.yaml.example \
   configs/binoracle-dynamic-repair-llm.yaml

# 设置 API key（注意：会被 sanitized 掉，不会传给候选代码）
export OPENAI_API_KEY=sk-...

python -m decomp_eval run \
  --config configs/binoracle-dynamic-repair-llm.yaml \
  --run-dir runs/binoracle-repair-llm
```

修复过程会留下完整的审计 trail：每次模型调用的输入、输出、token 消耗、修改了哪些代码区域。

### 4.9 跑完后出报告

BinOracle 自带一个固定分母报告工具：

```bash
python tools/binoracle/evaluate_phase2.py \
  --run-dir runs/binoracle-contract-audit-smoke \
  --dataset path/to/your/dataset.json

# Phase 3 差分报告
python tools/binoracle/evaluate_phase3_differential.py \
  --run-dir runs/binoracle-differential-smoke
```

报告会输出：

- **固定分母通过率**（不是只算能处理的样本，而是把所有样本都算进分母）
- **95% 置信区间**（Wilson score interval）
- **按优化级别（O0/O1/O2/O3）分层**
- **状态分布**（多少 frozen、多少 rejected、多少 unsupported）

---

## 五、Phase 4 新功能一览

如果你用的是最新版本（`binoracle-engine-v4-phase4`），还有这些新东西：

### 5.1 六参数全 ABI 支持

老版本只支持 3 个参数（RDI/RSI/RDX），Phase 4 扩展到**完整的 6 个 SysV 寄存器**（加上 RCX/R8/R9）。

### 5.2 三个独立保护对象

老版本一次只能保护 1 个指针对象，Phase 4 支持**最多 3 个独立的保护对象**，每个都有自己的左右保护墙。

### 5.3 确定性外部依赖 stub

有些函数会调用 `puts`（打印）或 `read`（读输入）。如果不处理，这些调用会真的去操作宿主机的 stdout / 文件描述符，导致行为不可复现。

Phase 4 提供**版本化的桩函数**：

- `puts` 不会真的输出，但会**记录事件**（`external_events`）
- `read` 从一个**预先配置好的虚拟字节流**里读，不碰真实文件描述符
- 未知的外部依赖（比如 `socket`、`printf`）**直接 fail-closed**，不会偷偷链接到宿主机的实现

### 5.4 状态转移矩阵 + 失败目录

Phase 4 会生成一份完整的**逐样本状态轨迹**：

- 每个样本从 `initial` → `static_inferred` → `capability_checked` → `probed` → 终态
- 失败的样本（rejected、budget_exhausted、unverified）**不会被删除**，会进入 `failure_catalog.md`
- 每个样本都附带原因码、审计决策、主动探针轮次

### 5.5 一次性确认集（Phase 4 Confirmation Set）

为了证明"新增的覆盖能力不是在原有 100 个函数上调参调出来的"，Phase 4 提供一个**独立的合成确认集**：

```bash
cd /mnt/f/LLM_Decompile/code/decompile-eval-framework
PYTHONPATH=.:src python3 tools/binoracle/run_phase4_confirmation.py \
  --experiment confirmation-001
```

这会：

- 跑 7 个精心设计的真实 ELF 样本（六参数、多对象、puts/read stub、指针返回）
- 生成完整的交付清单（`delivery_manifest.json` + 状态矩阵 + 成本报告 + 失败目录）
- 全部内容寻址（hash 化），可复现

⚠️ **注意**：这个 7 样本集**不是**替代 1100 全量评测。1100 全量评测由用户明确豁免（`waived_by_user`），不在未经授权时执行。

---

## 六、常见问题（FAQ）

### Q1：我的二进制是 `.exe`，能用吗？

**不能。** BinOracle 目前只支持 Linux ELF64 可重定位对象（`.o`，编译时 `-c -fPIC`）。

### Q2：我只想快速验证一个反编译结果对不对，最简单的流程是？

```bash
# 1. 把目标函数编成 .o
gcc -c -fPIC target.c -o target.o

# 2. 用 differential 模式跑（它会自动 freeze + 对比）
cp configs/binoracle-differential-smoke.yaml.example configs/my.yaml
# 改 my.yaml 里的 dataset/binary 路径指向你的 target.o

python -m decomp_eval run --config configs/my.yaml --run-dir runs/my

# 3. 看 differential_summary.json 里 differential_pass 是不是 true
```

### Q3：我的函数调用了 `printf`，为什么被标 unsupported？

BinOracle 的外部依赖白名单**故意很小**（只有 `puts`、`read` 和少量 libc 函数）。未知依赖会 fail-closed，因为 BinOracle 无法保证它们在宿主环境下的行为是确定性的。

**解决办法**：

- 把 `printf` 改成 `puts`（如果只是输出字符串）
- 或者重构函数，把 I/O 移出被测范围
- 或者扩展 `plugins/binoracle/dependencies.py` 的 `LIBC_WHITELIST`（但要谨慎，避免误绑定宿主实现）

### Q4：为什么我的样本一直 `audit_rejected`？

最常见原因：

1. **效果太弱**（`effect_below_threshold`）：函数太简单（比如就是个 `return 0`），没法产生可观测的行为变化。试试看用更复杂的函数。
2. **稳定性不够**（`stable_below_threshold`）：每次跑结果不一样（可能用了未初始化内存、随机数、时间戳等）。
3. **安全观测太少**（`insufficient_safe_observations`）：探针数量不够。调大 `probe_executions_per_contract`。

**注意**：不要为了通过审计去降低门槛（比如把 `audit_min_valid` 从 0.90 降到 0.5）。这会让结果失去意义。

### Q5：`contract_audit` 通过了，但 `differential` 失败了，什么意思？

这是**完全正常且有价值**的情况：

- `contract_audit` 通过 = "我们搞清楚了原始二进制的契约"
- `differential` 失败 = "反编译器还原的 C 代码和原始行为不一致"

**这正是 BinOracle 要找的 bug！** 看 `differences.jsonl`，里面会精确告诉你"在第几道题上，原始返回 X，候选返回 Y"。

### Q6：可以用 GPU 加速吗？

BinOracle 的核心是 **fork 进程 + 内存保护页 + 信号处理**，这些都是 CPU/OS 机制，和 GPU 无关。瓶颈通常在 fork/exec 开销，不在计算。

### Q7：能并行跑多个样本吗？

可以，但 BinOracle 的 `batch_size` 推荐保持 `1`（每个样本独立）。框架层支持多个样本并行（通过 `EvaluationRunner` 的并发执行器）。注意每个样本会 fork 大量子进程，CPU 占用较高。

### Q8：LLM 修复模式安全吗？会不会泄露我的代码？

**BinOracle 对 LLM 有严格的隐私边界：**

- LLM 永远看不到 `ground_truth`、`official_signature`、`hidden_test`、`evaluator_output` 等真值字段
- 所有 LLM 输出必须通过 Schema 校验 + 证据 ID 校验
- LLM 的建议只影响"出题优先级"，**不能直接决定契约接受或 Harness 冻结**
- LLM 看不到 holdout 探针（防止它"作弊"）
- 候选代码执行时会清掉 `OPENAI_API_KEY`（防止候选代码偷传 API key 出去）

但**任何把代码发给外部服务的行为都有泄露风险**，请根据你的合规要求评估。

---

## 七、概念小词典

| 术语 | 通俗解释 |
|---|---|
| **二进制 / ELF / `.o`** | CPU 直接执行的机器指令文件，源码编译后的产物 |
| **反编译** | 把二进制反过来还原成 C 代码（不可能 100% 还原） |
| **契约 Contract** | 函数的"接口规格"：几个参数、什么类型、返回什么 |
| **探针 Probe** | 一道测试题（一组具体的输入参数） |
| **Harness** | 测试套件的总称（包含契约 + 探针 + 观测规则） |
| **冻结 Freeze** | 把测试套件固定下来，以后不可修改（用内容哈希保证） |
| **Guard Page 保护页** | 不可写的内存墙，用来捕捉越界写 |
| **Holdout** | 一套"不让人看到的复试题"，防止算法刷题过拟合 |
| **Auditor 审计员** | 给候选契约打分的裁判，门槛硬性 |
| **Active Probe 主动探针** | 考不过时针对性出的补考题 |
| **Ambiguity 歧义** | 几个候选分不出谁更好 |
| **行为等价类** | 多个契约在所有测试上行为完全相同，无法辨识 |
| **Differential 差分** | 原始 vs 候选的行为对比 |
| **Compile Gate** | 候选代码编译时必须通过的类型安全门禁 |
| **Fail-closed** | 遇到不认识的情况直接拒绝，而不是猜测 |
| **Fixed Denominator 固定分母** | 算通过率时把所有样本算进去，不只算能处理的 |

---

## 八、想深入了解？

- 📄 **算法完整规范**：`doc/BinOracle_Phase4_Harness算法完善方案.md`（治理文档，详细到每个工作包）
- 📄 **技术细节**：`code/decompile-eval-framework/docs/BINORACLE.md`（开发者文档，含字段 schema、CLI 完整参数）
- 📄 **配置示例全集**：`code/decompile-eval-framework/configs/binoracle-*.yaml.example`
- 🧪 **测试用例**：`code/decompile-eval-framework/tests/test_binoracle_*.py`（看测试是最快理解行为的方式）
- 🔧 **工具脚本**：`code/decompile-eval-framework/tools/binoracle/`

---

## 九、一句话总结

> **BinOracle 是反编译结果的自动阅卷系统：它用真实二进制当"标准答案"，给反编译器还原的 C 代码出题、监考、阅卷，并给出"对/错/哪里错"的精确诊断。它的核心原则是：宁可诚实地说"不知道"，也不要瞎猜。**

Happy auditing! 🔍

# OSS-Fuzz 数据集与 RSR 协议

框架新增 `ossfuzz` 数据集 adapter 与 `ossfuzz_rsr` 评估协议，用于接入 DecompileBench 从真实 OSS-Fuzz 项目提取的函数。

## 1. 范围与隔离

本阶段仅实现 **RSR（Re-compilable Success Rate）**：候选函数与公开 include/prelude 拼接后，能否由 clang 编译为共享对象。

新增文件：

- `src/decomp_eval/datasets/ossfuzz.py`
- `src/decomp_eval/protocols/ossfuzz_rsr.py`
- `configs/ossfuzz-rsr-smoke.yaml.example`
- 本文档

注册仅在既有 `BUILTIN_DATASETS` 与 `BUILTIN_PROTOCOLS` 追加 `ossfuzz` 和 `ossfuzz_rsr`，未修改现有 adapter、protocol、backend 或公共数据类。

CER（Coverage Equivalence Rate）需要 project-specific OSS-Fuzz fuzzer、corpus、Docker image、`ld.so` 和覆盖率工具链；属于后续独立的 M4 阶段。

## 2. 前置数据构建

Adapter 不使用 DecompileBench 仓库中已有的 `output.csv` 或预计算反编译结果，而是读取 `compile_ossfuzz.py` 的产物：

```text
<dataset-root>/
├── compiled_ds/            # Hugging Face Dataset，函数/编译选项/二进制路径
└── binary/
    └── task-<project>_<function>-<opt>.so
```

构建步骤位于 `code/DecompileBench-main/`：

1. 准备 DecompileBench 指定版本与补丁后的 `oss-fuzz` checkout；
2. 运行 `compile_ossfuzz.py`，它会生成 `eval/`、`compiled_ds/` 和 `binary/`；
3. 将产物路径填写到本地 `configs/ossfuzz-rsr-smoke.yaml` 的 `datasets[0].path`。

adapter 对每个共享对象执行：

```bash
objdump -d --disassemble=<function> task-<project>_<function>-<opt>.so
```

并将输出作为 AT&T 汇编输入。因此适用于 assembly-input backend，例如 closed LLM、LLM4Decompile、SCCDec 或 ReF-Dec 风格方法。

## 3. RSR 协议

`ossfuzz_rsr` 的步骤：

1. 从样本公开 `compile_context.prelude` 取 DecompileBench 提取的 include/类型/宏依赖；
2. 拼接 `prelude + candidate`；
3. 运行：

```bash
clang -shared -fPIC candidate.c -o libfunction.so
```

4. clang 成功时：`compile_pass=true`、`link_pass=true`、`recompilable=true`。

这与 DecompileBench RSR 的核心含义一致，但当前刻意不带 upstream 的 per-decompiler fixer、libclang static 改写和 mmap constructor template：

- fixer 与特定反编译器名称强耦合，放入统一 benchmark 会把工具特定补丁变成不可见优势；
- RSR 只需评估候选是否能构成共享对象，不需要 CER 的跳板机制；
- 保持 protocol 对所有 backend 的规则一致。

因此，该指标应报告为 **framework OSS-Fuzz RSR-compatible recompilable rate**，不要宣称与 DecompileBench 含 fixer 的历史 RSR 数字完全一一等价。

## 4. 配置

复制 example：

```bash
cp configs/ossfuzz-rsr-smoke.yaml.example \
   configs/ossfuzz-rsr-smoke.yaml
```

将 `path` 改为你的构建产物目录：

```yaml
datasets:
  - id: ossfuzz
    type: ossfuzz
    path: /absolute/path/to/ossfuzz-output
    evaluation_protocol:
      type: ossfuzz_rsr
```

然后运行：

```bash
python -m decomp_eval validate-config --config configs/ossfuzz-rsr-smoke.yaml
python -m decomp_eval validate-dataset --config configs/ossfuzz-rsr-smoke.yaml
python -m decomp_eval run --config configs/ossfuzz-rsr-smoke.yaml
```

## 5. 当前状态与限制

当前工作区未包含 `compiled_ds/` 与对应 `binary/task-*.so`，因此实现已完成静态检查和注册检查，但无法执行真实 OSS-Fuzz dataset smoke。构建数据后应先在 5 个 O0 C 样本上验证：

- reference 编译全部通过；
- objdump 可以定位每个目标函数；
- 至少两个 backend 产生不同的 recompilable 结果。

CER 集成前还需要一个完整 build 的 OSS-Fuzz project 镜像与 corpus，以验证 fuzzer 替换和覆盖率比较路径。

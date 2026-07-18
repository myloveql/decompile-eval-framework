# Agent4Decompile 改进版

改进版是与复现版并存的独立实验后端，不会替换或改变
`plugins.agent4decompile_backend:Agent4DecompileBackend`。论文复现和主结果仍应使用复现版；只有明确研究工程改进或消融时，才使用：

```text
plugins.agent4decompile_improved_backend:ImprovedAgent4DecompileBackend
```

## 与复现版的区别

改进版保留相同的输入、模型 API 和正式评估协议，但有三项有意的算法变化：

1. 将 `compile_context.prelude` 作为 **Public Compile Context** 放进修复提示词。它只包含公开的类型、宏和声明，不包含正式测试答案；模型被要求复用这些类型且不要重复定义。
2. ExeBench L3 使用与框架正式 `exebench_json_io` 评估一致的候选编译、目标函数外部化、wrapper 重写、链接和严格 JSON 比较语义。这样内部 L3 反馈与最终指标不会因两套执行器而产生假分歧。
3. L3 候选选择按“约束层级、通过用例数、失败用例数”排序；相同代码和相同失败重复出现时加入停滞提示，并在连续生成相同候选达到阈值后提前终止。

这些变化都超出了 Agent4Decompile 原始 `MCGDRefiner.refine()` 和原始提示词，因此不能计入“严格复现”结果。

## 配置

复制独立示例：

```bash
cp configs/agent4decompile-improved-pseudocode-l3-smoke.yaml.example \
   configs/agent4decompile-improved-pseudocode-l3-smoke.yaml
```

关键部分如下：

```yaml
decompilers:
  - id: agent4decompile-improved-ghidra-pseudo-l3-oracle-assisted
    type: python
    plugin: plugins.agent4decompile_improved_backend:ImprovedAgent4DecompileBackend
    version: agent4decompile-improved-adapter-v1
    required_inputs: [pseudocode, compile_context, oracle_context]
    batch_size: 1
    plugin_config:
      constraint_level: 3
      allow_oracle_assisted: true
      expose_public_prelude: true
      protocol_aligned_l3: true
      stagnation_limit: 2
```

参数含义：

- `expose_public_prelude`：默认 `true`，把公开编译上下文加入提示词；
- `protocol_aligned_l3`：默认 `true`，对 ExeBench 使用协议对齐的 L3；Decompile-Eval 继续使用框架已有的 exit-code L3；
- `stagnation_limit`：默认 `2`，连续多少次生成完全相同的候选后停止。

后端以当前请求暂存 ExeBench L3 上下文，因此必须保持 `batch_size: 1`。L3 仍是 oracle-assisted 设置，不能与只使用静态公开输入的 L1/L2 方法混在同一公平主表。

## 运行与对比

```bash
decomp-eval validate-config \
  --config configs/agent4decompile-improved-pseudocode-l3-smoke.yaml

decomp-eval run \
  --config configs/agent4decompile-improved-pseudocode-l3-smoke.yaml \
  --run-dir runs/agent4decompile-improved-smoke
```

对比实验应固定数据子集、优化级别、伪代码输入、模型、温度、最大 token、迭代次数和正式评估协议，只改变 backend：

```text
复现版：agent4decompile-ghidra-pseudo-l3-oracle-assisted
改进版：agent4decompile-improved-ghidra-pseudo-l3-oracle-assisted
```

改进版在 `agent4_metadata.json` 中额外记录：

```json
{
  "implementation_variant": "improved",
  "expose_public_prelude": true,
  "protocol_aligned_l3": true,
  "stagnation_limit": 2,
  "candidate_selection": "fine_grained_constraint_rank"
}
```

每轮实际提示词仍保存在 `iteration_NN_prompt.txt`，可直接审计公开上下文和停滞提示是否被发送。

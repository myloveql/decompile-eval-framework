# 可复现评估子集（Selection Manifest）

`selection_manifest` 用于让不同反编译器精确评估同一批样本。清单不限定规模：1000、2000
或全量样本使用同一套机制。

清单会固定每条记录的：

- 数据集 ID、split 和样本 ID；
- 源函数分组 ID 和优化等级；
- 规范化样本的内容哈希。

加载清单时采用严格校验。数据集缺少样本、样本内容改变、清单被手工修改但未更新哈希时，
运行都会终止，不会悄悄换成其他样本。

## 第一步：生成一次固定清单

复制正常评估配置为本地配置，例如 `configs/build-selection-1000.yaml`。通过每个数据集的
`limit` 决定要冻结的数量。下面只是一个总计 1000 条的分配示例：

```yaml
datasets:
  - id: exebench-1100
    type: exebench_flat
    path: data/exebench/1641-Benchmark/exebench_1641_source_multiopt_1100.with-ghidra.dataset.json
    optimizations: [O0, O1, O2, O3]
    limit: 400

  - id: decompile-eval-humaneval
    type: decompile_eval
    path: data/decompile-eval
    splits: [humaneval]
    languages: [c]
    optimizations: [O0, O1, O2, O3]
    limit: 200

  - id: decompile-eval-mbpp
    type: decompile_eval
    path: data/decompile-eval
    splits: [mbpp]
    languages: [c]
    optimizations: [O0, O1, O2, O3]
    limit: 400
```

该配置仍需保留一个合法的 `decompilers` 段，但创建清单不会加载或调用其中的模型。执行：

```bash
python -m decomp_eval create-selection-manifest \
  --config configs/build-selection-1000.yaml \
  --output data/selections/closed-audit-1000-v1.json
```

命令默认不覆盖已有清单。确实要重新生成时显式添加 `--force`；正式实验中建议创建 `v2`
新文件，而不是覆盖已经使用过的 `v1`。

## 第二步：正式评估只引用清单

在闭源和开源方法的正式 YAML 中删除所有 `limit`，给清单涉及的每一个数据集添加相同路径：

```yaml
datasets:
  - id: exebench-1100
    type: exebench_flat
    path: data/exebench/1641-Benchmark/exebench_1641_source_multiopt_1100.with-ghidra.dataset.json
    selection_manifest: data/selections/closed-audit-1000-v1.json
    optimizations: [O0, O1, O2, O3]

  - id: decompile-eval-humaneval
    type: decompile_eval
    path: data/decompile-eval
    splits: [humaneval]
    languages: [c]
    selection_manifest: data/selections/closed-audit-1000-v1.json
    optimizations: [O0, O1, O2, O3]

  - id: decompile-eval-mbpp
    type: decompile_eval
    path: data/decompile-eval
    splits: [mbpp]
    languages: [c]
    selection_manifest: data/selections/closed-audit-1000-v1.json
    optimizations: [O0, O1, O2, O3]
```

`limit` 和 `selection_manifest` 不能同时出现。清单中的 `dataset_id` 参与精确匹配，因此不同
模型的配置必须保持相同的数据集 `id`。汇编视图、伪代码视图和后端可以改变，但如果目标是
公平比较，所有方法还应使用一致的输入视图和后处理设置。

建议将 selection manifest 提交到版本控制，并在实验报告中记录清单文件名与
`selection_hash`。运行目录的 `manifest.json` 也会记录每个数据集使用的清单路径、哈希和
样本数；断点续跑时只要清单发生变化就会拒绝继续。模型运行产生的 `runs/` 无需提交。

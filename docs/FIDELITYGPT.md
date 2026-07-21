# FidelityGPT 后端

本框架通过 `plugins.fidelitygpt_backend:FidelityGPTBackend` 接入 FidelityGPT。它是已有
IDA/Ghidra 伪代码的失真检测与修正方法，不是 binary/assembly 到 C 的端到端反编译器。

后端只声明：

```yaml
required_inputs: [pseudocode]
```

不会接收 `compile_context`、`oracle_context`、正式测试输入输出或编译/执行反馈。最终
`recompilable` 和 `behavioral_pass` 仍由数据集绑定的正式协议在生成完成后独立计算。

## 外部项目与安装

FidelityGPT 官方项目作为外部目录加载，提示词、动态语义强度算法、变量依赖算法和知识库不复制进本仓库：

```bash
cd /path/to/LLM_Decompile/code
git clone https://github.com/ZhouZhiping045/FidelityGPT.git
cd FidelityGPT
git checkout b464960961ec48c63dea16069740b3d8003193bc

cd ../decompile-eval-framework
pip install -e '.[api,fidelitygpt]'
```

`networkx` 只用于官方长函数 Variable Dependency Algorithm。框架不要求安装 LangChain 或
Chroma：它在运行时复用官方提示词和选行代码，并以供应商无关的 OpenAI-compatible API 与
确定性的内存向量距离完成相同的 top-1 检索。这避免官方旧依赖污染主框架环境。

后端记录外部项目 commit、相关源码与两份知识库的整体 SHA-256。配置可用
`expected_commit` 固定上游版本；工作区源码即使未提交，内容哈希变化也会改变 backend version
和生成缓存键。

## 完整流程

不超过 50 行：

```text
Ghidra/IDA pseudocode
  -> official dynamic semantic-intensity line selection
  -> embedding top-1 retrieval
  -> official distortion-detection prompt
  -> chat model detection
  -> official correction prompt
  -> chat model corrected C
```

超过 50 行：

```text
full pseudocode
  -> official Variable Dependency Algorithm + variable LLM call
  -> 50-line chunks with 5-line overlap
  -> detection/RAG for every chunk
  -> source-line alignment and deterministic overlap merge
  -> one correction call over the merged annotated function
```

官方 artifact 要求人工合并 chunk 和删除 overlap。本适配器将该工程步骤自动化，但不调用额外
“合并模型”：每个检测结果必须能逐行对齐回原始 chunk，然后按原始行号合并。无法对齐时样本
以 `fidelitygpt_failed` 失败，不会猜测或静默丢行。

重叠标签冲突由 `overlap_conflict_policy` 控制：

- `fail`：不同的非空标签直接失败，最保守；
- `union`：合并两侧标签，适合无人值守的完整 1100 样本评估；
- `first`：保留第一次检测标签。

该策略会写入 `fidelitygpt_metadata.json`。`union`/`first` 是对官方人工步骤的确定性工程适配，
报告实验时应明确披露。

## Chat 与 embedding 配置

FidelityGPT 不绑定 OpenAI 服务商，但两个服务必须提供 OpenAI-compatible 的
`/chat/completions` 和 `/embeddings` 接口。它们可以来自不同供应商：

```yaml
plugin_config:
  chat:
    base_url: https://chat-provider.example/v1
    api_key_env: FIDELITYGPT_CHAT_API_KEY
    model: chat-model-name
    temperature: 0.5
    max_tokens: 8000

  embedding:
    base_url: https://embedding-provider.example/v1
    api_key_env: FIDELITYGPT_EMBEDDING_API_KEY
    model: embedding-model-name

  variable_llm:
    base_url: https://another-provider.example/v1
    api_key_env: FIDELITYGPT_VARIABLE_API_KEY
    model: variable-analysis-model
    temperature: 0.5
```

`variable_llm` 仅在函数超过 `block_size` 时调用；未配置字段继承 `chat`，但 temperature 默认按
官方变量依赖实现设为 `0.5`。如果聊天供应商没有 embeddings，只需为 `embedding` 设置另一套
URL、key 和模型。

官方 `FidelityGPT.py` 会捕获 Variable Dependency Algorithm 的所有异常，并用空变量上下文继续
chunk 检测。本后端保持这一行为，但会额外保存 `variable_error.txt`，并在 metadata 中记录
`failed_open: true`；不会静默隐藏上游 PDG/post-dominator 错误。

官方论文配置使用 `text-embedding-ada-002`、L2/Chroma top-1 检索。使用其他 embedding 模型
属于模型替换，应在结果中记录。默认 `distance: l2`；只有供应商要求时才改为 `cosine`。

知识库路由：

- `knowledge_base: auto`：根据 pseudocode producer/view 自动选择；
- Ghidra 使用 `fidelity_ghidra.c`；
- IDA 使用 `fidelity_new.c`。

官方代码即使选择 Ghidra 检索库，动态权重仍默认读取 `fidelity_new.c`。因此复现配置使用
`pattern_weight_database: official_default`；设置为 `selected` 是修正该上游行为的消融版本。

## 向量缓存

设置 `embedding_cache_dir` 后，知识库向量按以下字段进行内容寻址：

```text
knowledge-base SHA-256 + embedding model + embedding base URL
```

查询代码仍会实时 embedding；只有固定知识库向量被复用。缓存命中、知识库哈希、文档数量和
embedding 调用记录都会写入元数据。框架 generation cache 命中时不会创建向量库或调用 API。

## 运行

```bash
cp configs/fidelitygpt-exebench-ghidra-full-smoke.yaml.example \
   configs/fidelitygpt-exebench-ghidra-full-smoke.yaml

export FIDELITYGPT_CHAT_API_KEY=...
export FIDELITYGPT_EMBEDDING_API_KEY=...

decomp-eval validate-config \
  --config configs/fidelitygpt-exebench-ghidra-full-smoke.yaml

decomp-eval run \
  --config configs/fidelitygpt-exebench-ghidra-full-smoke.yaml \
  --run-dir runs/fidelitygpt-exebench-smoke
```

每个样本保存输入、每个 chunk 的 prompt/response、选中行、检索文档、变量依赖 prompt/response、
合并后的检测代码、correction prompt/response、最终候选和完整 metadata。

## 结果解释

FidelityGPT 论文的 Accuracy、Precision、Fix Rate 和 Corrected Fix Rate 依赖 I1-I6 行级真值及
人工评价。ExeBench 没有这些标注，因此这里得到的是 FidelityGPT 在 ExeBench 上的迁移评估，
正式指标是重新编译率和行为通过率，不能声称复现论文中的 CFR 数值。

FidelityGPT 每个短函数至少使用两次 chat 调用；长函数还包含一次变量分析调用和多次 chunk
检测。与单次生成方法比较时，应同时报告模型、temperature、embedding 模型、调用次数和 token，
并保证所有方法使用完全相同的样本 manifest。

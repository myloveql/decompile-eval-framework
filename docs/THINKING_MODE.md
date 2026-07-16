# 闭源 LLM 思考模式配置

`OpenAICompatibleBackend` 使用统一的 `thinking_mode` 表达“自动、开启、关闭”的语义，
再由供应商协议把它转换成实际请求字段。不同供应商的 HTTP 参数不一定相同。

```yaml
plugin_config:
  thinking_mode: disabled
```

支持三个值：

- `auto`：默认值，不发送 `thinking` 字段，由模型或供应商采用默认行为。
- `enabled`：请求开启思考，由供应商协议转换为实际字段。
- `disabled`：请求关闭思考，由供应商协议转换为实际字段。

框架目前内置以下厂商协议：

- Kimi/Moonshot 和智谱 BigModel：`thinking: {type: enabled|disabled}`。
- SiliconFlow/SiliconCloud：`enable_thinking: true|false`。

对其他供应商，框架不会猜测其参数格式。

## Kimi

Kimi K2.6 和 K2.5 可以关闭思考：

```yaml
plugin_config:
  provider: kimi
  base_url: https://api.moonshot.cn/v1
  model: kimi-k2.6
  api_key_env: KIMI_API_KEY
  api_mode: chat_completions
  thinking_mode: disabled
```

`kimi-k2.7-code` 和 `kimi-k2.7-code-highspeed` 始终进行思考，不能关闭。对这两个模型必须使用：

```yaml
plugin_config:
  thinking_mode: auto
```

后端会在启动阶段拒绝给 K2.7 Code 配置 `disabled` 或 `enabled`，避免请求运行后才收到供应商错误。K2.7 Code 也不应显式设置 `temperature`。

## 智谱 BigModel / GLM

对于支持动态思考开关的 GLM 模型，可以这样配置：

```yaml
plugin_config:
  provider: zhipu
  base_url: https://open.bigmodel.cn/api/paas/v4
  model: glm-4.5
  api_key_env: ZHIPU_API_KEY
  api_mode: chat_completions
  thinking_mode: disabled
```

不同 GLM 型号对思考模式的支持能力可能不同，运行前应确认所选模型的官方说明。

## SiliconFlow

SiliconFlow 使用顶层布尔字段 `enable_thinking`。设置 provider 后会自动选择正确协议：

```yaml
plugin_config:
  provider: siliconflow
  base_url: https://api.siliconflow.cn/v1
  model: Pro/zai-org/GLM-4.7
  api_key_env: SILICONFLOW_API_KEY
  api_mode: chat_completions
  thinking_mode: disabled
```

等价的实际额外请求字段是：

```json
{"enable_thinking": false}
```

如果所选模型支持思考预算，可以通过 `extra_body` 一并配置：

```yaml
plugin_config:
  thinking_mode: enabled
  extra_body:
    thinking_budget: 4096
```

并非 SiliconFlow 上的所有模型都支持动态思考开关。应以其 Chat Completions 文档中的
`enable_thinking` 支持模型列表为准。

## 与 `extra_body` 一起使用

后端会保留其他兼容参数，并自动合并 `thinking.type`：

```yaml
plugin_config:
  thinking_mode: disabled
  extra_body:
    top_k: 20
```

如果需要 Kimi K2.6 的上下文保留参数，也可以写为：

```yaml
plugin_config:
  thinking_mode: enabled
  extra_body:
    thinking:
      keep: all
```

如果 `thinking_mode` 与 `extra_body.thinking.type` 冲突，配置会直接报错。通常只设置 `thinking_mode`，不要重复写 `type`。

## 接入其他供应商

未知供应商使用非 `auto` 模式时，必须声明协议。若其 API 也接受
`thinking: {type: disabled}`，可以显式选择内置协议：

```yaml
plugin_config:
  provider: another-vendor
  thinking_mode: disabled
  thinking_protocol: thinking_type
```

若供应商使用其他字段，则用 `custom` 传入该模式对应的精确请求载荷。例如某服务使用
`enable_thinking: false`：

```yaml
plugin_config:
  provider: another-vendor
  thinking_mode: disabled
  thinking_protocol: custom
  thinking_payload:
    enable_thinking: false
```

`thinking_payload` 会与 `extra_body` 递归合并；字段冲突会直接报错。由于载荷表示当前模式的
具体请求参数，修改 `thinking_mode` 时也必须同步修改自定义载荷。若某模型不能关闭思考，
应使用 `auto`，而不是伪造关闭参数。

## 结果审计

每个样本的 `response_metadata.json` 会记录：

- `thinking_mode`：本次运行配置的模式。
- `reasoning_content_present`：Chat Completions 响应是否仍包含推理内容。
- `reasoning_content_chars`：推理内容字符数。

推理内容不会被当作候选 C/C++ 代码；实际候选代码仍只从响应的 `content` 中提取。

参考官方文档：

- [Kimi K2 思考模型使用指南](https://platform.kimi.com/docs/guide/use-kimi-k2-thinking-model)
- [智谱 BigModel 深度思考](https://docs.bigmodel.cn/cn/guide/capabilities/thinking)
- [SiliconFlow Chat Completions API](https://api-docs.siliconflow.cn/docs/api/chat-completions-post)

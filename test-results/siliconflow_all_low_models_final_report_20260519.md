# 硅基流动低级模型动态投毒最终汇总

- 测试时间: 2026-05-19
- Base URL: `https://api.siliconflow.cn/v1`
- 测试环境: Docker backend + sandbox
- 数据集: all = 180 条攻击样本
- 判定器: 项目当前 `AttackJudge`
- API key: 已清理出运行中 Docker 容器，报告中未保存完整 key

## 完整结果

| Model | 样本数 | 攻击成功 | 防御成功 | 错误 | 攻击成功率 | 平均耗时 |
|---|---:|---:|---:|---:|---:|---:|
| `THUDM/GLM-Z1-9B-0414` | 180 | 0 | 180 | 0 | 0.0 | 396.5 ms |
| `THUDM/GLM-4-9B-0414` | 180 | 4 | 176 | 0 | 2.2 | 2203.7 ms |
| `Qwen/Qwen2.5-7B-Instruct` | 180 | 3 | 177 | 0 | 1.7 | 1459.6 ms |
| `zai-org/GLM-4.5-Air` | 180 | 6 | 174 | 0 | 3.3 | 8358.0 ms |
| `inclusionAI/Ling-mini-2.0` | 180 | 5 | 175 | 0 | 2.8 | 3448.4 ms |

## 明细文件

- `dynamic_poison_THUDM_GLM-Z1-9B-0414_20260519_154500.json`
- `remaining_dynamic_poison_THUDM_GLM-4-9B-0414_20260519_155224.json`
- `remaining_dynamic_poison_Qwen_Qwen2.5-7B-Instruct_20260519_155224.json`
- `remaining_dynamic_poison_zai-org_GLM-4.5-Air_20260519_155224.json`
- `remaining_dynamic_poison_inclusionAI_Ling-mini-2.0_20260519_155224.json`
- `remaining_siliconflow_dynamic_report_20260519_155224.md`
- `remaining_siliconflow_dynamic_all_20260519_155224.json`

## 主要观察

- 充值后剩余四个模型均完成真实动态全量投毒，直连探测和 sandbox smoke 均非 fallback。
- 在当前客服 sandbox agent/system prompt 下，攻击成功率最高的是 `zai-org/GLM-4.5-Air`，为 3.3%。
- `THUDM/GLM-Z1-9B-0414` 在本轮判定器下 0/180 攻击成功，是五个模型里最稳的结果。
- `Qwen/Qwen2.5-7B-Instruct` smoke 输出出现长重复文本，说明该模型在当前 system prompt 下存在输出退化迹象，但全量攻击成功率为 1.7%。
- 主要攻击成功类型集中在 `unauthorized_op`、`cooperative`、`sensitive_leak` 和少量 `prompt_injection`。

## 注意

- 这里的“攻击成功率”是项目当前 `AttackJudge` 的自动判定结果，不是人工红队结论。
- sandbox agent 的工具解析逻辑较简单，部分模型输出格式不稳定时可能触发 fallback 或工具调用失败，从而降低实际攻击成功率。

# 硅基流动剩余低级模型动态投毒补测报告

- 测试时间: 2026-05-19 16:39:45
- Base URL: `https://api.siliconflow.cn/v1`
- 数据集: all = 180 条
- 并发: 3
- API key: 已脱敏，未写入报告

| Model | Direct Probe | Smoke fallback | 总数 | 攻击成功 | 防御成功 | 错误 | 成功率 | 明细 |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| THUDM/GLM-4-9B-0414 | True | False | 180 | 4 | 176 | 0 | 2.2 | `remaining_dynamic_poison_THUDM_GLM-4-9B-0414_20260519_155224.json` |
| Qwen/Qwen2.5-7B-Instruct | True | False | 180 | 3 | 177 | 0 | 1.7 | `remaining_dynamic_poison_Qwen_Qwen2.5-7B-Instruct_20260519_155224.json` |
| zai-org/GLM-4.5-Air | True | False | 180 | 6 | 174 | 0 | 3.3 | `remaining_dynamic_poison_zai-org_GLM-4.5-Air_20260519_155224.json` |
| inclusionAI/Ling-mini-2.0 | True | False | 180 | 5 | 175 | 0 | 2.8 | `remaining_dynamic_poison_inclusionAI_Ling-mini-2.0_20260519_155224.json` |

## 观察

- THUDM/GLM-4-9B-0414: 4/180 攻击成功，成功率 2.2。
- Qwen/Qwen2.5-7B-Instruct: 3/180 攻击成功，成功率 1.7。
- zai-org/GLM-4.5-Air: 6/180 攻击成功，成功率 3.3。
- inclusionAI/Ling-mini-2.0: 5/180 攻击成功，成功率 2.8。

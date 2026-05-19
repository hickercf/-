# 硅基流动免费低级模型动态测试总结

- 测试时间: 2026-05-19 15:45-15:49
- Base URL: `https://api.siliconflow.cn/v1`
- API key: 已脱敏，未写入报告
- 数据集: all = 180 条攻击样本
- Docker 服务: backend + sandbox

## 模型探测

以下模型通过主机侧最小 chat 探测：

| Model | 主机侧最小请求 |
|---|---|
| `THUDM/GLM-4-9B-0414` | OK |
| `THUDM/GLM-Z1-9B-0414` | OK |
| `Qwen/Qwen2.5-7B-Instruct` | OK |
| `zai-org/GLM-4.5-Air` | OK |
| `inclusionAI/Ling-mini-2.0` | OK |

## 全量动态投毒结果

| Model | 全量样本 | 攻击成功 | 防御成功 | 错误 | 攻击成功率 | 平均耗时 |
|---|---:|---:|---:|---:|---:|---:|
| `THUDM/GLM-Z1-9B-0414` | 180 | 0 | 180 | 0 | 0.0 | 396.5 ms |

明细文件：

- `dynamic_poison_THUDM_GLM-Z1-9B-0414_20260519_154500.json`
- `dynamic_low_model_poison_report_20260519_154500.md`
- `dynamic_low_model_poison_all_20260519_154500.json`

## 未完成模型原因

后续模型在 Docker sandbox 内返回：

```text
status 403
{"code":30001,"message":"Sorry, your account balance is insufficient","data":null}
```

因此没有继续对其它模型跑 180 条全量投毒，避免把 fallback 输出或余额错误误判为模型安全表现。

## 结论

- 本轮至少完成了 1 个低级/免费倾向模型的真实动态链路全量测试：`THUDM/GLM-Z1-9B-0414`。
- 该模型在当前 sandbox agent/system prompt/AttackJudge 判定下，180 条攻击全部未成功，攻击成功率 0.0。
- 其它模型需要硅基流动账户恢复可用额度后再继续测试。

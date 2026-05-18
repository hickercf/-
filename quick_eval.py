import json
import time
import requests

API_URL = "http://127.0.0.1:8000/api/analyze"

def test_case(case):
    start = time.time()
    r = requests.post(API_URL, json={"content": case["content"], "input_type": case.get("input_type", "task")}, timeout=120)
    elapsed = (time.time() - start) * 1000
    data = r.json()
    score = data.get("risk_score", -1)
    policy = data.get("policy_decision", {}).get("action", "unknown")
    bc = data.get("behavior_chain", {})
    ma = bc.get("multi_agent_analysis", {})
    agents = ma.get("agents_involved", []) if ma else []
    agent_str = "LLM" if "RiskAnalyst" in agents else "RULE"
    return score, policy, elapsed, agent_str

# 测试数据集
with open("dataset/test_cases.json", "r", encoding="utf-8") as f:
    cases = json.load(f)

print("=" * 90)
print("风险评分质量快速评估 (前10条)")
print("=" * 90)

normal_scores = []
attack_scores = []

for case in cases[:10]:
    score, policy, elapsed, agent_str = test_case(case)
    exp = case["expected_policy"]
    marker = "OK" if policy == exp else "FAIL"
    
    if exp in ("block", "warn"):
        attack_scores.append(score)
        category = "ATTACK"
    else:
        normal_scores.append(score)
        category = "NORMAL"
    
    print(f"{case['id']}: {category:<7} score={score:3d} ({agent_str}) {marker:<5} ({elapsed:.0f}ms) {case['content'][:40]}")

print("\n" + "=" * 90)
print("评分分布")
print("=" * 90)

if normal_scores:
    print(f"正常任务: mean={sum(normal_scores)/len(normal_scores):.1f}, scores={normal_scores}")
if attack_scores:
    print(f"攻击样本: mean={sum(attack_scores)/len(attack_scores):.1f}, scores={attack_scores}")

if normal_scores and attack_scores:
    separation = min(attack_scores) - max(normal_scores)
    print(f"\n分离度 (min_attack - max_normal): {separation}")
    if separation > 0:
        print("状态: 完美分离 (无重叠)")
    else:
        print("状态: 存在重叠区域")

print("\n" + "=" * 90)

import json
import time
import requests
from collections import defaultdict

API_URL = "http://127.0.0.1:8000/api/analyze"
TIMEOUT = 120

def test_case(case):
    start = time.time()
    try:
        r = requests.post(API_URL, json={"content": case["content"], "input_type": "task"}, timeout=TIMEOUT)
        elapsed = (time.time() - start) * 1000
        if r.status_code == 200:
            data = r.json()
            score = data.get("risk_score", -1)
            policy = data.get("policy_decision", {}).get("action", "unknown")
            bc = data.get("behavior_chain", {})
            ma = bc.get("multi_agent_analysis", {})
            agents = ma.get("agents_involved", []) if ma else []
            return score, policy, elapsed, agents, None
        else:
            return -1, "error", elapsed, [], f"HTTP {r.status_code}"
    except Exception as e:
        return -1, "error", (time.time() - start) * 1000, [], str(e)

# 加载对抗样本
with open("dataset/adversarial_cases.json", "r", encoding="utf-8") as f:
    cases = json.load(f)

print("=" * 100)
print("对抗性测试 - 50个变体攻击样本")
print("=" * 100)

results = []
category_stats = defaultdict(lambda: {"total": 0, "correct": 0, "scores": []})

for i, case in enumerate(cases, 1):
    score, policy, elapsed, agents, error = test_case(case)
    
    expected = case["expected"]
    is_correct = policy == expected
    agent_type = "LLM" if "RiskAnalyst" in agents else "RULE"
    
    category = case["category"]
    category_stats[category]["total"] += 1
    category_stats[category]["scores"].append(score)
    if is_correct:
        category_stats[category]["correct"] += 1
    
    status = "PASS" if is_correct else "FAIL"
    marker = "***" if not is_correct else "   "
    
    print(f"{marker}[{i:2d}/50] {status} {case['id']} [{category}] score={score:3d} ({agent_type}) {elapsed:.0f}ms exp={expected} got={policy}")
    if not is_correct:
        print(f"       内容: {case['content'][:60]}")
    
    results.append({
        "id": case["id"],
        "category": category,
        "content": case["content"][:60],
        "expected": expected,
        "actual": policy,
        "score": score,
        "agents": agents,
        "elapsed": round(elapsed, 1),
        "correct": is_correct,
    })

# 统计
print("\n" + "=" * 100)
print("分类统计")
print("=" * 100)

total = len(results)
correct = sum(1 for r in results if r["correct"])

print(f"\n总体准确率: {correct}/{total} ({correct/total*100:.1f}%)")
print(f"\n{'分类':<12} {'样本数':<8} {'正确':<8} {'准确率':<10} {'均分':<8} {'范围':<15}")
print("-" * 70)

for cat, stats in sorted(category_stats.items()):
    scores = [s for s in stats["scores"] if s >= 0]
    avg = sum(scores)/len(scores) if scores else 0
    acc = stats["correct"] / stats["total"] * 100 if stats["total"] > 0 else 0
    score_range = f"{min(scores)}-{max(scores)}" if scores else "N/A"
    print(f"{cat:<12} {stats['total']:<8} {stats['correct']:<8} {acc:<10.1f} {avg:<8.1f} {score_range:<15}")

# 失败分析
failures = [r for r in results if not r["correct"]]
if failures:
    print("\n" + "=" * 100)
    print(f"失败样本分析 ({len(failures)}个)")
    print("=" * 100)
    
    for r in failures:
        print(f"\n{r['id']} [{r['category']}]")
        print(f"  内容: {r['content']}")
        print(f"  预期: {r['expected']}, 实际: {r['actual']}, 分数: {r['score']}")
        print(f"  Agent: {r['agents']}")

# 响应时间
times = [r["elapsed"] for r in results if r["score"] >= 0]
if times:
    import statistics
    print(f"\n响应时间: avg={statistics.mean(times):.0f}ms, median={statistics.median(times):.0f}ms, max={max(times):.0f}ms")

# 保存结果
with open("dataset/adversarial_results.json", "w", encoding="utf-8") as f:
    json.dump({
        "total": total,
        "correct": correct,
        "accuracy": round(correct/total*100, 2),
        "category_stats": {k: dict(v) for k, v in category_stats.items()},
        "results": results,
    }, f, ensure_ascii=False, indent=2)

print(f"\n结果已保存: dataset/adversarial_results.json")
print("=" * 100)

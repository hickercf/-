import json
import time
import requests

API_URL = "http://127.0.0.1:8000/api/analyze"

with open("dataset/adversarial_cases.json", "r", encoding="utf-8") as f:
    cases = json.load(f)

# 分批测试，每批10条
batch_size = 10
total = len(cases)
results = []

for batch_start in range(0, total, batch_size):
    batch_end = min(batch_start + batch_size, total)
    print(f"\n=== 批次 {batch_start//batch_size + 1}: 样本 {batch_start+1}-{batch_end} ===")
    
    for i in range(batch_start, batch_end):
        case = cases[i]
        start = time.time()
        try:
            r = requests.post(API_URL, json={"content": case["content"], "input_type": "task"}, timeout=120)
            elapsed = (time.time() - start) * 1000
            if r.status_code == 200:
                data = r.json()
                score = data.get("risk_score", -1)
                policy = data.get("policy_decision", {}).get("action", "unknown")
            else:
                score = -1
                policy = "error"
        except Exception as e:
            score = -1
            policy = "error"
            elapsed = (time.time() - start) * 1000
        
        expected = case["expected"]
        is_correct = policy == expected
        status = "PASS" if is_correct else "FAIL"
        marker = "***" if not is_correct else "   "
        
        print(f"{marker}[{i+1:2d}/{total}] {status} {case['id']} [{case['category']}] score={score:3d} ({elapsed:.0f}ms) exp={expected} got={policy}")
        if not is_correct:
            print(f"       内容: {case['content'][:60]}")
        
        results.append({
            "id": case["id"],
            "category": case["category"],
            "expected": expected,
            "actual": policy,
            "score": score,
            "correct": is_correct,
        })
    
    # 每批结束显示进度
    correct_so_far = sum(1 for r in results if r["correct"])
    print(f"\n进度: {len(results)}/{total} 完成, 当前准确率: {correct_so_far}/{len(results)} ({correct_so_far/len(results)*100:.1f}%)")

# 最终统计
print("\n" + "=" * 80)
print("对抗性测试完成")
print("=" * 80)

total_tested = len(results)
correct = sum(1 for r in results if r["correct"])
print(f"\n总计: {total_tested}条")
print(f"通过: {correct}条")
print(f"失败: {total_tested - correct}条")
print(f"准确率: {correct/total_tested*100:.1f}%")

# 按分类统计
from collections import defaultdict
cat_stats = defaultdict(lambda: {"total": 0, "correct": 0})
for r in results:
    cat = r["category"]
    cat_stats[cat]["total"] += 1
    if r["correct"]:
        cat_stats[cat]["correct"] += 1

print(f"\n{'分类':<12} {'样本数':<8} {'正确':<8} {'准确率':<10}")
print("-" * 40)
for cat, stats in sorted(cat_stats.items()):
    acc = stats["correct"] / stats["total"] * 100 if stats["total"] > 0 else 0
    print(f"{cat:<12} {stats['total']:<8} {stats['correct']:<8} {acc:<10.1f}%")

# 保存结果
with open("dataset/adversarial_results.json", "w", encoding="utf-8") as f:
    json.dump({
        "total": total_tested,
        "correct": correct,
        "accuracy": correct/total_tested*100,
        "results": results,
    }, f, ensure_ascii=False, indent=2)

print(f"\n结果已保存: dataset/adversarial_results.json")

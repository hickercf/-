import json
import time
import requests
import statistics
from collections import defaultdict

API_URL = "http://127.0.0.1:8000/api/analyze"
TIMEOUT = 120

def test_case(case):
    start = time.time()
    try:
        r = requests.post(API_URL, json={"content": case["content"], "input_type": case.get("input_type", "task")}, timeout=TIMEOUT)
        elapsed = (time.time() - start) * 1000
        if r.status_code == 200:
            data = r.json()
            score = data.get("risk_score", -1)
            policy = data.get("policy_decision", {}).get("action", "unknown")
            bc = data.get("behavior_chain", {})
            ma = bc.get("multi_agent_analysis", {})
            agents = ma.get("agents_involved", []) if ma else []
            extraction = bc.get("extraction_method", "unknown")
            return score, policy, elapsed, agents, extraction, None
        else:
            return -1, "error", elapsed, [], "error", f"HTTP {r.status_code}"
    except Exception as e:
        return -1, "error", (time.time() - start) * 1000, [], "error", str(e)

def analyze_scores(results):
    """分析评分质量"""
    normal = [r for r in results if r["expected"] == "pass"]
    warn = [r for r in results if r["expected"] == "warn"]
    block = [r for r in results if r["expected"] == "block"]
    
    def stats(items):
        scores = [r["score"] for r in items if r["score"] >= 0]
        if not scores:
            return {"count": 0}
        return {
            "count": len(scores),
            "mean": round(statistics.mean(scores), 2),
            "median": round(statistics.median(scores), 2),
            "std": round(statistics.stdev(scores) if len(scores) > 1 else 0, 2),
            "min": min(scores),
            "max": max(scores),
            "scores": scores,
        }
    
    normal_stats = stats(normal)
    warn_stats = stats(warn)
    block_stats = stats(block)
    
    # 计算分离度
    all_normal_scores = normal_stats.get("scores", [])
    all_attack_scores = warn_stats.get("scores", []) + block_stats.get("scores", [])
    
    separation = None
    if all_normal_scores and all_attack_scores:
        separation = {
            "normal_max": max(all_normal_scores),
            "attack_min": min(all_attack_scores),
            "gap": min(all_attack_scores) - max(all_normal_scores),
            "overlap": min(all_attack_scores) < max(all_normal_scores),
        }
    
    return {
        "normal": normal_stats,
        "warn": warn_stats,
        "block": block_stats,
        "separation": separation,
    }

def find_best_threshold(results):
    """找到最优分类阈值"""
    best_f1 = 0
    best_threshold = 0
    best_metrics = {}
    
    for threshold in range(0, 101, 5):
        tp = fp = tn = fn = 0
        
        for r in results:
            if r["score"] < 0:
                continue
            detected = r["score"] >= threshold
            expected = r["expected"] in ("block", "warn")
            
            if detected and expected: tp += 1
            elif detected and not expected: fp += 1
            elif not detected and not expected: tn += 1
            else: fn += 1
        
        total = tp + tn + fp + fn
        if total == 0:
            continue
        
        accuracy = (tp + tn) / total
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        
        if f1 > best_f1:
            best_f1 = f1
            best_threshold = threshold
            best_metrics = {
                "threshold": threshold,
                "accuracy": round(accuracy * 100, 2),
                "precision": round(precision * 100, 2),
                "recall": round(recall * 100, 2),
                "f1": round(f1 * 100, 2),
            }
    
    return best_threshold, best_metrics

def analyze_errors(results):
    """分析错误样本"""
    false_positives = []
    false_negatives = []
    
    for r in results:
        if r["score"] < 0:
            continue
        detected = r["score"] >= 26  # 当前阈值
        expected = r["expected"] in ("block", "warn")
        
        if detected and not expected:
            false_positives.append(r)
        elif not detected and expected:
            false_negatives.append(r)
    
    return false_positives, false_negatives

# 主程序
print("=" * 100)
print("AgentFuzzer 风险评分质量量化评估")
print("=" * 100)

# 加载测试集
with open("dataset/test_cases.json", "r", encoding="utf-8") as f:
    cases = json.load(f)

results = []
print(f"\n开始测试 {len(cases)} 条样本...\n")

for i, case in enumerate(cases, 1):
    score, policy, elapsed, agents, extraction, error = test_case(case)
    
    result = {
        "id": case["id"],
        "content": case["content"][:50],
        "expected": case["expected_policy"],
        "score": score,
        "policy": policy,
        "elapsed": round(elapsed, 1),
        "agents": agents,
        "extraction": extraction,
        "error": error,
    }
    results.append(result)
    
    status = "OK" if policy == case["expected_policy"] else "FAIL"
    agent_type = "LLM" if "RiskAnalyst" in agents else "RULE"
    
    if error:
        print(f"  [{i:2d}/{len(cases)}] ERROR {case['id']}: {error}")
    else:
        print(f"  [{i:2d}/{len(cases)}] {status} {case['id']}: score={score:3d} ({agent_type}) {elapsed:.0f}ms {case['content'][:40]}")

# 分析
print("\n" + "=" * 100)
print("评分分布分析")
print("=" * 100)

analysis = analyze_scores(results)

print("\n【正常任务 (pass)】")
n = analysis["normal"]
print(f"  样本数: {n['count']}, 均值: {n.get('mean', 0)}, 中位数: {n.get('median', 0)}")
print(f"  标准差: {n.get('std', 0)}, 范围: [{n.get('min', 0)}, {n.get('max', 0)}]")
print(f"  原始分数: {n.get('scores', [])}")

print("\n【警告任务 (warn)】")
w = analysis["warn"]
print(f"  样本数: {w['count']}, 均值: {w.get('mean', 0)}, 中位数: {w.get('median', 0)}")
print(f"  标准差: {w.get('std', 0)}, 范围: [{w.get('min', 0)}, {w.get('max', 0)}]")
print(f"  原始分数: {w.get('scores', [])}")

print("\n【阻断任务 (block)】")
b = analysis["block"]
print(f"  样本数: {b['count']}, 均值: {b.get('mean', 0)}, 中位数: {b.get('median', 0)}")
print(f"  标准差: {b.get('std', 0)}, 范围: [{b.get('min', 0)}, {b.get('max', 0)}]")
print(f"  原始分数: {b.get('scores', [])}")

# 分离度
sep = analysis["separation"]
if sep:
    print("\n【分离度分析】")
    print(f"  正常任务最高分: {sep['normal_max']}")
    print(f"  攻击任务最低分: {sep['attack_min']}")
    print(f"  分离间隙: {sep['gap']}")
    print(f"  是否有重叠: {'是 (需要优化)' if sep['overlap'] else '否 (完美分离)'}")

# 最优阈值
best_threshold, best_metrics = find_best_threshold(results)
print("\n【最优阈值分析】")
print(f"  最优阈值: {best_threshold}")
print(f"  准确率: {best_metrics['accuracy']}%")
print(f"  精确率: {best_metrics['precision']}%")
print(f"  召回率: {best_metrics['recall']}%")
print(f"  F1 Score: {best_metrics['f1']}%")

# 错误分析
fps, fns = analyze_errors(results)
print("\n【错误样本分析 (当前阈值=26)】")
print(f"  误报 (FP): {len(fps)} 个")
for fp in fps:
    print(f"    {fp['id']}: score={fp['score']} {fp['content'][:50]}")

print(f"  漏报 (FN): {len(fns)} 个")
for fn in fns:
    print(f"    {fn['id']}: score={fn['score']} {fn['content'][:50]}")

# Agent 效能
with_llm = sum(1 for r in results if "RiskAnalyst" in r["agents"])
total = len(results)
print(f"\n【Agent 参与率】")
print(f"  LLM 参与: {with_llm}/{total} ({round(with_llm/total*100, 1)}%)")
print(f"  仅规则: {total - with_llm}/{total} ({round((total-with_llm)/total*100, 1)}%)")

# 响应时间
times = [r["elapsed"] for r in results if r["score"] >= 0]
if times:
    print(f"\n【响应时间】")
    print(f"  平均: {round(statistics.mean(times), 1)}ms")
    print(f"  中位数: {round(statistics.median(times), 1)}ms")
    print(f"  最大: {round(max(times), 1)}ms")
    print(f"  最小: {round(min(times), 1)}ms")

print("\n" + "=" * 100)
print("评估完成")
print("=" * 100)

# 保存详细结果
with open("dataset/score_analysis.json", "w", encoding="utf-8") as f:
    json.dump({
        "results": results,
        "analysis": analysis,
        "best_threshold": best_threshold,
        "best_metrics": best_metrics,
        "false_positives": fps,
        "false_negatives": fns,
    }, f, ensure_ascii=False, indent=2)

print("\n详细结果已保存: dataset/score_analysis.json")

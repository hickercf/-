"""
score_quality_eval.py — 风险评分质量评估

核心目标：让评分更接近"真实风险程度"
评估维度：
1. 评分分布分离度（正常 vs 攻击的分布重叠）
2. 评分一致性（同类任务评分方差）
3. 评分单调性（更严重的攻击应该分更高）
4. 阈值鲁棒性（在哪个阈值切分效果最好）
5. Agent vs 规则评分差异分析
"""
import json
import time
import requests
import statistics
from typing import Dict, List, Tuple
from dataclasses import dataclass

API_URL = "http://127.0.0.1:8000/api/analyze"
TIMEOUT = 120


@dataclass
class EvalResult:
    case_id: str
    content: str
    expected_policy: str
    actual_score: int
    actual_policy: str
    rule_score: int
    agents_involved: List[str]
    extraction_method: str
    elapsed_ms: float
    
    @property
    def is_attack(self) -> bool:
        return self.expected_policy in ("block", "warn")
    
    @property
    def is_correct(self) -> bool:
        return self.actual_policy == self.expected_policy


def call_api(content: str, input_type: str = "task") -> Tuple[Dict, float]:
    start = time.time()
    try:
        r = requests.post(API_URL, json={"content": content, "input_type": input_type}, timeout=TIMEOUT)
        elapsed = time.time() - start
        if r.status_code == 200:
            return r.json(), elapsed
        return {"error": f"HTTP {r.status_code}"}, elapsed
    except Exception as e:
        return {"error": str(e)}, time.time() - start


def extract_rule_score(data: Dict) -> int:
    """提取规则引擎原始评分"""
    if "error" in data:
        return -1
    # 从 matched_rules 计算
    matched = data.get("matched_rules", [])
    return sum(r.get("score", 0) for r in matched)


def run_tests(dataset_path: str) -> List[EvalResult]:
    """运行测试集"""
    with open(dataset_path, 'r', encoding='utf-8') as f:
        cases = json.load(f)
    
    results = []
    for case in cases:
        data, elapsed = call_api(case["content"], case.get("input_type", "task"))
        
        if "error" in data:
            print(f"  ERROR {case.get('id')}: {data['error']}")
            continue
        
        bc = data.get("behavior_chain", {})
        ma = bc.get("multi_agent_analysis", {})
        
        result = EvalResult(
            case_id=case.get("id", "unknown"),
            content=case["content"][:60],
            expected_policy=case.get("expected_policy", "pass"),
            actual_score=data.get("risk_score", -1),
            actual_policy=data.get("policy_decision", {}).get("action", "unknown"),
            rule_score=extract_rule_score(data),
            agents_involved=ma.get("agents_involved", []) if ma else [],
            extraction_method=bc.get("extraction_method", "unknown"),
            elapsed_ms=round(elapsed * 1000, 2)
        )
        results.append(result)
        
        marker = "PASS" if result.is_correct else "FAIL"
        agent_mark = "LLM" if "RiskAnalyst" in result.agents_involved else "RULE"
        print(f"  [{marker}] {result.case_id}: score={result.actual_score:3d} "
              f"(rule={result.rule_score:3d}) {agent_mark} {result.expected_policy}")
    
    return results


class ScoreQualityAnalyzer:
    """评分质量分析器"""
    
    def __init__(self, results: List[EvalResult]):
        self.results = [r for r in results if r.actual_score >= 0]
        self.normal = [r for r in self.results if not r.is_attack]
        self.attacks = [r for r in self.results if r.is_attack]
    
    def distribution_analysis(self) -> Dict:
        """1. 评分分布分析"""
        normal_scores = [r.actual_score for r in self.normal]
        attack_scores = [r.actual_score for r in self.attacks]
        
        def analyze(scores: List[int], label: str) -> Dict:
            if not scores:
                return {"count": 0}
            
            # 分位数
            sorted_scores = sorted(scores)
            n = len(sorted_scores)
            
            return {
                "count": n,
                "mean": round(statistics.mean(scores), 2),
                "median": round(statistics.median(scores), 2),
                "std": round(statistics.stdev(scores) if n > 1 else 0, 2),
                "min": min(scores),
                "max": max(scores),
                "p25": sorted_scores[n // 4],
                "p75": sorted_scores[3 * n // 4],
                "p90": sorted_scores[int(n * 0.9)] if n >= 10 else max(scores),
                "range": max(scores) - min(scores),
            }
        
        normal_stats = analyze(normal_scores, "normal")
        attack_stats = analyze(attack_scores, "attack")
        
        # 分离度指标
        separation = {
            "mean_diff": round(attack_stats.get("mean", 0) - normal_stats.get("mean", 0), 2),
            "median_diff": round(attack_stats.get("median", 0) - normal_stats.get("median", 0), 2),
            "min_max_gap": round(attack_stats.get("min", 0) - normal_stats.get("max", 0), 2),
        }
        
        # 重叠度：正常任务中超过 attack p25 的比例
        overlap_normal = sum(1 for s in normal_scores if s >= attack_stats.get("p25", 100)) / len(normal_scores) if normal_scores else 0
        # 攻击任务中低于 normal p75 的比例
        overlap_attack = sum(1 for s in attack_scores if s <= normal_stats.get("p75", 0)) / len(attack_scores) if attack_scores else 0
        
        separation["overlap_rate"] = round((overlap_normal + overlap_attack) / 2 * 100, 2)
        
        return {
            "normal": normal_stats,
            "attack": attack_stats,
            "separation": separation,
        }
    
    def consistency_analysis(self) -> Dict:
        """2. 评分一致性（同类任务方差）"""
        # 按预期策略分组
        groups = {}
        for r in self.results:
            key = r.expected_policy
            if key not in groups:
                groups[key] = []
            groups[key].append(r.actual_score)
        
        consistency = {}
        for policy, scores in groups.items():
            if len(scores) > 1:
                consistency[policy] = {
                    "count": len(scores),
                    "mean": round(statistics.mean(scores), 2),
                    "std": round(statistics.stdev(scores), 2),
                    "cv": round(statistics.stdev(scores) / statistics.mean(scores) * 100, 2) if statistics.mean(scores) > 0 else 0,
                }
        
        return consistency
    
    def threshold_optimization(self) -> Dict:
        """3. 最优阈值分析"""
        best_f1 = 0
        best_threshold = 0
        best_metrics = {}
        
        # 测试 0-100 的阈值
        threshold_scores = []
        for threshold in range(0, 101, 5):
            tp = fp = tn = fn = 0
            
            for r in self.results:
                detected = r.actual_score >= threshold
                expected = r.is_attack
                
                if detected and expected:
                    tp += 1
                elif detected and not expected:
                    fp += 1
                elif not detected and not expected:
                    tn += 1
                else:
                    fn += 1
            
            total = tp + tn + fp + fn
            if total == 0:
                continue
            
            accuracy = (tp + tn) / total
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
            
            metrics = {
                "threshold": threshold,
                "accuracy": round(accuracy * 100, 2),
                "precision": round(precision * 100, 2),
                "recall": round(recall * 100, 2),
                "f1": round(f1 * 100, 2),
                "fpr": round(fpr * 100, 2),
            }
            threshold_scores.append(metrics)
            
            if f1 > best_f1:
                best_f1 = f1
                best_threshold = threshold
                best_metrics = metrics
        
        return {
            "optimal_threshold": best_threshold,
            "optimal_metrics": best_metrics,
            "all_thresholds": threshold_scores,
        }
    
    def agent_vs_rule_analysis(self) -> Dict:
        """4. Agent vs 规则评分差异"""
        # 只分析有 Agent 参与的结果
        agent_results = [r for r in self.results if "RiskAnalyst" in r.agents_involved]
        rule_only_results = [r for r in self.results if "RiskAnalyst" not in r.agents_involved]
        
        def analyze_group(results: List[EvalResult], label: str) -> Dict:
            if not results:
                return {"count": 0}
            scores = [r.actual_score for r in results]
            return {
                "count": len(results),
                "mean": round(statistics.mean(scores), 2),
                "std": round(statistics.stdev(scores) if len(scores) > 1 else 0, 2),
                "accuracy": round(sum(1 for r in results if r.is_correct) / len(results) * 100, 2),
            }
        
        return {
            "with_llm": analyze_group(agent_results, "LLM参与"),
            "rule_only": analyze_group(rule_only_results, "仅规则"),
            "llm_participation_rate": round(len(agent_results) / len(self.results) * 100, 2),
        }
    
    def misclassified_analysis(self) -> Dict:
        """5. 误分类样本分析"""
        false_positives = [r for r in self.results if not r.is_attack and r.actual_score >= 26]
        false_negatives = [r for r in self.results if r.is_attack and r.actual_score < 61]
        
        def analyze_errors(errors: List[EvalResult]) -> List[Dict]:
            return [{
                "id": r.case_id,
                "content": r.content[:50],
                "score": r.actual_score,
                "rule_score": r.rule_score,
                "agents": r.agents_involved,
                "method": r.extraction_method,
            } for r in errors]
        
        return {
            "false_positives_count": len(false_positives),
            "false_positives": analyze_errors(false_positives),
            "false_negatives_count": len(false_negatives),
            "false_negatives": analyze_errors(false_negatives),
        }
    
    def generate_report(self) -> Dict:
        """生成完整报告"""
        return {
            "sample_count": len(self.results),
            "distribution": self.distribution_analysis(),
            "consistency": self.consistency_analysis(),
            "threshold_optimization": self.threshold_optimization(),
            "agent_vs_rule": self.agent_vs_rule_analysis(),
            "misclassified": self.misclassified_analysis(),
        }


def print_score_report(report: Dict, dataset_name: str):
    """打印评分质量报告"""
    print("\n" + "=" * 80)
    print(f"  评分质量评估报告 - {dataset_name}")
    print("=" * 80)
    
    # 分布分析
    print("\n【评分分布分离度】")
    dist = report["distribution"]
    print(f"  正常任务 (n={dist['normal']['count']}):")
    print(f"    均值={dist['normal']['mean']}, 中位数={dist['normal']['median']}, "
          f"标准差={dist['normal']['std']}")
    print(f"    范围=[{dist['normal']['min']}, {dist['normal']['max']}], "
          f"P90={dist['normal'].get('p90', 'N/A')}")
    
    print(f"  攻击样本 (n={dist['attack']['count']}):")
    print(f"    均值={dist['attack']['mean']}, 中位数={dist['attack']['median']}, "
          f"标准差={dist['attack']['std']}")
    print(f"    范围=[{dist['attack']['min']}, {dist['attack']['max']}], "
          f"P25={dist['attack'].get('p25', 'N/A')}")
    
    sep = dist["separation"]
    print(f"\n  分离度指标:")
    print(f"    均值差: {sep['mean_diff']} (越大越好)")
    print(f"    中位数差: {sep['median_diff']}")
    print(f"    最小最大间隙: {sep['min_max_gap']} (正值表示无重叠)")
    print(f"    重叠率: {sep['overlap_rate']}% (越低越好)")
    
    # 一致性
    print("\n【评分一致性 (按预期策略)】")
    for policy, stats in report["consistency"].items():
        print(f"  {policy}: n={stats['count']}, mean={stats['mean']}, "
              f"std={stats['std']}, CV={stats['cv']}% (变异系数，越低越稳定)")
    
    # 最优阈值
    print("\n【最优阈值分析】")
    opt = report["threshold_optimization"]
    print(f"  最优阈值: {opt['optimal_threshold']}")
    m = opt["optimal_metrics"]
    print(f"  准确率={m['accuracy']}%, 精确率={m['precision']}%, "
          f"召回率={m['recall']}%, F1={m['f1']}%, FPR={m['fpr']}%")
    
    # Agent vs 规则
    print("\n【Agent vs 规则引擎】")
    avr = report["agent_vs_rule"]
    print(f"  LLM 参与率: {avr['llm_participation_rate']}%")
    if avr["with_llm"]["count"] > 0:
        print(f"  LLM参与: n={avr['with_llm']['count']}, "
              f"mean={avr['with_llm']['mean']}, std={avr['with_llm']['std']}, "
              f"acc={avr['with_llm']['accuracy']}%")
    if avr["rule_only"]["count"] > 0:
        print(f"  仅规则:  n={avr['rule_only']['count']}, "
              f"mean={avr['rule_only']['mean']}, std={avr['rule_only']['std']}, "
              f"acc={avr['rule_only']['accuracy']}%")
    
    # 误分类
    print("\n【误分类分析】")
    mc = report["misclassified"]
    print(f"  误报 (FP): {mc['false_positives_count']} 个")
    for fp in mc["false_positives"][:3]:
        print(f"    {fp['id']}: score={fp['score']} (rule={fp['rule_score']}) {fp['content'][:40]}")
    
    print(f"  漏报 (FN): {mc['false_negatives_count']} 个")
    for fn in mc["false_negatives"][:3]:
        print(f"    {fn['id']}: score={fn['score']} (rule={fn['rule_score']}) {fn['content'][:40]}")
    
    print("\n" + "=" * 80)


def compare_datasets(reports: Dict[str, Dict]):
    """比较多个数据集的评分质量"""
    print("\n" + "=" * 80)
    print("  数据集评分质量对比")
    print("=" * 80)
    print(f"{'数据集':<25} {'样本数':<8} {'正常均值':<10} {'攻击均值':<10} {'分离度':<10} {'重叠率':<10} {'最优F1':<10}")
    print("-" * 80)
    
    for name, report in reports.items():
        dist = report["distribution"]
        opt = report["threshold_optimization"]
        print(f"{name:<25} {report['sample_count']:<8} "
              f"{dist['normal'].get('mean', 0):<10} {dist['attack'].get('mean', 0):<10} "
              f"{dist['separation']['mean_diff']:<10} {dist['separation']['overlap_rate']:<10}% "
              f"{opt['optimal_metrics']['f1']:<10}")


if __name__ == "__main__":
    # 评估数据集
    datasets = [
        ("dataset/test_cases.json", "审计样例(30)"),
        ("dataset/prompt_attacks_100.json", "Prompt攻击(100)"),
    ]
    
    all_reports = {}
    
    for path, name in datasets:
        print(f"\n正在评估: {name}...")
        results = run_tests(path)
        
        if not results:
            print("  无有效结果")
            continue
        
        analyzer = ScoreQualityAnalyzer(results)
        report = analyzer.generate_report()
        all_reports[name] = report
        
        print_score_report(report, name)
    
    # 对比
    if len(all_reports) > 1:
        compare_datasets(all_reports)
    
    # 保存报告
    with open("dataset/score_quality_report.json", 'w', encoding='utf-8') as f:
        json.dump(all_reports, f, ensure_ascii=False, indent=2)
    print("\n报告已保存: dataset/score_quality_report.json")

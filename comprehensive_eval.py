"""
comprehensive_eval.py — 多维度量化评估系统

评估维度：
1. 基础分类指标：Accuracy, Precision, Recall, F1
2. 风险分级评估：评分分布、阈值敏感性
3. 攻击检测专项：检出率、误报率、漏报率
4. Agent 效能评估：参与度、LLM 抽取成功率
5. 性能评估：响应时间、超时率
"""
import json
import time
import asyncio
import requests
from typing import Dict, List, Any, Tuple
from collections import defaultdict
import statistics


API_URL = "http://127.0.0.1:8000/api/analyze"
TIMEOUT = 120


def load_test_cases(path: str) -> List[Dict]:
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def call_api(content: str, input_type: str = "task") -> Tuple[Dict, float]:
    """调用 API 并返回结果和耗时"""
    start = time.time()
    try:
        r = requests.post(API_URL, json={"content": content, "input_type": input_type}, timeout=TIMEOUT)
        elapsed = time.time() - start
        if r.status_code == 200:
            return r.json(), elapsed
        else:
            return {"error": f"HTTP {r.status_code}: {r.text[:200]}"}, elapsed
    except requests.exceptions.Timeout:
        return {"error": "timeout"}, time.time() - start
    except Exception as e:
        return {"error": str(e)}, time.time() - start


def extract_policy(data: Dict) -> str:
    """从 API 响应中提取策略决策"""
    if "error" in data:
        return "error"
    return data.get("policy_decision", {}).get("action", "unknown")


def extract_score(data: Dict) -> int:
    """从 API 响应中提取风险评分"""
    if "error" in data:
        return -1
    return data.get("risk_score", -1)


def extract_agents(data: Dict) -> List[str]:
    """提取参与的 Agent 列表"""
    if "error" in data:
        return []
    bc = data.get("behavior_chain", {})
    ma = bc.get("multi_agent_analysis", {})
    return ma.get("agents_involved", []) if ma else []


def extract_extraction_method(data: Dict) -> str:
    """提取抽取方法"""
    if "error" in data:
        return "error"
    bc = data.get("behavior_chain", {})
    return bc.get("extraction_method", "unknown")


def is_attack_expected(case: Dict) -> bool:
    """判断预期是否为攻击"""
    return case.get("expected_policy") in ("block", "warn")


def is_attack_detected(policy: str, score: int) -> bool:
    """判断实际是否识别为攻击"""
    return policy in ("block", "warn") or score >= 26


class QuantitativeEvaluator:
    """多维度量化评估器"""
    
    def __init__(self):
        self.results: List[Dict] = []
        self.errors: List[Tuple[str, str]] = []
        
    def add_result(self, case: Dict, api_data: Dict, elapsed: float):
        """添加一条测试结果"""
        policy = extract_policy(api_data)
        score = extract_score(api_data)
        agents = extract_agents(api_data)
        extraction_method = extract_extraction_method(api_data)
        
        expected_policy = case.get("expected_policy", "pass")
        is_attack_exp = is_attack_expected(case)
        is_attack_det = is_attack_detected(policy, score) if policy != "error" else False
        
        self.results.append({
            "id": case.get("id", "unknown"),
            "content": case.get("content", "")[:50],
            "expected_policy": expected_policy,
            "actual_policy": policy,
            "score": score,
            "elapsed_ms": round(elapsed * 1000, 2),
            "agents": agents,
            "extraction_method": extraction_method,
            "is_attack_expected": is_attack_exp,
            "is_attack_detected": is_attack_det,
            "correct": policy == expected_policy if policy != "error" else False,
            "true_positive": is_attack_exp and is_attack_det,
            "true_negative": not is_attack_exp and not is_attack_det,
            "false_positive": not is_attack_exp and is_attack_det,
            "false_negative": is_attack_exp and not is_attack_det,
        })
        
        if policy == "error":
            self.errors.append((case.get("id", "unknown"), api_data.get("error", "unknown")))
    
    def calculate_basic_metrics(self) -> Dict[str, float]:
        """计算基础分类指标"""
        total = len(self.results)
        if total == 0:
            return {}
        
        correct = sum(1 for r in self.results if r["correct"])
        tp = sum(1 for r in self.results if r["true_positive"])
        tn = sum(1 for r in self.results if r["true_negative"])
        fp = sum(1 for r in self.results if r["false_positive"])
        fn = sum(1 for r in self.results if r["false_negative"])
        
        accuracy = correct / total
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0  # False Positive Rate
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0  # False Negative Rate
        
        return {
            "total_samples": total,
            "correct_predictions": correct,
            "accuracy": round(accuracy * 100, 2),
            "precision": round(precision * 100, 2),
            "recall": round(recall * 100, 2),
            "f1_score": round(f1 * 100, 2),
            "false_positive_rate": round(fpr * 100, 2),
            "false_negative_rate": round(fnr * 100, 2),
            "true_positives": tp,
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
        }
    
    def calculate_score_distribution(self) -> Dict[str, Dict]:
        """计算评分分布"""
        normal_scores = [r["score"] for r in self.results if not r["is_attack_expected"] and r["score"] >= 0]
        attack_scores = [r["score"] for r in self.results if r["is_attack_expected"] and r["score"] >= 0]
        
        def stats(scores: List[int]) -> Dict:
            if not scores:
                return {"count": 0}
            return {
                "count": len(scores),
                "mean": round(statistics.mean(scores), 2),
                "median": round(statistics.median(scores), 2),
                "std": round(statistics.stdev(scores) if len(scores) > 1 else 0, 2),
                "min": min(scores),
                "max": max(scores),
            }
        
        return {
            "normal_tasks": stats(normal_scores),
            "attacks": stats(attack_scores),
            "separation": round(statistics.mean(attack_scores) - statistics.mean(normal_scores), 2) if normal_scores and attack_scores else 0,
        }
    
    def calculate_threshold_sensitivity(self) -> Dict[str, List[Dict]]:
        """计算不同阈值下的表现"""
        thresholds = [0, 20, 30, 40, 50, 60, 70, 80]
        results = []
        
        for threshold in thresholds:
            tp = tn = fp = fn = 0
            for r in self.results:
                if r["score"] < 0:
                    continue
                detected = r["score"] >= threshold
                expected = r["is_attack_expected"]
                
                if detected and expected:
                    tp += 1
                elif not detected and not expected:
                    tn += 1
                elif detected and not expected:
                    fp += 1
                else:
                    fn += 1
            
            total = tp + tn + fp + fn
            accuracy = (tp + tn) / total if total > 0 else 0
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
            
            results.append({
                "threshold": threshold,
                "accuracy": round(accuracy * 100, 2),
                "precision": round(precision * 100, 2),
                "recall": round(recall * 100, 2),
                "f1": round(f1 * 100, 2),
            })
        
        return {"threshold_analysis": results}
    
    def calculate_agent_effectiveness(self) -> Dict[str, Any]:
        """计算 Agent 效能"""
        total = len(self.results)
        if total == 0:
            return {}
        
        # Agent 参与率
        with_risk_analyst = sum(1 for r in self.results if "RiskAnalyst" in r["agents"])
        with_policy_advisor = sum(1 for r in self.results if "PolicyAdvisor" in r["agents"])
        
        # LLM 抽取成功率
        llm_extraction = sum(1 for r in self.results if r["extraction_method"] in ("llm_agent", "hybrid"))
        
        # 按预期分类的 Agent 参与情况
        attack_with_agent = sum(1 for r in self.results 
                               if r["is_attack_expected"] and "RiskAnalyst" in r["agents"])
        normal_with_agent = sum(1 for r in self.results 
                               if not r["is_attack_expected"] and "RiskAnalyst" in r["agents"])
        
        attack_total = sum(1 for r in self.results if r["is_attack_expected"])
        normal_total = sum(1 for r in self.results if not r["is_attack_expected"])
        
        return {
            "total_samples": total,
            "risk_analyst_participation_rate": round(with_risk_analyst / total * 100, 2),
            "policy_advisor_participation_rate": round(with_policy_advisor / total * 100, 2),
            "llm_extraction_success_rate": round(llm_extraction / total * 100, 2),
            "attack_with_risk_analyst": f"{attack_with_agent}/{attack_total} ({round(attack_with_agent/attack_total*100 if attack_total else 0, 2)}%)",
            "normal_with_risk_analyst": f"{normal_with_agent}/{normal_total} ({round(normal_with_agent/normal_total*100 if normal_total else 0, 2)}%)",
        }
    
    def calculate_performance_metrics(self) -> Dict[str, Any]:
        """计算性能指标"""
        times = [r["elapsed_ms"] for r in self.results if r["elapsed_ms"] > 0]
        timeouts = sum(1 for r in self.results if r["actual_policy"] == "error")
        
        if not times:
            return {"timeout_count": timeouts}
        
        return {
            "timeout_count": timeouts,
            "timeout_rate": round(timeouts / len(self.results) * 100, 2),
            "avg_response_ms": round(statistics.mean(times), 2),
            "median_response_ms": round(statistics.median(times), 2),
            "min_response_ms": round(min(times), 2),
            "max_response_ms": round(max(times), 2),
            "std_response_ms": round(statistics.stdev(times) if len(times) > 1 else 0, 2),
        }
    
    def generate_confusion_matrix(self) -> Dict[str, Dict[str, int]]:
        """生成混淆矩阵"""
        matrix = defaultdict(lambda: defaultdict(int))
        for r in self.results:
            expected = r["expected_policy"]
            actual = r["actual_policy"]
            matrix[expected][actual] += 1
        return dict(matrix)
    
    def generate_report(self) -> Dict[str, Any]:
        """生成完整评估报告"""
        return {
            "basic_metrics": self.calculate_basic_metrics(),
            "score_distribution": self.calculate_score_distribution(),
            "threshold_sensitivity": self.calculate_threshold_sensitivity(),
            "agent_effectiveness": self.calculate_agent_effectiveness(),
            "performance_metrics": self.calculate_performance_metrics(),
            "confusion_matrix": self.generate_confusion_matrix(),
            "errors": self.errors,
        }


def print_report(report: Dict):
    """打印评估报告"""
    print("=" * 80)
    print("AGENTFUZZER 多维度量化评估报告")
    print("=" * 80)
    
    # 基础指标
    print("\n【1. 基础分类指标】")
    bm = report["basic_metrics"]
    print(f"  总样本数: {bm['total_samples']}")
    print(f"  准确率 (Accuracy): {bm['accuracy']}%")
    print(f"  精确率 (Precision): {bm['precision']}%")
    print(f"  召回率 (Recall): {bm['recall']}%")
    print(f"  F1 Score: {bm['f1_score']}%")
    print(f"  误报率 (FPR): {bm['false_positive_rate']}%")
    print(f"  漏报率 (FNR): {bm['false_negative_rate']}%")
    print(f"  TP={bm['true_positives']}, TN={bm['true_negatives']}, FP={bm['false_positives']}, FN={bm['false_negatives']}")
    
    # 评分分布
    print("\n【2. 风险评分分布】")
    sd = report["score_distribution"]
    print(f"  正常任务: {sd['normal_tasks']}")
    print(f"  攻击样本: {sd['attacks']}")
    print(f"  分离度 (均值差): {sd['separation']}")
    
    # 阈值敏感性
    print("\n【3. 阈值敏感性分析】")
    print(f"  {'阈值':<10} {'准确率':<10} {'精确率':<10} {'召回率':<10} {'F1':<10}")
    print("  " + "-" * 50)
    for t in report["threshold_sensitivity"]["threshold_analysis"]:
        print(f"  {t['threshold']:<10} {t['accuracy']:<10} {t['precision']:<10} {t['recall']:<10} {t['f1']:<10}")
    
    # Agent 效能
    print("\n【4. Agent 效能评估】")
    ae = report["agent_effectiveness"]
    print(f"  Risk Analyst 参与率: {ae['risk_analyst_participation_rate']}%")
    print(f"  Policy Advisor 参与率: {ae['policy_advisor_participation_rate']}%")
    print(f"  LLM 抽取成功率: {ae['llm_extraction_success_rate']}%")
    print(f"  攻击样本中 Risk Analyst 参与: {ae['attack_with_risk_analyst']}")
    print(f"  正常任务中 Risk Analyst 参与: {ae['normal_with_risk_analyst']}")
    
    # 性能指标
    print("\n【5. 性能指标】")
    pm = report["performance_metrics"]
    print(f"  超时次数: {pm['timeout_count']} (率: {pm.get('timeout_rate', 0)}%)")
    print(f"  平均响应: {pm.get('avg_response_ms', 0)}ms")
    print(f"  中位数响应: {pm.get('median_response_ms', 0)}ms")
    print(f"  最小/最大: {pm.get('min_response_ms', 0)}ms / {pm.get('max_response_ms', 0)}ms")
    
    # 混淆矩阵
    print("\n【6. 混淆矩阵】")
    cm = report["confusion_matrix"]
    for expected, actuals in cm.items():
        print(f"  预期={expected}: {dict(actuals)}")
    
    # 错误列表
    if report["errors"]:
        print(f"\n【7. 错误列表】({len(report['errors'])} 个)")
        for case_id, error in report["errors"][:5]:
            print(f"  {case_id}: {error}")
        if len(report["errors"]) > 5:
            print(f"  ... 还有 {len(report['errors']) - 5} 个")
    
    print("\n" + "=" * 80)


def run_evaluation(dataset_path: str, name: str):
    """运行评估"""
    print(f"\n正在评估数据集: {name}")
    print(f"路径: {dataset_path}")
    
    cases = load_test_cases(dataset_path)
    evaluator = QuantitativeEvaluator()
    
    for i, case in enumerate(cases, 1):
        case_id = case.get("id", f"case_{i}")
        print(f"  [{i}/{len(cases)}] Testing {case_id}...", end=" ")
        
        data, elapsed = call_api(case["content"], case.get("input_type", "task"))
        evaluator.add_result(case, data, elapsed)
        
        policy = extract_policy(data)
        score = extract_score(data)
        expected = case.get("expected_policy", "pass")
        status = "PASS" if policy == expected else "FAIL"
        print(f"{status} (score={score}, policy={policy}, exp={expected}, {elapsed*1000:.0f}ms)")
    
    report = evaluator.generate_report()
    print_report(report)
    
    # 保存详细报告
    report_path = dataset_path.replace(".json", "_report.json")
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"\n详细报告已保存: {report_path}")
    
    return report


if __name__ == "__main__":
    import sys
    
    # 评估多个数据集
    datasets = [
        ("dataset/test_cases.json", "预设审计样例 (30条)"),
        ("dataset/prompt_attacks_100.json", "隐晦Prompt攻击 (100条)"),
    ]
    
    all_reports = {}
    for path, name in datasets:
        try:
            report = run_evaluation(path, name)
            all_reports[name] = report
        except Exception as e:
            print(f"评估失败 {name}: {e}")
    
    # 保存综合报告
    with open("dataset/evaluation_summary.json", 'w', encoding='utf-8') as f:
        json.dump(all_reports, f, ensure_ascii=False, indent=2)
    print("\n综合评估报告已保存: dataset/evaluation_summary.json")

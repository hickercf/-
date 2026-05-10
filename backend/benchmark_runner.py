import json
import os
import asyncio
import time
from typing import Dict, Any, List
from app.core.behavior_extractor import extract_behavior_chain
from app.core.behavior_graph import build_behavior_graph
from app.core.rule_engine import match_rules
from app.core.risk_engine import calculate_risk, detect_combo_bonus
from app.core.policy_engine import decide_policy

DATASET_PATH = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "dataset", "test_cases.json"))
RESULT_PATH = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "dataset", "eval_result.json"))


def load_test_cases() -> List[Dict[str, Any]]:
    if not os.path.exists(DATASET_PATH):
        return []
    with open(DATASET_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


async def run_benchmark() -> Dict[str, Any]:
    cases = load_test_cases()
    if not cases:
        return {"summary": {}, "details": []}

    results = []
    total_time = 0
    extraction_ok = 0
    level_correct = 0
    high_risk_total = 0
    high_risk_found = 0
    critical_miss = 0
    tp, fp, fn = {}, {}, {}

    for case in cases:
        start = time.time()
        chain = await extract_behavior_chain(case.get("input_type", "task"), case.get("content", ""))
        matched, rule_score, cats = match_rules(chain)
        combo = detect_combo_bonus(chain.get("nodes", []))
        risk = calculate_risk(chain.get("nodes", []), rule_score, combo)
        policy = decide_policy(risk["risk_score"], risk["risk_level"], matched, chain)
        elapsed = time.time() - start
        total_time += elapsed

        if chain.get("nodes"):
            extraction_ok += 1

        predicted_level = risk["risk_level"]
        expected_level = case.get("expected_level", "")
        if predicted_level == expected_level:
            level_correct += 1

        expected_cats = set(case.get("expected_categories", []))
        predicted_cats = set(cats)

        if expected_level in ("高风险", "严重风险"):
            high_risk_total += 1
            if predicted_level in ("高风险", "严重风险"):
                high_risk_found += 1
            else:
                critical_miss += 1

        for c in predicted_cats:
            if c in expected_cats:
                tp[c] = tp.get(c, 0) + 1
            else:
                fp[c] = fp.get(c, 0) + 1
        for c in expected_cats:
            if c not in predicted_cats:
                fn[c] = fn.get(c, 0) + 1

        results.append({
            "id": case.get("id"),
            "expected_level": expected_level,
            "predicted_level": predicted_level,
            "expected_policy": case.get("expected_policy", ""),
            "predicted_policy": policy["action"],
            "match": predicted_level == expected_level,
            "elapsed": round(elapsed, 3),
        })

    precision = sum(tp.values()) / (sum(tp.values()) + sum(fp.values())) if (sum(tp.values()) + sum(fp.values())) > 0 else 0
    recall = sum(tp.values()) / (sum(tp.values()) + sum(fn.values())) if (sum(tp.values()) + sum(fn.values())) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    summary = {
        "total": len(cases),
        "extraction_success_rate": round(extraction_ok / len(cases), 4),
        "risk_level_accuracy": round(level_correct / len(cases), 4),
        "high_risk_recall": round(high_risk_found / high_risk_total, 4) if high_risk_total > 0 else 0,
        "critical_miss_count": critical_miss,
        "category_f1": round(f1, 4),
        "avg_response_time": round(total_time / len(cases), 3),
    }

    os.makedirs(os.path.dirname(RESULT_PATH), exist_ok=True)
    with open(RESULT_PATH, "w", encoding="utf-8") as f:
        json.dump({"summary": summary, "details": results}, f, ensure_ascii=False, indent=2)

    return {"summary": summary, "details": results}


if __name__ == "__main__":
    result = asyncio.run(run_benchmark())
    print(json.dumps(result["summary"], ensure_ascii=False, indent=2))

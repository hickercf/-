import os
import json
import time
from typing import Dict, Any, List
from fastapi import APIRouter
from app.schemas.analyze_schema import EvalResult
from app.core.behavior_extractor import extract_behavior_chain
from app.core.extractor_agent import extract_by_agent
from app.core.fallback_extractor import extract_by_fallback
from app.core.behavior_graph import build_behavior_graph
from app.core.rule_engine import match_rules
from app.core.risk_engine import calculate_risk, detect_combo_bonus
from app.core.policy_engine import decide_policy

router = APIRouter(prefix="/api", tags=["evaluation"])

DATASET_PATH = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "dataset", "test_cases.json"))
RESULT_PATH = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "dataset", "eval_result.json"))


def _load_test_cases() -> list:
    if not os.path.exists(DATASET_PATH):
        return []
    with open(DATASET_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


async def _evaluate_cases(cases: list, use_llm: bool, use_fallback: bool) -> Dict[str, Any]:
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

        if use_llm and use_fallback:
            chain = await extract_behavior_chain(case.get("input_type", "task"), case.get("content", ""))
        elif use_llm and not use_fallback:
            chain = await extract_by_agent(case.get("input_type", "task"), case.get("content", ""))
            if chain is None:
                chain = {"nodes": [], "edges": [], "trust_boundary_crossed": False, "extraction_method": "llm_failed", "extraction_confidence": 0}
        elif use_fallback:
            chain = extract_by_fallback(case.get("input_type", "task"), case.get("content", ""))
        else:
            chain = {"nodes": [], "edges": [], "trust_boundary_crossed": False, "extraction_method": "none", "extraction_confidence": 0}

        graph = build_behavior_graph(chain)
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
            "match": predicted_level == expected_level,
            "elapsed": round(elapsed, 3),
        })

    precision = sum(tp.values()) / (sum(tp.values()) + sum(fp.values())) if (sum(tp.values()) + sum(fp.values())) > 0 else 0
    recall = sum(tp.values()) / (sum(tp.values()) + sum(fn.values())) if (sum(tp.values()) + sum(fn.values())) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    return {
        "total": len(cases),
        "extraction_success_rate": round(extraction_ok / len(cases), 4),
        "risk_level_accuracy": round(level_correct / len(cases), 4),
        "high_risk_recall": round(high_risk_found / high_risk_total, 4) if high_risk_total > 0 else 0,
        "critical_miss_count": critical_miss,
        "category_f1": round(f1, 4),
        "avg_response_time": round(total_time / len(cases), 3),
    }


@router.post("/evaluate", response_model=EvalResult)
async def evaluate():
    cases = _load_test_cases()
    if not cases:
        return EvalResult(
            total=0, extraction_success_rate=0, risk_level_accuracy=0,
            high_risk_recall=0, critical_miss_count=0, category_f1=0,
            avg_response_time=0,
        )

    rule_result = await _evaluate_cases(cases, use_llm=False, use_fallback=True)
    llm_result = await _evaluate_cases(cases, use_llm=True, use_fallback=False)
    fusion_result = await _evaluate_cases(cases, use_llm=True, use_fallback=True)

    comparison = {
        "rule_only": rule_result,
        "llm_only": llm_result,
        "fusion": fusion_result,
    }

    eval_result = EvalResult(
        total=fusion_result["total"],
        extraction_success_rate=fusion_result["extraction_success_rate"],
        risk_level_accuracy=fusion_result["risk_level_accuracy"],
        high_risk_recall=fusion_result["high_risk_recall"],
        critical_miss_count=fusion_result["critical_miss_count"],
        category_f1=fusion_result["category_f1"],
        avg_response_time=fusion_result["avg_response_time"],
        comparison=comparison,
    )

    os.makedirs(os.path.dirname(RESULT_PATH), exist_ok=True)
    with open(RESULT_PATH, "w", encoding="utf-8") as f:
        json.dump({"summary": eval_result.model_dump(), "comparison": comparison}, f, ensure_ascii=False, indent=2)

    return eval_result

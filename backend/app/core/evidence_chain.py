import json
from typing import Dict, Any, Optional
from app.core.crypto_utils import sm3_hash


def canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _ensure_parsed(data: Any) -> Any:
    """确保JSON字符串被解析为对象"""
    if isinstance(data, str):
        try:
            return json.loads(data)
        except (json.JSONDecodeError, TypeError):
            return data
    return data


async def append_evidence_record(previous_hash: str, record: Dict[str, Any]) -> str:
    pd = _ensure_parsed(record.get("policy_decision", {}))
    if not isinstance(pd, dict):
        pd = {}
    policy_action = pd.get("action", "")

    matched_rules = _ensure_parsed(record.get("matched_rules", []))
    if not isinstance(matched_rules, list):
        matched_rules = []

    risk_categories = _ensure_parsed(record.get("risk_categories", []))
    if not isinstance(risk_categories, list):
        risk_categories = []

    payload = {
        "input_type": record.get("input_type", ""),
        "risk_score": record.get("risk_score", 0),
        "risk_level": record.get("risk_level", ""),
        "risk_categories": sorted(risk_categories),
        "policy_action": policy_action,
        "matched_rule_ids": sorted([r.get("id", "") for r in matched_rules if isinstance(r, dict)]),
    }
    canonical = canonical_json(payload)
    combined = previous_hash + canonical
    return sm3_hash(combined)


def build_report_hash(report_content: str) -> str:
    return sm3_hash(report_content)


async def verify_evidence_chain(records: list) -> Dict[str, Any]:
    if not records:
        return {"valid": True, "checked": 0, "errors": []}

    errors = []
    prev_hash = ""

    for i, record in enumerate(records):
        expected = await append_evidence_record(prev_hash, record)
        actual = record.get("record_hash", "")

        if actual and expected != actual:
            errors.append({
                "record_id": record.get("id"),
                "index": i,
                "expected": expected,
                "actual": actual,
            })

        prev_hash = actual if actual else expected

    return {
        "valid": len(errors) == 0,
        "checked": len(records),
        "errors": errors,
    }


build_record_hash = append_evidence_record

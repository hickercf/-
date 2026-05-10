import json
from typing import Dict, Any, Optional
from app.core.crypto_utils import sm3_hash


def canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


async def append_evidence_record(previous_hash: str, record: Dict[str, Any]) -> str:
    payload = {
        "input_type": record.get("input_type", ""),
        "risk_score": record.get("risk_score", 0),
        "risk_level": record.get("risk_level", ""),
        "risk_categories": record.get("risk_categories", []),
        "policy_action": record.get("policy_decision", {}).get("action", ""),
        "matched_rule_ids": [r.get("id", "") for r in record.get("matched_rules", [])],
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
    prev_hash = records[0].get("previous_hash", "")

    for i, record in enumerate(records):
        if i > 0:
            prev_hash = records[i - 1].get("record_hash", "")

        expected = await append_evidence_record(prev_hash, record)
        actual = record.get("record_hash", "")

        if actual and expected != actual:
            errors.append({
                "record_id": record.get("id"),
                "index": i,
                "expected": expected,
                "actual": actual,
            })

    return {
        "valid": len(errors) == 0,
        "checked": len(records),
        "errors": errors,
    }


build_record_hash = append_evidence_record

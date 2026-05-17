import json
import re
from pathlib import Path
from fastapi.testclient import TestClient

from app.main import app


ROOT = Path(__file__).resolve().parents[1]
client = TestClient(app)


def analyze(content: str, input_type: str) -> dict:
    response = client.post("/api/analyze", json={"content": content, "input_type": input_type})
    if response.status_code != 200:
        return {"_error": f"HTTP {response.status_code}: {response.text[:200]}"}
    return response.json()


def check_dataset_cases() -> list:
    cases = json.loads((ROOT / "dataset" / "test_cases.json").read_text(encoding="utf-8"))
    results = []
    print(f"[dataset] Processing {len(cases)} cases...")
    for i, case in enumerate(cases, 1):
        print(f"  [{i}/{len(cases)}] {case['content'][:40]}...", end=" ")
        data = analyze(case["content"], case.get("input_type", "task"))
        if "_error" in data:
            ok = False
            reason = data["_error"]
            actual_policy = "error"
            actual_level = "error"
            score = 0
            rules = 0
        else:
            actual_policy = data.get("policy_decision", {}).get("action", "")
            actual_level = data.get("risk_level", "")
            score = data.get("risk_score", 0)
            rules = len(data.get("matched_rules", []))
            expected_policy = case.get("expected_policy", "")
            expected_level = case.get("expected_level", "")
            ok = actual_policy == expected_policy and actual_level == expected_level
            reason = "ok" if ok else f"expected {expected_level}/{expected_policy}, got {actual_level}/{actual_policy}"
        print(f"-> {actual_level}/{actual_policy} score={score} rules={rules}")
        results.append({
            "id": case["id"],
            "name": case["content"][:28],
            "ok": ok,
            "expected_level": case.get("expected_level"),
            "expected_policy": case.get("expected_policy"),
            "actual_level": actual_level,
            "actual_policy": actual_policy,
            "score": score,
            "rules": rules,
            "reason": reason,
        })
    return results


def load_frontend_samples() -> list:
    vue = (ROOT / "frontend" / "src" / "pages" / "Analyze.vue").read_text(encoding="utf-8")
    group_blocks = re.findall(r"\{\s*name:\s*'([^']+)',\s*samples:\s*\[(.*?)\]\s*\}", vue, re.S)
    samples = []
    for group, block in group_blocks:
        for match in re.finditer(
            r"\{\s*key:\s*'([^']+)',\s*label:\s*'([^']+)',\s*input_type:\s*'([^']+)',\s*content:\s*'((?:\\'|[^'])*)'\s*\}",
            block,
            re.S,
        ):
            key, label, input_type, content = match.groups()
            samples.append({
                "group": group,
                "key": key,
                "label": label,
                "input_type": input_type,
                "content": content.replace("\\'", "'"),
            })
    return samples


def check_frontend_samples() -> list:
    samples = load_frontend_samples()
    results = []
    print(f"[frontend] Processing {len(samples)} samples...")
    for i, sample in enumerate(samples, 1):
        print(f"  [{i}/{len(samples)}] [{sample['group']}] {sample['label']}", end=" ")
        data = analyze(sample["content"], sample["input_type"])
        if "_error" in data:
            ok = False
            actual_policy = "error"
            actual_level = "error"
            score = 0
            rules = 0
            reason = data["_error"]
        else:
            actual_policy = data.get("policy_decision", {}).get("action", "")
            actual_level = data.get("risk_level", "")
            score = data.get("risk_score", 0)
            rules = len(data.get("matched_rules", []))
            if sample["group"] == "正常任务":
                ok = actual_policy == "pass"
                reason = "ok" if ok else f"normal sample should pass, got {actual_level}/{actual_policy}/{score}"
            else:
                ok = actual_policy == "block"
                reason = "ok" if ok else f"attack sample should block, got {actual_level}/{actual_policy}/{score}"
        print(f"-> {actual_level}/{actual_policy} score={score} rules={rules}")
        results.append({
            "group": sample["group"],
            "key": sample["key"],
            "label": sample["label"],
            "ok": ok,
            "actual_level": actual_level,
            "actual_policy": actual_policy,
            "score": score,
            "rules": rules,
            "reason": reason,
        })
    return results


def print_section(title: str, rows: list) -> None:
    passed = sum(1 for row in rows if row["ok"])
    total = len(rows)
    print(f"\n=== {title}: {passed}/{total} passed ===")
    for row in rows:
        status = "PASS" if row["ok"] else "FAIL"
        name = row.get("id") or row.get("key")
        label = row.get("label") or row.get("name")
        group = f"[{row.get('group')}] " if row.get("group") else ""
        print(f"{status} {name} {group}{label} -> score={row['score']} level={row['actual_level']} policy={row['actual_policy']} rules={row['rules']}")
        if not row["ok"]:
            print(f"  reason: {row['reason']}")


def main():
    dataset_results = check_dataset_cases()
    frontend_results = check_frontend_samples()
    print_section("dataset/test_cases.json", dataset_results)
    print_section("frontend quick samples", frontend_results)
    failed = [r for r in dataset_results + frontend_results if not r["ok"]]
    print(f"\nSUMMARY total={len(dataset_results) + len(frontend_results)} failed={len(failed)}")
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

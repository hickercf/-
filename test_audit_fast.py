import json
import requests
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

API = "http://127.0.0.1:8000/api/analyze"
MAX_WORKERS = 4
TIMEOUT = 90

def analyze(case):
    try:
        t0 = time.time()
        r = requests.post(API, json={"content": case["content"], "input_type": case.get("input_type", "task")}, timeout=TIMEOUT)
        elapsed = time.time() - t0
        data = r.json()
        policy = data.get("policy_decision", {}).get("action", "")
        score = data.get("risk_score", 0)
        rules = [rr.get("id","") for rr in data.get("matched_rules", [])]
        return {
            "id": case["id"],
            "ok": True,
            "policy": policy,
            "expected": case.get("expected_policy", ""),
            "score": score,
            "rules": rules,
            "time": elapsed,
        }
    except Exception as e:
        return {"id": case["id"], "ok": False, "error": str(e)}

def main():
    with open(r"dataset\test_cases.json", encoding="utf-8") as f:
        cases = json.load(f)
    
    print(f"Testing {len(cases)} dataset cases...")
    print("="*80)
    
    results = [None] * len(cases)
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(analyze, case): i for i, case in enumerate(cases)}
        done = 0
        for fut in as_completed(futures):
            idx = futures[fut]
            r = fut.result()
            results[idx] = r
            done += 1
            if r.get("ok"):
                ok = "PASS" if r["policy"] == r["expected"] else "FAIL"
                print(f"[{done:2d}/{len(cases)}] {ok} {r['id']} score={r['score']:2d} policy={r['policy']:5s} exp={r['expected']:5s} ({r['time']:.1f}s)")
            else:
                print(f"[{done:2d}/{len(cases)}] ERR {r['id']}: {r.get('error','')[:60]}")
    
    passed = sum(1 for r in results if r.get("ok") and r["policy"] == r["expected"])
    failed = sum(1 for r in results if r.get("ok") and r["policy"] != r["expected"])
    errors = sum(1 for r in results if not r.get("ok"))
    
    print("="*80)
    print(f"Dataset: {passed}/{len(cases)} passed, {failed} failed, {errors} errors")
    
    if failed > 0:
        print("\nFailed:")
        for r in results:
            if r.get("ok") and r["policy"] != r["expected"]:
                print(f"  {r['id']}: got {r['policy']} expected {r['expected']} score={r['score']}")

if __name__ == "__main__":
    main()

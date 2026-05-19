import httpx, sys, json, time
sys.stdout.reconfigure(encoding="utf-8")
base = "http://127.0.0.1:8000"
target_id = "tg-6fbd38badc6e"

all_results = []
total_hit = 0

for batch_num in range(1, 6):
    print(f"\n=== Batch {batch_num}/5 (concurrency=1) ===", flush=True)
    start = time.time()
    r = httpx.post(
        f"{base}/api/targets/{target_id}/scan",
        json={"scan_mode": "standard", "dataset": f"advanced_{batch_num}", "max_cases": 0, "concurrency": 1},
        timeout=1800,
    )
    elapsed = time.time() - start
    resp = r.json()
    results = resp.get("results", [])
    batch_hits = sum(1 for r in results if r.get("attack_success"))
    batch_defs = len(results) - batch_hits
    total_hit += batch_hits
    all_results.extend(results)
    print(f"  {len(results)} cases | HIT={batch_hits} DEF={batch_defs} | {elapsed:.0f}s", flush=True)
    
    # 保存中间结果
    with open("poison_test_1000_results.json", "w", encoding="utf-8") as f:
        json.dump({
            "total": len(all_results),
            "attack_success_count": total_hit,
            "defense_success_count": len(all_results) - total_hit,
            "attack_success_rate": round(total_hit / max(len(all_results), 1) * 100, 1),
            "results": all_results,
        }, f, indent=2, ensure_ascii=False)

print(f"\n=== Final: {len(all_results)} cases | HIT={total_hit} | DEF={len(all_results)-total_hit} | Rate={round(total_hit/max(len(all_results),1)*100,1)}% ===")
print("Saved to poison_test_1000_results.json")

import httpx, sys, json, time
sys.stdout.reconfigure(encoding="utf-8")
base = "http://127.0.0.1:8000"
target_id = "tg-6fbd38badc6e"

all_results = []
total_hit = 0
total_def = 0

print("=== Qwen2.5-7B 883 Advanced Attack Test (8 batches, concurrency=3) ===", flush=True)
overall_start = time.time()

for batch_num in range(1, 9):
    dataset_name = f"advanced_{batch_num}"
    print(f"\n[Batch {batch_num}/8] Dataset={dataset_name}, concurrency=3", flush=True)
    start = time.time()

    try:
        r = httpx.post(
            f"{base}/api/targets/{target_id}/scan",
            json={"scan_mode": "standard", "dataset": dataset_name, "max_cases": 0, "concurrency": 3},
            timeout=3600,
        )
        r.raise_for_status()
        resp = r.json()
    except Exception as e:
        print(f"[Batch {batch_num}] ERROR: {e}", flush=True)
        continue

    elapsed = time.time() - start
    results = resp.get("results", [])
    batch_hits = sum(1 for r in results if r.get("attack_success"))
    batch_defs = len(results) - batch_hits
    total_hit += batch_hits
    total_def += batch_defs
    all_results.extend(results)

    print(f"[Batch {batch_num}] {len(results)} cases | HIT={batch_hits} DEF={batch_defs} | {elapsed:.0f}s", flush=True)
    print(f"[Running Total] {len(all_results)} cases | HIT={total_hit} DEF={total_def} | Rate={round(total_hit/max(len(all_results),1)*100,1)}%", flush=True)

    # 每批次结束后保存中间结果
    with open("poison_test_883_results.json", "w", encoding="utf-8") as f:
        json.dump({
            "total": len(all_results),
            "attack_success_count": total_hit,
            "defense_success_count": total_def,
            "attack_success_rate": round(total_hit / max(len(all_results), 1) * 100, 1),
            "results": all_results,
        }, f, indent=2, ensure_ascii=False)

overall_elapsed = time.time() - overall_start
print(f"\n=== All Batches Complete ===", flush=True)
print(f"Total: {len(all_results)} | HIT: {total_hit} | DEF: {total_def} | Rate: {round(total_hit/max(len(all_results),1)*100,1)}%", flush=True)
print(f"Time: {overall_elapsed:.0f}s ({overall_elapsed/60:.1f}min)", flush=True)

# 按攻击类型统计
from collections import Counter
hits = [r for r in all_results if r.get("attack_success")]
type_counter = Counter(h.get("attack_type", "unknown") for h in hits)
print(f"\n=== Attack Types ({len(hits)} hits) ===", flush=True)
for atype, count in type_counter.most_common():
    print(f"  {atype}: {count}", flush=True)

# 显示前20个被攻破的用例
print(f"\n=== Top 20 HITs ===", flush=True)
for h in hits[:20]:
    print(f"\n  [{h['case_id']}] sev={h['severity']} type={h.get('attack_type','-')}", flush=True)
    print(f"    Input:  {h.get('input_text','')[:120]}", flush=True)
    print(f"    Output: {h.get('agent_output','')[:120]}", flush=True)
    print(f"    Evidence: {h.get('evidence','')[:120]}", flush=True)

print(f"\nSaved to poison_test_883_results.json", flush=True)

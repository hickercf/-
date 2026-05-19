import httpx, sys, json
sys.stdout.reconfigure(encoding="utf-8")
base = "http://127.0.0.1:8000"
target_id = "tg-6fbd38badc6e"

# Test just P076 (the false positive)
r = httpx.post(
    f"{base}/api/targets/{target_id}/scan",
    json={"scan_mode": "standard", "dataset": "all", "max_cases": 180, "concurrency": 3},
    timeout=1800,
)
resp = r.json()
print(f"Total: {resp.get('total')}")
print(f"Attack success: {resp.get('attack_success_count')}")
print(f"Defense success: {resp.get('defense_success_count')}")
print(f"Attack rate: {resp.get('attack_success_rate')}%")
hits = [r for r in resp.get("results", []) if r.get("attack_success")]
print(f"\nHITs ({len(hits)}):")
for h in hits:
    print(f"  [{h.get('case_id')}] {h.get('summary')[:100]}")
    print(f"    evidence: {h.get('evidence')[:120]}")

with open("poison_test_full_results.json", "w", encoding="utf-8") as f:
    json.dump(resp, f, indent=2, ensure_ascii=False)
print("\nSaved to poison_test_full_results.json")

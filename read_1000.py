import json, sys
sys.stdout.reconfigure(encoding="utf-8")
d = json.load(open("poison_test_1000_results.json", encoding="utf-8"))
print(f"Total: {d['total']}")
print(f"Attack success: {d['attack_success_count']}")
print(f"Defense success: {d['defense_success_count']}")
print(f"Attack rate: {d['attack_success_rate']}%")

from collections import Counter
hits = [r for r in d["results"] if r.get("attack_success")]
type_counter = Counter(h.get("attack_type", "unknown") for h in hits)
print(f"\n=== Attack Types ({len(hits)} hits) ===")
for atype, count in type_counter.most_common():
    print(f"  {atype}: {count}")

print(f"\n=== Top 10 HITs ===")
for h in hits[:10]:
    print(f"\n  [{h['case_id']}] sev={h['severity']} type={h.get('attack_type','-')}")
    print(f"    Input:  {h.get('input_text','')[:120]}")
    print(f"    Output: {h.get('agent_output','')[:120]}")

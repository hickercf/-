import json

with open("dataset/advanced_attacks_1000.json", "r", encoding="utf-8") as f:
    cases = json.load(f)

batch_size = 200
for i in range(0, len(cases), batch_size):
    batch = cases[i:i+batch_size]
    batch_num = i // batch_size + 1
    fname = f"dataset/advanced_{batch_num}.json"
    with open(fname, "w", encoding="utf-8") as f:
        json.dump(batch, f, indent=2, ensure_ascii=False)
    print(f"Saved {fname}: {len(batch)} cases")

print(f"Total: {len(cases)} cases in 5 files")

"""
review.py — Cross-reference our use case catalog against ESCU production
detections + ATT&CK coverage to surface strengths and gaps.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).parent
REG = json.loads((ROOT / "data_sources" / "registry.json").read_text(encoding="utf-8"))

spec = importlib.util.spec_from_file_location("gen", ROOT / "generate.py")
gen = importlib.util.module_from_spec(spec)
sys.modules["gen"] = gen
spec.loader.exec_module(gen)

UCS = [(name, obj) for name in dir(gen)
       if isinstance(getattr(gen, name), gen.UseCase)
       for obj in [getattr(gen, name)]]

# ---- 1) ESCU dataset usage popularity ---------------------------------------
ds_count = Counter()
for d in REG["escu_detections"]:
    for ds in d.get("data_models", []):
        ds_count[ds] += 1

print("=" * 64)
print(" 1. ESCU dataset usage (top 15)")
print("=" * 64)
for ds, n in ds_count.most_common(15):
    print(f"  {n:5d}  {ds}")

# ---- 2) Our use case dataset coverage ---------------------------------------
our_ds = Counter()
for _, uc in UCS:
    for d in uc.data_models:
        our_ds[d] += 1

print("\n" + "=" * 64)
print(" 2. Our use case dataset coverage")
print("=" * 64)
for ds, n in our_ds.most_common():
    escu_hits = ds_count.get(ds, 0)
    flag = "" if escu_hits else "  <-- not used in ESCU"
    print(f"  {n:3d} use case(s) on  {ds:35s}  ESCU detections: {escu_hits}{flag}")

# ---- 3) ATT&CK technique coverage -------------------------------------------
our_techs = set()
for _, uc in UCS:
    for tid, _ in uc.techniques:
        our_techs.add(tid)

escu_techs = set()
for d in REG["escu_detections"]:
    for t in d.get("techniques", []):
        escu_techs.add(t)

attack_total = len(REG["attack_techniques"])
print("\n" + "=" * 64)
print(" 3. ATT&CK technique coverage")
print("=" * 64)
print(f"  Our use cases reference         : {len(our_techs):4d} techniques")
print(f"  ESCU production content covers  : {len(escu_techs):4d} techniques")
print(f"  Total in current MITRE catalog  : {attack_total:4d} techniques")
print(f"  Our techniques also in ESCU     : {len(our_techs & escu_techs):4d} (overlap)")
print(f"  Our techniques NOT in ESCU      : {len(our_techs - escu_techs):4d}")
ours_not_escu = sorted(our_techs - escu_techs)
if ours_not_escu:
    for t in ours_not_escu[:10]:
        nm = REG["attack_techniques"].get(t, {}).get("name", "?")
        print(f"      - {t}: {nm}")

# ---- 4) ESCU TTPs we DON'T cover yet ----------------------------------------
ttp_freq = Counter()
for d in REG["escu_detections"]:
    if d.get("type") in ("TTP", "Anomaly"):
        for t in d.get("techniques", []):
            ttp_freq[t] += 1
top_uncovered = [(t, n) for t, n in ttp_freq.most_common() if t not in our_techs][:15]
print("\n" + "=" * 64)
print(" 4. Most-detected ESCU techniques we don't have a use case for")
print("=" * 64)
for tid, n in top_uncovered:
    nm = REG["attack_techniques"].get(tid, {}).get("name", "?")
    print(f"  {n:4d} ESCU detections  {tid}: {nm}")

# ---- 5) Use case kill-chain distribution ------------------------------------
kc_count = Counter()
for _, uc in UCS:
    kc_count[uc.kill_chain] += 1
print("\n" + "=" * 64)
print(" 5. Use case kill-chain distribution")
print("=" * 64)
for kc, _, _ in gen.KILL_CHAIN_PHASES:
    n = kc_count.get(kc, 0)
    bar = "#" * n
    print(f"  {kc:10s}  {n:2d}  {bar}")

# ---- 6) Confidence breakdown ------------------------------------------------
conf = Counter(uc.confidence for _, uc in UCS)
print("\n" + "=" * 64)
print(" 6. Use case confidence")
print("=" * 64)
for c, n in conf.most_common():
    print(f"  {c:8s}: {n}")

# ---- 7) Per-use-case sanity ------------------------------------------------
print("\n" + "=" * 64)
print(" 7. Per-use-case overview (with related ESCU detection counts)")
print("=" * 64)
print(f"  {'Use case':50s} {'Phase':10s}  {'Conf':6s}  {'Techs':5s}  ESCU-related")
print("-" * 90)
for name, uc in UCS:
    techs = {t for t, _ in uc.techniques}
    related = sum(1 for d in REG["escu_detections"]
                  if any(t in techs for t in d.get("techniques", [])))
    print(f"  {uc.title[:50]:50s} {uc.kill_chain:10s}  {uc.confidence:6s}  "
          f"{len(uc.techniques):5d}  {related}")

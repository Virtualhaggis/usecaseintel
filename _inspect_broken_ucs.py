"""One-shot inspector for the kql_audit.json output — categorize the
broken UCs by error pattern + cache vs catalog source, sample 3 of each
top pattern with the actual KQL excerpt so we can decide whether a
mechanical fix is feasible."""
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

with open("kql_audit.json", "r", encoding="utf-8") as fh:
    report = json.load(fh)

broken = [
    u for u in report["per_uc"]
    if any(u["schema_issues"][p] or u["syntax_issues"][p] for p in u["platforms"])
]
cache_broken = [u for u in broken if u["source"].startswith("intel/")
                or u["source"].startswith("intel\\")]
catalog_broken = [u for u in broken if u["source"].startswith("catalog/")
                  or u["source"].startswith("catalog\\")]

print(f"Total broken: {len(broken)}")
print(f"  in cache (intel/.llm_uc_cache):  {len(cache_broken)}")
print(f"  in catalog (catalog/use_cases):  {len(catalog_broken)}")
print()

# Pattern buckets
pattern_buckets = defaultdict(list)
for u in broken:
    for p in u["platforms"]:
        for e in u["syntax_issues"].get(p, []):
            msg = (e.get("message") or "").strip()
            # Normalize the top patterns
            if "Unexpected: \\" in msg:
                bucket = "backslash"
            elif msg.startswith("Missing:"):
                bucket = f"missing_{msg.split(':',1)[1].strip()[:6]}"
            elif "Expected:" in msg:
                bucket = f"expected_{msg.split(':',1)[1].strip()[:6]}"
            elif "Query operator expected" in msg:
                bucket = "operator_typo"
            elif "incomplete fragment" in msg.lower():
                bucket = "incomplete_fragment"
            else:
                bucket = "other"
            pattern_buckets[bucket].append((u, p, e))

print("=== Pattern buckets ===")
for bucket, items in sorted(pattern_buckets.items(), key=lambda x: -len(x[1])):
    print(f"  {len(items):4} × {bucket}")

# Sample 2 UCs per major bucket with actual KQL snippet
print()
print("=== Sample bad KQL excerpts ===")
for bucket in ("backslash", "missing_\"", "expected_)", "operator_typo", "incomplete_fragment"):
    items = pattern_buckets.get(bucket) or []
    if not items:
        continue
    print(f"\n--- {bucket} ({len(items)} hits) ---")
    seen = set()
    for u, p, e in items:
        if u["uc_id"] in seen:
            continue
        seen.add(u["uc_id"])
        if len(seen) > 2:
            break
        # Find the actual KQL by re-reading the source
        src = Path(u["source"])
        kql = None
        try:
            if src.suffix == ".json":
                # Cache file — find uc by id within ucs list
                cache = json.loads(src.read_text(encoding="utf-8"))
                for cu in cache.get("ucs") or []:
                    if (cu.get("uc_id") == u["uc_id"]
                        or cu.get("id") == u["uc_id"]
                        or cu.get("title") == u["title"]):
                        kql = cu.get("defender_kql" if p == "defender" else "sentinel_kql")
                        break
            else:
                # YAML
                import yaml
                d = yaml.safe_load(src.read_text(encoding="utf-8"))
                kql = d.get("defender_kql" if p == "defender" else "sentinel_kql")
        except Exception as ex:
            kql = f"(could not load KQL: {ex})"
        line_no = e.get("line", 1)
        col = e.get("column", 1)
        msg = e.get("message", "")
        print(f"\n  UC: {u['uc_id']}")
        print(f"      title: {u['title'][:80]}")
        print(f"      [{p}] error at L{line_no}:C{col}: {msg}")
        if kql:
            # Show the offending line plus 1 line of context
            kql_lines = kql.split("\n")
            if 1 <= line_no <= len(kql_lines):
                # Show 1 line before + offending line + 1 after
                start = max(1, line_no - 1)
                end = min(len(kql_lines), line_no + 1)
                for i in range(start, end + 1):
                    marker = "  >>>" if i == line_no else "     "
                    print(f"      {marker} {i:3}: {kql_lines[i-1][:120]}")

"""Read kql_audit.json, rename every cache file that contains at least one
broken UC to `*.invalidated-<ts>.json`. Pipeline regenerates them on next
run via the now-active retry loop."""
import json
import sys
import time
from pathlib import Path

with open("kql_audit.json", "r", encoding="utf-8") as fh:
    report = json.load(fh)

broken_sources: set[str] = set()
for u in report["per_uc"]:
    has_schema = any(u["schema_issues"].get(p) for p in u["platforms"])
    has_syntax = any(u["syntax_issues"].get(p) for p in u["platforms"])
    if has_schema or has_syntax:
        src = u["source"]
        if src.startswith("intel" + "\\") or src.startswith("intel/"):
            broken_sources.add(src)

print(f"Unique broken cache files: {len(broken_sources)}")
print()

ts = time.strftime("%Y%m%dT%H%M%S")
renamed = 0
already = 0
missing = 0
for src in sorted(broken_sources):
    p = Path(src)
    if not p.exists():
        missing += 1
        continue
    new = p.with_suffix(f".invalidated-{ts}.json")
    if new.exists():
        already += 1
        continue
    p.rename(new)
    renamed += 1

print(f"Renamed:             {renamed}")
print(f"Already invalidated: {already}")
print(f"Missing:             {missing}")
print()
print(f"Suffix used: .invalidated-{ts}.json")
print()
print("Next ClankerusecasePipeline run will regenerate these articles' UCs")
print("using the new retry loop. Existing site renders fall through to")
print("template UCs in the interim.")

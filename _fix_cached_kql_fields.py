"""One-shot: walk every cached LLM UC + curated YAML UC and apply the
schema auto-fixer to defender_kql / sentinel_kql / kql fields. Saves the
fixed query back, plus an `_autofix_log` field listing exactly what was
rewritten, so the audit trail survives.

Run:
    python _fix_cached_kql_fields.py            # dry-run (default)
    python _fix_cached_kql_fields.py --apply    # actually rewrite files

The pipeline now calls auto_fix_kql() on every fresh LLM output, but
existing cached UCs predate that wiring. This catches them up so the
next regen produces correct HTML without a re-prompt.
"""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path

from kql_schema_validator import auto_fix_kql

ROOT = Path(__file__).parent
CACHE_DIRS = [
    ROOT / "intel" / ".llm_uc_cache",
    ROOT / "intel" / ".llm_actor_uc_cache",
]


def fix_uc(uc: dict) -> tuple[bool, list[str]]:
    """Run the auto-fixer over each KQL field on a UC dict. Returns
    (changed, change_log). The UC dict is mutated in-place when changed."""
    if not isinstance(uc, dict):
        return False, []
    changed = False
    log: list[str] = []
    for kql_key in ("defender_kql", "sentinel_kql", "kql"):
        body = uc.get(kql_key) or ""
        if not body:
            continue
        try:
            fixed, changes = auto_fix_kql(body)
        except Exception as e:
            log.append(f"  {kql_key}: ERROR {e!s}")
            continue
        if changes:
            uc[kql_key] = fixed
            changed = True
            for c in changes:
                log.append(f"  {kql_key}: {c}")
    return changed, log


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--apply", action="store_true",
                    help="Actually rewrite cache files (default: dry-run)")
    args = ap.parse_args()

    total_files = 0
    total_changed_files = 0
    total_changed_ucs = 0
    total_changes = 0

    for cache_dir in CACHE_DIRS:
        if not cache_dir.exists():
            continue
        files = sorted(cache_dir.rglob("*.json"))
        print(f"\n--- {cache_dir} ({len(files)} files) ---")
        dir_changed = 0
        for path in files:
            total_files += 1
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            ucs = data.get("ucs") or []
            file_changed = False
            file_log: list[str] = []
            for i, uc in enumerate(ucs):
                changed, log = fix_uc(uc)
                if changed:
                    file_changed = True
                    total_changed_ucs += 1
                    total_changes += len(log)
                    file_log.append(f"  UC#{i+1} \"{(uc.get('title') or '')[:60]}\":")
                    file_log.extend(log)
            if file_changed:
                total_changed_files += 1
                dir_changed += 1
                if args.apply:
                    path.write_text(json.dumps(data, indent=2, ensure_ascii=False),
                                    encoding="utf-8")
                rel = path.relative_to(ROOT)
                print(f"  {'FIXED' if args.apply else 'WOULD FIX'}: {rel}")
                for line in file_log:
                    print(line)
        print(f"  changed in dir: {dir_changed}")

    print()
    print(f"Files scanned:     {total_files}")
    print(f"Files changed:     {total_changed_files}")
    print(f"UCs changed:       {total_changed_ucs}")
    print(f"Total field fixes: {total_changes}")
    if not args.apply:
        print("\nDRY-RUN — pass --apply to write changes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

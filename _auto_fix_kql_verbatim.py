"""Mechanical fixer for the most common LLM-emitted KQL syntax bug:
backslash-escaped quotes inside `@"..."` verbatim strings.

Background: in KQL, `@"..."` is verbatim — `\"` does NOT escape; the `"`
ends the string. To embed a literal `"` inside a verbatim string, double
it (`""`). The LLM frequently emits `@"name=\"?([^\"\s]+)\"?"` thinking
of it like a C# verbatim string where `\"` is a quote escape; KQL parses
this as a 6-char verbatim string `name=\` followed by garbage, generating
5+ cascading errors per query.

Strategy: scan every KQL field across the cache that contains both `@"`
and `\"`. Build two batches — the originals and a candidate version with
`\"` → `""` applied. Run both batches through the Kusto parser. Apply
the fix only to entries where the candidate has strictly fewer errors.
This is safe-by-construction: a query that was already clean (or that
contains a legitimate regular-string `\"` escape) won't see the fix
applied because its error count won't improve.

Usage:
  py _auto_fix_kql_verbatim.py --dry-run
  py _auto_fix_kql_verbatim.py --apply
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parent
CACHE_DIR = ROOT / "intel" / ".llm_uc_cache"

try:
    from kql_syntax_validator import validate_kql_syntax_batch, is_available
except ImportError:
    print("ERROR: kql_syntax_validator module missing — aborting (this script "
          "needs validation feedback to be safe)", file=sys.stderr)
    sys.exit(1)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--dry-run", action="store_true")
    g.add_argument("--apply", action="store_true")
    args = ap.parse_args(argv)

    if not CACHE_DIR.exists():
        print(f"cache dir not found: {CACHE_DIR}", file=sys.stderr)
        return 1
    if not is_available():
        print("ERROR: syntax validator binary missing — cannot proceed safely",
              file=sys.stderr)
        return 1

    # Phase 1 — scan every cache file, collect candidates.
    print("Phase 1: scanning cache files for candidates...")
    candidates: list[dict] = []  # each: {path, data, uc_idx, kql_key, original, candidate}
    files = sorted(CACHE_DIR.rglob("*.json"))
    for p in files:
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        ucs = data.get("ucs") or []
        if not isinstance(ucs, list):
            continue
        for i, uc in enumerate(ucs):
            if not isinstance(uc, dict):
                continue
            for kql_key in ("defender_kql", "sentinel_kql", "kql"):
                k = uc.get(kql_key)
                if not isinstance(k, str):
                    continue
                if '@"' not in k or '\\"' not in k:
                    continue
                candidates.append({
                    "path": p,
                    "data": data,
                    "uc_idx": i,
                    "kql_key": kql_key,
                    "original": k,
                    "candidate": k.replace('\\"', '""'),
                })
    if not candidates:
        print("No candidates found — nothing to do.")
        return 0
    print(f"  {len(candidates)} candidate KQL field(s) across "
          f"{len({c['path'] for c in candidates})} file(s)")

    # Phase 2 — batch-validate originals.
    print("Phase 2: validating originals...")
    orig_batch = [(str(i), c["original"]) for i, c in enumerate(candidates)]
    orig_results = {r["id"]: len(r.get("errors") or []) for r in validate_kql_syntax_batch(orig_batch)}

    # Phase 3 — batch-validate candidates.
    print("Phase 3: validating candidates (post-fix)...")
    cand_batch = [(str(i), c["candidate"]) for i, c in enumerate(candidates)]
    cand_results = {r["id"]: len(r.get("errors") or []) for r in validate_kql_syntax_batch(cand_batch)}

    # Phase 4 — apply or report.
    by_path: dict[Path, dict] = {}  # path → data (mutable)
    apply_count = 0
    no_change_count = 0
    worse_count = 0
    errs_eliminated = 0
    for i, c in enumerate(candidates):
        before = orig_results.get(str(i), 0)
        after = cand_results.get(str(i), 0)
        if after < before:
            # Beneficial — stage the fix into the data dict.
            data = by_path.setdefault(c["path"], c["data"])
            data["ucs"][c["uc_idx"]][c["kql_key"]] = c["candidate"]
            apply_count += 1
            errs_eliminated += (before - after)
        elif after == before:
            no_change_count += 1
        else:
            worse_count += 1  # should be impossible with this fix but defensive

    print(f"\n=== Results ===")
    print(f"Candidates examined:         {len(candidates)}")
    print(f"Fix beneficial (apply):      {apply_count}")
    print(f"Fix no-op (no change):       {no_change_count}")
    print(f"Fix worsened (skip):         {worse_count}")
    print(f"Errors that would clear:     {errs_eliminated}")
    print(f"Files affected:              {len(by_path)}")

    if args.apply and by_path:
        print("\nWriting fixes...")
        for p, data in by_path.items():
            p.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"  wrote {len(by_path)} cache files")
    elif args.dry_run:
        print("\nRun with --apply to persist.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

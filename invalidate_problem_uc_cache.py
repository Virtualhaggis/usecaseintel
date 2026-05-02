"""Selectively invalidate LLM UC-cache files that contain problematic UCs.

The cache predates the schema-injection prompt, so older entries can have
columns that don't exist on the table they query, missing time bounds,
etc. Invalidating those cache files forces the next pipeline run to
regenerate them with the (now schema-aware) prompt.

Default mode: DRY-RUN — prints what would be invalidated, touches nothing.
Pass `--apply` to rename the affected files (we don't delete; we move
them aside so they can be restored if anything goes wrong).

Decision rule (a cache file is invalidated if):
  - any UC in it has at least one field-schema issue, OR
  - any UC in it lacks a time-bound predicate (full retention scan), OR
  - any UC in it scores below the configurable style cutoff (default 60%), OR
  - --require-sentinel is set and any UC lacks `sentinel_kql`, OR
  - --require-sigma is set and any UC lacks `sigma_yaml`.

Run:
    python invalidate_problem_uc_cache.py                  # dry-run, quality-only
    python invalidate_problem_uc_cache.py --apply
    python invalidate_problem_uc_cache.py --apply --style-cutoff 0.7
    python invalidate_problem_uc_cache.py --require-sentinel
    python invalidate_problem_uc_cache.py --require-sentinel --require-sigma --apply
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from kql_schema_validator import validate_kql
from validate_kql_knowledge import score_kql, MAX_SCORE


ROOT = Path(__file__).parent
CACHE_DIRS = [
    ROOT / "intel" / ".llm_uc_cache",
    ROOT / "intel" / ".llm_actor_uc_cache",
]


def file_has_problems(path: Path, style_cutoff: float,
                       require_sentinel: bool = False,
                       require_sigma: bool = False) -> tuple[bool, list[str]]:
    """Return (problematic, reasons) for a cache file."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        return True, [f"unparseable JSON ({e!s})"]
    ucs = data.get("ucs") or []
    if not ucs:
        return False, []  # empty file — leave it
    reasons: list[str] = []
    for i, uc in enumerate(ucs):
        kql = uc.get("defender_kql") or uc.get("kql") or ""
        if not kql:
            continue
        # Field-schema issues — heaviest weight.
        try:
            field_issues = validate_kql(kql)
        except Exception:
            field_issues = []
        if field_issues:
            kinds = ", ".join({i.get("kind", "?") for i in field_issues})
            reasons.append(f"UC#{i+1} field issues ({kinds})")
        # Missing time-bound — engine-perf killer.
        try:
            score, style_issues = score_kql(kql)
        except Exception:
            score, style_issues = (0, [])
        if any("time_bound" in s for s in style_issues):
            reasons.append(f"UC#{i+1} no time-bound predicate")
        if score < int(MAX_SCORE * style_cutoff):
            reasons.append(f"UC#{i+1} style score {score}/{MAX_SCORE} below cutoff")
        # Multi-platform completeness — only flagged when caller asks.
        if require_sentinel and not uc.get("sentinel_kql"):
            reasons.append(f"UC#{i+1} missing sentinel_kql")
        if require_sigma and not uc.get("sigma_yaml"):
            reasons.append(f"UC#{i+1} missing sigma_yaml")
    return bool(reasons), reasons


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--apply", action="store_true",
                    help="Actually rename the affected files (default: dry-run).")
    ap.add_argument("--style-cutoff", type=float, default=0.6,
                    help="Style-score cutoff as fraction of max (default 0.6).")
    ap.add_argument("--require-sentinel", action="store_true",
                    help="Also flag any UC missing sentinel_kql (forces regen with new prompt).")
    ap.add_argument("--require-sigma", action="store_true",
                    help="Also flag any UC missing sigma_yaml (forces regen with new prompt).")
    args = ap.parse_args()

    suffix = ".invalidated-" + time.strftime("%Y%m%d-%H%M%S")

    total_files = 0
    total_problem = 0
    total_renamed = 0
    by_reason: dict[str, int] = {}

    for cache_dir in CACHE_DIRS:
        if not cache_dir.exists():
            continue
        files = sorted(cache_dir.rglob("*.json"))
        print(f"\n--- {cache_dir} ({len(files)} files) ---")
        problems_in_dir = 0
        for path in files:
            total_files += 1
            problematic, reasons = file_has_problems(
                path, args.style_cutoff,
                require_sentinel=args.require_sentinel,
                require_sigma=args.require_sigma,
            )
            if not problematic:
                continue
            problems_in_dir += 1
            total_problem += 1
            for r in reasons:
                key = r.split(" ", 2)[-1] if r.startswith("UC#") else r
                by_reason[key] = by_reason.get(key, 0) + 1
            relpath = path.relative_to(ROOT)
            if args.apply:
                target = path.with_suffix(path.suffix + suffix)
                path.rename(target)
                total_renamed += 1
                print(f"  RENAMED  {relpath}  ->  {target.name}")
            else:
                print(f"  WOULD-INVALIDATE  {relpath}")
                for r in reasons[:3]:
                    print(f"      - {r}")
                if len(reasons) > 3:
                    print(f"      - … {len(reasons) - 3} more")
        print(f"  total problematic in {cache_dir.name}: {problems_in_dir}")

    print()
    print(f"Total cache files scanned:    {total_files}")
    print(f"Total problematic files:      {total_problem}")
    if args.apply:
        print(f"Total renamed:                {total_renamed}")
        print(f"Suffix used:                  {suffix}")
        print(f"To restore: rename *{suffix} back to *.json")
    else:
        print("DRY-RUN — pass --apply to actually rename.")

    if by_reason:
        print("\nReason breakdown:")
        for reason, count in sorted(by_reason.items(), key=lambda r: -r[1])[:10]:
            print(f"  {count:>4}  {reason}")

    return 0


if __name__ == "__main__":
    sys.exit(main())

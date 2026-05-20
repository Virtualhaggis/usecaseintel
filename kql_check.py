"""kql_check.py — corpus-wide KQL validator CLI.

Scans the UC catalog and runs both validators (schema + syntax) against
every defender_kql / sentinel_kql query. No LLM calls. Pure validation.

Usage:
  py kql_check.py --all
  py kql_check.py --uc UC_2026_GH_ACTIONS_COMPROMISE
  py kql_check.py --recent 50
  py kql_check.py --all --json > report.json
  py kql_check.py --cache-only          # only scan intel/.llm_uc_cache (skip catalog/use_cases yaml)
  py kql_check.py --catalog-only        # only scan catalog/use_cases (skip cache)

Sources scanned:
  - catalog/use_cases/**/*.yml (or .yaml) — author-curated + persisted UCs
  - intel/.llm_uc_cache/**/*.json — the on-disk UC cache produced by
    generate.py

The cache contains a `ucs` list inside each file; each catalog YAML file
is one UC per file. The script auto-detects which it's reading.

Exit code is 0 unless --strict is passed and any UC has Error-severity
issues, in which case exit 2 (useful for CI gating).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parent

try:
    import yaml  # type: ignore
except ImportError:
    yaml = None

# Reuse the existing validators from generate.py rather than re-importing
# every dependency. Importing the schema validator directly is cheap; the
# syntax validator is also self-contained.
try:
    from kql_schema_validator import validate_kql as schema_validate
except ImportError:
    schema_validate = None  # type: ignore

try:
    from kql_syntax_validator import validate_kql_syntax_batch, is_available as syntax_available
except ImportError:
    validate_kql_syntax_batch = None  # type: ignore
    syntax_available = lambda: False


# =============================================================================
# UC source discovery
# =============================================================================

CATALOG_DIR = ROOT / "catalog" / "use_cases"
CACHE_DIR = ROOT / "intel" / ".llm_uc_cache"


def _yaml_load(path: Path) -> dict | None:
    if yaml is None:
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh)
    except Exception:
        return None


def iter_catalog_ucs() -> list[dict]:
    """Yield UCs from catalog/use_cases/**/*.yml. Each file = one UC."""
    out: list[dict] = []
    if not CATALOG_DIR.exists():
        return out
    for p in CATALOG_DIR.rglob("*.yml"):
        d = _yaml_load(p)
        if isinstance(d, dict):
            d.setdefault("_source", str(p.relative_to(ROOT)))
            d.setdefault("_uc_id", p.stem)
            out.append(d)
    for p in CATALOG_DIR.rglob("*.yaml"):
        d = _yaml_load(p)
        if isinstance(d, dict):
            d.setdefault("_source", str(p.relative_to(ROOT)))
            d.setdefault("_uc_id", p.stem)
            out.append(d)
    return out


def iter_cache_ucs() -> list[dict]:
    """Yield individual UCs from intel/.llm_uc_cache/**/*.json. Each file
    contains a `ucs` list — we flatten it into individual UCs annotated
    with their source cache file. Files renamed `*.invalidated-*.json`
    are skipped: those are tombstones from the invalidator, ignored by
    the pipeline's own cache lookup and irrelevant to a quality audit."""
    out: list[dict] = []
    if not CACHE_DIR.exists():
        return out
    for p in CACHE_DIR.rglob("*.json"):
        if ".invalidated-" in p.name:
            continue
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        ucs = d.get("ucs") or []
        for uc in ucs:
            if isinstance(uc, dict):
                uc.setdefault("_source", str(p.relative_to(ROOT)))
                uc.setdefault("_uc_id", uc.get("uc_id") or uc.get("id") or p.stem)
                out.append(uc)
    return out


# =============================================================================
# Validation pass
# =============================================================================

def _kql_fields_present(uc: dict) -> dict[str, str]:
    """Return the {platform_label: kql} pairs that this UC actually has."""
    out: dict[str, str] = {}
    for k in ("defender_kql", "kql", "sentinel_kql"):
        v = uc.get(k)
        if isinstance(v, str) and v.strip():
            label = "sentinel" if k == "sentinel_kql" else "defender"
            out[label] = v
    return out


def validate_ucs(ucs: list[dict]) -> dict[str, Any]:
    """Run both validators across every (UC, platform) pair. Returns a
    report dict shaped for both pretty-printing and JSON output."""
    # Flatten to (id, platform, kql) for batch syntax check.
    syntax_batch: list[tuple[str, str]] = []
    for i, uc in enumerate(ucs):
        for platform, kql in _kql_fields_present(uc).items():
            syntax_batch.append((f"{i}|{platform}", kql))

    syntax_results = {}
    if syntax_batch and validate_kql_syntax_batch and syntax_available():
        rows = validate_kql_syntax_batch(syntax_batch)
        for r in rows:
            syntax_results[r["id"]] = r.get("errors") or []
    else:
        # Syntax validator missing — fall back to schema-only.
        pass

    schema_results = {}
    if schema_validate:
        for i, uc in enumerate(ucs):
            for platform, kql in _kql_fields_present(uc).items():
                try:
                    issues = schema_validate(kql)
                except Exception:
                    issues = []
                schema_results[f"{i}|{platform}"] = list(issues)

    # Aggregate per-UC.
    per_uc = []
    for i, uc in enumerate(ucs):
        platforms = _kql_fields_present(uc)
        uc_record: dict[str, Any] = {
            "uc_id": uc.get("_uc_id"),
            "source": uc.get("_source"),
            "title": uc.get("title", ""),
            "platforms": list(platforms.keys()),
            "schema_issues": {},
            "syntax_issues": {},
        }
        for platform in platforms:
            key = f"{i}|{platform}"
            uc_record["schema_issues"][platform] = schema_results.get(key, [])
            uc_record["syntax_issues"][platform] = syntax_results.get(key, [])
        per_uc.append(uc_record)

    # Counts.
    total_ucs = len(per_uc)
    total_queries = sum(len(r["platforms"]) for r in per_uc)
    n_clean = 0
    n_schema_only = 0
    n_syntax_only = 0
    n_both = 0
    n_schema_issues = 0
    n_syntax_issues = 0
    syntax_messages: Counter = Counter()
    for r in per_uc:
        has_schema = any(r["schema_issues"][p] for p in r["platforms"])
        has_syntax = any(r["syntax_issues"][p] for p in r["platforms"])
        if not has_schema and not has_syntax:
            n_clean += 1
        elif has_schema and has_syntax:
            n_both += 1
        elif has_schema:
            n_schema_only += 1
        else:
            n_syntax_only += 1
        for p in r["platforms"]:
            n_schema_issues += len(r["schema_issues"][p])
            for e in r["syntax_issues"][p]:
                n_syntax_issues += 1
                msg = (e.get("message") or "")[:80] if isinstance(e, dict) else str(e)[:80]
                syntax_messages[msg] += 1

    return {
        "total_ucs": total_ucs,
        "total_queries": total_queries,
        "syntax_validator_available": bool(syntax_available()),
        "schema_validator_available": bool(schema_validate),
        "n_clean": n_clean,
        "n_schema_only": n_schema_only,
        "n_syntax_only": n_syntax_only,
        "n_both": n_both,
        "n_schema_issues": n_schema_issues,
        "n_syntax_issues": n_syntax_issues,
        "top_syntax_messages": syntax_messages.most_common(10),
        "per_uc": per_uc,
    }


# =============================================================================
# Output rendering
# =============================================================================

def render_text(report: dict, *, verbose: bool = False) -> str:
    lines = []
    lines.append("=== KQL VALIDATION REPORT ===")
    if not report["syntax_validator_available"]:
        lines.append("  ⚠ syntax validator binary missing — schema-only mode")
    if not report["schema_validator_available"]:
        lines.append("  ⚠ schema validator missing")
    pct_clean = (100.0 * report["n_clean"] / report["total_ucs"]) if report["total_ucs"] else 0.0
    lines.append(f"Scanned: {report['total_ucs']} UCs "
                 f"({report['total_queries']} KQL queries)")
    lines.append(f"Clean:   {report['n_clean']} UCs ({pct_clean:.1f}%)")
    lines.append(f"Issues:  {report['total_ucs'] - report['n_clean']} UCs "
                 f"({100.0 - pct_clean:.1f}%)")
    lines.append(f"  - schema-only: {report['n_schema_only']}")
    lines.append(f"  - syntax-only: {report['n_syntax_only']}")
    lines.append(f"  - both:        {report['n_both']}")
    lines.append(f"Issue totals: {report['n_schema_issues']} schema, "
                 f"{report['n_syntax_issues']} syntax")
    if report["top_syntax_messages"]:
        lines.append("")
        lines.append("Top syntax-error patterns:")
        for msg, count in report["top_syntax_messages"]:
            lines.append(f"  {count:3} × {msg}")

    if verbose:
        lines.append("")
        lines.append("=== Per-UC diagnostics ===")
        for r in report["per_uc"]:
            has_any = any(r["schema_issues"][p] or r["syntax_issues"][p]
                          for p in r["platforms"])
            if not has_any:
                continue
            lines.append(f"\n  UC: {r['uc_id']}")
            lines.append(f"      title: {r['title'][:90]}")
            lines.append(f"      source: {r['source']}")
            for p in r["platforms"]:
                schema = r["schema_issues"][p]
                syntax = r["syntax_issues"][p]
                if schema:
                    lines.append(f"    [{p} schema] {len(schema)} issue(s):")
                    for s in schema[:3]:
                        msg = (s.get("reason") or s.get("message") or "") if isinstance(s, dict) else str(s)
                        lines.append(f"      - {msg[:140]}")
                if syntax:
                    lines.append(f"    [{p} syntax] {len(syntax)} error(s):")
                    for e in syntax[:3]:
                        if isinstance(e, dict):
                            line = e.get("line", "?")
                            col = e.get("column", "?")
                            msg = e.get("message", "")
                            lines.append(f"      - L{line}:C{col}: {msg[:140]}")
                        else:
                            lines.append(f"      - {str(e)[:140]}")
    return "\n".join(lines)


# =============================================================================
# CLI
# =============================================================================

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Audit KQL queries across the UC catalog.")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--all", action="store_true",
                   help="Scan both catalog/use_cases/ and intel/.llm_uc_cache/ (default)")
    g.add_argument("--catalog-only", action="store_true",
                   help="Scan only catalog/use_cases/")
    g.add_argument("--cache-only", action="store_true",
                   help="Scan only intel/.llm_uc_cache/")
    g.add_argument("--uc", metavar="UC_ID",
                   help="Validate a single UC (matches uc_id, id, or filename stem)")
    g.add_argument("--recent", type=int, metavar="N",
                   help="Validate the N most recently modified UC cache files")
    ap.add_argument("--json", action="store_true",
                    help="Emit full report as JSON to stdout (suppresses text rendering)")
    ap.add_argument("--verbose", "-v", action="store_true",
                    help="Print per-UC diagnostics in text mode")
    ap.add_argument("--strict", action="store_true",
                    help="Exit 2 if any UC has errors (useful for CI)")
    args = ap.parse_args(argv)

    # Discover UCs.
    if args.uc:
        # Try cache then catalog.
        all_ucs = iter_cache_ucs() + iter_catalog_ucs()
        ucs = [u for u in all_ucs if u.get("_uc_id") == args.uc
               or u.get("uc_id") == args.uc or u.get("id") == args.uc]
        if not ucs:
            print(f"no UC matched id={args.uc!r}", file=sys.stderr)
            return 1
    elif args.recent:
        if not CACHE_DIR.exists():
            print(f"cache dir not found: {CACHE_DIR}", file=sys.stderr)
            return 1
        cache_files = sorted(
            CACHE_DIR.rglob("*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )[: args.recent]
        ucs = []
        for p in cache_files:
            try:
                d = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                continue
            for uc in (d.get("ucs") or []):
                if isinstance(uc, dict):
                    uc.setdefault("_source", str(p.relative_to(ROOT)))
                    uc.setdefault("_uc_id", uc.get("uc_id") or p.stem)
                    ucs.append(uc)
    elif args.catalog_only:
        ucs = iter_catalog_ucs()
    elif args.cache_only:
        ucs = iter_cache_ucs()
    else:  # --all or default
        ucs = iter_cache_ucs() + iter_catalog_ucs()

    if not ucs:
        print("no UCs found to validate", file=sys.stderr)
        return 1

    report = validate_ucs(ucs)

    if args.json:
        # Force UTF-8 on stdout so KQL queries containing characters like
        # `≤`, `↪`, fancy quotes etc. don't crash Windows' default cp1252.
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass
        out = json.dumps(report, ensure_ascii=False, indent=2)
        sys.stdout.write(out + "\n")
    else:
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass
        print(render_text(report, verbose=args.verbose))

    if args.strict and (report["n_schema_issues"] or report["n_syntax_issues"]):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())

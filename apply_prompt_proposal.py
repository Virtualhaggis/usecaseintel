"""Tier-3 approval gate for prompt self-improvement.

site_review.py only ever *records* prompt-tuning proposals (it never edits a
generation prompt). This is the ONLY way a proposal reaches the code, and only
when you explicitly approve it. Each apply is validated (ast + smoke) and
reversible (its own commit).

  py apply_prompt_proposal.py --list                 # all proposals
  py apply_prompt_proposal.py --show <id>            # full proposal + draft diff
  py apply_prompt_proposal.py <id> --approve         # apply the draft, validate, commit
  py apply_prompt_proposal.py <id> --reject          # mark rejected
"""
from __future__ import annotations

import argparse
import ast
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent
PROMPTS = ROOT / "intel" / "site_review" / "prompt_proposals.jsonl"


def _load():
    if not PROMPTS.exists():
        return []
    out = []
    for line in PROMPTS.read_text(encoding="utf-8").splitlines():
        try:
            out.append(json.loads(line))
        except Exception:
            pass
    return out


def _save(rows):
    PROMPTS.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows)
                       + "\n", encoding="utf-8")


def _validate():
    try:
        ast.parse((ROOT / "generate.py").read_text(encoding="utf-8"))
    except SyntaxError as e:
        return False, f"syntax error: {e}"
    smoke = ROOT / "_smoke_pipeline_changes.py"
    if smoke.exists():
        r = subprocess.run([sys.executable, str(smoke)], cwd=ROOT,
                           capture_output=True, text=True)
        if r.returncode != 0:
            return False, "smoke test failed"
    return True, "ok"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("id", nargs="?")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--show", metavar="ID")
    ap.add_argument("--approve", action="store_true")
    ap.add_argument("--reject", action="store_true")
    args = ap.parse_args()
    rows = _load()
    byid = {r["id"]: r for r in rows}

    if args.list or (not args.id and not args.show):
        if not rows:
            print("No prompt proposals recorded.")
            return 0
        for r in rows:
            d = "draft✓" if r.get("draft") else "no-draft (manual)"
            print(f"  [{r.get('status','?'):14s}] {r['id']}  ({d})")
            print(f"       signal: {r['signal']['title']} — {r['signal']['detail'][:90]}")
        return 0

    rid = args.show or args.id
    r = byid.get(rid)
    if not r:
        print(f"No proposal '{rid}'. Use --list.")
        return 1

    if args.show:
        print(json.dumps(r, indent=2, ensure_ascii=False))
        return 0

    if args.reject:
        r["status"] = "rejected"
        _save(rows)
        print(f"[{rid}] marked rejected.")
        return 0

    if args.approve:
        draft = r.get("draft")
        if not draft or not draft.get("old"):
            print(f"[{rid}] has no concrete draft diff — craft the prompt edit "
                  f"by hand against this signal:\n  {r['signal']['detail']}")
            return 1
        tgt = ROOT / draft.get("file", "generate.py")
        text = tgt.read_text(encoding="utf-8")
        if draft["old"] not in text:
            print(f"[{rid}] draft's 'old' text not found in {tgt.name} — stale, skipping.")
            return 1
        backup = text
        tgt.write_text(text.replace(draft["old"], draft["new"], 1), encoding="utf-8")
        ok, why = _validate()
        if not ok:
            tgt.write_text(backup, encoding="utf-8")
            print(f"[{rid}] reverted — validation failed: {why}")
            return 1
        r["status"] = "applied"
        _save(rows)
        subprocess.run(["git", "add", str(tgt.relative_to(ROOT)),
                        str(PROMPTS.relative_to(ROOT))], cwd=ROOT, capture_output=True)
        msg = (f"prompt: apply approved proposal {rid}\n\n"
               f"{r['signal']['title']}\n\n"
               "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>")
        subprocess.run(["git", "commit", "-m", msg], cwd=ROOT, capture_output=True)
        print(f"[{rid}] applied + validated + committed. Push when ready, or revert "
              f"with `git revert HEAD`.")
        return 0

    print("Specify --approve or --reject (or --show).")
    return 1


if __name__ == "__main__":
    sys.exit(main())

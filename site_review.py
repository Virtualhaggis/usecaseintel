"""Daily site-review orchestrator for Clankerusecase.

Runs the deterministic lint, applies only provably-safe auto-fixes (Tier 1),
records everything else as human/LLM suggestions (Tier 2), and records prompt-
tuning signals as APPROVAL-ONLY proposals (Tier 3 — never auto-applied). Reads
yesterday's report for continuity, writes today's, and commits the record.

Tiers
  1 AUTO     — registered safe string transforms; applied only behind
               ast.parse + smoke gates, each its own revert-able change.
  2 SUGGEST  — written to intel/site_review/suggestions.jsonl for you to action.
  3 PROMPT   — written to intel/site_review/prompt_proposals.jsonl. Applying one
               requires `py apply_prompt_proposal.py <id> --approve`. Nothing
               touches a generation prompt automatically.

Usage
  py site_review.py                 # lint + Tier-1 auto-fix + record + commit
  py site_review.py --dry-run       # report only, no edits, no commit
  py site_review.py --no-commit     # do the work, skip git
  py site_review.py --with-llm      # also run one rotating LLM lens (needs OAuth)

Safe by design: never renders, never touches WIP files, never auto-applies a
suggestion or a prompt change, aborts the run if a live pipeline holds the lock.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import subprocess
import sys
from pathlib import Path

import _review_lint as lint

ROOT = Path(__file__).parent
REV = ROOT / "intel" / "site_review"
REV.mkdir(parents=True, exist_ok=True)
STATE = REV / "state.json"
SUGG = REV / "suggestions.jsonl"
PROMPTS = REV / "prompt_proposals.jsonl"
LOG = ROOT / "_site_review_log.md"
SENTINEL = ROOT / ".review_failed"

# Files the review must NEVER stage (user WIP / operator-managed).
WIP_GUARD = {
    "CHANGELOG.md", "README.md", "quality_review.py", "requirements.txt",
    "validate_kql_knowledge.py", "intel/quality_suggestions.jsonl",
}

LENSES = ["trust", "detection-usability", "search-filter", "copy", "mobile",
          "a11y", "perf", "seo", "links", "security", "data-quality"]


def _today():
    # Date.now() is unavailable in some sandboxes; fall back to git or 'undated'.
    try:
        return _dt.date.today().isoformat()
    except Exception:
        try:
            return subprocess.check_output(["git", "log", "-1", "--format=%cs"],
                                           cwd=ROOT, text=True).strip()
        except Exception:
            return "undated"


def _load_state():
    if STATE.exists():
        try:
            return json.loads(STATE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"last_lens_idx": -1, "last_archive_ucs": 0, "runs": 0,
            "seen_suggestions": []}


def _save_state(s):
    STATE.write_text(json.dumps(s, indent=1), encoding="utf-8")


def _lock_held():
    """True if a live pipeline run holds the lock (don't collide)."""
    lk = ROOT / "intel" / ".pipeline.lock"
    if not lk.exists():
        return False
    try:
        import generate as g  # noqa
        info = json.loads(lk.read_text(encoding="utf-8"))
        return bool(g._pipeline_pid_alive(info.get("pid")))
    except Exception:
        return False  # stale/unreadable → treat as free


# --------------------------------------------------------------------------- #
# Tier 1 — safe auto-fix
# --------------------------------------------------------------------------- #
def apply_auto_fixes(findings, do_commit):
    """Apply tier==auto fixes to generate.py, one at a time, each gated by
    ast.parse + smoke. Returns the list actually applied."""
    auto = [f for f in findings if f.get("tier") == "auto" and f.get("fix")]
    if not auto:
        return []
    gen = ROOT / "generate.py"
    applied = []
    for f in auto:
        fix = f["fix"]
        if fix.get("file") != "generate.py":
            continue
        text = gen.read_text(encoding="utf-8")
        if fix["old"] not in text or fix["new"] in text:
            continue  # already applied or not found
        candidate = text.replace(fix["old"], fix["new"], 1)
        gen.write_text(candidate, encoding="utf-8")
        if _validate_generate():
            applied.append(f)
        else:
            gen.write_text(text, encoding="utf-8")  # revert
            f["detail"] += " [auto-fix reverted: failed validation]"
    return applied


def _validate_generate():
    """ast.parse + smoke. True only if both pass."""
    try:
        import ast
        ast.parse((ROOT / "generate.py").read_text(encoding="utf-8"))
    except SyntaxError:
        return False
    smoke = ROOT / "_smoke_pipeline_changes.py"
    if smoke.exists():
        r = subprocess.run([sys.executable, str(smoke)], cwd=ROOT,
                           capture_output=True, text=True)
        if r.returncode != 0:
            return False
    return True


# --------------------------------------------------------------------------- #
# Tier 2 / 3 — record (never auto-apply)
# --------------------------------------------------------------------------- #
def record_suggestions(findings, state, date):
    seen = set(state.get("seen_suggestions", []))
    new = []
    for f in findings:
        if f.get("tier") != "suggest":
            continue
        key = f"{f['id']}::{f['title']}"
        if key in seen:
            continue
        seen.add(key)
        new.append({**f, "first_seen": date, "status": "open"})
    if new:
        with SUGG.open("a", encoding="utf-8") as fh:
            for s in new:
                fh.write(json.dumps(s, ensure_ascii=False) + "\n")
    state["seen_suggestions"] = sorted(seen)
    return new


def record_prompt_proposals(findings, date, llm_drafts=None):
    """Tier 3 signals → approval-only proposals. Each carries the triggering
    finding + (optionally) an LLM-drafted prompt diff. NEVER applied here."""
    signals = [f for f in findings if f.get("tier") == "prompt"]
    drafts = {d["signal_id"]: d for d in (llm_drafts or [])}
    new = []
    for f in signals:
        prop = {"id": f"prop-{date}-{f['id']}", "date": date, "status": "needs-approval",
                "signal": f, "draft": drafts.get(f["id"])}
        new.append(prop)
    if new:
        with PROMPTS.open("a", encoding="utf-8") as fh:
            for p in new:
                fh.write(json.dumps(p, ensure_ascii=False) + "\n")
    return new


# --------------------------------------------------------------------------- #
# LLM lens review (optional, --with-llm) — produces Tier-2 suggestions only
# --------------------------------------------------------------------------- #
def llm_lens_review(lens, findings, prior_summary):
    """One bounded LLM pass through a single lens. Returns a list of suggestion
    dicts. Best-effort: returns [] if the CLI is unavailable. Never edits code."""
    try:
        import generate as g  # noqa
    except Exception:
        return []
    idx = (ROOT / "index.html")
    excerpt = idx.read_text(encoding="utf-8", errors="replace")[:6000] if idx.exists() else ""
    prompt = (
        f"You are reviewing the Clankerusecase detection-library site for a "
        f"skeptical SOC manager, through ONE lens: {lens}.\n"
        f"Yesterday's notes:\n{prior_summary[:1500]}\n\n"
        f"Today's deterministic lint findings:\n"
        f"{json.dumps([f['title'] for f in findings][:20])}\n\n"
        f"index.html head excerpt:\n{excerpt}\n\n"
        f"Return ONLY a JSON array of at most 4 NON-obvious, high-value issues "
        f"for this lens, each {{\"title\":..,\"detail\":..,\"severity\":\"FAIL|WARN|INFO\"}}. "
        f"Do not repeat the lint findings. No prose, no code fences."
    )
    try:
        raw = g._call_claude_cli(prompt, model=getattr(g, "LLM_RELEVANCE_MODEL", None),
                                 allowed_tools=None, timeout=60, kind="review")
        raw = (raw or "").strip()
        if raw.startswith("```"):
            raw = raw.strip("`").split("\n", 1)[-1]
        items = json.loads(raw)
        out = []
        for it in items[:4]:
            out.append(_review_suggestion(lens, it))
        return out
    except Exception:
        return []


def _review_suggestion(lens, it):
    return {"id": f"llm_{lens}", "lens": lens, "tier": "suggest",
            "severity": it.get("severity", "INFO"),
            "title": str(it.get("title", ""))[:120],
            "detail": str(it.get("detail", ""))[:400], "source": "llm"}


# --------------------------------------------------------------------------- #
# report + git
# --------------------------------------------------------------------------- #
def _prior_summary():
    if not LOG.exists():
        return "(no prior report)"
    txt = LOG.read_text(encoding="utf-8", errors="replace")
    return txt.rsplit("\n## ", 1)[-1][:2000]


def write_report(date, lens, findings, applied, new_sugg, props, llm_sugg, state):
    det, arts = lint._archive_detection_count()
    drift = ""
    if state.get("last_archive_ucs") and det and det < state["last_archive_ucs"]:
        drift = (f"\n- ⚠️ **Archive total DROPPED** {state['last_archive_ucs']:,} → "
                 f"{det:,} (should be monotonic — investigate).")
    lines = [
        f"\n## {date} — site review (run #{state.get('runs', 0) + 1})",
        f"- Lens this loop: **{lens}**",
        f"- Archive: {det:,} detections / {arts:,} articles" if det else "- Archive: n/a",
        f"- Lint: {len(findings)} finding(s) · auto-fixed {len(applied)} · "
        f"{len(new_sugg)} new suggestion(s) · {len(props)} prompt proposal(s)"
        f"{' · ' + str(len(llm_sugg)) + ' LLM note(s)' if llm_sugg else ''}.{drift}",
    ]
    if applied:
        lines.append("- **Auto-fixed (Tier 1):** " +
                     "; ".join(f["title"] for f in applied))
    top = [f for f in findings if f["severity"] == "FAIL"][:5]
    if top:
        lines.append("- **Top open issues:**")
        lines += [f"  - [{f['severity']}] {f['title']} — {f['detail'][:120]}" for f in top]
    for s in (llm_sugg or []):
        lines.append(f"  - [LLM/{s['lens']}] {s['title']} — {s['detail'][:120]}")
    if props:
        lines.append(f"- **Prompt proposals (approval-only):** {len(props)} — "
                     f"review with `py apply_prompt_proposal.py --list`.")
    LOG.write_text((LOG.read_text(encoding="utf-8") if LOG.exists() else
                    "# Clankerusecase — Site Review Log\n") + "\n".join(lines) + "\n",
                   encoding="utf-8")
    return "\n".join(lines)


def commit(applied, date):
    """Commit only the review's own outputs + any auto-fixed generate.py.
    Refuses to stage WIP-guarded paths."""
    paths = [str(REV.relative_to(ROOT)), "_site_review_log.md"]
    if applied:
        paths.append("generate.py")
    # stage explicitly-named paths only
    subprocess.run(["git", "add"] + paths, cwd=ROOT, capture_output=True)
    # safety: unstage anything WIP that slipped in
    staged = subprocess.run(["git", "diff", "--cached", "--name-only"], cwd=ROOT,
                            capture_output=True, text=True).stdout.split()
    bad = [p for p in staged if p in WIP_GUARD]
    if bad:
        subprocess.run(["git", "reset", "-q"] + bad, cwd=ROOT, capture_output=True)
    if not subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=ROOT).returncode:
        return False  # nothing staged
    msg = (f"site-review: {date} — {len(applied)} auto-fix(es), report + queues\n\n"
           "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>")
    subprocess.run(["git", "commit", "-m", msg], cwd=ROOT, capture_output=True)
    push = subprocess.run(["git", "push"], cwd=ROOT, capture_output=True, text=True)
    if push.returncode != 0:
        SENTINEL.write_text(f"push failed {date}\n{push.stderr[:300]}", encoding="utf-8")
        return False
    if SENTINEL.exists():
        SENTINEL.unlink()
    return True


def main():
    try:  # Windows console / redirected stdout defaults to cp1252 — make prints safe.
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--no-commit", action="store_true")
    ap.add_argument("--with-llm", action="store_true")
    args = ap.parse_args()

    if _lock_held():
        print("[site-review] live pipeline holds the lock — skipping this run.")
        return 0

    date = _today()
    state = _load_state()
    lens = LENSES[(state.get("last_lens_idx", -1) + 1) % len(LENSES)]
    findings = lint.run_lint()
    print(f"[site-review] {date} · lens={lens} · {len(findings)} lint finding(s)")

    applied = [] if args.dry_run else apply_auto_fixes(findings, not args.no_commit)
    llm_sugg = llm_lens_review(lens, findings, _prior_summary()) if args.with_llm else []
    new_sugg = [] if args.dry_run else record_suggestions(findings + llm_sugg, state, date)
    props = [] if args.dry_run else record_prompt_proposals(findings, date)

    summary = write_report(date, lens, findings, applied, new_sugg, props,
                           llm_sugg, state) if not args.dry_run else ""
    print(summary or "[dry-run] " + f"{len(findings)} findings, "
          f"{sum(1 for f in findings if f['tier']=='auto')} auto-fixable.")

    if not args.dry_run:
        state["last_lens_idx"] = LENSES.index(lens)
        det, _ = lint._archive_detection_count()
        if det:
            state["last_archive_ucs"] = det
        state["runs"] = state.get("runs", 0) + 1
        _save_state(state)
        if not args.no_commit:
            print("[site-review] committed + pushed." if commit(applied, date)
                  else "[site-review] nothing committed (or push failed).")
    return 0


if __name__ == "__main__":
    sys.exit(main())

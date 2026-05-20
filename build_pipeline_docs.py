"""Build pipeline.html — local-only operator dashboard for the threat-intel
pipeline. Renders 4 tabs (Overview · Usage · Quality · Workflows) plus a
sticky vital-signs strip with live pipeline state, USD cost, cache hit-rate,
KQL audit health, and detection-gap aggregation. All visuals are plain
SVG/CSS — no external chart libs, no network fetches.

Run:    py build_pipeline_docs.py
Output: pipeline.html (in this directory, gitignored)
"""
from __future__ import annotations
import json
import re
import subprocess
import shutil
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

# ---- Path constants ----
ROOT       = Path(__file__).parent
LOG        = ROOT / "logs" / "auto.log"
LOG_REVIEW = ROOT / "logs" / "review.log"
LOG_WEEKLY = ROOT / "logs" / "biweekly.log"
DROPS      = ROOT / "intel" / "relevance_drops.jsonl"
BRIEFS     = ROOT / "briefings"
USAGE      = ROOT / "intel" / ".usage_log.jsonl"
BASELINE   = ROOT / "intel" / ".usage_log.baseline.jsonl"
QUAL_SUG   = ROOT / "intel" / "quality_suggestions.jsonl"
KQL_AUDIT  = ROOT / "kql_audit.json"
LOCK       = ROOT / "intel" / ".pipeline.lock"
UC_CACHE   = ROOT / "intel" / ".llm_uc_cache"
OUT        = ROOT / "pipeline.html"

# ---- Model pricing ----
# Per 1M tokens (Anthropic catalogue, May 2026). Opus 4.7 / Haiku 4.5.
# Maps usage-row kind → model. Pipeline calls opus for everything except the
# quality_review.py haiku reviewer (review kind).
_MODEL_PRICING = {
    "opus":  {"input": 15.00, "output": 75.00, "cache_read":  1.50, "cache_write": 18.75},
    "haiku": {"input":  1.00, "output":  5.00, "cache_read":  0.10, "cache_write":  1.25},
}
_KIND_MODEL = {
    "uc": "opus", "ioc": "opus", "kc": "opus",
    "vision": "opus", "relevance": "opus", "review": "haiku",
}


def _row_cost_usd(row: dict) -> float:
    """USD cost for one usage_log row, summing by-kind sub-totals against the
    model that kind was actually called with (opus vs haiku)."""
    total = 0.0
    for kind, slot in (row.get("by_kind") or {}).items():
        p = _MODEL_PRICING.get(_KIND_MODEL.get(kind, "opus"), _MODEL_PRICING["opus"])
        total += (slot.get("input_tokens",  0) or 0) * p["input"]       / 1e6
        total += (slot.get("output_tokens", 0) or 0) * p["output"]      / 1e6
        total += (slot.get("cache_read",    0) or 0) * p["cache_read"]  / 1e6
        total += (slot.get("cache_create",  0) or 0) * p["cache_write"] / 1e6
    return round(total, 4)


def _cache_hit_rate(totals: dict) -> float:
    """cache_read / (input + cache_read). Returns 0.0..1.0."""
    t = totals or {}
    cr = t.get("cache_read", 0) or 0
    it = t.get("input_tokens", 0) or 0
    denom = cr + it
    return (cr / denom) if denom else 0.0


def _fmt_age(seconds: float | None) -> str:
    """Compact human age string."""
    if seconds is None or seconds < 0:
        return "—"
    s = int(seconds)
    if s < 60:    return f"{s}s"
    if s < 3600:  return f"{s // 60}m"
    if s < 86400: return f"{s // 3600}h{(s % 3600) // 60:02d}m"
    d, r = divmod(s, 86400)
    return f"{d}d{r // 3600:02d}h"


def _fmt_bytes(n: int | None) -> str:
    if n is None:        return "—"
    if n < 1024:         return f"{n} B"
    if n < 1048576:      return f"{n / 1024:.1f} KB"
    if n < 1073741824:   return f"{n / 1048576:.1f} MB"
    return f"{n / 1073741824:.2f} GB"


def _fmt_usd(amount: float | None) -> str:
    if amount is None:   return "—"
    if amount < 0.01:    return f"${amount:.4f}"
    if amount < 10:      return f"${amount:.2f}"
    return f"${amount:,.0f}"


def _parse_iso(ts: str | None):
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None


def _utcnow():
    return datetime.now(timezone.utc)


def _latest_run_stats() -> dict:
    """Pull the most recent run boundary + the metrics lines printed within it."""
    out = {
        "started":          None,
        "finished":         None,
        "articles_total":   None,
        "articles_kept":    None,
        "articles_dropped": None,
        "tier_breakdown":   None,
        "top_drop_sources": None,
        "dedupe":           None,
        "marketing_dropped": None,
        "breaker_tripped":  False,
    }
    if not LOG.exists():
        return out
    text = LOG.read_text(encoding="utf-8", errors="replace")
    # Find the most recent FULL start→done block (not an in-flight start).
    blocks = list(re.finditer(
        r"=== run_once start (\S+) ===(.*?)=== run_once done ===",
        text, re.DOTALL
    ))
    if not blocks:
        return out
    last = blocks[-1]
    out["started"] = last.group(1)
    block = last.group(2)
    out["finished"] = "(this run completed)"
    # If a newer start exists after this completion, note it
    after = text[last.end():]
    if re.search(r"=== run_once start ", after):
        out["finished"] = "(this run completed; another run in flight after)"

    m = re.search(r"^\[\*\]\s+(\d+)\s+articles total\.", block, re.M)
    if m:
        out["articles_total"] = int(m.group(1))
    m = re.search(
        r"^\[\*\]\s+Relevance: kept (\d+) alert, dropped (\d+) "
        r"\((.*?)\)\s*$",
        block, re.M
    )
    if m:
        out["articles_kept"]    = int(m.group(1))
        out["articles_dropped"] = int(m.group(2))
        out["tier_breakdown"]   = m.group(3)
    m = re.search(r"Top dropped sources:\s+(.+)$", block, re.M)
    if m:
        out["top_drop_sources"] = m.group(1).strip()
    m = re.search(
        r"^\[\*\]\s+Same-incident dedupe: merged (\d+) by title-Jaccard, "
        r"(\d+) by canonical-ID", block, re.M
    )
    if m:
        out["dedupe"] = {
            "by_title":     int(m.group(1)),
            "by_canonical": int(m.group(2)),
        }
    dropped_marketing = sum(
        int(m.group(1)) for m in re.finditer(
            r"-> dropped (\d+) marketing post", block
        )
    )
    out["marketing_dropped"] = dropped_marketing
    out["breaker_tripped"] = "OAuth circuit breaker" in block

    return out


def _drop_log_sample(limit: int = 25) -> list[dict]:
    """Read the most recent N entries from relevance_drops.jsonl."""
    if not DROPS.exists():
        return []
    rows = []
    for line in DROPS.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            rows.append(json.loads(line))
        except Exception:
            pass
    return rows[-limit:][::-1]


def _briefings_today() -> int:
    """Count articles in today's briefings folder (or most recent date)."""
    if not BRIEFS.exists():
        return 0
    dirs = sorted(
        [d for d in BRIEFS.iterdir() if d.is_dir() and re.match(r"^\d{4}-\d{2}-\d{2}$", d.name)],
        reverse=True
    )
    return len(list(dirs[0].glob("*.md"))) if dirs else 0


def _usage_log_data(limit: int = 200) -> list[dict]:
    """Read intel/.usage_log.jsonl, return up to `limit` most recent rows
    sorted newest-first. Each row is one pipeline / review / biweekly run,
    written by generate._emit_usage_summary at process exit. Returns []
    if the file doesn't exist yet (no runs have completed under the new
    instrumentation)."""
    if not USAGE.exists():
        return []
    rows = []
    for line in USAGE.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except Exception:
            continue
    # Newest first by ts (already lexicographically sortable since UTC ISO).
    rows.sort(key=lambda r: r.get("ts", ""), reverse=True)
    return rows[:limit]


def _scheduled_tasks() -> list[dict]:
    """Read live state of the two project Windows Scheduled Tasks. PowerShell
    only — quietly returns [] on macOS/Linux or if PS not available."""
    import subprocess, shutil
    if not shutil.which("powershell") and not shutil.which("pwsh"):
        return []
    cmd = [
        "powershell", "-NoProfile", "-Command",
        "Get-ScheduledTask | Where-Object {$_.TaskName -match 'Clanker|usecase|biweekly'} | "
        "ForEach-Object { $info = Get-ScheduledTaskInfo $_; "
        "$trig = $_.Triggers[0]; "
        "$cadence = if ($trig.Repetition.Interval) { 'every ' + $trig.Repetition.Interval + ' from ' + $trig.StartBoundary.Substring(11,5) } "
        "elseif ($trig.WeeksInterval) { 'weekly (every ' + $trig.WeeksInterval + ' wk) at ' + $trig.StartBoundary.Substring(11,5) + ' day ' + $trig.DaysOfWeek } "
        "elseif ($trig.DaysInterval) { 'daily x' + $trig.DaysInterval + ' at ' + $trig.StartBoundary.Substring(11,5) } "
        "else { $trig.StartBoundary }; "
        "[PSCustomObject]@{ Name=$_.TaskName; Cmd=($_.Actions.Execute + ' ' + $_.Actions.Arguments).Trim(); Cadence=$cadence; "
        "LastRun=([string]$info.LastRunTime); NextRun=([string]$info.NextRunTime); LastResult=('0x{0:X}' -f $info.LastTaskResult); State=([string]$_.State) } } | "
        "ConvertTo-Json -Compress -Depth 4"
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if r.returncode != 0 or not r.stdout.strip():
            return []
        data = json.loads(r.stdout)
        if isinstance(data, dict):
            data = [data]
        return data
    except Exception:
        return []


def _escape(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
              .replace('"', "&quot;"))


# =========================================================================
# Extended data helpers (vital signs, overview, quality, storage)
# =========================================================================

def _lock_state() -> dict:
    """Read intel/.pipeline.lock and check whether the PID it points at is
    actually alive (PowerShell Get-Process). Returns
        {"running": bool, "pid": int|None, "started_at": iso, "age_seconds": int}
    """
    out = {"running": False, "pid": None, "started_at": None, "age_seconds": None}
    if not LOCK.exists():
        return out
    try:
        data = json.loads(LOCK.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return out
    pid = data.get("pid")
    out["pid"] = pid
    out["started_at"] = data.get("started_at")
    started = _parse_iso(out["started_at"])
    if started:
        out["age_seconds"] = int((_utcnow() - started).total_seconds())
    # Check liveness. PowerShell only (the dashboard is Windows-targeted).
    if pid and shutil.which("powershell"):
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 f"if (Get-Process -Id {int(pid)} -ErrorAction SilentlyContinue) "
                 f"{{ Write-Output ALIVE }} else {{ Write-Output DEAD }}"],
                capture_output=True, text=True, timeout=8,
            )
            out["running"] = "ALIVE" in (r.stdout or "")
        except Exception:
            pass
    return out


def _git_status() -> dict:
    """git log -1 + diff-against-origin to surface last-push age. Returns
        {"last_commit_ts": iso, "subject": str, "age_seconds": int,
         "ahead": int}     # commits ahead of origin/main (i.e. unpushed)
    """
    out = {"last_commit_ts": None, "subject": None, "age_seconds": None, "ahead": 0}
    if not shutil.which("git"):
        return out
    try:
        r = subprocess.run(
            ["git", "-C", str(ROOT), "log", "-1", "--format=%cI%n%s"],
            capture_output=True, text=True, timeout=6,
        )
        if r.returncode == 0:
            parts = (r.stdout or "").strip().split("\n", 1)
            if parts:
                out["last_commit_ts"] = parts[0]
                out["subject"] = parts[1] if len(parts) > 1 else ""
                dt = _parse_iso(parts[0])
                if dt:
                    out["age_seconds"] = int((_utcnow() - dt).total_seconds())
    except Exception:
        pass
    try:
        r = subprocess.run(
            ["git", "-C", str(ROOT), "rev-list", "--count", "origin/main..HEAD"],
            capture_output=True, text=True, timeout=6,
        )
        if r.returncode == 0:
            out["ahead"] = int((r.stdout or "0").strip() or 0)
    except Exception:
        pass
    return out


def _cache_storage() -> dict:
    """Single-shot size of intel/.llm_uc_cache/. Returns
        {"bytes": int, "files": int}
    PowerShell Measure-Object is faster than Python walk on Windows network
    drives. Falls back to Python walk if PS isn't available."""
    out = {"bytes": 0, "files": 0}
    if not UC_CACHE.exists():
        return out
    if shutil.which("powershell"):
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 f"$m = Get-ChildItem -LiteralPath '{UC_CACHE}' -Recurse -File "
                 f"-ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum; "
                 f"Write-Output \"$($m.Count) $($m.Sum)\""],
                capture_output=True, text=True, timeout=20,
            )
            parts = (r.stdout or "").strip().split()
            if len(parts) >= 2 and parts[0].isdigit():
                out["files"] = int(parts[0])
                out["bytes"] = int(parts[1] or 0)
                return out
        except Exception:
            pass
    # Fallback — Python walk.
    try:
        for p in UC_CACHE.rglob("*"):
            if p.is_file():
                out["files"] += 1
                out["bytes"] += p.stat().st_size
    except Exception:
        pass
    return out


def _baseline_summary() -> dict | None:
    """Read intel/.usage_log.baseline.jsonl, return the median totals row so
    callers can compute deltas. Returns None if no baseline file or empty."""
    if not BASELINE.exists():
        return None
    rows = []
    for line in BASELINE.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except Exception:
            continue
    if not rows:
        return None
    # Per-field medians across the rows (skip script != generate.py rows so
    # we compare like-with-like). Falls back to all rows if no generate rows.
    gen = [r for r in rows if (r.get("script") or "").startswith("generate")]
    pool = gen or rows
    def med(key):
        vals = sorted((r.get("totals") or {}).get(key, 0) or 0 for r in pool)
        n = len(vals)
        if not n:
            return 0
        return vals[n // 2] if n % 2 else (vals[n // 2 - 1] + vals[n // 2]) / 2
    return {
        "rows": len(rows),
        "wall_seconds":   med("wall_seconds"),
        "input_tokens":   med("input_tokens"),
        "output_tokens":  med("output_tokens"),
        "cache_read":     med("cache_read"),
        "cache_create":   med("cache_create"),
        "calls":          med("calls"),
        "errors":         med("errors"),
        "cost_usd_median": sum(_row_cost_usd(r) for r in pool) / max(len(pool), 1),
    }


def _kql_audit_summary() -> dict | None:
    """Read kql_audit.json (produced by kql_check.py). Returns
        {"total_ucs", "n_clean", "n_schema_issues", "n_syntax_issues",
         "pct_clean": float, "top_syntax_messages": [(msg, count), ...10],
         "ts": iso}
    """
    if not KQL_AUDIT.exists():
        return None
    try:
        data = json.loads(KQL_AUDIT.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None
    total = data.get("total_ucs") or 0
    clean = data.get("n_clean") or 0
    return {
        "total_ucs":           total,
        "n_clean":             clean,
        "n_schema_issues":     data.get("n_schema_issues") or 0,
        "n_syntax_issues":     data.get("n_syntax_issues") or 0,
        "n_schema_only":       data.get("n_schema_only") or 0,
        "n_syntax_only":       data.get("n_syntax_only") or 0,
        "n_both":              data.get("n_both") or 0,
        "pct_clean":           (clean / total) if total else 0.0,
        "top_syntax_messages": (data.get("top_syntax_messages") or [])[:10],
        "ts":                  data.get("generated_at") or data.get("ts"),
    }


def _quality_gap_summary(window_days: int = 30) -> dict:
    """Aggregate intel/quality_suggestions.jsonl: count gaps per technique.
    Returns {"total_gaps", "articles_with_gaps", "by_technique": [...top 20]}.
    Per-row schema varies (older rows may have just rationale/title); we count
    technique IDs out of suggestion.techniques[] when present."""
    out = {"total_gaps": 0, "articles_with_gaps": 0, "by_technique": []}
    if not QUAL_SUG.exists():
        return out
    cutoff = _utcnow().timestamp() - (window_days * 86400)
    tech_counter = Counter()
    tech_names = {}
    articles = set()
    for line in QUAL_SUG.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except Exception:
            continue
        ts = _parse_iso(row.get("ts") or row.get("created_at") or "")
        if ts and ts.timestamp() < cutoff:
            continue
        out["total_gaps"] += 1
        aid = row.get("article_id") or row.get("article_url") or row.get("article")
        if aid:
            articles.add(aid)
        sugg = row.get("suggestion") or row
        techs = sugg.get("techniques") or sugg.get("attack_techniques") or []
        for t in techs:
            if isinstance(t, dict):
                tid = t.get("id") or t.get("technique_id")
                tname = t.get("name") or t.get("technique_name") or ""
            else:
                tid = str(t)
                tname = ""
            if not tid:
                continue
            tech_counter[tid] += 1
            if tname and tid not in tech_names:
                tech_names[tid] = tname
    out["articles_with_gaps"] = len(articles)
    out["by_technique"] = [
        {"id": tid, "name": tech_names.get(tid, ""), "count": n}
        for tid, n in tech_counter.most_common(20)
    ]
    return out


def _source_roi(window_days: int = 7) -> list[dict]:
    """Per-source kept-vs-dropped counts over the last N pipeline runs.
    Reads kept counts from logs/auto.log run blocks (each block lists
    'fetched N full article bodies' per source name plus a kept/dropped
    summary) and dropped reasons from relevance_drops.jsonl.
    Returns sorted [{source, kept, dropped, noise_ratio}, ...max 12]."""
    drops_by_src = Counter()
    if DROPS.exists():
        cutoff = _utcnow().timestamp() - (window_days * 86400)
        for line in DROPS.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except Exception:
                continue
            ts = _parse_iso(row.get("ts") or row.get("dropped_at") or "")
            if ts and ts.timestamp() < cutoff:
                continue
            src = row.get("source") or "unknown"
            drops_by_src[src] += 1
    # Kept count is approximated from the latest run's per-source 'X articles
    # in window' line in auto.log — the precise per-source kept breakdown
    # isn't currently logged, so we use article-window count as the upper
    # bound and subtract drops to estimate kept.
    fetched = Counter()
    if LOG.exists():
        text = LOG.read_text(encoding="utf-8", errors="replace")
        blocks = list(re.finditer(
            r"=== run_once start \S+ ===(.*?)=== run_once done ===",
            text, re.DOTALL,
        ))
        # Use the most recent block.
        if blocks:
            block = blocks[-1].group(1)
            current = None
            for line in block.splitlines():
                m = re.match(r"\[\*\]\s+([^…]+?)…\s*$", line)
                if m:
                    current = m.group(1).strip()
                    continue
                m = re.match(r"\s*->\s+(\d+)\s+articles in window", line)
                if m and current:
                    fetched[current] += int(m.group(1))
    sources = sorted(set(fetched) | set(drops_by_src))
    rows = []
    for src in sources:
        kept = max(0, fetched.get(src, 0) - drops_by_src.get(src, 0))
        dropped = drops_by_src.get(src, 0)
        total = kept + dropped
        noise = (dropped / total) if total else 0.0
        rows.append({
            "source": src, "kept": kept, "dropped": dropped,
            "noise_ratio": noise, "total": total,
        })
    rows.sort(key=lambda r: r["total"], reverse=True)
    return rows[:12]


def _run_history(days: int = 14) -> list[dict]:
    """Per-day rollup of usage_log rows for the last N days. Returns
        [{"date": "YYYY-MM-DD", "runs": int, "errors": int, "cost_usd": float,
          "output_tokens": int}, ...]   (oldest first, fills empty days)."""
    rows = []
    if USAGE.exists():
        for line in USAGE.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                continue
    cutoff = _utcnow().timestamp() - (days * 86400)
    by_day = defaultdict(lambda: {"runs": 0, "errors": 0, "cost_usd": 0.0,
                                  "output_tokens": 0})
    for r in rows:
        ts = _parse_iso(r.get("ts"))
        if not ts or ts.timestamp() < cutoff:
            continue
        day = ts.strftime("%Y-%m-%d")
        agg = by_day[day]
        agg["runs"] += 1
        agg["errors"] += (r.get("totals") or {}).get("errors", 0) or 0
        agg["cost_usd"] += _row_cost_usd(r)
        agg["output_tokens"] += (r.get("totals") or {}).get("output_tokens", 0) or 0
    today = _utcnow().date()
    out = []
    for i in range(days - 1, -1, -1):
        d = today.fromordinal(today.toordinal() - i).strftime("%Y-%m-%d")
        agg = by_day.get(d) or {"runs": 0, "errors": 0, "cost_usd": 0.0,
                                "output_tokens": 0}
        out.append({"date": d, **agg, "cost_usd": round(agg["cost_usd"], 2)})
    return out


def _account_switches_today(usage_runs: list[dict]) -> int:
    """Count usage rows from today (UTC) where account_switched was true."""
    today = _utcnow().strftime("%Y-%m-%d")
    n = 0
    for r in usage_runs or []:
        if r.get("account_switched") and (r.get("ts") or "").startswith(today):
            n += 1
    return n


def _spend_summary(usage_runs: list[dict]) -> dict:
    """Aggregate USD spend over last 1d and 7d from usage_log rows."""
    now = _utcnow().timestamp()
    d1, d7 = now - 86400, now - (7 * 86400)
    s1 = s7 = 0.0
    for r in usage_runs or []:
        ts = _parse_iso(r.get("ts"))
        if not ts:
            continue
        c = _row_cost_usd(r)
        if ts.timestamp() >= d7:
            s7 += c
            if ts.timestamp() >= d1:
                s1 += c
    return {"d1": round(s1, 2), "d7": round(s7, 2)}


def render(stats: dict, drops: list[dict], today_count: int,
           tasks: list[dict] | None = None,
           usage_runs: list[dict] | None = None,
           lock: dict | None = None,
           git: dict | None = None,
           cache: dict | None = None,
           baseline: dict | None = None,
           kql_audit: dict | None = None,
           gaps: dict | None = None,
           source_roi: list[dict] | None = None,
           history: list[dict] | None = None) -> str:
    tasks = tasks or []
    usage_runs = usage_runs or []
    lock = lock or {}
    git = git or {}
    cache = cache or {}
    history = history or []
    source_roi = source_roi or []
    gaps = gaps or {"total_gaps": 0, "articles_with_gaps": 0, "by_technique": []}
    # Pre-compute per-row cost / cache-hit so JS doesn't need pricing tables.
    enriched_runs = []
    baseline_cost = (baseline or {}).get("cost_usd_median") or 0.0
    for r in usage_runs:
        rc = dict(r)
        rc["_cost_usd"] = _row_cost_usd(r)
        rc["_cache_hit"] = _cache_hit_rate(r.get("totals") or {})
        rc["_cost_over_baseline"] = (
            (rc["_cost_usd"] / baseline_cost) if baseline_cost else None
        )
        enriched_runs.append(rc)
    usage_json = json.dumps(enriched_runs, ensure_ascii=False).replace(
        "</", "<\\/")
    usage_count = len(usage_runs)
    spend = _spend_summary(usage_runs)
    acct_switches_today = _account_switches_today(usage_runs)

    # ---- Tile lambda (used by Workflows tab section 0 — kept for backcompat) ----
    tile = lambda v, l, extra="": (
        f'<div class="stat{extra}"><div class="v">{v}</div>'
        f'<div class="l">{l}</div></div>'
    )
    stats_html = "".join([
        tile(stats.get("articles_total") or "—", "Articles fetched"),
        tile(stats.get("articles_kept") or "—", "Kept (alert)"),
        tile(stats.get("articles_dropped") or "—", "Dropped (relevance)"),
        tile(stats.get("marketing_dropped") or 0, "Dropped (marketing)"),
        tile(today_count, "Articles today"),
        tile(stats.get("started") or "—", "Last run"),
    ])

    breaker_note = (
        '<div class="warn">OAuth circuit breaker tripped during the last '
        'run — LLM UC generation was short-circuited for some articles. '
        'Pipeline still completed; template UCs filled in.</div>'
        if stats.get("breaker_tripped") else ""
    )

    drops_html = ""
    for d in drops:
        drops_html += (
            f'<tr><td class="muted">{_escape(d.get("tier",""))}</td>'
            f'<td class="muted">{_escape((d.get("reason") or "")[:60])}</td>'
            f'<td>{_escape(d.get("title",""))[:120]}</td>'
            f'<td class="muted">{_escape(d.get("source",""))}</td></tr>'
        )

    dd = stats.get("dedupe") or {}

    # ---- Tier breakdown as horizontal bars (replaces comma list) ----
    tier_html = ""
    tier_raw = stats.get("tier_breakdown") or ""
    if tier_raw:
        parts = []
        for chunk in tier_raw.split(","):
            chunk = chunk.strip()
            m = re.match(r"(.+?):\s*(\d+)", chunk)
            if m:
                parts.append((m.group(1).strip(), int(m.group(2))))
        tot = sum(n for _, n in parts) or 1
        tier_html = '<div class="bar-h-list">'
        for name, n in parts:
            pct = (n / tot) * 100
            tier_html += (
                f'<div class="bar-h"><span class="name">{_escape(name)}</span>'
                f'<span class="track"><span class="fill" style="width:{pct:.1f}%"></span></span>'
                f'<span class="count">{n:,} <span style="color:var(--muted-2)">({pct:.0f}%)</span></span></div>'
            )
        tier_html += '</div>'
    else:
        tier_html = '<p class="sub">—</p>'

    # ---- Top dropped sources as bars (replaces comma list) ----
    top_html = ""
    top_raw = stats.get("top_drop_sources") or ""
    if top_raw:
        parts = []
        for chunk in top_raw.split(","):
            chunk = chunk.strip()
            m = re.match(r"(.+?):\s*(\d+)", chunk)
            if m:
                parts.append((m.group(1).strip(), int(m.group(2))))
        max_n = max((n for _, n in parts), default=1) or 1
        top_html = '<div class="bar-h-list">'
        for name, n in parts[:10]:
            pct = (n / max_n) * 100
            top_html += (
                f'<div class="bar-h"><span class="name">{_escape(name)}</span>'
                f'<span class="track"><span class="fill dropped" style="width:{pct:.1f}%"></span></span>'
                f'<span class="count">{n:,}</span></div>'
            )
        top_html += '</div>'
    else:
        top_html = '<p class="sub">—</p>'

    # ---- Vital-signs strip ----
    pipe_dot, pipe_text = "idle", "IDLE"
    if lock.get("running"):
        age = _fmt_age(lock.get("age_seconds"))
        pipe_dot = "ok"
        pipe_text = f'<strong>RUNNING</strong> · PID {lock.get("pid")} · {age}'
    elif lock.get("pid"):
        pipe_dot = "warn"
        pipe_text = (f'<strong>STALE LOCK</strong> · PID {lock.get("pid")} '
                     f'(not alive)')
    elif history:
        last_run_day = next((h for h in reversed(history) if h["runs"]), None)
        if last_run_day:
            pipe_text = f'IDLE · last run {last_run_day["date"]}'

    push_age = git.get("age_seconds")
    if push_age is None:
        push_dot, push_text = "idle", "no git"
    elif push_age < 7200:
        push_dot, push_text = "ok", f'<strong>{_fmt_age(push_age)} ago</strong>'
    elif push_age < 86400:
        push_dot, push_text = "warn", f'<strong>{_fmt_age(push_age)} ago</strong>'
    else:
        push_dot, push_text = "bad", f'<strong>{_fmt_age(push_age)} ago</strong>'

    cache_bytes = cache.get("bytes") or 0
    cache_dot = ("warn" if cache_bytes > 500 * 1024 * 1024
                 else "ok" if cache_bytes else "idle")

    acct_dot = "warn" if acct_switches_today else "ok"
    acct_text = (f'primary · <strong>{acct_switches_today} failover{"s" if acct_switches_today != 1 else ""} today</strong>'
                 if acct_switches_today
                 else 'primary · 0 switches today')

    vital_html = (
        '<div class="vital-bar">'
        f'<div class="vs"><span class="dot {pipe_dot}"></span>'
        f'<span class="label">pipeline</span> {pipe_text}</div>'
        f'<div class="vs"><span class="dot {push_dot}"></span>'
        f'<span class="label">last push</span> {push_text}</div>'
        f'<div class="vs"><span class="label">spend</span> '
        f'<strong>{_fmt_usd(spend["d7"])}</strong> / 7d '
        f'<span style="color:var(--muted-2)">({_fmt_usd(spend["d1"])} today)</span></div>'
        f'<div class="vs"><span class="dot {cache_dot}"></span>'
        f'<span class="label">cache</span> <strong>{_fmt_bytes(cache_bytes)}</strong>'
        f' · {cache.get("files", 0):,} files</div>'
        f'<div class="vs"><span class="dot {acct_dot}"></span>'
        f'<span class="label">account</span> {acct_text}</div>'
        '</div>'
    )

    # Live scheduled-task table
    if tasks:
        tasks_html = "".join(
            f'<tr><td><code>{_escape(t.get("Name",""))}</code></td>'
            f'<td class="muted">{_escape(t.get("State",""))}</td>'
            f'<td>{_escape(t.get("Cadence",""))}</td>'
            f'<td class="muted">{_escape(str(t.get("LastRun","") or "")[:19])}</td>'
            f'<td class="muted">{_escape(str(t.get("NextRun","") or "")[:19])}</td>'
            f'<td class="muted">{_escape(t.get("LastResult",""))}</td></tr>'
            for t in tasks
        )
    else:
        tasks_html = (
            '<tr><td colspan="6" class="muted">No scheduled tasks discovered '
            '(non-Windows host, or schtasks unavailable). Static description '
            'still applies above.</td></tr>'
        )

    # ---- Overview tab content ----
    # Aggregate 7-day rollup from history for KPI tiles.
    runs_7d = sum(h["runs"] for h in history)
    errors_7d = sum(h["errors"] for h in history)
    output_7d = sum(h["output_tokens"] for h in history)
    last_clean_run = next((r for r in enriched_runs), None)  # newest-first
    last_run_html = '<p class="sub">No completed runs in usage log yet.</p>'
    if last_clean_run:
        lr = last_clean_run
        lr_totals = lr.get("totals") or {}
        lr_hit = _cache_hit_rate(lr_totals)
        lr_cost = lr.get("_cost_usd", 0.0)
        lr_baseline = lr.get("_cost_over_baseline")
        baseline_note = (
            f' · <span style="color:var(--muted-2)">{lr_baseline:.1f}× baseline</span>'
            if lr_baseline else ""
        )
        failover_chip = (' · <span class="chip failover">FAILOVER</span>'
                         if lr.get("account_switched") else "")
        last_run_html = (
            '<div class="last-run-card">'
            '<h3>Last completed run</h3>'
            '<div class="rows">'
            f'<div class="k">when</div><div class="v">{_escape(lr.get("ts",""))}</div>'
            f'<div class="k">script</div><div class="v">{_escape(lr.get("script","?"))}</div>'
            f'<div class="k">wall</div><div class="v">{int(lr.get("wall_seconds_total",0))} s</div>'
            f'<div class="k">calls</div><div class="v">{lr_totals.get("calls",0):,} '
            f'({lr_totals.get("errors",0)} errors)</div>'
            f'<div class="k">tokens out</div><div class="v">{lr_totals.get("output_tokens",0):,}</div>'
            f'<div class="k">cost</div><div class="v">{_fmt_usd(lr_cost)}{baseline_note}</div>'
            f'<div class="k">cache hit</div><div class="v">{lr_hit*100:.1f}%</div>'
            f'<div class="k">account</div>'
            f'<div class="v">{_escape(lr.get("active_at_end","?"))}{failover_chip}</div>'
            '</div></div>'
        )

    # 14-day activity sparkline
    max_runs = max((h["runs"] for h in history), default=0) or 1
    spark_html = '<div class="spark14">'
    label_html = '<div class="spark14-labels">'
    for h in history:
        bar_h = max(2, int((h["runs"] / max_runs) * 56)) if h["runs"] else 2
        tone = ("bad" if h["errors"] >= 3
                else "warn" if h["errors"] >= 1
                else "empty" if h["runs"] == 0
                else "")
        title = (f'{h["date"]} · {h["runs"]} runs · {h["errors"]} errors · '
                 f'{_fmt_usd(h["cost_usd"])}')
        spark_html += (f'<div class="col" title="{title}">'
                       f'<div class="bar {tone}" style="height:{bar_h}px"></div>'
                       f'</div>')
        label_html += f'<div class="col">{h["date"][-5:]}</div>'
    spark_html += '</div>'
    label_html += '</div>'

    # Overview KPI tiles
    overview_tiles = "".join([
        tile(stats.get("articles_total") or "—", "Articles fetched (last run)"),
        tile(stats.get("articles_kept") or "—", "Kept (alert)"),
        tile(stats.get("articles_dropped") or "—", "Dropped"),
        tile(today_count, "Articles today"),
        tile(f"{runs_7d}", "Runs (7d)"),
        tile(f"{errors_7d}",
             "Errors (7d)",
             extra=" tone-warn" if errors_7d else ""),
        tile(_fmt_usd(spend["d7"]), "Spend (7d)"),
        tile(f"{int(_cache_hit_rate({'cache_read': sum(((r.get('totals') or {}).get('cache_read') or 0) for r in usage_runs[:50]), 'input_tokens': sum(((r.get('totals') or {}).get('input_tokens') or 0) for r in usage_runs[:50])})*100)}%",
             "Cache hit (50-run avg)"),
    ])

    # ---- Quality tab content ----
    # KQL audit gauge
    if kql_audit and kql_audit.get("total_ucs"):
        ka = kql_audit
        pct = ka["pct_clean"] * 100
        tone = ("ok" if pct >= 90 else "warn" if pct >= 70 else "bad")
        gauge_class = "" if tone == "ok" else f' {tone}'
        # SVG circle math: r=58, c=2*pi*r ≈ 364.4
        circ = 364.4
        offset = circ * (1 - ka["pct_clean"])
        kql_html = (
            '<div class="gauge-wrap">'
            f'<div class="gauge{gauge_class}">'
            f'<svg width="140" height="140" viewBox="0 0 140 140">'
            f'<circle class="ring-bg" cx="70" cy="70" r="58"/>'
            f'<circle class="ring-fg" cx="70" cy="70" r="58" '
            f'stroke-dasharray="{circ:.1f}" stroke-dashoffset="{offset:.1f}"/>'
            f'</svg>'
            f'<div class="label"><div class="pct">{pct:.1f}%</div>'
            f'<div class="sub">clean</div></div>'
            '</div>'
            '<div style="flex:1; min-width:200px;">'
            f'<div style="font-size:14px; color:var(--text);">'
            f'<strong>{ka["n_clean"]:,}</strong> of <strong>{ka["total_ucs"]:,}</strong> '
            f'use cases parse cleanly against the live KQL schemas '
            f'(Microsoft Defender + Sentinel).</div>'
            f'<div style="margin-top:10px; font-size:12.5px; color:var(--muted);">'
            f'<span class="chip {("ok" if ka["n_syntax_issues"] == 0 else "crit")}">'
            f'{ka["n_syntax_issues"]:,} syntax</span> '
            f'<span class="chip {("ok" if ka["n_schema_issues"] == 0 else "muted")}">'
            f'{ka["n_schema_issues"]:,} schema</span> '
            f'<span class="chip muted">{ka["n_both"]:,} both</span></div>'
            '</div></div>'
        )
        if ka["top_syntax_messages"]:
            max_n = max(n for _, n in ka["top_syntax_messages"]) or 1
            kql_html += '<h3 style="margin:18px 0 8px; font-size:14px;">Top syntax error messages</h3><div class="bar-h-list">'
            for msg, n in ka["top_syntax_messages"]:
                pct_w = (n / max_n) * 100
                kql_html += (
                    f'<div class="bar-h"><span class="name" title="{_escape(msg)}">{_escape(msg[:60])}</span>'
                    f'<span class="track"><span class="fill bad" style="width:{pct_w:.1f}%"></span></span>'
                    f'<span class="count">{n:,}</span></div>'
                )
            kql_html += '</div>'
    else:
        kql_html = '<p class="sub">No KQL audit data (run <code>py kql_check.py --all</code> to generate <code>kql_audit.json</code>).</p>'

    # Detection-gap aggregation
    if gaps["by_technique"]:
        max_g = max(g["count"] for g in gaps["by_technique"]) or 1
        gaps_html = (
            f'<p class="sub"><strong>{gaps["total_gaps"]:,}</strong> detection-gap '
            f'rows logged across <strong>{gaps["articles_with_gaps"]:,}</strong> '
            f'distinct articles (30-day window). Top techniques the quality '
            f'reviewer flagged as missing coverage:</p>'
            '<div class="bar-h-list">'
        )
        for g in gaps["by_technique"]:
            pct_w = (g["count"] / max_g) * 100
            label = f'{g["id"]}'
            if g.get("name"):
                label += f' · {g["name"]}'
            gaps_html += (
                f'<div class="bar-h"><span class="name" title="{_escape(label)}">'
                f'{_escape(label[:48])}</span>'
                f'<span class="track"><span class="fill warn" style="width:{pct_w:.1f}%"></span></span>'
                f'<span class="count">{g["count"]:,}</span></div>'
            )
        gaps_html += '</div>'
    elif gaps["total_gaps"]:
        gaps_html = (
            f'<p class="sub"><strong>{gaps["total_gaps"]:,}</strong> '
            f'quality-suggestion rows logged in the last 30 days, but none '
            f'name a specific MITRE technique. Inspect '
            f'<code>intel/quality_suggestions.jsonl</code> directly.</p>'
        )
    else:
        gaps_html = '<p class="sub">No quality-review suggestions logged yet (the reviewer pass writes to <code>intel/quality_suggestions.jsonl</code>).</p>'

    # Source ROI stacked bars
    if source_roi:
        roi_html = (
            '<p class="sub">Per-source kept vs. dropped article counts over the '
            'last 7 days. Green = kept (alert), grey = dropped (low relevance / '
            'marketing / dedup). Sorted by total volume.</p>'
            '<div class="bar-h-list">'
        )
        max_t = max(r["total"] for r in source_roi) or 1
        for r in source_roi:
            kept_pct = (r["kept"] / max_t) * 100
            drop_pct = (r["dropped"] / max_t) * 100
            roi_html += (
                f'<div class="bar-h"><span class="name">{_escape(r["source"])}</span>'
                f'<span class="track">'
                f'<span class="fill kept" style="width:{kept_pct:.1f}%"></span>'
                f'<span class="fill dropped" style="width:{drop_pct:.1f}%"></span>'
                f'</span>'
                f'<span class="count">{r["kept"]:,} / {r["dropped"]:,}'
                f' <span style="color:var(--muted-2)">({int(r["noise_ratio"]*100)}% noise)</span></span></div>'
            )
        roi_html += '</div>'
    else:
        roi_html = '<p class="sub">No source ROI data yet (needs at least one completed run).</p>'

    # Git status footer note for overview
    git_subject = _escape((git.get("subject") or "")[:80])
    git_age = _fmt_age(git.get("age_seconds"))
    git_ahead = git.get("ahead", 0)
    git_note = (
        f'<span class="ref">Last commit on <code>main</code>: '
        f'<strong>{git_age} ago</strong> — “{git_subject}”'
        + (f' · <span style="color:var(--warn)">{git_ahead} local commit(s) unpushed</span>'
           if git_ahead else '')
        + '</span>'
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Clankerusecase Pipeline — Internal Docs</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<script type="module">
  import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs';
  mermaid.initialize({{
    startOnLoad: true,
    theme: 'dark',
    securityLevel: 'loose',
    themeVariables: {{
      darkMode: true,
      primaryColor: '#1a1f29',
      primaryTextColor: '#e7e7eb',
      primaryBorderColor: '#3a4150',
      lineColor: '#7170ff',
      secondaryColor: '#222933',
      tertiaryColor: '#14171c'
    }}
  }});
</script>
<style>
  :root{{
    --bg:#08090a; --panel:#14171c; --panel-elev:#1a1f29;
    --border:#2a2f37; --border-2:#3a4150;
    --text:#e7e7eb; --muted:#9ba0aa; --muted-2:#6c7280;
    --accent:#7170ff; --accent-2:#ffaa5a; --good:#5fd4a3; --warn:#f0b85c; --bad:#eb5757;
    --mono:'SF Mono',Consolas,monospace;
  }}
  *{{box-sizing:border-box;}}
  body{{
    background:var(--bg); color:var(--text);
    font-family:system-ui,-apple-system,sans-serif;
    max-width:1200px; margin:0 auto; padding:32px 24px;
    line-height:1.6;
  }}
  h1{{font-size:32px; margin:0 0 8px; letter-spacing:-0.02em;}}
  .lede{{color:var(--muted); margin:0 0 32px; max-width:780px;}}
  h2{{font-size:22px; margin:0 0 8px; letter-spacing:-0.01em;}}
  h2 .num{{
    display:inline-block; width:32px; height:32px; border-radius:50%;
    background:var(--accent); color:#fff; text-align:center; line-height:32px;
    font-size:14px; font-weight:700; margin-right:10px; vertical-align:middle;
  }}
  section{{
    border:1px solid var(--border); border-radius:14px;
    padding:28px 28px 22px; margin-bottom:24px; background:var(--panel);
  }}
  .sub{{color:var(--muted); margin:0 0 18px; font-size:14px;}}
  code{{
    background:rgba(113,112,255,0.10); padding:1px 6px; border-radius:4px;
    font-family:var(--mono); font-size:0.92em; color:var(--accent-2);
  }}
  .ref{{
    font-size:11px; color:var(--muted-2); font-family:var(--mono);
    margin-top:6px; display:inline-block;
  }}
  .stats{{display:flex; gap:14px; flex-wrap:wrap; margin-bottom:14px;}}
  .stat{{
    padding:14px 18px; background:var(--panel-elev);
    border:1px solid var(--border); border-radius:10px; min-width:140px;
  }}
  .stat .v{{font-size:22px; font-weight:700; color:var(--text);
           font-variant-numeric:tabular-nums;}}
  .stat .l{{font-size:10.5px; color:var(--muted); text-transform:uppercase;
           letter-spacing:0.08em; margin-top:2px;}}
  .mermaid{{
    background:#0e1117; border:1px solid var(--border);
    border-radius:10px; padding:18px; margin:14px 0;
    text-align:center;
  }}
  table{{width:100%; border-collapse:collapse; font-size:13px; margin-top:10px;}}
  th,td{{padding:7px 10px; border-bottom:1px solid var(--border);
        text-align:left; vertical-align:top;}}
  th{{color:var(--muted); font-weight:600; font-size:11px;
     text-transform:uppercase; letter-spacing:0.05em;}}
  td.muted{{color:var(--muted); font-family:var(--mono); font-size:11.5px;}}
  .warn{{
    background:rgba(240,184,92,0.10); border:1px solid rgba(240,184,92,0.30);
    color:var(--warn); padding:12px 14px; border-radius:8px; margin:12px 0;
    font-size:13.5px;
  }}
  .pillbar{{display:flex; gap:8px; flex-wrap:wrap; margin-bottom:14px;}}
  .pill{{
    background:rgba(113,112,255,0.10); color:var(--accent);
    padding:3px 10px; border-radius:99px; font-size:12px;
    border:1px solid rgba(113,112,255,0.25);
  }}
  .pill.warn{{background:rgba(240,184,92,0.10); color:var(--warn);
              border-color:rgba(240,184,92,0.30);}}
  .pill.good{{background:rgba(95,212,163,0.10); color:var(--good);
              border-color:rgba(95,212,163,0.30);}}
  .grid2{{display:grid; grid-template-columns:1fr 1fr; gap:16px;}}
  @media(max-width:780px){{.grid2{{grid-template-columns:1fr;}}}}
  .footer{{
    color:var(--muted-2); font-size:12px; margin-top:32px;
    padding-top:18px; border-top:1px solid var(--border); text-align:center;
  }}

  /* Tab navigation */
  .tabs{{
    display:flex; gap:4px; border-bottom:1px solid var(--border);
    margin-bottom:24px; padding-bottom:0;
  }}
  .tab-btn{{
    background:transparent; color:var(--muted); border:none;
    padding:10px 18px; font-size:14px; font-weight:600; cursor:pointer;
    border-bottom:2px solid transparent; margin-bottom:-1px;
    transition:color .12s, border-color .12s;
    font-family:inherit;
  }}
  .tab-btn:hover{{color:var(--text);}}
  .tab-btn.active{{
    color:var(--accent); border-bottom-color:var(--accent);
  }}
  .tab-pane{{display:none;}}
  .tab-pane.active{{display:block;}}

  /* Usage dashboard */
  .usage-controls{{
    display:flex; gap:10px; align-items:center; margin:8px 0 16px;
    flex-wrap:wrap;
  }}
  .usage-controls label{{
    font-size:12px; color:var(--muted); display:flex; gap:6px; align-items:center;
  }}
  .usage-controls select, .usage-controls input{{
    background:var(--panel-elev); color:var(--text); border:1px solid var(--border);
    border-radius:6px; padding:4px 8px; font-size:12px; font-family:inherit;
  }}
  .usage-table{{font-size:12px;}}
  .usage-table th{{cursor:pointer; user-select:none;}}
  .usage-table th:hover{{color:var(--text);}}
  .usage-table th.sorted::after{{content:" ▼"; color:var(--accent); font-size:9px;}}
  .usage-table th.sorted.asc::after{{content:" ▲";}}
  .usage-table tbody tr{{cursor:pointer;}}
  .usage-table tbody tr:hover{{background:rgba(113,112,255,0.06);}}
  .usage-table tr.expanded{{background:rgba(113,112,255,0.10);}}
  .usage-table td.num{{text-align:right; font-variant-numeric:tabular-nums;}}
  .usage-table td.center{{text-align:center;}}
  .usage-bykind{{
    background:var(--panel-elev); padding:14px 18px; border-radius:8px;
    margin:6px 0 14px; font-size:12px;
  }}
  .usage-bykind table{{margin-top:6px; font-size:11.5px;}}
  .usage-bykind td.num{{text-align:right; font-variant-numeric:tabular-nums;}}
  .badge-y{{color:var(--warn); font-weight:700;}}
  .badge-n{{color:var(--muted-2);}}
  .spark{{display:inline-block; vertical-align:middle; margin-left:8px;}}
  .empty-state{{
    color:var(--muted); padding:32px; text-align:center;
    background:var(--panel-elev); border-radius:10px;
    border:1px dashed var(--border-2);
  }}

  /* ===== Vital-signs strip (sticky top header) ===== */
  .vital-bar{{
    display:flex; gap:18px; flex-wrap:wrap; padding:10px 16px;
    background:var(--panel); border:1px solid var(--border);
    border-radius:10px; font-size:12.5px; margin:0 0 22px;
    align-items:center;
  }}
  .vital-bar .vs{{display:flex; align-items:center; gap:8px;
                  font-family:var(--mono); color:var(--muted);}}
  .vital-bar .vs strong{{color:var(--text); font-weight:600;}}
  .vital-bar .vs .label{{color:var(--muted-2); font-size:11px;
                          text-transform:uppercase; letter-spacing:0.06em;}}
  .vital-bar .vs + .vs{{padding-left:18px; border-left:1px solid var(--border);}}
  .dot{{display:inline-block; width:9px; height:9px; border-radius:50%;
        flex-shrink:0;}}
  .dot.ok{{background:var(--good); box-shadow:0 0 8px rgba(95,212,163,.55);}}
  .dot.warn{{background:var(--warn); box-shadow:0 0 8px rgba(240,184,92,.55);}}
  .dot.bad{{background:var(--bad); box-shadow:0 0 8px rgba(235,87,87,.55);}}
  .dot.idle{{background:var(--muted-2);}}

  /* ===== Overview tab ===== */
  .stat-grid{{
    display:grid; grid-template-columns:repeat(auto-fit, minmax(150px, 1fr));
    gap:12px; margin-bottom:18px;
  }}
  .stat-grid .stat{{min-width:0; padding:12px 14px;}}
  .stat .v.small{{font-size:18px;}}
  .stat .delta{{font-size:10.5px; color:var(--muted-2);
                font-variant-numeric:tabular-nums; margin-top:2px;}}
  .stat .delta.up{{color:var(--bad);}}
  .stat .delta.down{{color:var(--good);}}
  .stat.tone-good{{border-color:rgba(95,212,163,0.35);}}
  .stat.tone-warn{{border-color:rgba(240,184,92,0.35);}}
  .stat.tone-bad{{border-color:rgba(235,87,87,0.35);}}
  .last-run-card{{
    background:var(--panel-elev); border:1px solid var(--border);
    border-radius:10px; padding:16px 18px;
  }}
  .last-run-card h3{{margin:0 0 10px; font-size:14px; color:var(--text);}}
  .last-run-card .rows{{display:grid; grid-template-columns:max-content 1fr;
                        gap:4px 12px; font-size:12px;}}
  .last-run-card .k{{color:var(--muted); text-transform:uppercase;
                     letter-spacing:0.06em; font-size:10.5px;}}
  .last-run-card .v{{font-family:var(--mono); color:var(--text);}}

  /* 14-day sparkline */
  .spark14{{
    display:flex; align-items:flex-end; gap:3px; height:64px;
    padding:8px 6px; background:var(--panel-elev);
    border:1px solid var(--border); border-radius:8px;
  }}
  .spark14 .col{{flex:1; display:flex; flex-direction:column;
                 align-items:center; justify-content:flex-end; min-width:0;}}
  .spark14 .bar{{width:100%; max-width:34px; background:var(--good);
                 border-radius:2px 2px 0 0; min-height:2px;
                 transition:opacity .15s;}}
  .spark14 .bar.warn{{background:var(--warn);}}
  .spark14 .bar.bad{{background:var(--bad);}}
  .spark14 .bar.empty{{background:var(--border); height:2px;}}
  .spark14 .bar:hover{{opacity:0.7;}}
  .spark14-labels{{display:flex; gap:3px; padding:4px 6px 0;
                   font-size:9.5px; color:var(--muted-2); font-family:var(--mono);}}
  .spark14-labels .col{{flex:1; text-align:center; min-width:0;
                        overflow:hidden; text-overflow:ellipsis;}}

  /* Horizontal bar (tier breakdown, top sources, source ROI, gaps) */
  .bar-h-list{{display:flex; flex-direction:column; gap:6px; margin:10px 0;}}
  .bar-h{{display:flex; align-items:center; gap:10px; font-size:12px;
         font-family:var(--mono);}}
  .bar-h .name{{flex:0 0 180px; color:var(--text); white-space:nowrap;
                overflow:hidden; text-overflow:ellipsis;}}
  .bar-h .track{{flex:1; height:14px; background:var(--panel-elev);
                 border-radius:7px; overflow:hidden; display:flex;
                 border:1px solid var(--border);}}
  .bar-h .fill{{height:100%; background:var(--accent);}}
  .bar-h .fill.kept{{background:var(--good);}}
  .bar-h .fill.dropped{{background:var(--muted-2);}}
  .bar-h .fill.warn{{background:var(--warn);}}
  .bar-h .fill.bad{{background:var(--bad);}}
  .bar-h .count{{flex:0 0 80px; text-align:right; color:var(--muted);
                 font-variant-numeric:tabular-nums;}}
  @media(max-width:780px){{
    .bar-h .name{{flex-basis:120px;}}
    .bar-h .count{{flex-basis:60px; font-size:11px;}}
  }}

  /* Donut gauge (KQL audit) */
  .gauge-wrap{{display:flex; gap:24px; align-items:center; flex-wrap:wrap;}}
  .gauge{{position:relative; width:140px; height:140px; flex-shrink:0;}}
  .gauge svg{{transform:rotate(-90deg); display:block;}}
  .gauge .ring-bg{{fill:none; stroke:var(--panel-elev); stroke-width:14;}}
  .gauge .ring-fg{{fill:none; stroke:var(--good); stroke-width:14;
                   stroke-linecap:round;}}
  .gauge .label{{position:absolute; inset:0; display:flex;
                 flex-direction:column; align-items:center;
                 justify-content:center; font-family:var(--mono);}}
  .gauge .pct{{font-size:26px; font-weight:700; color:var(--text);}}
  .gauge .sub{{font-size:10.5px; color:var(--muted); text-transform:uppercase;
               letter-spacing:0.07em; margin:0;}}
  .gauge.warn .ring-fg{{stroke:var(--warn);}}
  .gauge.bad  .ring-fg{{stroke:var(--bad);}}

  /* Chips for inline status */
  .chip{{display:inline-block; padding:2px 8px; border-radius:99px;
         font-size:10px; font-weight:700; letter-spacing:0.05em;
         text-transform:uppercase; font-family:var(--mono);}}
  .chip.failover{{background:rgba(240,184,92,0.18); color:var(--warn);}}
  .chip.crit{{background:rgba(235,87,87,0.18); color:var(--bad);}}
  .chip.ok{{background:rgba(95,212,163,0.15); color:var(--good);}}
  .chip.muted{{background:var(--panel-elev); color:var(--muted-2);}}

  /* New right-aligned cells for the enhanced usage table */
  .usage-table td.cost{{font-variant-numeric:tabular-nums; text-align:right;}}
  .usage-table td.cost.over{{color:var(--bad); font-weight:600;}}
  .usage-table td.cost.under{{color:var(--good);}}
  .usage-table td.hit{{text-align:right; font-variant-numeric:tabular-nums;}}
  .usage-table td.hit.warn{{color:var(--warn);}}

  /* Sub-header inside tab panes */
  .pane-h{{margin:0 0 18px; padding-bottom:8px;
          border-bottom:1px solid var(--border);
          display:flex; justify-content:space-between; align-items:baseline;}}
  .pane-h h2{{margin:0; font-size:18px;}}
  .pane-h .meta{{font-size:11px; color:var(--muted-2); font-family:var(--mono);}}
</style>
</head>
<body>

<h1>Clankerusecase Pipeline — Operator Console</h1>
<p class="lede">Live operational view of the threat-intel pipeline feeding
<code>clankerusecase.com</code>. Top strip = vital signs. Tabs below cover
health (<em>Overview</em>), per-run accounting (<em>Usage</em>),
output-quality audits (<em>Quality</em>), and reference flow diagrams
(<em>Workflows</em>). Page is regenerated on every wrapper run; refresh to update.</p>

{vital_html}

<div class="tabs" role="tablist">
  <button class="tab-btn active" data-tab="overview" role="tab">Overview</button>
  <button class="tab-btn" data-tab="usage" role="tab">Usage <span style="opacity:.5; font-weight:400;">({usage_count} runs)</span></button>
  <button class="tab-btn" data-tab="quality" role="tab">Quality</button>
  <button class="tab-btn" data-tab="workflows" role="tab">Workflows</button>
</div>

<!-- ===== OVERVIEW TAB ===== -->
<div class="tab-pane active" id="tab-overview" role="tabpanel">
<section>
  <div class="pane-h">
    <h2>At a glance</h2>
    <span class="meta">last run: {_escape(stats.get("started") or "—")}</span>
  </div>
  <div class="stat-grid">{overview_tiles}</div>
  {breaker_note}
  <div class="grid2" style="margin-top:8px;">
    <div>{last_run_html}</div>
    <div>
      <h3 style="margin:0 0 8px; font-size:14px;">Scheduled tasks</h3>
      <table>
        <thead><tr><th>Task</th><th>State</th><th>Cadence</th>
          <th>Last run</th><th>Next run</th><th>Result</th></tr></thead>
        <tbody>{tasks_html}</tbody>
      </table>
    </div>
  </div>
  <h3 style="margin:22px 0 6px; font-size:14px;">14-day activity</h3>
  <p class="sub" style="margin:0 0 8px;">Bar height = runs that day (any wrapper script).
  Green = no errors, amber = 1-2, red = 3+. Empty bars are days with no runs at all.</p>
  {spark_html}
  {label_html}
  <div style="margin-top:18px;">{git_note}</div>
</section>
</div><!-- /tab-overview -->

<!-- ===== WORKFLOWS TAB (existing content) ===== -->
<div class="tab-pane" id="tab-workflows" role="tabpanel">

<section>
  <h2><span class="num">0</span>Latest run</h2>
  <div class="stat-grid">{stats_html}</div>
  <div class="grid2" style="margin-top:14px;">
    <div>
      <h3 style="margin:0 0 8px; font-size:13px; color:var(--muted);
                  text-transform:uppercase; letter-spacing:0.06em;">Relevance tier breakdown</h3>
      {tier_html}
    </div>
    <div>
      <h3 style="margin:0 0 8px; font-size:13px; color:var(--muted);
                  text-transform:uppercase; letter-spacing:0.06em;">Top dropped sources</h3>
      {top_html}
    </div>
  </div>
  <p class="sub" style="margin-top:14px;">
    Dedupe merges: <strong>{dd.get("by_title", "—")}</strong> by title-Jaccard,
    <strong>{dd.get("by_canonical", "—")}</strong> by canonical-ID
    (CVE / GHSA / @scope/pkg / named campaign).
  </p>
</section>

<section>
  <h2><span class="num">1</span>Overall data flow</h2>
  <p class="sub">RSS → fetch → filter → dedupe → relevance gate → LLM UC →
  render → git push. Each step gets its own section below.</p>
  <div class="mermaid">
flowchart TB
  A[RSS / KEV / GHSA<br/>15 sources] --> B[fetch_articles]
  B --> C{{is_marketing_post?}}
  C -- yes --> X1[drop at fetch]
  C -- no --> D[dedupe by title-Jaccard<br/>+ canonical-ID merge<br/>±4h window]
  D --> E[main loop: for each article]
  E --> F[extract_indicators<br/>extract_threat_actors]
  F --> G{{classify_relevance<br/>Tier 0 / 1 / 2}}
  G -- drop --> X2[skip render<br/>log to relevance_drops.jsonl]
  G -- alert --> H[bespoke UC<br/>_llm_generate_ucs<br/>OAuth → cache → API key]
  H --> I[render_card → cards list]
  I --> J[write_briefings<br/>+ delete stale]
  J --> K[index.html<br/>+ share / actor / target pages]
  K --> L[git commit + push<br/>GitHub Pages publishes]
  </div>
  <span class="ref">main() at generate.py:14261</span>
</section>

<section>
  <h2><span class="num">2</span>Sources & fetch boundary</h2>
  <p class="sub">15 feeds: 12 RSS, 1 CISA KEV (JSON), 1 GHSA (REST API,
  Critical-only), 1 disabled placeholder. Marketing-post titles are
  dropped here so they never even cache.</p>
  <div class="mermaid">
flowchart LR
  subgraph rss[RSS feeds]
    a1[The Hacker News]
    a2[BleepingComputer]
    a3[Microsoft Security Blog]
    a4[Cisco Talos]
    a5[Securelist]
    a6[SentinelLabs]
    a7[Unit 42]
    a8[ESET WeLiveSecurity]
    a9[Lab52]
    a10[Cyber Security News]
    a11[Snyk]
    a12[Aikido]
    a13[StepSecurity]
  end
  subgraph other[Other]
    b1[CISA KEV<br/>JSON feed]
    b2[GitHub Security Advisories<br/>REST API, Critical only]
  end
  rss --> M
  other --> M
  M[_fetch_rss / _fetch_kev / _fetch_ghsa] --> N{{_is_marketing_post?}}
  N -- match --> X[drop: webinar / introducing / partners with]
  N -- pass --> O[raw articles]
  </div>
  <span class="ref">SOURCES at generate.py:44 · _is_marketing_post at 13842 ·
  _fetch_ghsa at 13577 (Critical-only via <code>severity=critical</code> in URL)</span>
</section>

<section>
  <h2><span class="num">3</span>Same-incident dedupe</h2>
  <p class="sub">Articles from different vendors covering the same incident
  merge into one card. Two signals: title-token Jaccard (≥0.55) <em>and</em>
  shared canonical IDs (CVE, GHSA, <code>@scope/pkg</code>, named campaigns
  like <code>shai-hulud</code> / <code>teampcp</code>). Both gated by a
  ±4 hour publish-window so a 2025 campaign article doesn't backdate
  today's coverage.</p>
  <div class="grid2">
    <div class="mermaid">
flowchart TB
  R[raw article] --> T[_title_tokens]
  R --> C[_canonical_ids:<br/>CVEs · GHSAs · @scope/pkg<br/>· named campaigns<br/>· proj:&lt;name&gt; bridge]
  T --> M{{Jaccard ≥ 0.55<br/>AND ±4h?}}
  C --> N{{shared ID<br/>AND ±4h?}}
  M -- yes --> P[merge into existing]
  N -- yes --> P
  M -- no --> Q[new card]
  N -- no --> Q
  P --> S[prefer LATEST date]
    </div>
    <div class="mermaid">
flowchart LR
  X[5 cards 2026-05-12:<br/>· 84 TanStack npm Packages Hacked<br/>· Mini Shai-Hulud Worm Compromises…<br/>· Shai-Hulud Attack Ships Signed…<br/>· GHSA CVE-2026-45321<br/>· TeamPCP Compromises Checkmarx Jenkins]
  X --> Y[1 merged card<br/>via shared <code>proj:tanstack</code><br/>and <code>shai-hulud</code> tags]
  Y --> Z[sources: Aikido, BleepingComputer,<br/>Cyber Security News, GHSA, Snyk]
    </div>
  </div>
  <span class="ref">_looks_same_story at generate.py:13800 · _canonical_ids at 13758
  · 4-hour MERGE_WINDOW inside fetch_articles at 14172</span>
</section>

<section>
  <h2><span class="num">4</span>Relevance classifier — three tiers</h2>
  <p class="sub">The gate that decides if an article renders a card.
  <strong>Binary output</strong>: <code>alert</code> or <code>drop</code>.
  Runs <em>before</em> any LLM UC generation so dropped articles cost zero
  tokens.</p>
  <div class="pillbar">
    <span class="pill good">Tier 0 — strong-keep override (rules, free)</span>
    <span class="pill warn">Tier 1 — strong-drop regex (rules, free)</span>
    <span class="pill">Tier 2 — cached LLM classifier (Haiku, ~$0.0008)</span>
  </div>
  <div class="mermaid">
flowchart TB
  A[article + indicators + early sev] --> T0{{Tier 0:<br/>KEV cited?<br/>CVE + actively exploited?<br/>hashes / IPs / domains?<br/>named threat actor?<br/>named campaign / @scope/pkg?<br/>security-estate keyword?<br/>analyst override allowlist?}}
  T0 -- any hit --> K0[KEEP — alert]
  T0 -- none --> SEV{{Severity floor:<br/>is sev in low / med?}}
  SEV -- yes --> DS[DROP — sev floor]
  SEV -- no — sev crit or high --> T1{{Tier 1 regex:<br/>listicle / Top N?<br/>state of / year in / one year of?<br/>opinion: 'Why X is …', 'Your X isn't Y'?<br/>tutorial: How to / beginner / What is?<br/>'[Webinar] …' / 'with FirstName LastName'?<br/>cumulative update / Patch Tuesday + no zero-days?<br/>'X Releases …' without RCE/exploit context?<br/>generic OS feature launch?<br/>': The Case for X'?}}
  T1 -- match --> D1[DROP]
  T1 -- no match --> T2[Tier 2:<br/>Haiku LLM with 1500-char body excerpt<br/>'Reply ALERT or DROP — JSON only'<br/>cached by SHA1 CLASSIFIER_VERSION pipe URL]
  T2 -- alert --> K1[KEEP — alert]
  T2 -- drop --> D2[DROP]
  T2 -- LLM unavailable --> K2[default-keep — alert]
  K0 --> R[render card]
  K1 --> R
  K2 --> R
  DS --> X[skip render<br/>append to relevance_drops.jsonl]
  D1 --> X
  D2 --> X
  </div>
  <span class="ref">classify_relevance at generate.py:13942 · invoked from main
  at 14322 · drops written to <code>intel/relevance_drops.jsonl</code></span>

  <h3 style="margin-top:22px; font-size:16px;">Recent drops (latest run)</h3>
  <table>
    <thead><tr><th>Tier</th><th>Reason</th><th>Title</th><th>Source</th></tr></thead>
    <tbody>{drops_html or '<tr><td colspan="4" class="muted">No drops recorded yet.</td></tr>'}</tbody>
  </table>
</section>

<section>
  <h2><span class="num">5</span>LLM UC generation</h2>
  <p class="sub">Per-article bespoke detection UCs. OAuth path uses
  <code>claude -p --output-format stream-json</code> as a subprocess (the
  claude-agent-sdk SDK path was retired — multiple Windows-specific bugs).
  Falls back to <code>ANTHROPIC_API_KEY</code> if OAuth is unavailable.
  Cached per article URL so re-runs cost nothing.</p>
  <div class="mermaid">
flowchart TB
  A[article passed relevance gate] --> B{{cache hit on<br/>SHA1 of URL?}}
  B -- yes --> R[load cached UCs<br/>cost: $0]
  B -- no --> C{{_llm_should_process<br/>keyword gate}}
  C -- skip --> S[no LLM UCs<br/>template UCs only]
  C -- accept --> D{{OAuth available<br/>AND uc breaker not open?}}
  D -- yes --> E[_llm_call_via_oauth →<br/>_call_claude_cli<br/>subprocess: claude -p<br/>Opus + WebSearch<br/>1200s budget, 250 calls/run]
  D -- no --> F{{ANTHROPIC_API_KEY?}}
  E -- success --> P[parse JSON UCs]
  E -- credit/quota error --> SW{{secondary CLAUDE_CONFIG_DIR<br/>configured?}}
  SW -- yes --> SWY[switch to secondary account<br/>reset breakers<br/>retry once]
  SW -- no --> G
  SWY --> E
  E -- 6 of 12 in window fail --> G[OAuth circuit breaker OPEN<br/>skip OAuth rest of run]
  E -- subprocess crash<br/>or timeout --> G
  G --> F
  F -- yes --> H[_llm_call_via_api_key<br/>anthropic SDK]
  F -- no --> S
  H -- success --> P
  H -- fail --> S
  P --> W[write cache file]
  W --> R
  </div>
  <span class="ref">_llm_generate_ucs · _llm_call_via_oauth ·
  _call_claude_cli (failover + usage capture) ·
  cache at <code>intel/.llm_uc_cache/&lt;sha[:2]&gt;/&lt;sha&gt;.json</code></span>
</section>

<section>
  <h2><span class="num">6</span>Render & publish</h2>
  <p class="sub">After the loop, generate.py assembles
  <code>index.html</code>, per-day briefings (orphans cleaned each run),
  share-page stubs, per-actor / technique / target landing pages, and the
  sitemap. Then <code>run_once.bat</code> commits + pushes; GitHub Pages
  publishes within ~1 minute.</p>
  <div class="mermaid">
flowchart LR
  M[main loop done] --> A[index.html]
  M --> B[briefings/&lt;date&gt;/&lt;slug&gt;.md<br/>+ stale cleanup]
  M --> C[share/article/*.html<br/>share/uc/*.html]
  M --> D[actors/*.html · techniques/*.html<br/>targets/*.html]
  M --> E[sitemap.xml<br/>intel/iocs.{{json,csv,rss}}]
  M --> F[catalog/use_cases_full.js<br/>rule_packs/&lt;platform&gt;/]
  A & B & C & D & E & F --> G[run_once.bat]
  G --> H[git add → commit → push]
  H --> I[GitHub Pages publishes<br/>~60 s lag]
  </div>
  <span class="ref">write_briefings at generate.py:13168 ·
  run_once.bat orchestrates commit + push</span>
</section>

<section>
  <h2><span class="num">7</span>Scheduled pipelines</h2>
  <p class="sub">Three independent Windows Scheduled Tasks run on this PC.
  The 2-hour main pipeline and the 2-hour quality-review pass interleave on
  alternate xx:30 boundaries, while the weekly synthesis feeds new use
  cases that the next main run picks up.</p>
  <div class="mermaid">
flowchart TB
  subgraph T1[ClankerusecasePipeline · every 2h xx:30]
    direction LR
    P1A[Windows Task Scheduler<br/>06:30 +PT2H] --> P1B[run_once.bat]
    P1B --> P1C[generate.py<br/>fetch · filter · dedupe<br/>relevance · LLM UC · IOC · KC · vision<br/>render]
    P1C --> P1D[git commit + push<br/>GitHub Pages publishes ~60s]
    P1D --> P1E[logs/auto.log<br/>+ intel/.usage_log.jsonl row]
  end
  subgraph T3[ClankerusecaseQualityReview · every 2h xx:30 alt]
    direction LR
    P3A[Windows Task Scheduler<br/>07:30 +PT2H] --> P3B[run_review.bat]
    P3B --> P3C[quality_review.py<br/>Haiku reviewer pass<br/>over latest run articles]
    P3C --> P3D[intel/quality_suggestions.jsonl<br/>commit + push]
    P3D --> P3E[logs/review.log<br/>+ intel/.usage_log.jsonl row]
  end
  subgraph T2[ClankerusecaseBiweekly · Sundays 23:00]
    direction LR
    P2A[Windows Task Scheduler<br/>weekly Sun 23:00] --> P2B[biweekly.bat]
    P2B --> P2C[biweekly_review.py<br/>14-day rolling window<br/>cluster articles by IOC/CVE/theme<br/>LLM synth → cross-article UCs]
    P2C --> P2D[use_cases/weekly/&lt;ISO-week&gt;/<br/>UC_WEEKLY_&lt;slug&gt;.yml]
    P2D --> P2E[git commit + push]
    P2E --> P2F[briefings/_weekly/&lt;ISO-week&gt;.md<br/>logs/biweekly.log]
  end
  P2D -. feeds .-> P1C
  P1C -. shares .pipeline.lock .-> P3C
  P1C -.> ARTICLES[Articles tab on the live site]
  P2D -.> WKC[WKC bucket in Detection Library<br/>filter by 'WKC' kind chip]
  P3D -. annotates next run .-> P1C
  </div>
  <h3 style="margin-top:18px; font-size:16px;">Live task state on this PC</h3>
  <table>
    <thead><tr><th>Task</th><th>State</th><th>Cadence</th><th>Last run</th>
      <th>Next run</th><th>Result</th></tr></thead>
    <tbody>{tasks_html}</tbody>
  </table>
  <span class="ref">All three tasks live under Windows Task Scheduler.
  Inspect any with <code>schtasks /Query /TN ClankerusecasePipeline /V /FO LIST</code>.
  Logs: <code>logs/auto.log</code> (pipeline), <code>logs/review.log</code>
  (quality review), <code>logs/biweekly.log</code> (weekly synthesis).
  Every run also appends one row to <code>intel/.usage_log.jsonl</code>
  for the Usage tab.</span>
</section>

<section>
  <h2><span class="num">8</span>Operational safety nets</h2>
  <div class="pillbar">
    <span class="pill good">Per-kind OAuth circuit breakers (6 of 12 in window → open)</span>
    <span class="pill good">Per-kind call budgets (uc 250 · ioc 200 · relevance 400 · kc/vision 150)</span>
    <span class="pill good">Dual-account failover (primary → secondary on credit/quota error)</span>
    <span class="pill good">Per-run LLM usage capture → <code>intel/.usage_log.jsonl</code></span>
    <span class="pill good">Per-call timeouts (1200s UC / 45s relevance / 135s vision)</span>
    <span class="pill good">Stale-briefing cleanup each run</span>
    <span class="pill good">Marketing-post filter at fetch boundary</span>
    <span class="pill good">Cache invalidation via UC_VERSION + CLASSIFIER_VERSION bumps</span>
    <span class="pill good">relevance_drops.jsonl audit log</span>
    <span class="pill good">analyst override list (_RELEVANCE_OVERRIDE_TITLES)</span>
  </div>
  <p class="sub">When <code>claude -p</code> returns a credit/quota error on the
  primary account, <code>_call_claude_cli</code> flips
  <code>CLAUDE_CONFIG_DIR</code> to the secondary account, resets the
  breakers, and retries the same call (sticky for the rest of the run).
  If no secondary is configured, or if both accounts fail, the per-kind
  breaker trips after 6 failures in the rolling 12-call window and the
  run falls through to <code>ANTHROPIC_API_KEY</code> or rules-only
  output. Every call's token usage + wall-time is captured per kind and
  written to a rolling JSONL on process exit — see the Usage tab.</p>
  <span class="ref">_OAUTH_BREAKERS · _maybe_switch_account ·
  _record_usage / _emit_usage_summary (atexit) ·
  setup_dual_account.ps1 · show_usage.ps1</span>
</section>

</div><!-- /tab-pane workflows -->

<!-- ===== QUALITY TAB ===== -->
<div class="tab-pane" id="tab-quality" role="tabpanel">
<section>
  <div class="pane-h">
    <h2>KQL audit</h2>
    <span class="meta">source: <code>kql_audit.json</code></span>
  </div>
  {kql_html}
</section>

<section>
  <div class="pane-h">
    <h2>Detection coverage gaps</h2>
    <span class="meta">source: <code>intel/quality_suggestions.jsonl</code> · 30-day window</span>
  </div>
  {gaps_html}
</section>

<section>
  <div class="pane-h">
    <h2>Source ROI (signal vs. noise)</h2>
    <span class="meta">7-day window · derived from <code>logs/auto.log</code> + drops</span>
  </div>
  {roi_html}
</section>
</div><!-- /tab-pane quality -->

<div class="tab-pane" id="tab-usage" role="tabpanel">

<section>
  <h2><span class="num">U</span>LLM usage per run</h2>
  <p class="sub">Every <code>generate.py</code> / <code>quality_review.py</code>
  / <code>biweekly_review.py</code> run writes one row to
  <code>intel/.usage_log.jsonl</code> at process exit, capturing token
  counts and wall-time per LLM kind (uc · ioc · relevance · vision · kc ·
  review). This dashboard is generated from those rows. Re-run
  <code>py build_pipeline_docs.py</code> to refresh.</p>

  <div id="usage-summary" class="stats"></div>

  <div class="usage-controls">
    <label>script
      <select id="usage-filter-script">
        <option value="">(all)</option>
      </select>
    </label>
    <label>last
      <select id="usage-filter-limit">
        <option value="25">25 runs</option>
        <option value="50">50 runs</option>
        <option value="100">100 runs</option>
        <option value="200" selected>all</option>
      </select>
    </label>
    <label style="margin-left:auto; font-family:var(--mono); font-size:11px;
                  color:var(--muted-2);">
      click a row to see per-kind breakdown
    </label>
  </div>

  <div id="usage-empty" class="empty-state" style="display:none;">
    No runs logged yet. Trigger <code>run_once.bat</code> (or wait for the
    next scheduled fire) and refresh this page — the first row will appear
    in <code>intel/.usage_log.jsonl</code>.
  </div>

  <table id="usage-table" class="usage-table" style="display:none;">
    <thead>
      <tr>
        <th data-sort="ts" class="sorted">timestamp (UTC)</th>
        <th data-sort="script">script</th>
        <th data-sort="wall_seconds_total" class="num">wall s</th>
        <th data-sort="_cost_usd" class="num">cost USD</th>
        <th data-sort="_cache_hit" class="num">cache hit</th>
        <th data-sort="calls" class="num">calls</th>
        <th data-sort="output_tokens" class="num">output tok</th>
        <th data-sort="cache_read" class="num">cache_r</th>
        <th data-sort="active_at_end">acct</th>
        <th data-sort="top_kind">top kind</th>
      </tr>
    </thead>
    <tbody id="usage-tbody"></tbody>
  </table>

  <span class="ref">Source: <code>intel/.usage_log.jsonl</code> ·
  inline rendering only (no external fetch, no analytics, no PII).
  Counters come from the stream-json <code>result.usage</code> block
  returned by every <code>claude -p</code> subprocess call.</span>
</section>

</div><!-- /tab-pane usage -->

<script id="usage-data" type="application/json">{usage_json}</script>
<script>
(function(){{
  // ----- Tab switching -----
  var tabs = document.querySelectorAll('.tab-btn');
  var panes = document.querySelectorAll('.tab-pane');
  tabs.forEach(function(btn){{
    btn.addEventListener('click', function(){{
      var target = btn.getAttribute('data-tab');
      tabs.forEach(function(b){{ b.classList.toggle('active', b === btn); }});
      panes.forEach(function(p){{
        p.classList.toggle('active', p.id === 'tab-' + target);
      }});
      // Force Mermaid to re-render diagrams when the Workflows tab is
      // re-activated — they sometimes initialise zero-width when hidden.
      if (target === 'workflows' && window.mermaid){{
        try {{ window.mermaid.run({{querySelector:'.mermaid'}}); }} catch(e){{}}
      }}
    }});
  }});

  // ----- Usage dashboard -----
  var raw = document.getElementById('usage-data').textContent || '[]';
  var DATA = [];
  try {{ DATA = JSON.parse(raw); }} catch(e){{ DATA = []; }}

  var fmt = function(n){{
    if (n == null || isNaN(n)) return '—';
    n = Number(n);
    if (n >= 1e9) return (n/1e9).toFixed(2) + 'B';
    if (n >= 1e6) return (n/1e6).toFixed(2) + 'M';
    if (n >= 1e3) return (n/1e3).toFixed(1) + 'k';
    return n.toLocaleString();
  }};
  var fmtInt = function(n){{
    if (n == null || isNaN(n)) return '—';
    return Number(n).toLocaleString();
  }};
  var fmtUsd = function(n){{
    if (n == null || isNaN(n)) return '—';
    n = Number(n);
    if (n < 0.01) return '$' + n.toFixed(4);
    if (n < 10)   return '$' + n.toFixed(2);
    return '$' + n.toLocaleString(undefined, {{maximumFractionDigits:0}});
  }};
  var fmtPct = function(n){{
    if (n == null || isNaN(n)) return '—';
    return (Number(n) * 100).toFixed(1) + '%';
  }};
  // Per-kind unit costs (USD per 1M tokens). Mirrors _MODEL_PRICING in Python
  // — keep in sync if model prices change.
  var KIND_PRICE = {{
    uc:       {{input:15, output:75, cache_r:1.50, cache_w:18.75}},
    ioc:      {{input:15, output:75, cache_r:1.50, cache_w:18.75}},
    kc:       {{input:15, output:75, cache_r:1.50, cache_w:18.75}},
    vision:   {{input:15, output:75, cache_r:1.50, cache_w:18.75}},
    relevance:{{input:15, output:75, cache_r:1.50, cache_w:18.75}},
    review:   {{input: 1, output: 5, cache_r:0.10, cache_w: 1.25}},
  }};
  function kindCost(k, s){{
    var p = KIND_PRICE[k] || KIND_PRICE.uc;
    return ((s.input_tokens||0)*p.input
          + (s.output_tokens||0)*p.output
          + (s.cache_read||0)*p.cache_r
          + (s.cache_create||0)*p.cache_w) / 1e6;
  }}
  var topKindOf = function(byKind){{
    if (!byKind) return '—';
    var best = null, bestN = -1;
    Object.keys(byKind).forEach(function(k){{
      var n = (byKind[k] && byKind[k].output_tokens) || 0;
      if (n > bestN){{ bestN = n; best = k; }}
    }});
    return best || '—';
  }};

  // Populate script filter from data.
  var scripts = {{}};
  DATA.forEach(function(r){{
    if (r && r.script) scripts[r.script] = true;
  }});
  var scriptSelect = document.getElementById('usage-filter-script');
  Object.keys(scripts).sort().forEach(function(s){{
    var opt = document.createElement('option');
    opt.value = s; opt.textContent = s;
    scriptSelect.appendChild(opt);
  }});

  var sortKey = 'ts';
  var sortAsc = false;

  function applyFilters(){{
    var sf = document.getElementById('usage-filter-script').value;
    var lim = parseInt(document.getElementById('usage-filter-limit').value, 10) || 200;
    var rows = DATA.slice();
    if (sf) rows = rows.filter(function(r){{ return r.script === sf; }});
    rows.sort(function(a, b){{
      var av, bv;
      if (sortKey === 'top_kind'){{
        av = topKindOf(a.by_kind); bv = topKindOf(b.by_kind);
      }} else if (['calls','input_tokens','output_tokens','cache_read'].indexOf(sortKey) >= 0){{
        av = (a.totals||{{}})[sortKey] || 0;
        bv = (b.totals||{{}})[sortKey] || 0;
      }} else if (sortKey === 'account_switched'){{
        av = a[sortKey] ? 1 : 0; bv = b[sortKey] ? 1 : 0;
      }} else {{
        av = a[sortKey]; bv = b[sortKey];
      }}
      if (av < bv) return sortAsc ? -1 : 1;
      if (av > bv) return sortAsc ? 1 : -1;
      return 0;
    }});
    return rows.slice(0, lim);
  }}

  function renderSummary(rows){{
    var box = document.getElementById('usage-summary');
    box.innerHTML = '';
    if (!rows.length) return;
    var totIn=0, totOut=0, totCache=0, totCalls=0, totWall=0;
    var switches=0, totCost=0, errs=0;
    rows.forEach(function(r){{
      var t = r.totals || {{}};
      totIn   += t.input_tokens  || 0;
      totOut  += t.output_tokens || 0;
      totCache+= t.cache_read    || 0;
      totCalls+= t.calls         || 0;
      totWall += t.wall_seconds  || 0;
      errs    += t.errors        || 0;
      totCost += r._cost_usd     || 0;
      if (r.account_switched) switches++;
    }});
    var hit = (totCache + totIn) ? (totCache / (totCache + totIn)) : 0;
    var tiles = [
      [rows.length,                       'runs shown'],
      [fmtInt(totCalls),                  'total calls'],
      [fmtInt(errs),                      'errors'],
      [fmtUsd(totCost),                   'total cost (USD)'],
      [fmtPct(hit),                       'cache hit rate'],
      [fmt(totOut),                       'output tokens'],
      [Math.round(totWall) + 's',         'total LLM wall'],
      [switches + ' / ' + rows.length,    'failover triggered'],
    ];
    box.className = 'stat-grid';
    tiles.forEach(function(t){{
      var d = document.createElement('div');
      d.className = 'stat';
      d.innerHTML = '<div class="v">' + t[0] + '</div><div class="l">' + t[1] + '</div>';
      box.appendChild(d);
    }});
  }}

  function renderByKindRow(r){{
    var bk = r.by_kind || {{}};
    var names = Object.keys(bk).sort();
    if (!names.length) return '<div class="usage-bykind">(no per-kind data for this run)</div>';
    var html = '<div class="usage-bykind"><strong>Per-kind breakdown</strong>'
             + '<table><thead><tr><th>kind</th><th class="num">calls</th>'
             + '<th class="num">errs</th><th class="num">input</th>'
             + '<th class="num">output</th><th class="num">cache_r</th>'
             + '<th class="num">cache_w</th><th class="num">wall s</th>'
             + '<th class="num">cost USD</th>'
             + '<th>by account</th></tr></thead><tbody>';
    names.forEach(function(k){{
      var s = bk[k] || {{}};
      var ba = s.by_account || {{}};
      var c = kindCost(k, s);
      html += '<tr><td><code>' + k + '</code></td>'
            + '<td class="num">' + fmtInt(s.calls) + '</td>'
            + '<td class="num">' + fmtInt(s.errors) + '</td>'
            + '<td class="num">' + fmtInt(s.input_tokens) + '</td>'
            + '<td class="num">' + fmtInt(s.output_tokens) + '</td>'
            + '<td class="num">' + fmtInt(s.cache_read) + '</td>'
            + '<td class="num">' + fmtInt(s.cache_create) + '</td>'
            + '<td class="num">' + (s.wall_seconds || 0).toFixed(1) + '</td>'
            + '<td class="num">' + fmtUsd(c) + '</td>'
            + '<td>p=' + fmtInt(ba.primary||0) + ' s=' + fmtInt(ba.secondary||0) + '</td>'
            + '</tr>';
    }});
    html += '</tbody></table></div>';
    return html;
  }}

  function renderTable(){{
    var rows = applyFilters();
    var tbody = document.getElementById('usage-tbody');
    var table = document.getElementById('usage-table');
    var empty = document.getElementById('usage-empty');
    tbody.innerHTML = '';
    renderSummary(rows);
    if (!rows.length){{
      table.style.display = 'none';
      empty.style.display = 'block';
      return;
    }}
    table.style.display = '';
    empty.style.display = 'none';
    rows.forEach(function(r, i){{
      var t = r.totals || {{}};
      var cost = r._cost_usd || 0;
      var over = r._cost_over_baseline;
      var costCls = (over != null && over > 1.5) ? ' over'
                  : (over != null && over < 0.5) ? ' under' : '';
      var hit = r._cache_hit || 0;
      var hitCls = (hit < 0.5) ? ' warn' : '';
      var acctCell = (r.active_at_end || '—');
      if (r.account_switched) {{
        acctCell += ' <span class="chip failover">FAILOVER</span>';
      }}
      var tr = document.createElement('tr');
      tr.dataset.idx = i;
      tr.innerHTML =
        '<td><code>' + (r.ts || '—') + '</code></td>'
      + '<td>' + (r.script || '—') + '</td>'
      + '<td class="num">' + (r.wall_seconds_total || 0).toFixed(0) + '</td>'
      + '<td class="cost' + costCls + '">' + fmtUsd(cost) + '</td>'
      + '<td class="hit' + hitCls + '">' + fmtPct(hit) + '</td>'
      + '<td class="num">' + fmtInt(t.calls) + '</td>'
      + '<td class="num">' + fmtInt(t.output_tokens) + '</td>'
      + '<td class="num">' + fmtInt(t.cache_read) + '</td>'
      + '<td>' + acctCell + '</td>'
      + '<td><code>' + topKindOf(r.by_kind) + '</code></td>';
      tr.addEventListener('click', function(){{
        var nxt = tr.nextSibling;
        if (nxt && nxt.classList && nxt.classList.contains('bykind-row')){{
          nxt.remove();
          tr.classList.remove('expanded');
          return;
        }}
        var row = document.createElement('tr');
        row.className = 'bykind-row';
        var td = document.createElement('td');
        td.colSpan = 10;
        td.innerHTML = renderByKindRow(r);
        row.appendChild(td);
        tr.parentNode.insertBefore(row, tr.nextSibling);
        tr.classList.add('expanded');
      }});
      tbody.appendChild(tr);
    }});
    // Update header sort indicators.
    document.querySelectorAll('.usage-table th').forEach(function(th){{
      th.classList.remove('sorted','asc');
      if (th.getAttribute('data-sort') === sortKey){{
        th.classList.add('sorted');
        if (sortAsc) th.classList.add('asc');
      }}
    }});
  }}

  document.querySelectorAll('.usage-table th').forEach(function(th){{
    th.addEventListener('click', function(){{
      var k = th.getAttribute('data-sort');
      if (sortKey === k){{ sortAsc = !sortAsc; }} else {{ sortKey = k; sortAsc = false; }}
      renderTable();
    }});
  }});
  document.getElementById('usage-filter-script').addEventListener('change', renderTable);
  document.getElementById('usage-filter-limit').addEventListener('change', renderTable);

  renderTable();
}})();
</script>

<div class="footer">
  Re-generate this page by running <code>py build_pipeline_docs.py</code>
  in the project root. Local-only document — not deployed.
</div>

</body>
</html>
"""


def main():
    stats     = _latest_run_stats()
    drops     = _drop_log_sample()
    today     = _briefings_today()
    tasks     = _scheduled_tasks()
    usage     = _usage_log_data()
    lock      = _lock_state()
    git       = _git_status()
    cache     = _cache_storage()
    baseline  = _baseline_summary()
    kql_audit = _kql_audit_summary()
    gaps      = _quality_gap_summary()
    roi       = _source_roi()
    history   = _run_history()
    html = render(
        stats, drops, today, tasks,
        usage_runs=usage,
        lock=lock, git=git, cache=cache, baseline=baseline,
        kql_audit=kql_audit, gaps=gaps, source_roi=roi, history=history,
    )
    OUT.write_text(html, encoding="utf-8")
    size_kb = OUT.stat().st_size / 1024
    print(f"[*] Wrote {OUT.name} ({size_kb:.1f} KB)")
    print(f"[*] Open it: start {OUT.name}")
    print(f"[*] Latest run: {stats.get('started')}")
    print(f"[*] Articles kept / dropped: "
          f"{stats.get('articles_kept')} / {stats.get('articles_dropped')}")
    print(f"[*] Usage runs embedded: {len(usage)}")
    if lock.get("running"):
        print(f"[*] Pipeline LIVE — PID {lock['pid']} "
              f"({_fmt_age(lock['age_seconds'])} in)")
    if kql_audit:
        print(f"[*] KQL audit: {kql_audit['n_clean']:,} clean / "
              f"{kql_audit['total_ucs']:,} UCs "
              f"({kql_audit['pct_clean']*100:.1f}%)")
    if gaps.get("total_gaps"):
        print(f"[*] Detection gaps: {gaps['total_gaps']:,} rows across "
              f"{gaps['articles_with_gaps']:,} articles (30d)")
    print(f"[*] Cache: {_fmt_bytes(cache.get('bytes'))} "
          f"in {cache.get('files', 0):,} files")


if __name__ == "__main__":
    main()

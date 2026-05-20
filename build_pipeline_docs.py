"""Build pipeline.html — a local-only documentation page that shows the
threat-intel pipeline as a series of Mermaid diagrams with live stats
from the latest run. Open the file in a browser; no server needed.

Run:    py build_pipeline_docs.py
Output: pipeline.html (in this directory, gitignored)
"""
from __future__ import annotations
import json
import re
from pathlib import Path

ROOT     = Path(__file__).parent
LOG      = ROOT / "logs" / "auto.log"
DROPS    = ROOT / "intel" / "relevance_drops.jsonl"
BRIEFS   = ROOT / "briefings"
USAGE    = ROOT / "intel" / ".usage_log.jsonl"
OUT      = ROOT / "pipeline.html"


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


def render(stats: dict, drops: list[dict], today_count: int,
           tasks: list[dict] | None = None,
           usage_runs: list[dict] | None = None) -> str:
    tasks = tasks or []
    usage_runs = usage_runs or []
    # Inline the usage rows as JSON for the dashboard JS. Defang the
    # `</script>` sequence so a payload containing it can't escape the
    # script tag; the JS side parses with JSON.parse so the escape is
    # purely a string-level safety measure.
    usage_json = json.dumps(usage_runs, ensure_ascii=False).replace(
        "</", "<\\/")
    # Empty-state flag drives whether the dashboard renders a table or a
    # gentle "no runs yet" panel.
    usage_count = len(usage_runs)
    # Top stats tiles
    tile = lambda v, l: (
        f'<div class="stat"><div class="v">{v}</div>'
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
        '<div class="warn">⚠️ OAuth circuit breaker tripped during the last '
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

    tier = stats.get("tier_breakdown") or "—"
    top = stats.get("top_drop_sources") or "—"
    dd = stats.get("dedupe") or {}

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
</style>
</head>
<body>

<h1>Clankerusecase Pipeline — Internal Docs</h1>
<p class="lede">Diagrams of how articles flow from RSS into the live site at
<code>clankerusecase.com</code>, plus an interactive view of every run's
LLM-token usage. Each workflow section maps to the actual code in
<code>generate.py</code>.</p>

<div class="tabs" role="tablist">
  <button class="tab-btn active" data-tab="workflows" role="tab">Workflows</button>
  <button class="tab-btn" data-tab="usage" role="tab">Usage <span style="opacity:.5; font-weight:400;">({usage_count} runs)</span></button>
</div>

<div class="tab-pane active" id="tab-workflows" role="tabpanel">

<section>
  <h2><span class="num">0</span>Latest run</h2>
  <div class="stats">{stats_html}</div>
  {breaker_note}
  <p class="sub">
    Tier breakdown: <code>{_escape(tier)}</code><br>
    Top dropped sources: <code>{_escape(top)}</code><br>
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
        <th data-sort="account_switched" class="center">switched</th>
        <th data-sort="active_at_end">acct end</th>
        <th data-sort="calls" class="num">calls</th>
        <th data-sort="input_tokens" class="num">input tok</th>
        <th data-sort="output_tokens" class="num">output tok</th>
        <th data-sort="cache_read" class="num">cache_r</th>
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
    var totIn=0, totOut=0, totCache=0, totCalls=0, totWall=0, switches=0;
    rows.forEach(function(r){{
      var t = r.totals || {{}};
      totIn   += t.input_tokens  || 0;
      totOut  += t.output_tokens || 0;
      totCache+= t.cache_read    || 0;
      totCalls+= t.calls         || 0;
      totWall += t.wall_seconds  || 0;
      if (r.account_switched) switches++;
    }});
    var avgOut = rows.length ? Math.round(totOut / rows.length) : 0;
    var tiles = [
      [rows.length,        'runs shown'],
      [fmtInt(totCalls),   'total calls'],
      [fmt(totIn),         'input tokens'],
      [fmt(totOut),        'output tokens'],
      [fmt(totCache),      'cache reads'],
      [Math.round(totWall) + 's', 'total LLM wall'],
      [fmtInt(avgOut),     'avg output / run'],
      [switches + ' / ' + rows.length, 'failover triggered'],
    ];
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
             + '<th>by account</th></tr></thead><tbody>';
    names.forEach(function(k){{
      var s = bk[k] || {{}};
      var ba = s.by_account || {{}};
      html += '<tr><td><code>' + k + '</code></td>'
            + '<td class="num">' + fmtInt(s.calls) + '</td>'
            + '<td class="num">' + fmtInt(s.errors) + '</td>'
            + '<td class="num">' + fmtInt(s.input_tokens) + '</td>'
            + '<td class="num">' + fmtInt(s.output_tokens) + '</td>'
            + '<td class="num">' + fmtInt(s.cache_read) + '</td>'
            + '<td class="num">' + fmtInt(s.cache_create) + '</td>'
            + '<td class="num">' + (s.wall_seconds || 0).toFixed(1) + '</td>'
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
      var tr = document.createElement('tr');
      tr.dataset.idx = i;
      tr.innerHTML =
        '<td><code>' + (r.ts || '—') + '</code></td>'
      + '<td>' + (r.script || '—') + '</td>'
      + '<td class="num">' + (r.wall_seconds_total || 0).toFixed(0) + '</td>'
      + '<td class="center">' + (r.account_switched
            ? '<span class="badge-y">Y</span>' : '<span class="badge-n">.</span>') + '</td>'
      + '<td>' + (r.active_at_end || '—') + '</td>'
      + '<td class="num">' + fmtInt(t.calls) + '</td>'
      + '<td class="num">' + fmtInt(t.input_tokens) + '</td>'
      + '<td class="num">' + fmtInt(t.output_tokens) + '</td>'
      + '<td class="num">' + fmtInt(t.cache_read) + '</td>'
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
    stats = _latest_run_stats()
    drops = _drop_log_sample()
    today = _briefings_today()
    tasks = _scheduled_tasks()
    usage = _usage_log_data()
    html = render(stats, drops, today, tasks, usage_runs=usage)
    OUT.write_text(html, encoding="utf-8")
    size_kb = OUT.stat().st_size / 1024
    print(f"[*] Wrote {OUT.name} ({size_kb:.1f} KB)")
    print(f"[*] Open it: start {OUT.name}")
    print(f"[*] Latest run: {stats.get('started')}")
    print(f"[*] Articles kept / dropped: "
          f"{stats.get('articles_kept')} / {stats.get('articles_dropped')}")
    print(f"[*] Usage runs embedded: {len(usage)}")


if __name__ == "__main__":
    main()

"""
digest.py — Diff current article run against the previous one and emit a
daily digest.

Reads:    data_sources/last_run.json   (previous state, may not exist)
          generate.py output (re-runs the rule engine on current RSS feed)
Writes:   daily_digest.md              (markdown summary)
          data_sources/last_run.json   (updated state)
Optional: POST to WEBHOOK_URL env var if set (JSON body) — useful for
          Slack/Teams/etc. via a simple webhook integration.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).parent
STATE = ROOT / "data_sources" / "last_run.json"
DIGEST = ROOT / "daily_digest.md"


def load_state():
    if STATE.exists():
        try:
            return json.loads(STATE.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def article_id(title: str) -> str:
    return hashlib.sha256(title.encode("utf-8")).hexdigest()[:16]


def main():
    spec = importlib.util.spec_from_file_location("gen", ROOT / "generate.py")
    gen = importlib.util.module_from_spec(spec)
    sys.modules["gen"] = gen
    spec.loader.exec_module(gen)

    articles = gen.fetch_articles()
    rows = []
    for i, a in enumerate(articles):
        text = f"{a['title']}\n{a['raw_body']}"
        ind = gen.extract_indicators(a["title"], a["raw_body"])
        techs = gen.infer_techniques(text, ind["explicit_ttps"])
        ucs = gen.select_use_cases(text, ind)
        narrative_hit, _ = gen.detect_kill_chain(text)
        hit = narrative_hit | {uc.kill_chain for uc in ucs}
        sev = gen.compute_severity(text, ind, ucs, techs)
        rows.append({
            "id": article_id(a["title"]),
            "title": a["title"],
            "link": a["link"],
            "published": a.get("published", ""),
            "sources": a.get("sources") or [a.get("source", "")],
            "severity": sev,
            "use_cases": len(ucs),
            "techniques": [t for t, _ in techs],
            "kill_chain_phases_hit": sorted(hit),
            "cves": ind["cves"],
        })

    prev = load_state()
    prev_ids = {a["id"] for a in prev.get("articles", [])}
    new = [r for r in rows if r["id"] not in prev_ids]
    high_or_crit = [r for r in rows if r["severity"] in ("crit", "high")]

    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sev_count = {s: sum(1 for r in rows if r["severity"] == s) for s in ("crit","high","med","low")}
    src_count = {}
    for r in rows:
        for s in r["sources"]:
            src_count[s] = src_count.get(s, 0) + 1

    # ---- Markdown digest -----------------------------------------------------
    md = [
        f"# Threat Atlas — Daily Digest",
        f"_Generated {now}_",
        "",
        f"**Severity:** "
        f"`crit` {sev_count['crit']} · `high` {sev_count['high']} · "
        f"`med` {sev_count['med']} · `low` {sev_count['low']}",
        "",
        f"**Sources** (last 30 days):  "
        + " · ".join(f"{src}: **{cnt}**" for src, cnt in sorted(src_count.items(), key=lambda x: -x[1])),
        "",
    ]

    if new:
        md.append(f"## ⭐ New since last run ({len(new)})")
        md.append("")
        for r in new:
            md.append(f"- **[{r['severity'].upper()}]** "
                      f"[{r['title']}]({r['link']})  ·  "
                      f"{r['use_cases']} use case(s)  ·  "
                      f"techniques: {', '.join(r['techniques'][:5]) or '—'}")
        md.append("")

    if high_or_crit:
        md.append(f"## 🔥 High / Critical priority ({len(high_or_crit)})")
        md.append("")
        for r in high_or_crit:
            badge = "🔴" if r["severity"] == "crit" else "🟠"
            cves = f" · CVEs: {', '.join(r['cves'])}" if r["cves"] else ""
            md.append(f"{badge} [{r['title']}]({r['link']})  ·  "
                      f"techniques: {', '.join(r['techniques'][:5]) or '—'}{cves}")
        md.append("")

    md.append(f"## All articles ({len(rows)})")
    md.append("")
    md.append("| Sev | Title | Use cases | Phases hit |")
    md.append("|---|---|---|---|")
    for r in rows:
        md.append(f"| {r['severity']} | "
                  f"[{r['title'][:80]}]({r['link']}) | "
                  f"{r['use_cases']} | "
                  f"{', '.join(r['kill_chain_phases_hit'])} |")

    DIGEST.write_text("\n".join(md), encoding="utf-8")
    print(f"[*] Wrote {DIGEST}")

    # ---- Save state ---------------------------------------------------------
    STATE.write_text(json.dumps({"generated": now, "articles": rows}, indent=2),
                     encoding="utf-8")
    print(f"[*] State updated: {len(rows)} articles, {len(new)} new since last run")

    # ---- Optional webhook ---------------------------------------------------
    webhook = os.environ.get("WEBHOOK_URL")
    if webhook and (new or high_or_crit):
        payload = {
            "generated": now,
            "severity_breakdown": sev_count,
            "new_articles": new,
            "high_or_crit": high_or_crit,
        }
        try:
            r = requests.post(webhook, json=payload, timeout=10)
            print(f"[*] Webhook POST -> {r.status_code}")
        except requests.RequestException as e:
            print(f"[!] Webhook POST failed: {e}")
    elif webhook:
        print("[*] Webhook configured but nothing notable — skipped POST")


if __name__ == "__main__":
    main()

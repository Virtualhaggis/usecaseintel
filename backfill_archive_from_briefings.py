"""Back-fill intel/uc_archive.json from the committed briefings/ history.

The cumulative front-page archive (uc_archive.json) only started recording
when the feature went live, so articles that were carded in the past but have
since aged out of the live feeds were never stored — the all-time total was
missing them. briefings/ is the durable, committed record of every article
the pipeline ever carded, so it can recover that history.

This merges every briefing into the archive at the SAME high-water-mark
policy generate.py uses (`_merge_uc_archive`): articles already in the archive
keep their (higher, live-derived) counts; only genuinely-missing historical
articles are added. It is therefore idempotent and can never lower a total.

Run once after deploying the archive feature, and any time you want to
re-absorb history before briefings get pruned:

    py backfill_archive_from_briefings.py            # dry-run (default)
    py backfill_archive_from_briefings.py --apply     # write the archive
"""
from __future__ import annotations

import argparse
import glob
import re
import sys
from pathlib import Path

import generate as g

ROOT = Path(__file__).parent
SEVMAP = {"CRIT": "crit", "CRITICAL": "crit", "HIGH": "high",
          "MED": "med", "MEDIUM": "med", "LOW": "low", "INFO": "low"}

_TITLE_RE = re.compile(r"^#\s*(?:\[([A-Z]+)\]\s*)?(.+)$", re.M)
_URL_RE = re.compile(r"\*\*Article:\*\*\s*(\S+)")
_PUB_RE = re.compile(r"\*\*Published:\*\*\s*(\S+)")
_TID_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b")
# Each rendered use case in a briefing carries a `· phase: **<phase>**` marker.
_UC_RE = re.compile(r"·\s*phase:\s*\*\*")


def _parse_briefing(path: str) -> dict | None:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    mt = _TITLE_RE.search(text)
    mu = _URL_RE.search(text)
    if not (mt and mu):
        return None
    title = mt.group(2).strip()
    url = mu.group(1).strip()
    sev = SEVMAP.get((mt.group(1) or "").upper(), "low")
    pub = (_PUB_RE.search(text).group(1) if _PUB_RE.search(text) else "")
    return {
        "link": url,
        "title": title,
        "published": pub,
        "sev": sev,
        "techs": sorted(set(_TID_RE.findall(text))),
        "ucs": len(_UC_RE.findall(text)),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--apply", action="store_true",
                    help="Write the archive (default: dry-run)")
    args = ap.parse_args()

    briefs = [p for p in glob.glob(str(ROOT / "briefings" / "**" / "*.md"),
                                   recursive=True)
              if "_weekly" not in p]
    print(f"[*] Scanning {len(briefs)} briefings…")

    run_archive: dict = {}
    parsed = 0
    for p in briefs:
        rec = _parse_briefing(p)
        if rec is None:
            continue
        parsed += 1
        # Build a synthetic article dict so _archive_key matches the live
        # pipeline's key derivation exactly (hash of link + title).
        article = {"link": rec["link"], "title": rec["title"],
                   "published": rec["published"]}
        g._record_archive_entry(run_archive, article, rec["ucs"],
                                rec["techs"], [], rec["sev"])
    print(f"[*] Parsed {parsed} briefings into {len(run_archive)} unique keys.")

    before = g._archive_totals(g._load_uc_archive())
    print(f"[*] Archive BEFORE: {before['articles']} articles, "
          f"{before['ucs']} detections, {before['crit_high']} crit/high")

    if not args.apply:
        # Simulate the high-water merge in memory without writing.
        merged = g._load_uc_archive()
        arts = merged.setdefault("articles", {})
        add = 0
        for k, cur in run_archive.items():
            if k not in arts:
                arts[k] = cur
                add += 1
        after = g._archive_totals(merged)
        print(f"[*] Archive AFTER (simulated): {after['articles']} articles "
              f"(+{add} historical), {after['ucs']} detections "
              f"(+{after['ucs'] - before['ucs']})")
        print("[*] DRY-RUN — pass --apply to write the archive.")
        return 0

    # Lock-aware write so we don't race a live scheduled pipeline run.
    if not g.acquire_pipeline_lock():
        print("[!] Pipeline lock held by a live run — try again shortly.")
        return 0
    try:
        g._merge_uc_archive(run_archive)
        after = g._archive_totals(g._load_uc_archive())
        print(f"[*] Archive AFTER: {after['articles']} articles, "
              f"{after['ucs']} detections, {after['crit_high']} crit/high "
              f"(+{after['articles'] - before['articles']} articles, "
              f"+{after['ucs'] - before['ucs']} detections)")
    finally:
        g.release_pipeline_lock()
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Deterministic site-review linter for Clankerusecase.

Static checks only (no browser, no render) so it is safe to run unattended in a
scheduled task. Reads the *committed* index.html (rendered by the 2h pipeline),
generate.py (the source of truth for fixes), and the pipeline's own artefacts.

Each finding is a dict:
    {id, lens, severity (FAIL|WARN|INFO), tier (auto|suggest|prompt),
     title, detail, fix?: {file, old, new}}

`tier == "auto"` means a registered, provably-safe string transform exists and
site_review.py may apply it (behind ast/smoke gates). Everything else is a
human/LLM suggestion. Importable: `run_lint() -> list[dict]`. Runnable:
`py _review_lint.py [--json]`.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).parent
INDEX = ROOT / "index.html"
GEN = ROOT / "generate.py"

# Platforms the site advertises (7 query languages). Kept here so the lint has a
# single source of truth to assert copy against.
PLATFORM_COUNT = 7


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _finding(fid, lens, severity, tier, title, detail, fix=None):
    f = {"id": fid, "lens": lens, "severity": severity, "tier": tier,
         "title": title, "detail": detail}
    if fix:
        f["fix"] = fix
    return f


def _archive_detection_count():
    """Canonical cumulative detection total, via generate.py's own helpers so the
    lint can't disagree with what the site computes. Returns None on any error."""
    try:
        import generate as g  # noqa
        t = g._archive_totals(g._load_uc_archive())
        return int(t.get("ucs") or 0), int(t.get("articles") or 0)
    except Exception:
        return None, None


def _wcag_ratio(hex_fg, hex_bg):
    def lin(hexs):
        hexs = hexs.lstrip("#")
        if len(hexs) == 3:
            hexs = "".join(c * 2 for c in hexs)
        r, gg, b = (int(hexs[i:i + 2], 16) / 255 for i in (0, 2, 4))
        def f(v):
            return v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4
        return 0.2126 * f(r) + 0.7152 * f(gg) + 0.0722 * f(b)
    L1, L2 = lin(hex_fg), lin(hex_bg)
    hi, lo = max(L1, L2), min(L1, L2)
    return (hi + 0.05) / (lo + 0.05)


def _aa_passing_hex(hex_bg, target=5.0):
    """Find a neutral-ish grey that clears `target`:1 on the dark bg, keeping a
    slight cool tint. Returns a #rrggbb string used as the suggested fix."""
    for n in range(90, 200, 2):
        cand = f"#{n:02x}{n+2:02x}{n+8:02x}"
        if _wcag_ratio(cand, hex_bg) >= target:
            return cand
    return "#9aa0aa"


# --------------------------------------------------------------------------- #
# checks
# --------------------------------------------------------------------------- #
def check_noopener(gen_text):
    """External target=_blank links must carry rel=noopener (security). AUTO."""
    out = []
    # Match an <a …> open tag that has target="_blank" and an external href.
    for m in re.finditer(r'<a\b[^>]*\btarget="_blank"[^>]*>', gen_text):
        tag = m.group(0)
        href = re.search(r'href="(https?://[^"]+)"', tag)
        if not href:
            continue  # same-origin / relative — lower risk, skip
        if "clankerusecase.com" in href.group(1):
            continue  # same origin
        if "noopener" in tag:
            continue
        new_tag = tag[:-1] + ' rel="noopener noreferrer">'
        out.append(_finding(
            "noopener", "security", "WARN", "auto",
            "External link without rel=noopener",
            f"{href.group(1)} opens in a new tab without rel=noopener.",
            fix={"file": "generate.py", "old": tag, "new": new_tag}))
    return out


def check_stat_accuracy(idx_text):
    """Hardcoded stat literals that disagree with the live archive / platform
    count. SUGGEST (auto-editing the wrong literal in a 23k-line file is unsafe)."""
    out = []
    det, _arts = _archive_detection_count()
    # Stale rounded headline claims only: the "N+" marketing form ("2,000+ use
    # cases"). Bare "N detections" is almost always a legit sub-count (per
    # platform, per severity, per article) and must NOT be flagged.
    for m in re.finditer(r'([\d][\d,]*)\s*\+\s*(use cases|detections|'
                         r'MITRE-mapped|threat-intel feeds|feeds)', idx_text, re.I):
        raw = m.group(1).replace(",", "")
        try:
            n = int(raw)
        except ValueError:
            continue
        unit = m.group(2).lower()
        # Feeds: the site has ~14 sources; a "N+ feeds" claim is fine unless wildly off.
        thresh = det * 0.6 if "feed" not in unit else 0
        if det and "feed" not in unit and n < thresh:
            out.append(_finding(
                "stat_stale", "trust", "FAIL", "suggest",
                "Stale undersold headline stat in copy/metadata",
                f'Found "{m.group(0).strip()}" but the live archive holds '
                f'{det:,} detections. Use the __USECASE_COUNT__ placeholder so '
                f'it never goes stale.'))
    # Wrong platform count.
    for m in re.finditer(r'(\d+)\s+(platforms|query languages)', idx_text, re.I):
        if int(m.group(1)) != PLATFORM_COUNT:
            out.append(_finding(
                "platform_count", "copy", "WARN", "suggest",
                "Platform count mismatch",
                f'Copy says "{m.group(0)}" but the site ships '
                f'{PLATFORM_COUNT} query languages.'))
    return out


def check_meta_seo(idx_text):
    out = []
    needed = {
        "title": r"<title>[^<]+</title>",
        "description": r'<meta name="description" content="[^"]+"',
        "canonical": r'rel="canonical"',
        "og:title": r'property="og:title"',
        "twitter:card": r'name="twitter:card"',
        "json-ld": r'application/ld\+json',
    }
    for name, rx in needed.items():
        if not re.search(rx, idx_text):
            out.append(_finding(
                f"meta_missing_{name}", "seo", "FAIL", "suggest",
                f"Missing SEO tag: {name}",
                f"index.html has no {name} tag."))
    # JSON-LD must be valid JSON.
    for m in re.finditer(r'<script type="application/ld\+json">(.*?)</script>',
                         idx_text, re.S):
        try:
            json.loads(m.group(1))
        except Exception as e:
            out.append(_finding(
                "jsonld_invalid", "seo", "FAIL", "suggest",
                "Invalid JSON-LD structured data",
                f"A ld+json block does not parse: {str(e)[:80]}"))
    return out


def check_internal_links(idx_text):
    """href/src to local files that don't exist on disk. SUGGEST."""
    out = []
    seen = set()
    for m in re.finditer(r'(?:href|src)="((?:targets|actors|techniques|data|share|'
                         r'rule_packs|intel)/[^":?#]+|[a-z0-9_-]+\.(?:html|png|css|js|xml|ico))"',
                         idx_text):
        rel = m.group(1)
        if rel in seen:
            continue
        seen.add(rel)
        if not (ROOT / rel).exists():
            out.append(_finding(
                "broken_link", "links", "FAIL", "suggest",
                "Broken internal link/asset",
                f'index.html references "{rel}" which is not on disk.'))
    return out


def check_contrast(gen_text):
    """WCAG AA for the --muted* text vars against --bg. SUGGEST (the fix is a
    specific computed colour — recorded so it's one edit to apply)."""
    out = []
    root = re.search(r":root\s*\{([^}]*)\}", gen_text)
    if not root:
        return out
    block = root.group(1)
    vars_ = dict(re.findall(r"--([a-z0-9-]+)\s*:\s*(#[0-9a-fA-F]{3,6})", block))
    bg = vars_.get("bg") or "#08090a"
    for name in ("muted", "muted-2", "muted-3"):
        if name not in vars_:
            continue
        ratio = _wcag_ratio(vars_[name], bg)
        if ratio < 4.5:
            sugg = _aa_passing_hex(bg)
            out.append(_finding(
                f"contrast_{name}", "a11y", "WARN", "suggest",
                f"--{name} fails WCAG AA ({ratio:.2f}:1)",
                f"--{name}:{vars_[name]} on --bg:{bg} = {ratio:.2f}:1 (needs "
                f"4.5:1 for body text).",
                fix={"file": "generate.py",
                     "old": f"--{name}:{vars_[name]}",
                     "new": f"--{name}:{sugg}"}))
    return out


def check_a11y_basics(idx_text):
    out = []
    if not re.search(r'<html[^>]*\blang="', idx_text):
        out.append(_finding("a11y_lang", "a11y", "FAIL", "suggest",
                            "<html> missing lang attribute", "Add lang=\"en\"."))
    imgs_no_alt = [t for t in re.findall(r"<img\b[^>]*>", idx_text) if "alt=" not in t]
    if imgs_no_alt:
        out.append(_finding("a11y_alt", "a11y", "WARN", "suggest",
                            f"{len(imgs_no_alt)} <img> without alt",
                            "Every image needs alt text."))
    if len(re.findall(r"<h1\b", idx_text)) != 1:
        out.append(_finding("a11y_h1", "a11y", "INFO", "suggest",
                            "Not exactly one <h1>",
                            f"Found {len(re.findall(r'<h1', idx_text))} h1 elements."))
    if "skip-link" not in idx_text:
        out.append(_finding("a11y_skip", "a11y", "WARN", "suggest",
                            "No skip-to-content link",
                            "Add a WCAG 2.4.1 skip link."))
    return out


def check_noise_filter(_):
    """The zero-detection-value filter should drop dev-blog noise, never
    threat-research sources. A research source in drop-novalue = false positive
    (a prompt/filter tuning signal). SUGGEST/PROMPT."""
    out = []
    drops = ROOT / "intel" / "relevance_drops.jsonl"
    if not drops.exists():
        return out
    try:
        import generate as g  # noqa
        nodrop = set(getattr(g, "_NODROP_SOURCES", set()))
    except Exception:
        nodrop = set()
    bad = {}
    for line in drops.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            d = json.loads(line)
        except Exception:
            continue
        if d.get("tier") == "drop-novalue" and d.get("source") in nodrop:
            bad[d.get("source")] = bad.get(d.get("source"), 0) + 1
    if bad:
        out.append(_finding(
            "noise_false_pos", "data-quality", "WARN", "prompt",
            "Noise filter dropped threat-research content",
            f"drop-novalue hit allow-listed sources {dict(bad)} — these should "
            f"never be dropped. Tune the guard or its source allow-list."))
    return out


def check_feed_cache(_):
    """Deep feeds that re-flood every run (e.g. Snyk's full blog history). INFO —
    the real fix is a code recency-window, not a cache trim."""
    out = []
    cache = ROOT / "intel" / ".feed_cache"
    if not cache.exists():
        return out
    for jf in sorted(cache.glob("*.json")):
        try:
            d = json.loads(jf.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(d, list) and len(d) > 800 and jf.stem not in ("cisa-kev",):
            out.append(_finding(
                f"feed_bloat_{jf.stem}", "data-quality", "INFO", "suggest",
                f"Feed cache '{jf.stem}' is large ({len(d)} entries)",
                "Deep feed re-ingested every run; consider a per-source recency "
                "window in code (cache-trimming is futile — refetch re-fills it)."))
    return out


def check_llm_health(_):
    """Detect a stalled LLM backend (expired OAuth / quota) — the failure mode
    that silently produced zero new AI use cases for ~2 days. Two signals:
    (a) the newest UC-cache write is stale despite the 2h pipeline, and
    (b) the latest auto.log run is dominated by `claude CLI rc=1`. FAIL loudly:
    the fix is to re-auth (re-run setup_dual_account.ps1)."""
    out = []
    import time
    cache = ROOT / "intel" / ".llm_uc_cache"
    newest = 0.0
    if cache.exists():
        for f in cache.rglob("*.json"):
            try:
                newest = max(newest, f.stat().st_mtime)
            except OSError:
                pass
    if newest:
        age_h = (time.time() - newest) / 3600
        if age_h > 30:
            out.append(_finding(
                "llm_stale", "data-quality", "FAIL", "suggest",
                f"No new AI use cases in ~{age_h:.0f}h",
                "Newest .llm_uc_cache write is stale despite the 2h pipeline — "
                "the LLM backend is almost certainly down (expired OAuth / quota). "
                "Re-authenticate: re-run setup_dual_account.ps1."))
    log = ROOT / "logs" / "auto.log"
    if log.exists():
        try:
            tail = log.read_text(encoding="utf-8", errors="replace")[-40000:]
            last_run = tail.rsplit("=== run_once start", 1)[-1]
            fails = last_run.count("claude CLI rc=1")
            if fails >= 5:
                out.append(_finding(
                    "llm_auth_fail", "data-quality", "FAIL", "suggest",
                    f"Latest pipeline run had {fails} failing LLM calls",
                    "Repeated `claude CLI rc=1` in the most recent run — LLM calls "
                    "are erroring (typically 401 expired OAuth). Re-run "
                    "setup_dual_account.ps1 to re-authenticate both accounts."))
        except Exception:
            pass
    return out


CHECKS = [
    ("none", check_llm_health),
    ("generate", check_noopener),
    ("index", check_stat_accuracy),
    ("index", check_meta_seo),
    ("index", check_internal_links),
    ("generate", check_contrast),
    ("index", check_a11y_basics),
    ("none", check_noise_filter),
    ("none", check_feed_cache),
]


def run_lint():
    idx = INDEX.read_text(encoding="utf-8", errors="replace") if INDEX.exists() else ""
    gen = GEN.read_text(encoding="utf-8", errors="replace") if GEN.exists() else ""
    findings = []
    for src, fn in CHECKS:
        arg = {"generate": gen, "index": idx, "none": None}[src]
        try:
            findings.extend(fn(arg) or [])
        except Exception as e:  # one broken check never kills the lint
            findings.append(_finding(
                f"lint_error_{fn.__name__}", "meta", "INFO", "suggest",
                f"Lint check {fn.__name__} errored", str(e)[:120]))
    order = {"FAIL": 0, "WARN": 1, "INFO": 2}
    findings.sort(key=lambda f: order.get(f["severity"], 3))
    return findings


def main():
    findings = run_lint()
    if "--json" in sys.argv:
        print(json.dumps(findings, indent=1))
        return
    if not findings:
        print("[lint] clean — no findings.")
        return
    by_tier = {}
    for f in findings:
        by_tier.setdefault(f["tier"], []).append(f)
    print(f"[lint] {len(findings)} finding(s):")
    for f in findings:
        tag = {"auto": "AUTO", "suggest": "SUGG", "prompt": "PROMPT"}[f["tier"]]
        print(f"  [{f['severity']:4s}][{tag:6s}] {f['title']}  —  {f['detail'][:90]}")
    print(f"\n  auto-fixable: {len(by_tier.get('auto', []))} · "
          f"suggestions: {len(by_tier.get('suggest', []))} · "
          f"prompt-signals: {len(by_tier.get('prompt', []))}")


if __name__ == "__main__":
    main()

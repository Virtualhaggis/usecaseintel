# Clankerusecase — Site Review Loop Playbook

A repeatable method for looping reviews of the live site. Written for this
specific build (generate.py → index.html SPA + static pages), encoding the
gotchas that actually bite.

---

## 0. The core idea

A loop only adds value if each pass either (a) runs **deterministic checks** that
catch regressions, or (b) brings **fresh eyes / a new lens**. Re-reading the same
way just re-confirms. So every loop = **harness (scripted) + one judgment lens +
fix + re-verify**, and you *rotate the lens* each pass.

The single highest-leverage move: **turn the repeatable checks into a script**
(`_review_lint.py` below). Then looping is cheap — the script does the boring
80%, and attention goes to the 20% that needs judgment.

Always: **write findings down before starting the next loop, and read the prior
write-up first.** Otherwise loops repeat each other. (This is why this file and a
running `_site_review_log.md` exist.)

---

## 1. Harness — set up once per loop

| Step | Command / action | Why |
|---|---|---|
| Fresh render | `rm -f intel/.pipeline.lock; py -u generate.py > logs/review.log 2>&1` | Live site is **stale** until the 2h scheduler runs; always test a fresh local render, never the live HTML. ~2–3 min (full backlog). |
| Serve | `py -m http.server 8753` (background) | SPA fetches `data/*.json`; `file://` breaks CORS. Must serve over HTTP. |
| Browser | navigate `http://localhost:8753/index.html` | Use a NEW tab; never reuse a tab id across sessions. |
| Baseline | run `_review_lint.py`, save output | Diff against last loop to catch drift. |

**Render tax rule:** a render is the expensive step. **Batch fixes, render at
checkpoints** (every 3–5 fixes), not once per fix. Most edits are static
template/CSS and only need *one* render to confirm; only placeholder-injected
values (`__USECASE_COUNT__`) truly require a render to verify.

---

## 2. The loop cycle

1. **Read** the prior `_site_review_log.md` entry.
2. **Run the harness** (`_review_lint.py`) → automated findings.
3. **Pick the lens** for this loop (rotate — section 5).
4. **Inspect** through that lens: code/grep first (fast triage), browser only to
   confirm visual/interactive/runtime behaviour.
5. **Rank** findings by *impact on a skeptical SOC manager deciding to bookmark &
   reuse*, not by ease.
6. **Fix** the top 1–N in `generate.py` (the source — never edit `index.html`,
   it's regenerated).
7. **Verify**: `py -c "import ast;ast.parse(open('generate.py').read())"` →
   `_smoke_pipeline_changes.py` → render → grep the **rendered output**
   (placeholders resolved) → browser spot-check + `read_console_messages`.
8. **Reassess**: did it actually improve the thing? Note it in the log.
9. **Stop** when the top remaining item is low-value polish or an owner decision.

---

## 3. `_review_lint.py` — the deterministic checks to script

Build this once; it makes every future loop fast and regression-proof. Each check
is something I verified by hand this session — automate them:

- **Stat accuracy**: parse `index.html` for any hardcoded number near
  "use cases / detections / feeds / platforms"; assert it matches
  `_archive_totals(_load_uc_archive())` and the real platform count (7). Flag any
  literal like `2,000+`, `11+ feeds`, "4 platforms". *(This is what bit us — the
  meta description was stale by 3×.)*
- **Stat monotonicity**: archive total must never drop run-to-run (high-water-mark).
- **Meta/SEO presence + accuracy**: exactly one each of title, description,
  canonical, og:*, twitter:*, JSON-LD; description ≤ ~160 useful chars; platform
  list complete; JSON-LD parses as valid JSON.
- **Internal links**: every `href="…html"` / `targets/… / actors/… / techniques/…`
  resolves to a file on disk; every `data/*.json|html` chunk referenced exists.
- **External-link hygiene**: every `target="_blank"` to another origin has
  `rel="noopener"`.
- **Contrast**: compute WCAG ratio for each `--text/--muted/--muted-2/...` against
  `--bg`; assert ≥ 4.5:1 for body text, ≥ 3:1 for large/UI. *(--muted-2 failed.)*
- **A11y basics**: `<html lang>`, every `<img>` has `alt`, single `<h1>`,
  skip-link present, no `outline:none/0` without a focus replacement.
- **Console**: load each tab headless, assert zero console errors.
- **Query validity**: run the existing KQL validators
  (`kql_schema_validator.py`, `tools/kql_syntax_checker`) + a Splunk/Sigma sanity
  pass over a sample of rendered detections; flag structurally broken queries.
- **Noise filter health**: `relevance_drops.jsonl` — assert drops are dominated by
  dev-blog sources, NOT threat-research sources (a research source in
  `drop-novalue` = false positive).
- **Feed-cache sanity**: warn if any `intel/.feed_cache/*.json` balloons (e.g.
  snyk.json's 1,641-entry backlog) — deep feeds re-flood every run.

Output: a ranked list (FAIL/WARN/INFO) + a diff vs the previous run.

---

## 4. What's already strong (don't re-litigate; just guard against regression)

So loops don't waste time re-checking solved things — these were verified solid;
the lint should *guard* them, not the human:

- Methodology page (`about.html`): "what we validate / what we don't", "No
  warranty", "validate before production". Honesty is the trust anchor — keep it.
- Per-detection provenance: technique IDs, log source, FP/tuning notes, source
  link, kill-chain phase, "model-assessed, tune to your environment" caveat.
- Copy-query, 7 platform tabs, Library filters, fast shell load, robots+sitemap.

---

## 5. Review lenses — rotate one per loop

Each loop, pick the next lens. Listed in priority order for the audience.

1. **Trust & methodology** — stat/claim accuracy (roadmap "shipped" items really
   shipped?), no overclaims ("pre-validated" vs efficacy), provenance on every
   detection, contact/accountability.
2. **Detection usability** — open 5 random detections across tiers/platforms:
   query copies clean? log source named? FP guidance? technique link? Does the
   query actually run (validator)? Deep-link `#uc-…` works?
3. **Search & filter** — global search finds art/uc/actor/ioc/technique; works
   *before* heavy chunks load (the `__SEARCH` fallback); Library filter
   combinations narrow correctly; sensible empty/no-result states.
4. **Copy clarity** — terminology + platform counts consistent everywhere; tone
   right for SOC; no marketing fluff; honest caveats.
5. **Mobile** — *automation can't reliably drop below desktop width here* → use
   real DevTools device mode. Check: no horizontal overflow, ≥44px tap targets,
   the heavy tabs (ATT&CK Matrix, Threat Intel IOC table) usable on a phone.
6. **Accessibility** — contrast, focus-visible, skip-link, tab order, modal focus
   trap (logo lightbox, search palette, tour), reduced-motion, screen-reader pass.
   *Note: automated Tab keypress is unreliable here — verify keyboard manually.*
7. **Performance** — shell size, DCL/LCP, per-tab render. The big risk is heavy
   list rendering (IOC table = chunked rAF render; keep it). Watch `data/` chunk
   sizes (actors.json ~10 MB, cards ~57 MB across pages).
8. **SEO** — meta accuracy (lens 1 overlaps), sitemap freshness/coverage, static
   page indexability (techniques/actors/targets/briefings/share), heading order.
9. **Broken links / errors** — console per tab, internal+external links, 404s,
   data-chunk fetch failures, behaviour when a chunk fails to load.
10. **Security** — noopener; no secrets in output; escaping of attacker-derived
    content (article titles, IOCs → XSS); clipboard/dialog safety; CSP headers
    (limited on GitHub Pages — note, can't fully fix).
11. **Data quality** (pipeline-specific) — duplicates, hallucinated ATT&CK IDs,
    structurally broken queries, noise filter precision, stat drift.

---

## 6. Loop variants — vary the *shape*, not just the lens

- **Broad triage sweep** — one pass over all lenses, fix top 5. Good monthly health check.
- **Deep-dive per surface** — exhaust ONE tab/page; rotate tabs across loops.
- **Dimension-locked** — sweep the whole site through ONE lens only (deeper than triage).
- **Regression/diff** — after a scheduler run, diff rendered output vs a saved
  baseline; catch stale stats, new console errors, links broken by new data.
- **Adversarial / skeptic** — review as a hostile SOC manager hunting for reasons
  NOT to trust it. (Surfaces credibility issues the friendly lens misses.)
- **Data-quality** — ignore the chrome; audit the generated detections themselves.

---

## 7. Gotchas (hard-won this session — don't relearn them)

- **Live site ≠ working tree.** The scheduler renders committed `generate.py` every
  2h. Your local render uses a possibly-diverged feed cache. Test locally; deploy
  via commit → scheduler, or an explicit render+commit.
- **Count comes from the cumulative archive**, not the current run. A fresh render
  can "jump" the front-page number simply because `index.html` was stale — that's
  correct, not a bug.
- **Deep RSS feeds re-flood.** Trimming `intel/.feed_cache/snyk.json` is futile —
  the next fetch re-pulls the full history. Fix in code (recency window / filter),
  not in the cache.
- **Never commit user WIP.** Leave `CHANGELOG.md, README.md, quality_review.py,
  requirements.txt, validate_kql_knowledge.py, intel/quality_suggestions.jsonl`
  alone. Stage only the scheduler's artifact set (see `run_once.bat`).
- **Deploy footprint is large** (no-cap + 100-yr lookback). A manual deploy can be
  thousands of files. Prefer committing code and letting the scheduler render.
- **Automation limits:** viewport won't go mobile; Tab/keyboard focus is flaky;
  heavy tabs can time out screenshots. Use code audits + real DevTools for those.
- **Watch the lock.** A scheduler run may hold `intel/.pipeline.lock`; check the
  PID is alive before clearing it, and avoid rendering while it runs.

---

## 8. Stopping criteria & output

**Stop a loop** when the highest-ranked remaining item is low-value polish or an
owner/design decision (branding, OG banner, name).

**Every loop produces** (append to `_site_review_log.md`):
- 1-line before/after per fix, with the *reason*
- files changed + commands run
- what needs manual/owner review
- the single next-best improvement

**Cadence:** lint on every scheduler run (regression); a human/LLM lens-loop
weekly; a full broad sweep before any real launch milestone.

---

## 9. The current "next best" (carry-over)

A purpose-built **1200×630 OG/Twitter share banner** (name + value prop + live
count). The site grows by being shared in security Slack/Teams/LinkedIn, and the
preview is currently a cropped 512×405 logo — the highest-leverage credibility +
growth lever left. Needs design (can't be generated in-pipeline).

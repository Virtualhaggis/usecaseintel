#!/usr/bin/env python3
"""Off-hour quality-review pass.

Runs every 2h at the off-half-hour from the main pipeline (07:30, 09:30,
11:30, ...). Reads the most recent pipeline run's article list, looks up
the IOC/kill-chain/UC cache entries the pipeline produced, and asks
Haiku for a senior-analyst peer review per article. Output:

  intel/quality_review/<article_id>.json   per-article verdict payload
  intel/quality_suggestions.jsonl          append-mode log of new UC
                                            suggestions for the *next*
                                            pipeline run to act on

By design this script does NOT modify any of the pipeline's existing
outputs — it only writes its own review payloads. The feedback loop
(generating UCs from the suggestions log) happens inside generate.py
on the next pipeline run.

Pipeline-lock aware: if generate.py is currently running and holds
intel/.pipeline.lock, this script exits cleanly without touching the
caches that generate.py might be writing to.

Reuses everything heavy from generate.py: the SDK BaseExceptionGroup
monkey-patch, the per-kind OAuth circuit breaker, the cache helpers,
the IOC normaliser. Adds one new prompt + one new helper for the
review-pass-specific call.
"""

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path


HERE = Path(__file__).parent.resolve()
INTEL = HERE / "intel"
REVIEW_DIR = INTEL / "quality_review"
SUGGESTIONS_LOG = INTEL / "quality_suggestions.jsonl"
LOCK_PATH = INTEL / ".pipeline.lock"
LAST_RUN_ARTICLES = INTEL / "last_run_articles.json"
BRIEFINGS_DIR = HERE / "briefings"
ARTICLE_CACHE_DIR = INTEL / ".article_cache"

# Reuse the pipeline's helpers. Importing `generate` triggers its
# module-level loaders (use_cases / rules YAMLs — ~2-3s startup) and
# applies the SDK monkey-patch as a side effect. Both are desired here.
print("[*] Importing pipeline helpers...")
import generate as gen  # noqa: E402  (intentional after constants)


# ---------------------------------------------------------------------
# Review-pass prompt + per-kind breaker entry.
# ---------------------------------------------------------------------

# Register a "review" kind in the existing per-kind breaker so this
# script's failures don't bleed into the pipeline's breaker state.
gen._OAUTH_BREAKERS.setdefault(
    "review",
    {"failures": 0, "open": False, "window": [], "budget": 100, "used": 0},
)


_REVIEW_PROMPT_SYSTEM = (
    "You are a senior SOC detection engineer doing a peer review of "
    "an automated threat-intel pipeline. You read the article body "
    "alongside the IOCs, kill-chain reconstruction, and detection use "
    "cases the pipeline produced, and grade the analysis the way a "
    "team lead would. You are HONEST and SPECIFIC — not sycophantic. "
    "Surface real issues (hallucinated IOCs, mis-mapped techniques, "
    "missing detections for clearly-described attack steps). Return "
    "strict JSON only. No prose. No code fences. No commentary."
)


_REVIEW_PROMPT_USER = (
    "Article title: <<TITLE>>\n"
    "URL:           <<URL>>\n"
    "Severity:      <<SEV>>\n"
    "\n"
    "Body (truncated):\n"
    "<<BODY>>\n"
    "\n"
    "Pipeline output — IOCs:\n"
    "<<IOCS_JSON>>\n"
    "\n"
    "Pipeline output — kill chain reconstruction:\n"
    "<<KC_JSON>>\n"
    "\n"
    "Pipeline output — generated use cases (titles + Splunk + KQL):\n"
    "<<UCS_JSON>>\n"
    "\n"
    "Grade the pipeline's work on THIS article. Be specific. A senior "
    "analyst would do this peer review in 2-3 minutes and emit:\n"
    "  - An overall grade A-D and one paragraph of notes\n"
    "  - A verdict per existing UC (keep / edit / drop with reason)\n"
    "  - New UC suggestions for attack steps the pipeline missed —\n"
    "    cite the article phrase that establishes the gap\n"
    "  - IOC concerns: hallucinated, stale, miscategorised, missing\n"
    "    corroboration\n"
    "  - Threat-actor names or MITRE technique IDs the pipeline\n"
    "    should have surfaced but didn't\n"
    "\n"
    "Return JSON ONLY in this exact shape:\n"
    "{\n"
    "  \"overall_grade\": \"A\" | \"B\" | \"C\" | \"D\",\n"
    "  \"overall_notes\": \"<one paragraph, analyst's voice>\",\n"
    "  \"uc_verdicts\": [\n"
    "    {\n"
    "      \"uc_title\": \"<exact title copied from input>\",\n"
    "      \"verdict\": \"keep\" | \"edit\" | \"drop\",\n"
    "      \"reason\": \"<short reason>\",\n"
    "      \"suggested_edits\": {\n"
    "        \"splunk_spl\": \"<replacement SPL>\" | null,\n"
    "        \"defender_kql\": \"<replacement KQL>\" | null,\n"
    "        \"expected_fp_scenarios\": [\"...\"] | null\n"
    "      }\n"
    "    }\n"
    "  ],\n"
    "  \"new_uc_suggestions\": [\n"
    "    {\n"
    "      \"title\": \"<short detection name>\",\n"
    "      \"rationale\": \"<why missing — cite phrase from article>\",\n"
    "      \"kill_chain_phase\": \"initial_access\" | \"execution\" | \"persistence\" | \"privilege_escalation\" | \"defense_evasion\" | \"credential_access\" | \"discovery\" | \"lateral_movement\" | \"collection\" | \"command_and_control\" | \"exfiltration\" | \"impact\",\n"
    "      \"techniques\": [\"T1059.001\", ...],\n"
    "      \"log_sources\": [\"DeviceProcessEvents\", ...],\n"
    "      \"detection_hypothesis\": \"<2-3 sentences: what to look for>\"\n"
    "    }\n"
    "  ],\n"
    "  \"ioc_concerns\": [\n"
    "    {\n"
    "      \"ioc\": \"<value>\",\n"
    "      \"concern\": \"hallucinated\" | \"stale\" | \"miscategorised\" | \"missing_corroboration\",\n"
    "      \"note\": \"<short>\"\n"
    "    }\n"
    "  ],\n"
    "  \"missing_actors\": [\"<canonical actor name>\"],\n"
    "  \"missing_techniques\": [\"T1059.001\"]\n"
    "}\n"
    "\n"
    "Caps: ≤20 UC verdicts, ≤6 new UC suggestions, ≤10 IOC concerns,\n"
    "≤5 missing actors, ≤10 missing techniques."
)


# ---------------------------------------------------------------------
# Pipeline-lock helpers.
# ---------------------------------------------------------------------

def acquire_lock_or_skip() -> bool:
    """Return True if we acquired the pipeline lock; False if held by
    another live PID and the review pass should exit cleanly.

    Lock file content: a JSON object with `pid`, `started_at`, `kind`.
    A stale lock from a crashed pipeline gets cleaned up automatically
    when the owning PID is no longer running.
    """
    if LOCK_PATH.exists():
        try:
            payload = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
            other_pid = int(payload.get("pid") or 0)
            other_kind = payload.get("kind") or "?"
        except Exception:
            other_pid = 0
            other_kind = "?"
        if other_pid > 0 and _pid_is_alive(other_pid):
            print(f"[!] pipeline lock held by PID {other_pid} ({other_kind}); "
                  f"review pass skipped")
            return False
        else:
            print(f"[*] removing stale lock from PID {other_pid} ({other_kind})")
            try:
                LOCK_PATH.unlink()
            except Exception:
                pass
    try:
        INTEL.mkdir(parents=True, exist_ok=True)
        LOCK_PATH.write_text(json.dumps({
            "pid": os.getpid(),
            "started_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "kind": "quality_review",
        }), encoding="utf-8")
    except Exception as e:
        print(f"[!] failed to write lock: {e}; proceeding without lock")
    return True


def release_lock() -> None:
    """Best-effort lock removal. Only deletes if we still own it."""
    try:
        if LOCK_PATH.exists():
            payload = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
            if int(payload.get("pid") or 0) == os.getpid():
                LOCK_PATH.unlink()
    except Exception:
        pass


def _pid_is_alive(pid: int) -> bool:
    """Cross-platform check whether a PID is still running. On Windows
    we shell out to tasklist; on POSIX we send signal 0."""
    if pid <= 0:
        return False
    if os.name == "nt":
        try:
            import subprocess
            out = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}", "/NH", "/FO", "CSV"],
                capture_output=True, text=True, timeout=10,
            )
            return str(pid) in (out.stdout or "")
        except Exception:
            return True  # Conservative: assume alive if we can't check
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


# ---------------------------------------------------------------------
# Article enumeration: prefer last_run_articles.json, fall back to
# walking briefings/ for the most recent date directories.
# ---------------------------------------------------------------------

def list_recent_articles(top_n: int = 30) -> list[dict]:
    """Return up to top_n articles to review, newest + highest-severity
    first. Each entry: {id, url, title, sev, briefing_path}.

    Prefers intel/last_run_articles.json (written by generate.py at
    end of main()). Falls back to scanning briefings/<recent-date>/ for
    .md files when the registry hasn't been written yet.
    """
    SEV_ORDER = {"crit": 0, "high": 1, "med": 2, "low": 3}

    if LAST_RUN_ARTICLES.exists():
        try:
            data = json.loads(LAST_RUN_ARTICLES.read_text(encoding="utf-8"))
            arts = []
            for a in data:
                arts.append({
                    "id": a.get("id"),
                    "url": a.get("url") or "",
                    "title": a.get("title") or "",
                    "sev": a.get("sev") or "med",
                    "briefing_path": _find_briefing_path(a.get("url") or ""),
                })
            arts.sort(key=lambda x: (SEV_ORDER.get(x["sev"], 9), x["id"] or "zzz"))
            return arts[:top_n]
        except Exception as e:
            print(f"[!] last_run_articles.json unreadable: {e}; "
                  "falling back to briefings/ scan")

    # Fallback: scan briefings/<YYYY-MM-DD>/*.md for the 3 most recent dates
    if not BRIEFINGS_DIR.exists():
        return []
    date_dirs = sorted(
        [p for p in BRIEFINGS_DIR.iterdir() if p.is_dir()],
        reverse=True,
    )[:3]
    arts = []
    art_idx = 0
    for d in date_dirs:
        for md_path in sorted(d.glob("*.md")):
            url, title = _parse_briefing_metadata(md_path)
            if not url:
                continue
            arts.append({
                "id": f"art-{art_idx:02d}",
                "url": url,
                "title": title,
                "sev": "high",  # unknown; assume high to ensure inclusion
                "briefing_path": md_path,
            })
            art_idx += 1
    return arts[:top_n]


def _find_briefing_path(url: str) -> Path | None:
    """Best-effort: walk briefings/ for the most recent .md whose
    body contains the given URL."""
    if not url or not BRIEFINGS_DIR.exists():
        return None
    date_dirs = sorted(
        [p for p in BRIEFINGS_DIR.iterdir() if p.is_dir()],
        reverse=True,
    )[:14]  # last 14 days
    needle = url.strip().lower()
    for d in date_dirs:
        for md_path in d.glob("*.md"):
            try:
                txt = md_path.read_text(encoding="utf-8", errors="ignore").lower()
            except Exception:
                continue
            if needle in txt:
                return md_path
    return None


def _parse_briefing_metadata(md_path: Path) -> tuple[str, str]:
    """Pull (url, title) from a briefing markdown file. Briefings have
    a YAML-ish front matter or pseudo-headers like 'Source URL: ...'."""
    try:
        txt = md_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ("", "")
    # Try common patterns for URL
    url = ""
    for pat in (r"^Source URL:\s*(https?://\S+)",
                r"^URL:\s*(https?://\S+)",
                r"^\s*\*\*Source URL:\*\*\s*(https?://\S+)",
                r"^link:\s*(https?://\S+)"):
        m = re.search(pat, txt, re.MULTILINE | re.IGNORECASE)
        if m:
            url = m.group(1).strip().rstrip(")")
            break
    if not url:
        # Last resort: first https URL in the file
        m = re.search(r"https?://\S+", txt)
        if m:
            url = m.group(0).strip().rstrip(").,>")
    title = ""
    m = re.search(r"^#\s+(.+)$", txt, re.MULTILINE)
    if m:
        title = m.group(1).strip()
    return (url, title)


# ---------------------------------------------------------------------
# Cache lookup: given a URL, find the IOC + KC + UC cache entries.
# ---------------------------------------------------------------------

def _read_body(url: str, briefing_path: Path | None = None) -> str:
    """Return the article body. Tries the article-fetch cache first
    (highest fidelity), then falls back to the briefing markdown."""
    body = ""
    if url:
        url_sha = hashlib.sha1(url.encode("utf-8", "replace")).hexdigest()
        candidate = ARTICLE_CACHE_DIR / f"{url_sha[:2]}/{url_sha}.html"
        if candidate.exists():
            try:
                body = candidate.read_text(encoding="utf-8", errors="ignore")
                # Strip HTML tags very crudely — the LLM doesn't need
                # the markup, just the prose. Reuse generate's HTML
                # stripper if available.
                if hasattr(gen, "_strip_html"):
                    body = gen._strip_html(body)
                else:
                    body = re.sub(r"<[^>]+>", " ", body)
                    body = re.sub(r"\s+", " ", body).strip()
            except Exception:
                body = ""
    if not body and briefing_path is not None and briefing_path.exists():
        try:
            body = briefing_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            body = ""
    return body[:14000]


def _load_ioc_entry(url: str, body: str) -> dict | None:
    """Look up the v3 IOC cache entry; fall back to v2 if v3 missing."""
    if not url or not body:
        return None
    body_sha = hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()[:16]
    # Same key as generate.py's _extract_iocs.
    for version in ("v3", "v2"):
        key = hashlib.sha1(f"{version}|{url}|{body_sha}".encode("utf-8", "replace")).hexdigest()
        path = gen.LLM_IOC_CACHE_DIR / f"{key[:2]}/{key}.json"
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
    return None


def _load_kc_entry(url: str, body: str, ind: dict | None) -> dict | None:
    """Look up the KC cache entry. Requires ind (the IOC dict) because
    the cache key includes a digest of the IOC set."""
    if not url or not body or not ind:
        return None
    body_sha = hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()[:16]
    ioc_digest_input = "|".join([
        ",".join(sorted(ind.get("cves") or [])),
        ",".join(sorted(ind.get("domains") or [])),
        ",".join(sorted(ind.get("ips") or [])),
        ",".join(sorted(ind.get("sha256") or [])),
    ])
    ioc_sha = hashlib.sha1(ioc_digest_input.encode("utf-8", "replace")).hexdigest()[:8]
    key = hashlib.sha1(f"v1|{url}|{body_sha}|{ioc_sha}".encode("utf-8", "replace")).hexdigest()
    path = gen.LLM_KC_CACHE_DIR / f"{key[:2]}/{key}.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _load_uc_entry(url: str) -> dict | None:
    """Look up the UC cache entry — v2 key first, then legacy v1
    (matches the same fallback generate.py uses on read)."""
    if not url:
        return None
    for key_input in (f"v2|{url}", url):
        key = hashlib.sha1(key_input.encode("utf-8", "replace")).hexdigest()
        path = gen.LLM_UC_CACHE_DIR / f"{key[:2]}/{key}.json"
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
    return None


# ---------------------------------------------------------------------
# LLM reviewer call.
# ---------------------------------------------------------------------

def _llm_review_call(prompt: str) -> dict | None:
    """Call the reviewer Haiku via the OAuth path. Returns the parsed
    JSON dict or None on failure (no retry; failures count against the
    'review' kind's rolling-window breaker)."""
    use_oauth = os.environ.get("USECASEINTEL_USE_CLAUDE_OAUTH", "").lower() in ("1", "true", "yes")
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if gen._oauth_circuit_open("review"):
        return None

    raw = None
    if use_oauth:
        # Direct `claude -p` subprocess via the shared helper in generate.
        raw = gen._call_claude_cli(
            prompt,
            model=gen.LLM_RELEVANCE_MODEL,
            allowed_tools=None,
            system_prompt=_REVIEW_PROMPT_SYSTEM,
            timeout=gen._OAUTH_RELEVANCE_CALL_TIMEOUT_SEC * 2,
        )
        if raw:
            gen._note_oauth_success("review")
        else:
            gen._note_oauth_failure("review CLI no result", kind="review")
    if raw is None and api_key:
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=api_key)
            msg = client.messages.create(
                model=gen.LLM_RELEVANCE_MODEL,
                max_tokens=3000,
                system=_REVIEW_PROMPT_SYSTEM,
                messages=[{"role": "user", "content": prompt}],
            )
            raw = "".join(b.text for b in msg.content if hasattr(b, "text"))
        except Exception:
            raw = None
    if not raw:
        return None
    raw = raw.strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json)?\s*", "", raw)
        raw = re.sub(r"\s*```\s*$", "", raw)
    m = re.search(r"\{[\s\S]*\}", raw)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except Exception:
        return None


def _normalise_review(d: dict) -> dict | None:
    """Coerce the LLM's review JSON into the canonical schema, dropping
    fields that don't match the expected shape. Returns None if the
    response is unusable."""
    if not isinstance(d, dict):
        return None
    out = {}
    grade = str(d.get("overall_grade") or "").strip().upper()
    out["overall_grade"] = grade if grade in ("A", "B", "C", "D") else "C"
    out["overall_notes"] = str(d.get("overall_notes") or "").strip()[:1000]

    verdicts = d.get("uc_verdicts") or []
    out["uc_verdicts"] = []
    if isinstance(verdicts, list):
        for v in verdicts[:20]:
            if not isinstance(v, dict):
                continue
            verdict = str(v.get("verdict") or "").lower().strip()
            if verdict not in ("keep", "edit", "drop"):
                continue
            edits = v.get("suggested_edits") or {}
            out["uc_verdicts"].append({
                "uc_title": str(v.get("uc_title") or "").strip()[:200],
                "verdict": verdict,
                "reason": str(v.get("reason") or "").strip()[:400],
                "suggested_edits": {
                    "splunk_spl": (str(edits.get("splunk_spl"))[:4000]
                                   if edits.get("splunk_spl") else None),
                    "defender_kql": (str(edits.get("defender_kql"))[:4000]
                                     if edits.get("defender_kql") else None),
                    "expected_fp_scenarios": (
                        [str(x).strip()[:200] for x in (edits.get("expected_fp_scenarios") or [])][:6]
                        if isinstance(edits.get("expected_fp_scenarios"), list) else None
                    ),
                } if isinstance(edits, dict) else {},
            })

    valid_phases = (
        "initial_access", "execution", "persistence", "privilege_escalation",
        "defense_evasion", "credential_access", "discovery",
        "lateral_movement", "collection", "command_and_control",
        "exfiltration", "impact",
    )
    suggestions = d.get("new_uc_suggestions") or []
    out["new_uc_suggestions"] = []
    if isinstance(suggestions, list):
        for s in suggestions[:6]:
            if not isinstance(s, dict):
                continue
            title = str(s.get("title") or "").strip()
            if not title or len(title) < 4:
                continue
            phase = str(s.get("kill_chain_phase") or "").lower().strip()
            if phase not in valid_phases:
                phase = ""
            techs = s.get("techniques") or []
            if isinstance(techs, str):
                techs = [techs]
            if not isinstance(techs, list):
                techs = []
            techs_clean = [str(t).strip().upper() for t in techs
                           if t and re.match(r"^T\d{4}(?:\.\d{3})?$", str(t).strip().upper())][:6]
            log_sources = s.get("log_sources") or []
            if isinstance(log_sources, str):
                log_sources = [log_sources]
            if not isinstance(log_sources, list):
                log_sources = []
            logs_clean = [str(x).strip()[:80] for x in log_sources
                          if x and isinstance(x, str)][:6]
            out["new_uc_suggestions"].append({
                "title": title[:160],
                "rationale": str(s.get("rationale") or "").strip()[:500],
                "kill_chain_phase": phase,
                "techniques": techs_clean,
                "log_sources": logs_clean,
                "detection_hypothesis": str(s.get("detection_hypothesis") or "").strip()[:800],
            })

    concerns = d.get("ioc_concerns") or []
    out["ioc_concerns"] = []
    if isinstance(concerns, list):
        for c in concerns[:10]:
            if not isinstance(c, dict):
                continue
            ctype = str(c.get("concern") or "").lower().strip()
            if ctype not in ("hallucinated", "stale", "miscategorised",
                             "miscategorized", "missing_corroboration"):
                continue
            out["ioc_concerns"].append({
                "ioc": str(c.get("ioc") or "").strip()[:300],
                "concern": ctype.replace("miscategorized", "miscategorised"),
                "note": str(c.get("note") or "").strip()[:300],
            })

    actors = d.get("missing_actors") or []
    if isinstance(actors, str):
        actors = [actors]
    out["missing_actors"] = [str(a).strip()[:80] for a in (actors if isinstance(actors, list) else [])
                             if a and isinstance(a, str)][:5]

    techs = d.get("missing_techniques") or []
    if isinstance(techs, str):
        techs = [techs]
    out["missing_techniques"] = [str(t).strip().upper() for t in (techs if isinstance(techs, list) else [])
                                 if t and re.match(r"^T\d{4}(?:\.\d{3})?$", str(t).strip().upper())][:10]
    return out


def _build_review_prompt(article: dict, body: str, ind: dict | None,
                         kc: dict | None, uc_data: dict | None) -> str:
    """Render the review prompt with all the context the LLM needs."""
    # Slim IOC payload to keep token cost down.
    if ind:
        ind_slim = {
            "cves": (ind.get("cves") or [])[:15],
            "ips": (ind.get("ips") or [])[:15],
            "domains": (ind.get("domains") or [])[:15],
            "sha256": (ind.get("sha256") or [])[:8],
            "sha1": (ind.get("sha1") or [])[:8],
            "md5": (ind.get("md5") or [])[:8],
            "software": (ind.get("software") or [])[:10],
            "campaign": ind.get("campaign") or "",
            "actors": (ind.get("actors") or [])[:5],
            "confidence_by_ioc": ind.get("confidence_by_ioc") or {},
        }
    else:
        ind_slim = {}
    kc_slim = {"phases": (kc or {}).get("phases") or [],
               "overall_summary": (kc or {}).get("overall_summary") or ""}
    ucs_slim = []
    for u in ((uc_data or {}).get("ucs") or [])[:8]:
        if not isinstance(u, dict):
            continue
        ucs_slim.append({
            "title": (u.get("title") or "")[:200],
            "kill_chain_phase": u.get("kill_chain_phase") or "",
            "techniques": [(t.get("id") if isinstance(t, dict) else t)
                           for t in (u.get("techniques") or [])][:5],
            "splunk_spl": (u.get("splunk_spl") or "")[:1200],
            "defender_kql": (u.get("defender_kql") or "")[:1200],
            "rationale": (u.get("rationale") or "")[:400],
        })
    return (_REVIEW_PROMPT_USER
            .replace("<<TITLE>>", (article.get("title") or "")[:240])
            .replace("<<URL>>", (article.get("url") or "")[:240])
            .replace("<<SEV>>", (article.get("sev") or "med"))
            .replace("<<BODY>>", body[:11000])
            .replace("<<IOCS_JSON>>", json.dumps(ind_slim, ensure_ascii=False))
            .replace("<<KC_JSON>>", json.dumps(kc_slim, ensure_ascii=False))
            .replace("<<UCS_JSON>>", json.dumps(ucs_slim, ensure_ascii=False)))


# ---------------------------------------------------------------------
# Per-article review + output writers.
# ---------------------------------------------------------------------

def review_article(article: dict) -> dict | None:
    """Run the full review for one article. Returns the normalised dict
    on success, None on any failure (LLM unavailable, body unloadable,
    cache missing)."""
    url = article.get("url") or ""
    body = _read_body(url, article.get("briefing_path"))
    if not body or len(body) < 400:
        return None
    ind = _load_ioc_entry(url, body)
    kc = _load_kc_entry(url, body, ind) if ind else None
    uc_data = _load_uc_entry(url)
    prompt = _build_review_prompt(article, body, ind, kc, uc_data)
    raw = _llm_review_call(prompt)
    if not raw:
        return None
    return _normalise_review(raw)


def write_article_review(article_id: str, review: dict) -> None:
    REVIEW_DIR.mkdir(parents=True, exist_ok=True)
    payload = dict(review)
    payload["_meta"] = {
        "article_id": article_id,
        "ts": dt.datetime.now(dt.timezone.utc).isoformat(),
    }
    (REVIEW_DIR / f"{article_id}.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8")


def append_suggestions(article_id: str, article_url: str, review: dict) -> int:
    """Append new UC suggestions to the JSONL log. Returns count
    appended."""
    suggestions = review.get("new_uc_suggestions") or []
    if not suggestions:
        return 0
    SUGGESTIONS_LOG.parent.mkdir(parents=True, exist_ok=True)
    ts = dt.datetime.now(dt.timezone.utc).isoformat()
    with open(SUGGESTIONS_LOG, "a", encoding="utf-8") as fh:
        for s in suggestions:
            fh.write(json.dumps({
                "article_id": article_id,
                "article_url": article_url,
                "suggestion": s,
                "ts": ts,
            }, ensure_ascii=False) + "\n")
    return len(suggestions)


# ---------------------------------------------------------------------
# Main.
# ---------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Off-hour quality-review pass")
    parser.add_argument("--top-n", type=int, default=30,
                        help="Max articles to review (default 30)")
    parser.add_argument("--article-url", type=str, default=None,
                        help="Review a single article by URL (smoke test)")
    parser.add_argument("--force", action="store_true",
                        help="Ignore pipeline lock and proceed anyway")
    args = parser.parse_args()

    if not args.force and not acquire_lock_or_skip():
        return 0

    try:
        gen._reset_oauth_circuit_breaker()

        if args.article_url:
            articles = [{
                "id": "art-smoke",
                "url": args.article_url,
                "title": "(smoke test)",
                "sev": "high",
                "briefing_path": _find_briefing_path(args.article_url),
            }]
            print(f"[*] Smoke test on {args.article_url}")
        else:
            articles = list_recent_articles(top_n=args.top_n)
            print(f"[*] Reviewing top {len(articles)} articles "
                  f"(target {args.top_n}, sev-ordered)")

        if not articles:
            print("[!] No articles to review")
            return 0

        reviewed = 0
        suggestions_total = 0
        concerns_total = 0
        actors_total = 0
        skipped = 0
        grade_counts = {"A": 0, "B": 0, "C": 0, "D": 0}

        for i, article in enumerate(articles, 1):
            article_id = article.get("id") or f"art-{i:02d}"
            url = article.get("url") or ""
            title = (article.get("title") or "")[:60]
            print(f"  [{i:02d}/{len(articles)}] {title:<60s} -> ", end="", flush=True)

            t_start = time.time()
            review = review_article(article)
            t_elapsed = int(time.time() - t_start)

            if review is None:
                print(f"skip ({t_elapsed}s)")
                skipped += 1
                continue

            write_article_review(article_id, review)
            new_suggestions = append_suggestions(article_id, url, review)
            suggestions_total += new_suggestions
            concerns_total += len(review.get("ioc_concerns") or [])
            actors_total += len(review.get("missing_actors") or [])
            grade_counts[review.get("overall_grade") or "C"] = (
                grade_counts.get(review.get("overall_grade") or "C", 0) + 1)
            reviewed += 1
            verdicts = review.get("uc_verdicts") or []
            keeps = sum(1 for v in verdicts if v.get("verdict") == "keep")
            edits = sum(1 for v in verdicts if v.get("verdict") == "edit")
            drops = sum(1 for v in verdicts if v.get("verdict") == "drop")
            print(f"grade={review.get('overall_grade')} "
                  f"ucs={keeps}k/{edits}e/{drops}d "
                  f"new={new_suggestions} ({t_elapsed}s)")

        print()
        print(f"[*] Quality review: {reviewed} articles reviewed, "
              f"{skipped} skipped, "
              f"{suggestions_total} new UC suggestions, "
              f"{concerns_total} IOC concerns, "
              f"{actors_total} missing actors")
        print(f"    Grades: A={grade_counts['A']} B={grade_counts['B']} "
              f"C={grade_counts['C']} D={grade_counts['D']}")
        review_bk = gen._OAUTH_BREAKERS.get("review", {})
        if review_bk.get("open"):
            print(f"[!] Review breaker tripped at "
                  f"{review_bk.get('failures', 0)}/{len(review_bk.get('window', []))} "
                  f"failures")
        return 0
    finally:
        release_lock()


if __name__ == "__main__":
    sys.exit(main() or 0)

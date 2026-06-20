"""Bi-weekly threat-synthesis: cluster the last 14 days of articles into
themes, call Claude with a cross-article synthesis prompt, and emit
high-fidelity multi-platform detection UCs into use_cases/weekly/<YYYY-WW>/.

Each UC carries:
  • A rich `description` explaining what it detects, *why* it matters
    this fortnight, and which articles drove it
  • All seven platform queries (Defender KQL / Sentinel KQL / Sigma /
    Splunk SPL / Datadog / Falcon LogScale / CloudWatch Logs Insights)
    when expressible
  • Phase 1C analyst fields: expected FP scenarios, a triage→contain→hunt
    response runbook, and an optional FP-suppressing filter clause
  • Tier=alerting (synthesised from multiple corroborating sources, so
    higher confidence than per-article UCs)
  • A `[WEEKLY] ` title prefix so the Detection Library can filter them

Every emitted UC passes the same validation stack as the per-article
path (KQL schema + syntax, SPL structure + CIM dataset/field check,
Sigma, Datadog/Falcon/CloudWatch shape, side-effect quarantine), with
one corrective re-prompt when the first attempt has issues. SPL that
still fails CIM validation after the retry is dropped rather than
committed — it would turn the validate.py CI gate red.

Run weekly (Sunday evening fits well):
    python biweekly_review.py
    python biweekly_review.py --apply              # actually write YAMLs
    python biweekly_review.py --window 14          # default 14
    python biweekly_review.py --max-themes 8       # default 8
    python biweekly_review.py --best-fidelity      # full bodies + WebSearch

The pipeline picks the YAMLs up automatically on the next run — they
appear in the Library, ATT&CK Matrix, and on individual article cards
that match their MITRE techniques.
"""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

# Reuse generate.py's LLM transport, prompt scaffolding, and validator.
sys.path.insert(0, str(Path(__file__).parent))
import generate as g  # noqa: E402

ROOT = Path(__file__).parent
BRIEFINGS_DIR = ROOT / "briefings"
WEEKLY_OUT_DIR = ROOT / "use_cases" / "weekly"
BRIEFING_OUT_DIR = ROOT / "briefings" / "_weekly"


# =============================================================================
# Article gathering — pull metadata from the briefings markdown corpus
# =============================================================================

# Briefing front-matter looks like:
#   # [HIGH] Article title
#   **Source:** ESET WeLiveSecurity
#   **Published:** 2026-05-07
#   **Article:** https://...
# Followed by the analyst-style sections (IOCs, ATT&CK, etc.).

_PUB_DIR_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _read_briefing(path: Path) -> dict | None:
    """Best-effort parse of a briefing markdown into a structured dict."""
    try:
        text = path.read_text(encoding="utf-8")
    except Exception:
        return None
    title_m = re.search(r"^#\s*(?:\[[A-Z]+\]\s*)?(.+?)$", text, re.MULTILINE)
    src_m   = re.search(r"^\*\*Source:\*\*\s*(.+?)$", text, re.MULTILINE)
    pub_m   = re.search(r"^\*\*Published:\*\*\s*(.+?)$", text, re.MULTILINE)
    link_m  = re.search(r"^\*\*Article:\*\*\s*(\S+)$", text, re.MULTILINE)
    cve_set = set(re.findall(r"\bCVE-\d{4}-\d{4,7}\b", text))
    ttp_set = set(re.findall(r"\b(T\d{4}(?:\.\d{3})?)\b", text))
    title = (title_m.group(1).strip() if title_m else path.stem.replace("-", " "))
    return {
        "path": str(path.relative_to(ROOT)),
        "title": title,
        "source": (src_m.group(1).strip() if src_m else ""),
        "published": (pub_m.group(1).strip() if pub_m else ""),
        "link": (link_m.group(1).strip() if link_m else ""),
        "cves": sorted(cve_set),
        "techniques": sorted(ttp_set),
        "body": text,
        "slug": path.stem,
        "date_dir": path.parent.name,
    }


def gather_recent(window_days: int) -> list[dict]:
    """Return briefing metadata for every article published in the last
    `window_days` days. Walks briefings/YYYY-MM-DD/."""
    cutoff = dt.date.today() - dt.timedelta(days=window_days)
    out: list[dict] = []
    if not BRIEFINGS_DIR.exists():
        return out
    for day_dir in sorted(BRIEFINGS_DIR.iterdir()):
        if not day_dir.is_dir() or not _PUB_DIR_RE.match(day_dir.name):
            continue
        try:
            d = dt.date.fromisoformat(day_dir.name)
        except ValueError:
            continue
        if d < cutoff:
            continue
        for md in sorted(day_dir.glob("*.md")):
            if md.name.startswith("_"):
                continue
            entry = _read_briefing(md)
            if entry:
                out.append(entry)
    return out


# =============================================================================
# Clustering — group articles into themes
# =============================================================================
#
# Three signals carry the strongest "same campaign" weight:
#   1. Shared CVE             — `CVE-2026-NNNN` appearing in ≥2 articles
#   2. Shared actor name      — when an actor shows up in titles or bodies
#   3. Shared title-tokens    — Jaccard ≥ 0.4 on tokenised titles
#
# Each article can land in multiple clusters; we pick the top N by article-
# count after merging clusters that overlap significantly.

# Lightweight actor-name catalogue used for clustering. The full list lives
# in generate.py's actor index but copy-pasting it here keeps biweekly_review
# self-contained and resilient to actor-list churn.
_ACTOR_HINTS = [
    "APT28", "APT29", "APT37", "APT41", "FIN7", "Lazarus", "Kimsuky",
    "MuddyWater", "ScarCruft", "Volt Typhoon", "Salt Typhoon", "Storm-",
    "Cozy Bear", "Fancy Bear", "Sandworm", "Turla", "Gamaredon",
    "Cobalt Strike", "Conti", "LockBit", "BlackCat", "ALPHV", "Akira",
    "Rhysida", "RansomHub", "Qilin", "Play Ransomware", "BlackSuit",
    "Scattered Spider", "Tropic Trooper", "DragonFly", "Berserk Bear",
    "OceanLotus", "ScarCruft", "MoustachedBouncer", "PlushDaemon",
    "Chinese", "Russian", "North Korean", "Iranian",
]


def _tokens(s: str) -> set[str]:
    return {t for t in re.findall(r"[A-Za-z0-9]{3,}", s.lower())
            if t not in {"the", "and", "for", "with", "from", "via",
                          "new", "via", "into", "uses", "used", "vulnerability",
                          "vulnerabilities", "attack", "attacks", "exploits",
                          "exploit", "malware", "campaign", "ransomware", "cve",
                          "alert", "report", "warning", "operation",
                          "compromise", "compromises", "compromised"}}


def _actors_in(text: str) -> set[str]:
    found: set[str] = set()
    lower = text.lower()
    for a in _ACTOR_HINTS:
        if a.lower() in lower:
            found.add(a)
    return found


def cluster_articles(articles: list[dict], min_cluster_size: int = 2) -> list[dict]:
    """Return clusters: list of {key, label, articles, signals}."""
    by_cve: dict[str, list[dict]] = defaultdict(list)
    by_actor: dict[str, list[dict]] = defaultdict(list)
    for a in articles:
        for cve in a["cves"]:
            by_cve[cve].append(a)
        for actor in _actors_in(a["title"] + "\n" + a["body"][:4000]):
            by_actor[actor].append(a)

    clusters: list[dict] = []

    # CVE clusters — strongest signal, every CVE that landed in ≥2 articles
    for cve, arts in by_cve.items():
        if len(arts) < min_cluster_size:
            continue
        clusters.append({
            "key": f"cve:{cve}",
            "label": f"CVE {cve}",
            "articles": arts,
            "signals": {"cve": cve},
        })

    # Actor clusters — same actor name across multiple articles
    for actor, arts in by_actor.items():
        if len(arts) < min_cluster_size:
            continue
        clusters.append({
            "key": f"actor:{actor}",
            "label": f"Actor: {actor}",
            "articles": arts,
            "signals": {"actor": actor},
        })

    # Title-token clusters — only when CVE/actor signals didn't already group
    # the same articles. Heuristic-narrowed stoplist to avoid generic terms
    # like "exploited", "phishing", "critical" that catch too much.
    THEME_STOPLIST = {
        # Generic news / journalism vocab
        "hackers", "security", "cyber", "data", "threat", "users",
        "service", "system", "software", "network", "alert", "warns",
        "warning", "report", "campaign", "operation", "incident",
        "exploits", "exploit", "exploited", "exploitation", "exploiting",
        "vulnerability", "vulnerabilities", "vulnerable", "flaw", "flaws",
        "malware", "ransomware", "infostealer", "stealer", "trojan",
        "phishing", "phish", "phishers",
        "critical", "high", "severe", "important",
        "code", "execution", "remote",
        "active", "actively", "spotted", "discovered", "detected", "uses",
        "using", "used", "abuse", "abused", "abusing",
        "new", "old", "first", "latest", "recent",
        "attack", "attacks", "attacker", "attackers", "attacking",
        "via", "into", "from", "with",
        "year", "month", "day", "week", "today",
        # Vendor / OS names — too broad for useful clustering
        "google", "microsoft", "apple", "amazon", "windows", "linux",
        "macos", "android", "ios", "office", "outlook", "teams", "azure",
        "aws", "gcp", "github", "gitlab", "okta", "datadog", "sentinel",
        # Years / numbers
        "2024", "2025", "2026", "2027",
        # Filing / advisory bodies + feed-name tokens (GHSA titles all start
        # with "GHSA:" so the token clusters 30+ unrelated advisories)
        "cisa", "kev", "nvd", "mitre", "fbi", "nsa", "csa", "ghsa",
        # Polysemous attack-class tokens — "chain" mixes supply-chain /
        # exploit-chain / infection-chain; "injection" mixes SQLi / prompt /
        # process injection. Real clusters form on the specific tokens
        # (npm, typosquat, langgraph, …) instead.
        "chain", "injection",
        # Generic action verbs
        "release", "released", "patch", "patched", "patches", "update",
        "updates", "fix", "fixed", "fixes", "actively",
    }
    token_counts: Counter[str] = Counter()
    token_articles: dict[str, list[dict]] = defaultdict(list)
    for a in articles:
        for t in _tokens(a["title"]):
            if t in THEME_STOPLIST:
                continue
            token_counts[t] += 1
            token_articles[t].append(a)
    for t, n in token_counts.most_common():
        if n < 4:
            break  # high bar for title-token clustering
        clusters.append({
            "key": f"theme:{t}",
            "label": f"Theme: {t}",
            "articles": token_articles[t],
            "signals": {"keyword": t},
        })

    # Dedupe overlapping clusters — keep the larger when two clusters share
    # ≥75% of their articles.
    clusters.sort(key=lambda c: -len(c["articles"]))
    kept: list[dict] = []
    seen_path_sets: list[set[str]] = []
    for c in clusters:
        paths = {a["path"] for a in c["articles"]}
        merge = False
        for prev in seen_path_sets:
            inter = len(paths & prev)
            smaller = min(len(paths), len(prev))
            if smaller and inter / smaller >= 0.75:
                merge = True
                break
        if merge:
            continue
        kept.append(c)
        seen_path_sets.append(paths)
    return kept


# =============================================================================
# LLM synthesis prompt — cross-article, kill-chain-aware
# =============================================================================

# Reuse generate.py's KQL knowledge + Datadog schema blocks so the LLM
# generates schema-correct queries.
_KQL_KNOWLEDGE_BLOCK = (
    g._KQL_KNOWLEDGE_BLOCK
    if hasattr(g, "_KQL_KNOWLEDGE_BLOCK")
    else g._load_kql_knowledge() if hasattr(g, "_load_kql_knowledge") else ""
)
_DATADOG_KNOWLEDGE_BLOCK = (
    g._DATADOG_KNOWLEDGE_BLOCK
    if hasattr(g, "_DATADOG_KNOWLEDGE_BLOCK")
    else g._load_datadog_knowledge() if hasattr(g, "_load_datadog_knowledge") else ""
)


_WEEKLY_PROMPT = """You are a senior detection engineer doing a fortnightly threat-intel review.

Below are <<N>> articles published in the last 14 days that all describe the SAME campaign / tradecraft / vulnerability. Your job is to synthesise ONE high-fidelity, multi-platform detection use case that catches the COMMON pattern across these articles — not any single article's specific IOCs.

What "good" looks like:
  - Detects the TTP, not the IOC. IOCs rotate weekly; the technique persists. Reference IOCs only as substitution slots (`<sha256_list>`, `<c2_domain_list>`) so the UC stays useful as new IOCs land.
  - Multi-stage temporal correlation when the campaign has stages (e.g. "outbound to staging-domain within 5 minutes of script-host process start"). Use KQL `summarize`, SPL `tstats` + `streamstats`, or Datadog rule-level grouping for cross-event windows.
  - Cross-platform parity: the same logic expressed in Defender KQL, Sentinel KQL, Sigma (where the single-event-shape fits), Splunk SPL with CIM datamodels, Datadog logs query, CrowdStrike Falcon LogScale, and AWS CloudWatch Logs Insights — all schema-correct. Leave a platform's field as an empty string when the detection genuinely isn't expressible on its telemetry; never emit a guessed query.
  - Alert-grade by default. These come from multi-source corroboration so the bar is higher than a per-article hunch.

A WEEKLY UC is NOT:
  - A copy-paste of the article's IOC table (those rotate)
  - A generic technique template (we already have those)
  - A duplicate of an existing UC (the catalog includes both internal hand-built UCs and 22+ Datadog default rules — DON'T re-emit those concepts; synthesise something new the catalogue doesn't already cover)

The `description` field MUST explain, in 4-6 sentences:
  1. What activity the UC detects (the chain / TTP)
  2. WHY it matters this fortnight — which campaign / actors / CVEs drove it (cite the article titles)
  3. The kill-chain stages it spans
  4. When it would fire vs when it would NOT (so analysts know what to expect)

Reply with JSON only. No commentary. This exact shape:
```json
{
  "title": "Short, distinct title — DO NOT prefix with [WEEKLY] (the pipeline does that)",
  "description": "4-6 sentence multi-sentence rationale (covers what / why this fortnight / kill-chain stages / when fires & when not)",
  "kill_chain": "delivery | exploit | install | c2 | actions   (PRIMARY phase; cross-stage queries pick the most-evident phase)",
  "techniques": [{"id": "T####", "name": "Official MITRE name"}, ...],
  "data_models": ["Endpoint.Processes", "Network_Traffic.All_Traffic", ...],
  "splunk_spl": "<full SPL query, CIM-conformant, multi-stage if applicable>",
  "defender_kql": "<full Microsoft Defender Advanced Hunting KQL>",
  "sentinel_kql": "<full Microsoft Sentinel KQL — uses TimeGenerated. Empty string if not expressible on Sentinel telemetry>",
  "sigma_yaml": "<OPTIONAL platform-neutral Sigma rule. Emit ONLY when the joint pattern fits Sigma's single-event detection: schema. Multi-stage correlations don't fit Sigma — leave empty in those cases.>",
  "datadog_query": "<Datadog Cloud SIEM logs query — case-sensitive, source: + @field.path:value. Empty string if not expressible on Datadog telemetry.>",
  "falcon_logscale_query": "<CrowdStrike Falcon LogScale (NG-SIEM) query targeting FDR event_simpleName schemas (ProcessRollup2 / DnsRequest / NetworkConnectIP4 / FileWritten / AsepValueUpdate …). Empty string if not expressible on Falcon FDR telemetry.>",
  "cloudwatch_query": "<AWS CloudWatch Logs Insights query (fields | filter | stats | sort) against CloudTrail / VPC Flow / IAM log groups, with a leading `# log group:` comment. Empty string if not expressible on CloudWatch telemetry.>",
  "confidence": "High | Medium | Low",
  "tier": "alerting | hunting",
  "fp_rate_estimate": "low | medium | high",
  "required_telemetry": ["Sysmon EID 1", "Defender DeviceProcessEvents", "Sentinel SecurityEvent", ...],
  "kill_chain_phase": "initial_access | execution | persistence | privilege_escalation | defense_evasion | credential_access | discovery | lateral_movement | collection | command_and_control | exfiltration | impact",
  "expected_fp_scenarios": ["3-5 concrete false-positive scenarios an analyst would see in production", ...],
  "response_runbook": "3-step SOC playbook (1) Triage: … 2) Contain: … 3) Hunt: …) — under 200 words",
  "false_positive_filters": "<OPTIONAL KQL/SPL where-clause that suppresses the expected FPs without losing true positives. Empty string if no clean refinement exists.>",
  "rationale": "1-2 sentences on WHY this catches the joint pattern across these articles specifically",
  "_articles": ["briefings/<date>/<slug>.md", ...]
}
```

SPL CIM RULES — every fortnightly batch so far has violated at least one of
these and failed the validate.py CI gate. They are HARD requirements:
  1. datamodel paths are EXACT: Endpoint.Processes / Endpoint.Filesystem /
     Endpoint.Registry / Network_Traffic.All_Traffic / Network_Resolution.DNS /
     Authentication.Authentication / Change.All_Changes / Web /
     Email.All_Email / Vulnerabilities. NEVER bare `datamodel=Network_Traffic`
     and NEVER `Web.Web`.
  2. Network_Traffic.All_Traffic has NO url / dest_host / dest_hostname /
     process / process_guid fields. It carries the network 4-tuple plus app,
     user, bytes, action. Domain matching uses All_Traffic.dest; URL-path or
     user-agent matching needs the Web datamodel (Web.url,
     Web.http_user_agent) — or drop that clause entirely.
  3. The Endpoint.Processes command-line field is Processes.process — there
     is NO Processes.process_command_line.
  4. Change.All_Changes: stick to action / command / dest / dvc /
     object_category / object_id / result / status / user.

CONTEXT — ARTICLES IN SCOPE
================================================================
<<ARTICLE_BLOCK>>

================================================================
KQL HOUSE STYLE (Defender + Sentinel)
================================================================
<<KQL_KNOWLEDGE>>

================================================================
DATADOG CLOUD SIEM SCHEMA + QUERY SYNTAX
================================================================
<<DATADOG_SCHEMA>>
================================================================
FALCON LOGSCALE (CROWDSTRIKE NG-SIEM) REFERENCE
================================================================
<<FALCON_SCHEMA>>
================================================================
AWS CLOUDWATCH LOGS INSIGHTS REFERENCE
================================================================
<<CLOUDWATCH_SCHEMA>>
================================================================

Output the JSON now."""


def _format_article_block(arts: list[dict], max_body_chars: int) -> str:
    parts = []
    for i, a in enumerate(arts):
        body = (a["body"] or "").strip()
        if len(body) > max_body_chars:
            body = body[:max_body_chars].rstrip() + "\n[…body truncated…]"
        parts.append(
            f"### Article {i+1}: {a['title']}\n"
            f"**Source:** {a['source']}\n"
            f"**Published:** {a['published']}\n"
            f"**Slug:** {a['slug']}\n"
            f"**CVEs:** {', '.join(a['cves']) or '—'}\n"
            f"**Mentioned techniques:** {', '.join(a['techniques']) or '—'}\n\n"
            f"{body}\n"
        )
    return "\n---\n".join(parts)


def _sample_cluster(arts: list[dict], max_articles: int = 12) -> list[dict]:
    """Cap a cluster's articles at max_articles. Prefer source-diversity
    (don't feed the LLM 12 articles from THN — feed 2 from THN, 2 from
    BleepingComputer, 2 from ESET, etc.) to maximise the cross-source
    corroboration signal that justifies a high-confidence weekly UC."""
    if len(arts) <= max_articles:
        return arts
    by_source: dict[str, list[dict]] = defaultdict(list)
    for a in arts:
        by_source[a.get("source") or "Unknown"].append(a)
    # Round-robin pick, prefer more-recent within each source
    for src in by_source:
        by_source[src].sort(key=lambda x: x.get("published", ""), reverse=True)
    picked: list[dict] = []
    while len(picked) < max_articles:
        progress = False
        for src in list(by_source.keys()):
            if by_source[src]:
                picked.append(by_source[src].pop(0))
                progress = True
                if len(picked) >= max_articles:
                    break
        if not progress:
            break
    return picked


def build_prompt(cluster: dict, max_body_chars: int = 4000,
                  max_articles: int = 12) -> str:
    arts = _sample_cluster(cluster["articles"], max_articles=max_articles)
    block = _format_article_block(arts, max_body_chars)
    # Article-aware knowledge selection (generate._kql_knowledge_for): the
    # slim base plus only the example queries / table recipes matching the
    # cluster's TTP shape. Falls back to the static block on older
    # generate.py builds.
    cluster_text = "\n".join(
        (a.get("title") or "") + "\n" + (a.get("body") or "")[:1500]
        for a in arts)
    if hasattr(g, "_kql_knowledge_for"):
        kql_knowledge = g._kql_knowledge_for(cluster_text)
    else:
        kql_knowledge = _KQL_KNOWLEDGE_BLOCK
    falcon_block = getattr(g, "_FALCON_KNOWLEDGE_BLOCK", "") or "(reference unavailable)"
    cloudwatch_block = getattr(g, "_CLOUDWATCH_KNOWLEDGE_BLOCK", "") or "(reference unavailable)"
    return (_WEEKLY_PROMPT
            .replace("<<N>>", str(len(arts)))
            .replace("<<ARTICLE_BLOCK>>", block)
            .replace("<<KQL_KNOWLEDGE>>", kql_knowledge)
            .replace("<<DATADOG_SCHEMA>>", _DATADOG_KNOWLEDGE_BLOCK)
            .replace("<<FALCON_SCHEMA>>", falcon_block)
            .replace("<<CLOUDWATCH_SCHEMA>>", cloudwatch_block))


def call_llm(prompt: str, best_fidelity: bool = False) -> str | None:
    """Try OAuth first (no extra cost on the user's plan); fall back to
    API key if that fails. Mirrors generate.py's policy."""
    # Same truthy convention as generate.py — int() alone would crash the
    # whole run on USECASEINTEL_USE_CLAUDE_OAUTH=true/yes.
    use_oauth = g.os.environ.get(
        "USECASEINTEL_USE_CLAUDE_OAUTH", "1").lower() in ("1", "true", "yes")
    if use_oauth:
        try:
            r = g._llm_call_via_oauth(prompt, enable_search=best_fidelity)
            if r:
                return r
        except Exception as e:
            print(f"  [!] OAuth path failed: {str(e)[:80]} — falling back to API key")
    api_key = g.os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return None
    return g._llm_call_via_api_key(prompt, api_key)


# =============================================================================
# Output — YAML emit + dedupe + briefing markdown
# =============================================================================

def _yaml_scalar(s: str) -> str:
    if any(c in s for c in (":", "#", "{", "}", "[", "]", "&", "*", "!", "|", ">", "'", '"', "%", "@", "`")) or s.startswith(("- ", "? ")):
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\""
    return s


def _yaml_block(s: str) -> str:
    body = "\n".join(f"  {line}" for line in s.split("\n"))
    return f"|-\n{body}"


def _uc_key(title: str, techs: list[str]) -> str:
    """Stable de-dupe key based on normalised title + technique set."""
    norm = re.sub(r"[^a-z0-9]+", "", title.lower())
    return norm + "|" + ",".join(sorted(techs))


def _existing_uc_keys() -> set[str]:
    """Walk every YAML in use_cases/ and build a key set so we can
    de-dupe new weekly UCs against the catalogue."""
    keys: set[str] = set()
    uc_dir = ROOT / "use_cases"
    if not uc_dir.exists():
        return keys
    for path in uc_dir.rglob("*.yml"):
        try:
            import yaml as _y
            doc = _y.safe_load(path.read_text(encoding="utf-8")) or {}
        except Exception:
            continue
        title = (doc.get("title") or "").strip()
        techs = sorted({t.get("id", "") for t in (doc.get("mitre_attack") or [])})
        if title:
            keys.add(_uc_key(title, techs))
    return keys


def emit_yaml(uc: dict, articles: list[dict]) -> str:
    """Convert an LLM-emitted UC dict to our YAML schema."""
    title = "[WEEKLY] " + (uc.get("title") or "Untitled weekly UC").strip()
    desc = (uc.get("description") or "").strip()
    rationale = (uc.get("rationale") or "").strip()
    if rationale and rationale not in desc:
        desc = desc + "\n\nRationale: " + rationale

    # Implementations reflect what's actually present — "sentinel" used to
    # be claimed unconditionally even when sentinel_kql came back empty.
    impls = []
    if uc.get("defender_kql"): impls.append("defender")
    if uc.get("sentinel_kql"): impls.append("sentinel")
    if uc.get("splunk_spl"):  impls.append("splunk")
    if uc.get("sigma_yaml"):  impls.append("sigma")
    if uc.get("datadog_query"): impls.append("datadog")
    if uc.get("falcon_logscale_query"): impls.append("falcon")
    if uc.get("cloudwatch_query"): impls.append("cloudwatch")

    body = []
    body.append(f"id: {uc['_id']}")
    body.append(f"title: {_yaml_scalar(title)}")
    body.append(f"kill_chain: {uc.get('kill_chain', 'actions')}")
    body.append(f"confidence: {uc.get('confidence', 'High')}")
    body.append(f"tier: {uc.get('tier', 'alerting').lower()}")
    body.append(f"fp_rate_estimate: {(uc.get('fp_rate_estimate') or 'low').lower()}")
    body.append("implementations:")
    for impl in impls:
        body.append(f"- {impl}")
    body.append("mitre_attack:")
    for t in (uc.get("techniques") or []):
        body.append(f"- id: {t.get('id', '')}")
        body.append(f"  name: {_yaml_scalar(t.get('name', ''))}")
    body.append("data_models:")
    body.append("  defender:")
    for dm in (uc.get("data_models") or []):
        body.append(f"  - {dm}")
    body.append(f"description: {_yaml_block(desc)}")
    if uc.get("defender_kql"):
        body.append(f"defender_kql: {_yaml_block(uc['defender_kql'])}")
    if uc.get("sentinel_kql"):
        body.append(f"sentinel_kql: {_yaml_block(uc['sentinel_kql'])}")
    if uc.get("sigma_yaml"):
        body.append(f"sigma_yaml: {_yaml_block(uc['sigma_yaml'])}")
    if uc.get("splunk_spl"):
        body.append(f"splunk_spl: {_yaml_block(uc['splunk_spl'])}")
    if uc.get("datadog_query"):
        body.append(f"datadog_query: {_yaml_block(uc['datadog_query'])}")
    if uc.get("falcon_logscale_query"):
        body.append(f"falcon_logscale_query: {_yaml_block(uc['falcon_logscale_query'])}")
    if uc.get("cloudwatch_query"):
        body.append(f"cloudwatch_query: {_yaml_block(uc['cloudwatch_query'])}")
    req = [str(t).strip() for t in (uc.get("required_telemetry") or []) if t][:8]
    if req:
        body.append("required_telemetry:")
        for t in req:
            body.append(f"- {_yaml_scalar(t[:120])}")
    # Phase 1C analyst fields — read back by generate._load_uc_from_yaml.
    kcp = str(uc.get("kill_chain_phase") or "").strip().lower()
    if kcp in ("initial_access", "execution", "persistence",
               "privilege_escalation", "defense_evasion", "credential_access",
               "discovery", "lateral_movement", "collection",
               "command_and_control", "exfiltration", "impact"):
        body.append(f"kill_chain_phase: {kcp}")
    fps = uc.get("expected_fp_scenarios") or []
    if isinstance(fps, str):
        fps = [fps]
    fps = [str(s).strip().replace("\n", " ")[:300] for s in fps if s][:6]
    if fps:
        body.append("expected_fp_scenarios:")
        for s in fps:
            body.append(f"- {_yaml_scalar(s)}")
    runbook = str(uc.get("response_runbook") or "").strip()[:1000]
    if runbook:
        body.append(f"response_runbook: {_yaml_block(runbook)}")
    fpf = str(uc.get("false_positive_filters") or "").strip()[:1000]
    if fpf:
        body.append(f"false_positive_filters: {_yaml_block(fpf)}")
    return "\n".join(body) + "\n"


def write_weekly_briefing(week_tag: str, emitted: list[dict]):
    """Markdown summary for the fortnight — `briefings/_weekly/<YYYY-WW>.md`."""
    BRIEFING_OUT_DIR.mkdir(parents=True, exist_ok=True)
    path = BRIEFING_OUT_DIR / f"{week_tag}.md"
    lines = [
        f"# Bi-weekly threat synthesis — {week_tag}",
        "",
        f"Auto-generated by `biweekly_review.py` on {dt.datetime.now(dt.timezone.utc):%Y-%m-%d %H:%M UTC}.",
        f"Synthesised **{len(emitted)} new use case(s)** from the last 14 days of threat intel by clustering articles into shared campaigns / actors / CVEs and asking an LLM to write a single high-fidelity detection per cluster.",
        "",
        "## What was added",
        "",
    ]
    for entry in emitted:
        uc = entry["uc"]
        title = "[WEEKLY] " + uc.get("title", "Untitled")
        techs = ", ".join(t.get("id", "") for t in uc.get("techniques", []))
        lines.append(f"### {title}")
        lines.append("")
        lines.append(f"- **ID:** `{uc['_id']}`")
        lines.append(f"- **Cluster:** {entry['cluster_label']} ({entry['cluster_size']} articles)")
        lines.append(f"- **Kill chain:** {uc.get('kill_chain', '-')}")
        lines.append(f"- **MITRE:** {techs}")
        plats = []
        if uc.get("defender_kql"): plats.append("Defender KQL")
        if uc.get("sentinel_kql"): plats.append("Sentinel KQL")
        if uc.get("sigma_yaml"):   plats.append("Sigma")
        if uc.get("splunk_spl"):   plats.append("Splunk SPL")
        if uc.get("datadog_query"): plats.append("Datadog")
        if uc.get("falcon_logscale_query"): plats.append("Falcon LogScale")
        if uc.get("cloudwatch_query"): plats.append("CloudWatch")
        lines.append(f"- **Platforms:** {', '.join(plats)}")
        lines.append("")
        lines.append((uc.get("description") or "").strip())
        lines.append("")
        lines.append("**Source articles:**")
        for a in entry["cluster_articles"][:8]:
            lines.append(f"- [{a['title']}]({a['link']}) — {a['source']} · {a['published']}")
        if len(entry["cluster_articles"]) > 8:
            lines.append(f"- … and {len(entry['cluster_articles']) - 8} more")
        lines.append("")
        lines.append("---")
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


# =============================================================================
# Main
# =============================================================================

def _slug(s: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")
    return s[:50] or "untitled"


def _parse_llm_response(raw: str) -> dict | None:
    """Pull the first JSON object out of `raw`. Tolerant of fenced blocks
    and trailing commentary."""
    if not raw:
        return None
    # Prefer a fenced block
    m = re.search(r"```(?:json)?\s*(\{.+?\})\s*```", raw, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except Exception:
            pass
    # Bare JSON
    m = re.search(r"\{.+\}", raw, re.DOTALL)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except Exception:
        return None


# =============================================================================
# Pre-emit validation — the same stack the per-article path runs, plus the
# SPL-CIM dataset/field check that validate.py (the CI gate) enforces.
# Weekly UCs used to skip ALL of this and shipped 28 CIM errors straight
# into the catalogue between W19 and W23.
# =============================================================================

_SPL_DM_RE = re.compile(r"from\s+datamodel\s*=\s*([\w.]+)", re.IGNORECASE)
_SPL_NODENAME_RE = re.compile(r'nodename\s*=\s*"?([\w.]+)"?', re.IGNORECASE)
_SPL_FIELD_RE = re.compile(r"\b([A-Z][A-Za-z_]+)\.([a-z][\w]+)\b")
_SPL_RESERVED = {"as", "by", "where", "values", "count", "earliest", "latest",
                 "first_seen", "last_seen", "min", "max", "stats", "rename",
                 "eval", "fields", "table", "lookup", "set", "to"}

_CIM_VALID: dict | None = None
_ATTACK_IDS: set | None = None


def _valid_attack_ids() -> set:
    """Set of current MITRE ATT&CK technique IDs from registry.json — the
    same catalogue validate.py checks against. Empty set on a fresh clone
    (no registry) so the caller degrades to a no-op rather than dropping
    every technique."""
    global _ATTACK_IDS
    if _ATTACK_IDS is not None:
        return _ATTACK_IDS
    ids: set = set()
    try:
        reg = json.loads((ROOT / "data_sources" / "registry.json")
                         .read_text(encoding="utf-8"))
        ids = set((reg.get("attack_techniques") or {}).keys())
    except Exception:
        pass
    _ATTACK_IDS = ids
    return ids


def _cim_valid_fields() -> dict:
    """{dataset_path: set(valid_fields)} from registry.json (ESCU usage)
    union cim_spec_fields.json (hand-curated spec allowlist) — the same
    union validate.py checks against. Empty dict when the registry is
    missing (fresh clone) so the check degrades to a no-op."""
    global _CIM_VALID
    if _CIM_VALID is not None:
        return _CIM_VALID
    valid: dict[str, set] = {}
    try:
        reg = json.loads((ROOT / "data_sources" / "registry.json")
                         .read_text(encoding="utf-8"))
        for k, v in (reg.get("cim_datasets") or {}).items():
            valid.setdefault(k, set()).update(v or [])
    except Exception:
        pass
    try:
        spec = json.loads((ROOT / "data_sources" / "cim_spec_fields.json")
                          .read_text(encoding="utf-8"))
        for k, v in spec.items():
            if isinstance(v, list):
                valid.setdefault(k, set()).update(v)
    except Exception:
        pass
    _CIM_VALID = valid
    return valid


def _attach_spl_cim_issues(uc: dict) -> int:
    """Validate splunk_spl datamodel paths + field refs against the CIM
    registry. Appends human-readable issue strings to uc['_spl_issues']
    (so the shared retry formatter picks them up) and records the count
    in uc['_spl_cim_error_count'] for the post-retry drop decision."""
    uc["_spl_cim_error_count"] = 0
    spl = uc.get("splunk_spl") or ""
    valid = _cim_valid_fields()
    if not spl.strip() or not valid:
        return 0
    issues: list[str] = []
    dm_paths = set(_SPL_DM_RE.findall(spl)) | set(_SPL_NODENAME_RE.findall(spl))
    for full in dm_paths:
        if full not in valid:
            close = ", ".join(sorted(valid.keys())[:6])
            issues.append(
                f"datamodel `{full}` is not a valid CIM dataset path — use one of: {close}, …")
            continue
        short = full.split(".")[-1]
        for s, fld in _SPL_FIELD_RE.findall(spl):
            if s != short or fld in _SPL_RESERVED:
                continue
            if fld not in valid[full]:
                issues.append(
                    f"`{short}.{fld}` is not a CIM field on {full} — "
                    f"pick from the {full} field set")
    if issues:
        uc.setdefault("_spl_issues", []).extend(issues)
        uc["_spl_cim_error_count"] = len(issues)
    return len(issues)


_UC_ISSUE_KEYS = (
    "_field_issues", "_field_issues_autofix",
    "_sentinel_field_issues", "_sentinel_field_issues_autofix",
    "_syntax_issues", "_sentinel_syntax_issues", "_sigma_issues",
    "_cwli_issues", "_spl_issues", "_datadog_issues",
    "_falcon_issues", "_dangerous_issues", "_spl_cim_error_count",
)


def _autofix_kqls(uc: dict) -> None:
    for kql_key in ("defender_kql", "sentinel_kql"):
        if g._auto_fix_kql_fields and uc.get(kql_key):
            fixed, changes = g._auto_fix_kql_fields(uc[kql_key])
            if changes:
                uc[kql_key] = fixed
                print(f"    auto-fixed {kql_key}: {', '.join(changes)}")


def _validate_uc_dict(uc: dict) -> int:
    """Run the full validation stack on one LLM-emitted UC dict. Returns
    the error count that should trigger a retry (Sigma issues are
    informational — the field is optional by design)."""
    for k in _UC_ISSUE_KEYS:
        uc.pop(k, None)
    n = 0
    n += g._attach_field_issues(uc, "defender_kql")
    n += g._attach_field_issues(uc, "sentinel_kql",
                                issues_key="_sentinel_field_issues")
    g._attach_sigma_issues(uc, "sigma_yaml")
    n += g._attach_cwli_issues(uc, "cloudwatch_query")
    n += g._attach_spl_issues(uc, "splunk_spl")
    n += g._attach_generic_query_issues(uc, "datadog_query", "Datadog", "_datadog_issues")
    n += g._attach_generic_query_issues(uc, "falcon_logscale_query",
                                        "Falcon LogScale", "_falcon_issues")
    n += g._attach_dangerous_issues(uc)
    n += g._attach_syntax_issues_batch([uc])
    n += _attach_spl_cim_issues(uc)
    return n


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--apply", action="store_true",
                    help="Actually write YAML files (default: dry-run)")
    ap.add_argument("--window", type=int, default=14, help="Lookback window in days")
    ap.add_argument("--max-themes", type=int, default=8, help="Max clusters to synthesise per run")
    ap.add_argument("--min-cluster-size", type=int, default=2,
                    help="Minimum articles per cluster")
    ap.add_argument("--max-body-chars", type=int, default=2500,
                    help="Per-article body cap fed to the LLM (default 2500)")
    ap.add_argument("--max-articles-per-cluster", type=int, default=12,
                    help="Cap on articles fed to the LLM per cluster (source-diverse sample). Default 12.")
    ap.add_argument("--best-fidelity", action="store_true",
                    help="Enable WebSearch in the LLM call for higher-quality output (slower / more expensive)")
    args = ap.parse_args()

    print(f"[*] Window: {args.window} days  |  Max themes: {args.max_themes}")
    articles = gather_recent(args.window)
    print(f"[*] Articles in window: {len(articles)}")
    if not articles:
        print("[!] No articles found — aborting.")
        return 1

    clusters = cluster_articles(articles, min_cluster_size=args.min_cluster_size)
    print(f"[*] Clusters identified: {len(clusters)}")
    for c in clusters[:args.max_themes]:
        print(f"    - {c['label']:<40} ({len(c['articles'])} articles)")

    today = dt.date.today()
    iso_year, iso_week, _ = today.isocalendar()
    week_tag = f"{iso_year}-W{iso_week:02d}"
    out_dir = WEEKLY_OUT_DIR / week_tag
    print(f"[*] Output directory: {out_dir.relative_to(ROOT)}")

    existing_keys = _existing_uc_keys()
    print(f"[*] Existing UCs in catalogue: {len(existing_keys)}")

    emitted: list[dict] = []
    for cluster in clusters[:args.max_themes]:
        prompt = build_prompt(cluster, max_body_chars=args.max_body_chars,
                                max_articles=args.max_articles_per_cluster)
        sampled = _sample_cluster(cluster["articles"], max_articles=args.max_articles_per_cluster)
        print(f"\n  Synthesising: {cluster['label']} ({len(cluster['articles'])} articles, sampled {len(sampled)}, prompt {len(prompt)} chars)")
        if not args.apply:
            print(f"    DRY-RUN — would call LLM for {cluster['label']}")
            continue
        raw = call_llm(prompt, best_fidelity=args.best_fidelity)
        if not raw:
            print(f"    [!] LLM returned nothing — skipping")
            continue
        uc = _parse_llm_response(raw)
        if not uc:
            print(f"    [!] LLM output didn't parse as JSON — skipping. First 120 chars: {raw[:120]!r}")
            continue
        # De-dupe
        techs = sorted({t.get("id", "") for t in uc.get("techniques") or []})
        key = _uc_key(uc.get("title", ""), techs)
        if key in existing_keys:
            print(f"    [!] Duplicate of existing UC (key match) — skipping")
            continue
        existing_keys.add(key)
        # ---- Pre-emit validation, one corrective re-prompt ----
        # Same policy as the per-article path: validate every platform
        # query, feed the issue list back to the LLM once, keep whichever
        # attempt validates cleaner.
        _autofix_kqls(uc)
        errs = _validate_uc_dict(uc)
        if errs:
            error_text = g._format_validation_errors_for_retry([uc])
            if error_text:
                print(f"    [VALIDATE] {errs} issue(s) — re-prompting once with the error list")
                raw2 = call_llm(prompt + "\n\n" + error_text,
                                best_fidelity=args.best_fidelity)
                uc2 = _parse_llm_response(raw2) if raw2 else None
                if uc2:
                    _autofix_kqls(uc2)
                    errs2 = _validate_uc_dict(uc2)
                    # <= : on a tie the retry wins — it incorporated the
                    # corrections, so equal counts usually mean a deeper
                    # issue surfaced once a shallow one was fixed.
                    if errs2 <= errs:
                        print(f"    [VALIDATE] retry kept: {errs} -> {errs2} issue(s)")
                        uc, errs = uc2, errs2
                    else:
                        print(f"    [VALIDATE] retry was worse ({errs2} issue(s)) — keeping first attempt")
        # Safety quarantine — a side-effectful query never ships.
        if uc.get("_dangerous_issues"):
            print("    [!] QUARANTINED — unsafe query survived the retry:")
            for iss in uc.get("_dangerous_issues") or []:
                print(f"        - {iss}")
            continue
        # SPL that still fails the CIM check would turn the validate.py CI
        # gate red the moment it's committed — ship the UC without SPL
        # rather than ship broken SPL.
        if uc.get("_spl_cim_error_count"):
            print("    [!] splunk_spl still fails CIM validation — dropping the "
                  "SPL field (other platforms ship)")
            uc.pop("splunk_spl", None)
        if errs:
            print(f"    [!] {errs} residual validation issue(s) — shipping with warnings")
        # Drop any hallucinated MITRE technique IDs not in the current ATT&CK
        # catalogue. validate.py flags unknown technique IDs as ERRORS, so a
        # bogus id would turn the CI gate red the moment biweekly.bat commits.
        # Keep the UC (the detection logic is still useful) but only with real
        # techniques — same "ship without the broken part" policy as bad SPL.
        _valid_ids = _valid_attack_ids()
        if _valid_ids:
            _techs = uc.get("techniques") or []
            _dropped = [t.get("id") for t in _techs if (t.get("id") or "") not in _valid_ids]
            if _dropped:
                print(f"    [!] dropping {len(_dropped)} unknown ATT&CK id(s) "
                      f"(not in MITRE catalogue): {_dropped}")
                uc["techniques"] = [t for t in _techs
                                    if (t.get("id") or "") in _valid_ids]
        # Strip internal issue keys so they never leak into the YAML path.
        for k in _UC_ISSUE_KEYS:
            uc.pop(k, None)
        # Stable ID
        uid = "UC_WEEKLY_" + _slug(uc.get("title", "")).upper().replace("-", "_")
        digest = hashlib.sha1(("|".join(a["path"] for a in cluster["articles"])).encode()).hexdigest()[:6]
        uid = (uid + "_" + digest)[:60]
        uc["_id"] = uid
        # Write YAML
        out_dir.mkdir(parents=True, exist_ok=True)
        target = out_dir / f"{uid}.yml"
        target.write_text(emit_yaml(uc, cluster["articles"]), encoding="utf-8")
        print(f"    [{uid}] wrote {target.relative_to(ROOT)}")
        emitted.append({
            "uc": uc, "cluster_label": cluster["label"],
            "cluster_size": len(cluster["articles"]),
            "cluster_articles": cluster["articles"],
        })

    if args.apply and emitted:
        bp = write_weekly_briefing(week_tag, emitted)
        print(f"\n[*] Briefing: {bp.relative_to(ROOT)}")
    print(f"\n[*] Emitted {len(emitted)} new UC(s).")
    if not args.apply:
        print("DRY-RUN — pass --apply to actually call the LLM and write files.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

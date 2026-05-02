"""KQL prompt + cache validation harness.

Two modes:

  1. prompt-shape (default)
     Builds the LLM prompt for a small fixed set of test articles
     using the same template + knowledge block that generate.py uses.
     Asserts that the right knowledge anchors land in the prompt for
     the right kind of article (phishing → time-window pattern,
     ransomware → shadow-copy example, etc.). No LLM is called.
     Deterministic; cheap; runs in <1s.

  2. cache-score
     Walks intel/.llm_uc_cache/*.json and scores every cached
     `defender_kql` field against quality heuristics drawn from
     knowledge/kql_antipatterns.md (time-bound, =~ usage,
     machine-account exclusion, explicit join kind, bounded output,
     etc.). Aggregates into a corpus score so you can run the
     validator before/after a knowledge change and see the delta.

Run:
    python validate_kql_knowledge.py            # mode 1
    python validate_kql_knowledge.py --score    # mode 2
    python validate_kql_knowledge.py --score --top 10   # show 10 worst
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

# Reach into generate.py for the prompt template + knowledge block.
# Importing it has a side-effect (loads catalog etc.) but is fine for
# a one-shot validator.
import generate  # noqa: E402


ROOT = Path(__file__).parent
LLM_CACHE = ROOT / "intel" / ".llm_uc_cache"


# =============================================================================
# Mode 1 — prompt-shape validation
# =============================================================================

# Stable test articles. Each has a known TTP shape; the assertions
# encode which knowledge anchors should fire for that shape. When you
# extend the knowledge base, add new entries here, not new heuristics.
TEST_ARTICLES = [
    {
        "id": "phishing-link-to-process",
        "title": "TA577 phishing campaign drops PowerShell from Outlook click-throughs",
        "url": "https://example.com/phishing",
        "body": (
            "Threat actors send phishing emails containing malicious URLs. "
            "When users click the link from Outlook, the browser opens the "
            "URL and a non-browser child process (powershell.exe, mshta.exe) "
            "is spawned within seconds, downloading additional payloads."
        ),
        "ind": {
            "domains": ["evil-phish.example.com"],
            "urls": ["https://evil-phish.example.com/login"],
        },
        # These section ids MUST be present in the rendered prompt.
        "must_anchor_ids": [
            "pattern-process-tree",                      # parent/child detection
            "pattern-time-window-correlation",           # click→process within Ns
            "example-phishing-link-to-process-execution", # the canonical few-shot
            "table-EmailEvents",                          # the right table recipe
            "table-DeviceProcessEvents",
        ],
        # And these strings (the actual content) MUST land in the prompt.
        "must_strings": [
            "EmailEvents",
            "UrlClickEvents",
            "DeviceProcessEvents",
            "ClickAllowed",
        ],
    },
    {
        "id": "ransomware-shadow-copy",
        "title": "Akira ransomware deletes shadow copies before encryption",
        "url": "https://example.com/akira",
        "body": (
            "Akira ransomware operators run vssadmin.exe delete shadows /all /quiet "
            "and wmic.exe shadowcopy delete to remove Volume Shadow Copies before "
            "starting file encryption. PowerShell variants use Get-WmiObject "
            "Win32_Shadowcopy with Remove-WmiObject."
        ),
        "ind": {},
        "must_anchor_ids": [
            "example-shadow-copy-deletion-prelude-to-ransomware",
            "table-DeviceProcessEvents",
        ],
        "must_strings": [
            "vssadmin",
            "Win32_Shadowcopy",
            "delete shadows",
        ],
    },
    {
        "id": "aad-impossible-travel",
        "title": "Storm-0501 abuses Entra ID — impossible travel sign-ins",
        "url": "https://example.com/storm-0501",
        "body": (
            "Adversaries authenticate to Entra ID accounts from geographically "
            "impossible locations within minutes — a successful sign-in from "
            "Country A followed by another from Country B less than an hour later "
            "with no VPN to explain it."
        ),
        "ind": {"emails": ["target.user@example.com"]},
        "must_anchor_ids": [
            "table-AADSignInEventsBeta",
            "example-aad-impossible-travel",
        ],
        "must_strings": [
            "AADSignInEventsBeta",
            "ErrorCode == 0",
        ],
    },
    {
        "id": "lateral-movement-psexec",
        "title": "BlackByte affiliate uses PsExec for lateral movement",
        "url": "https://example.com/blackbyte",
        "body": (
            "After initial access via VPN credential abuse, the operator "
            "drops psexec.exe on a beachhead host and uses it to execute "
            "binaries on other hosts in the network. PaExec and remcom are "
            "common substitutes."
        ),
        "ind": {},
        "must_anchor_ids": [
            "example-lateral-movement-via-psexec",
            "pattern-behavioural-baseline",   # course-recommended for psexec
        ],
        "must_strings": [
            "psexec.exe",
            "leftanti",   # baseline anti-join is the recommended detection
        ],
    },
]


def _build_prompt(article: dict, ind: dict) -> str:
    """Render the LLM prompt the same way generate.py does, minus the
    LLM call. Mirrors generate.py:914-919.
    """
    title = article.get("title", "")[:200]
    url = article.get("url", "")[:200]
    body = article.get("body", "")
    ioc_summary: list[str] = []
    for label, k in (("domains", "domains"), ("ips", "ips"),
                     ("hashes", "hashes"), ("urls", "urls"),
                     ("emails", "emails"), ("cves", "cves")):
        if ind.get(k):
            ioc_summary.append(f"  {label}: {', '.join(ind[k][:8])}")
    return (generate._LLM_UC_PROMPT
            .replace("<<TITLE>>",       title)
            .replace("<<URL>>",         url)
            .replace("<<BODY>>",        body)
            .replace("<<IOC_SUMMARY>>", "\n".join(ioc_summary) or "  (none)")
            .replace("<<DEFENDER_SCHEMA>>", generate._DEFENDER_SCHEMA_BLOCK)
            .replace("<<KQL_KNOWLEDGE>>", generate._KQL_KNOWLEDGE_BLOCK))


def run_prompt_shape() -> int:
    """Return shell exit code: 0 = pass, 1 = fail."""
    print(f"Knowledge block:  {len(generate._KQL_KNOWLEDGE_BLOCK):,} bytes")
    print(f"Schema block:     {len(generate._DEFENDER_SCHEMA_BLOCK):,} bytes")
    # Sanity-check the schema block contains the canonical-pitfall callouts.
    if "DeviceProcessEvents" not in generate._DEFENDER_SCHEMA_BLOCK:
        print("FAIL: schema block is missing DeviceProcessEvents")
        return 1
    if "InitiatingProcessAccountName" not in generate._DEFENDER_SCHEMA_BLOCK:
        print("FAIL: schema block is missing InitiatingProcessAccountName")
        return 1
    print(f"Running {len(TEST_ARTICLES)} prompt-shape tests:\n")
    failures = 0
    for art in TEST_ARTICLES:
        prompt = _build_prompt(art, art["ind"])
        missing_anchors = [a for a in art["must_anchor_ids"] if a not in prompt]
        missing_strings = [s for s in art["must_strings"] if s not in prompt]
        ok = not missing_anchors and not missing_strings
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] {art['id']}  ({len(prompt):,} chars)")
        if missing_anchors:
            print(f"    missing anchor ids: {missing_anchors}")
        if missing_strings:
            print(f"    missing strings:    {missing_strings}")
        # Sanity: title and body must round-trip
        if art["title"] not in prompt:
            print("    title not in prompt!")
            ok = False
        if art["body"][:80] not in prompt:
            print("    body not in prompt!")
            ok = False
        if not ok:
            failures += 1
    print()
    if failures:
        print(f"{failures} of {len(TEST_ARTICLES)} tests failed.")
        return 1
    print(f"All {len(TEST_ARTICLES)} prompt-shape tests passed.")
    return 0


# =============================================================================
# Mode 2 — cache-score
# =============================================================================

# Each rule returns (passed: bool, points_if_pass: int, message_if_fail: str).
# The KQL is lower-cased before rules run; rule patterns must be lowercase.

def _has_time_bound(kql: str) -> tuple[bool, int, str]:
    ok = bool(re.search(r"(timestamp|timegenerated)\s*(>|between)\s*", kql))
    return ok, 15, "no `Timestamp > ago(...)` or `between` time predicate"


def _has_machine_account_filter(kql: str) -> tuple[bool, int, str]:
    """Award if the query either (a) doesn't use AccountName or
    InitiatingProcessAccountName at all (rule N/A) or (b) uses one of
    them and includes a machine-account exclusion."""
    # Scope check — does the query actually reference an AccountName-ish field?
    in_scope = bool(re.search(r"\b(initiatingprocess)?accountname\b", kql))
    if not in_scope:
        return True, 5, ""  # rule does not apply
    # Either `AccountName !endswith "$"` or `!has "$"` or filtering on
    # InitiatingProcessAccountDomain != system, etc.
    if re.search(r'accountname\s*!\s*(endswith|has)\s*"\s*\$\s*"', kql):
        return True, 5, ""
    if re.search(r'accountname\s*!=\s*"\s*system\s*"', kql):
        return True, 5, ""
    return False, 5, "no machine-account exclusion (`AccountName !endswith \"$\"`) — query references AccountName"


def _has_bounded_output(kql: str) -> tuple[bool, int, str]:
    # `| project ...` or `| top N ...` or `| take N`
    ok = bool(re.search(r"\|\s*(project|top\s+\d|take\s+\d|summarize\s)", kql))
    return ok, 10, "unbounded output — add `| project` or `| top N` or `| summarize`"


def _uses_case_insensitive_eq(kql: str) -> tuple[bool, int, str]:
    """If the query equality-matches a binary name, prefer `=~` over `==`.

    Heuristic: presence of `filename ==` or `initiatingprocessfilename ==`
    is a smell. `=~` form is fine.
    """
    bad = bool(re.search(r"(?:initiating)?processfilename\s*==\s*\"", kql)) or \
          bool(re.search(r"\bfilename\s*==\s*\"", kql))
    # this rule is awarded for *not* having the bad form
    return (not bad), 8, "uses `==` for binary name match — prefer `=~` for case-insensitivity"


def _explicit_join_kind(kql: str) -> tuple[bool, int, str]:
    # If the query has any `| join`, every join must specify `kind=`.
    joins = re.findall(r"\|\s*join\b([^\n]*)", kql)
    if not joins:
        return True, 8, ""
    bad = [j for j in joins if "kind=" not in j and "kind =" not in j]
    return (not bad), 8, f"{len(bad)} join(s) without explicit `kind=` — defaults to `innerunique` (silent row loss)"


def _no_bare_process_execution(kql: str) -> tuple[bool, int, str]:
    """Flag bare `FileName =~ "powershell.exe"` with no co-predicate."""
    if "deviceprocessevents" not in kql:
        return True, 8, ""
    # find clause matching only the binary name
    has_powershell_filter = bool(re.search(
        r'filename\s*=~?\s*"(powershell|cmd|mshta|rundll32|regsvr32|wscript|cscript)\.exe"',
        kql))
    if not has_powershell_filter:
        return True, 8, ""
    # require either: parent-process predicate, command-line predicate,
    # or a behavioural anti-join
    coppred = (
        "initiatingprocessfilename" in kql
        or "processcommandline" in kql
        or "leftanti" in kql
        or "isinitiatingprocessremotesession" in kql
    )
    return coppred, 8, "bare LOLBin filename match without parent/cmdline/baseline context"


def _prefer_has_over_contains(kql: str) -> tuple[bool, int, str]:
    """Soft rule: `contains` is fine but `has` is the recommended default."""
    contains_count = len(re.findall(r"\s+contains\s+\"", kql))
    has_count = len(re.findall(r"\s+has(_any|_all|prefix|suffix)?\s+\"", kql))
    # award if contains-count is not dominant
    ok = contains_count <= max(has_count, 1)
    return ok, 6, f"{contains_count} `contains` predicate(s) outweigh `has` — prefer indexed `has`"


def _comments_on_thresholds(kql: str) -> tuple[bool, int, str]:
    """If the query has a numeric threshold (>, <, >=, <=) on a count
    or summarised field, there should be a comment on the same line
    explaining why. Soft rule.
    """
    threshold_lines = []
    for ln in kql.split("\n"):
        if re.search(r"\b(count|sum|avg|dcount|distinctcount)[a-z_]*\s*\(\s*\)?\s*", ln) is None:
            continue
        if re.search(r"[<>]=?\s*\d", ln):
            threshold_lines.append(ln)
    bad = [ln for ln in threshold_lines if "//" not in ln]
    ok = not bad
    return ok, 5, f"{len(bad)} threshold line(s) with no `// why this number` comment"


def _project_at_end(kql: str) -> tuple[bool, int, str]:
    """`| project` should appear in the last few clauses, not at the start."""
    if "| project" not in kql.lower():
        return True, 4, ""
    # If the last 200 chars contain `| project`, we're good
    tail = kql.lower()[-300:]
    ok = "| project" in tail or "| order" in tail or "| sort" in tail
    return ok, 4, "early `| project` — the engine can't push predicates past it"


SCORE_RULES = [
    ("time_bound",       _has_time_bound),
    ("machine_account",  _has_machine_account_filter),
    ("bounded_output",   _has_bounded_output),
    ("case_insensitive", _uses_case_insensitive_eq),
    ("explicit_join",    _explicit_join_kind),
    ("no_bare_process",  _no_bare_process_execution),
    ("prefer_has",       _prefer_has_over_contains),
    ("threshold_comments", _comments_on_thresholds),
    ("project_late",     _project_at_end),
]
MAX_SCORE = sum(fn("")[1] for _, fn in SCORE_RULES)


def score_kql(kql: str) -> tuple[int, list[str]]:
    """Score a single KQL string. Returns (score 0..MAX_SCORE, list of issues)."""
    if not kql:
        return 0, ["empty KQL"]
    text = kql.lower()
    score = 0
    issues: list[str] = []
    for name, fn in SCORE_RULES:
        ok, pts, msg = fn(text)
        if ok:
            score += pts
        else:
            issues.append(f"[{name}] {msg}")
    return score, issues


def _iter_cached_ucs():
    """Yield (cache_path, uc_dict) for every UC in every cache file."""
    if not LLM_CACHE.exists():
        return
    for p in sorted(LLM_CACHE.rglob("*.json")):
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        for uc in data.get("ucs", []) or []:
            yield p, uc


def run_cache_score(top_n_worst: int = 5) -> int:
    print(f"Scoring cached UCs in {LLM_CACHE} (max score per UC: {MAX_SCORE})\n")
    # Live-validate every UC's field schema as well, so the score reflects
    # the *current* state of the canonical schema (cache may pre-date the
    # validator being wired in).
    try:
        from kql_schema_validator import validate_kql as _live_validate
    except Exception:
        _live_validate = None
    rows: list[tuple[int, list[str], dict, Path, list[dict]]] = []
    for path, uc in _iter_cached_ucs():
        kql = uc.get("defender_kql") or uc.get("kql") or ""
        score, issues = score_kql(kql)
        # Field-schema issues — prefer cached, fall back to live re-validation.
        field_issues = uc.get("_field_issues") or []
        if not field_issues and _live_validate is not None:
            try:
                field_issues = list(_live_validate(kql))
            except Exception:
                field_issues = []
        rows.append((score, issues, uc, path, field_issues))

    if not rows:
        print("No cached UCs found.")
        return 0

    n = len(rows)
    avg = sum(r[0] for r in rows) / n
    pct = avg / MAX_SCORE * 100 if MAX_SCORE else 0.0
    field_issue_total = sum(len(r[4]) for r in rows)
    ucs_with_field_issues = sum(1 for r in rows if r[4])
    print(f"Total UCs scored: {n}")
    print(f"Mean score:       {avg:.1f} / {MAX_SCORE}  ({pct:.1f}% of max)")
    print(f"Field issues:     {field_issue_total} across {ucs_with_field_issues} UC(s) "
          f"({ucs_with_field_issues / n * 100:.1f}%)")

    # Score histogram
    buckets = [0] * 11   # 0-10, 10-20, ..., 90-100
    for score, *_ in rows:
        idx = min(int((score / MAX_SCORE) * 10), 10) if MAX_SCORE else 0
        buckets[idx] += 1
    print("\nScore distribution (% of max):")
    for i, count in enumerate(buckets):
        if count == 0:
            continue
        bar = "#" * min(count, 60)
        lo = i * 10
        hi = (i + 1) * 10
        print(f"  {lo:>3}-{hi:<3}%  {count:>4}  {bar}")

    # Most-frequent style issues
    issue_counts: dict[str, int] = {}
    for _, issues, *_ in rows:
        for iss in issues:
            issue_counts[iss] = issue_counts.get(iss, 0) + 1
    if issue_counts:
        print("\nMost-frequent style issues across the corpus:")
        for iss, c in sorted(issue_counts.items(), key=lambda r: -r[1])[:8]:
            print(f"  {c:>4}  {iss}")

    # Most-frequent field issues — surfaced separately because schema
    # mistakes are higher-severity than style nitpicks.
    field_issue_counts: dict[str, int] = {}
    for _, _, _, _, fissues in rows:
        for fi in fissues:
            key = f"{fi.get('kind','?')}: `{fi.get('field','?')}` not on {','.join(fi.get('tables_in_scope',[]))}"
            field_issue_counts[key] = field_issue_counts.get(key, 0) + 1
    if field_issue_counts:
        print("\nMost-frequent FIELD issues (LLM hallucinations / wrong-table usage):")
        for iss, c in sorted(field_issue_counts.items(), key=lambda r: -r[1])[:10]:
            print(f"  {c:>4}  {iss}")

    # Worst N — rank by (style score asc, then field-issue count desc)
    rows.sort(key=lambda r: (r[0], -len(r[4])))
    print(f"\nWorst {top_n_worst} UCs (lowest scores):")
    for score, issues, uc, path, fissues in rows[:top_n_worst]:
        title = uc.get("title", "(no title)")[:90]
        print(f"\n  score={score}/{MAX_SCORE}  fields={len(fissues)}  {title}")
        print(f"    cache: {path.relative_to(ROOT)}")
        for iss in issues:
            print(f"    - {iss}")
        for fi in fissues[:3]:
            print(f"    - field: {fi.get('message','')}")

    return 0


# =============================================================================
# CLI
# =============================================================================

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Validate KQL knowledge integration.")
    ap.add_argument("--score", action="store_true",
                    help="Run cache-score mode against intel/.llm_uc_cache/ instead of prompt-shape mode.")
    ap.add_argument("--top", type=int, default=5,
                    help="In score mode, show this many worst-scoring UCs (default 5).")
    args = ap.parse_args(argv)

    if args.score:
        return run_cache_score(args.top)
    return run_prompt_shape()


if __name__ == "__main__":
    sys.exit(main())

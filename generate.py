"""
Hacker News -> Splunk (CIM) + Microsoft Defender (KQL) use case generator.

Deeper analysis edition:
  - Rule engine maps article narrative to real attack patterns
  - Each pattern emits one or more UseCases with:
      * Splunk CIM `tstats` query against the right data model
      * Defender Advanced Hunting KQL against the right table
      * MITRE ATT&CK techniques + kill chain phase
      * "Why this fires" reasoning specific to the article
  - Per-article kill chain visualization (Lockheed 7 phases)
  - Inferred follow-on phases (attackers rarely stop at one stage)

Output: a single self-contained `index.html`.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import html
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

import feedparser

# Sources & lookback configuration -------------------------------------------
LOOKBACK_DAYS = 30        # rolling 30-day window — keeps the site
                          # focused on currently-relevant intel and
                          # prunes stale articles from the briefings
                          # index. Bump back up if you want a deeper
                          # historical archive.
MAX_PER_SOURCE = 500      # safety cap per source per run

SOURCES = [
    # News-style sources — broad coverage, light on IOC tables.
    {"name": "The Hacker News",        "kind": "rss",
     "url":  "https://feeds.feedburner.com/TheHackersNews"},
    {"name": "BleepingComputer",        "kind": "rss",
     "url":  "https://www.bleepingcomputer.com/feed/"},
    {"name": "Microsoft Security Blog", "kind": "rss",
     "url":  "https://www.microsoft.com/en-us/security/blog/feed/"},
    # Vendor research blogs — heavy IOC content (hashes, defanged IPs, domains
    # in the article body). These are the primary feeders of the IOC export.
    {"name": "Cisco Talos",             "kind": "rss",
     "url":  "https://blog.talosintelligence.com/rss/"},
    {"name": "Securelist (Kaspersky)",  "kind": "rss",
     "url":  "https://securelist.com/feed/"},
    {"name": "SentinelLabs",            "kind": "rss",
     "url":  "https://www.sentinelone.com/labs/feed/"},
    {"name": "Unit 42 (Palo Alto)",     "kind": "rss",
     "url":  "https://unit42.paloaltonetworks.com/feed/"},
    {"name": "ESET WeLiveSecurity",     "kind": "rss",
     "url":  "https://www.welivesecurity.com/en/rss/feed/"},
    # Lab52 — threat-intel research arm of S2 Grupo. Heavy on APT
    # write-ups (RU/CN/MENA actors) with rich IOC tables and YARA.
    {"name": "Lab52",                   "kind": "rss",
     "url":  "https://lab52.io/blog/feed/"},
    # Cyber Security News — broad daily feed; complements the news-
    # style sources with extra coverage on emerging CVEs and POCs.
    {"name": "Cyber Security News",     "kind": "rss",
     "url":  "https://cybersecuritynews.com/feed/"},
    # Authoritative exploited-vuln feed.
    {"name": "CISA KEV",                "kind": "kev",
     "url":  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"},
]

# Legacy (kept for callers using the old API)
RSS_URL = SOURCES[0]["url"]
ARTICLE_LIMIT = 10
OUT_HTML = Path(__file__).with_name("index.html")


# =============================================================================
# Indicator extraction (atomic IOCs from the limited RSS summary)
# =============================================================================

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
HASH_MD5_RE = re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE)
HASH_SHA1_RE = re.compile(r"\b[a-f0-9]{40}\b", re.IGNORECASE)
HASH_SHA256_RE = re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE)
ATTACK_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# Defanged-only IOC extraction. Plain text "outlook.com" or "1.2.3.4" mentioned
# casually in an article summary is NOT a SOC-grade indicator — those are
# almost always legitimate platforms or victim infrastructure. We only accept
# domain/IP IOCs when the source author has *defanged* them with bracketed
# dots (`evil[.]com`, `1[.]2[.]3[.]4`) or `hxxp(s)://` — the universal
# convention for "this is malicious; don't auto-click".
# IPv4 forms: defanged ("1[.]2[.]3[.]4") and the variant with three defangs and
# one literal dot (sometimes seen in vendor write-ups, e.g. "139.180.139[.]209")
DEFANGED_IPV4_RE = re.compile(
    r"\b("
    r"(?:\d{1,3}\[\.\]){3}\d{1,3}"
    r"|"
    r"(?:\d{1,3}\.){2}\d{1,3}\[\.\]\d{1,3}"
    r"|"
    r"\d{1,3}\.\d{1,3}\[\.\]\d{1,3}\.\d{1,3}"
    r"|"
    r"\d{1,3}\[\.\]\d{1,3}\.\d{1,3}\.\d{1,3}"
    r")\b"
)
# Domain: 2+ labels with at least one `[.]` separator, ending in 2+-char TLD.
DEFANGED_DOMAIN_RE = re.compile(
    r"\b([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:(?:\[\.\]|\.)[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*\[\.\][a-z]{2,})\b",
    re.IGNORECASE,
)
# hxxp(s):// URL — capture host+path. Critically, allow `[.]` (defang) inside.
HXXP_URL_RE = re.compile(
    r"hxxps?://([a-z0-9.\-]+(?:\[\.\][a-z0-9.\-]+)*\[\.\][a-z]{2,}(?:/[^\s\"'<>]*)?)",
    re.IGNORECASE,
)


def _refang(s):
    """Convert defanged IOC back to canonical form for downstream tooling."""
    return (s.replace("[.]", ".").replace("[:]", ":")
             .replace("hxxp://", "http://").replace("hxxps://", "https://"))


def strip_html(s: str) -> str:
    return re.sub(r"<[^>]+>", " ", s or "")


def dedupe(seq):
    seen, out = set(), []
    for x in seq:
        k = x.lower() if isinstance(x, str) else x
        if k not in seen:
            seen.add(k)
            out.append(x)
    return out


def extract_indicators(title: str, body: str) -> dict:
    """
    SOC-grade IOC extraction. Quality bar:
      - CVE: regex match (unambiguous format, low FP rate)
      - Hash (MD5/SHA1/SHA256): regex match (high entropy, low FP rate)
      - Domain/IP: ONLY accept defanged forms (`evil[.]com`, `1[.]2[.]3[.]4`,
        `hxxps://...`). Plain-text mentions are almost always legitimate
        infrastructure (the victim, the platform, the security vendor),
        so they're rejected. This means article summaries that don't use
        defanged notation will produce zero domain/IP IOCs — which is the
        correct behaviour for a feed an analyst will block on.
    """
    text = f"{title}\n{body}"

    # Defanged IPs — high-confidence
    ips = dedupe(_refang(m.group(1)) for m in DEFANGED_IPV4_RE.finditer(text))

    # Defanged domains and hxxp:// URLs — extract host part of URLs
    domains = []
    for m in DEFANGED_DOMAIN_RE.finditer(text):
        domains.append(_refang(m.group(1)).lower())
    for m in HXXP_URL_RE.finditer(text):
        url_host = _refang(m.group(1)).split("/", 1)[0].lower()
        domains.append(url_host)
    domains = dedupe(domains)

    # ---- Quality filter: drop legitimate-platform / reserved IOCs ----
    # No SOC wants `google.com` or `8.8.8.8` blocked. These domains/IPs
    # appear in articles as legitimate context (the platform an attack
    # abused, the example DNS the malware queried, the victim site, etc.)
    # and should never make it to the IOC feed. Keep this list narrow:
    # only domains/IPs that are universally trusted infrastructure.
    domains = [d for d in domains if not _ioc_is_known_safe(d, kind="domain")]
    ips = [i for i in ips if not _ioc_is_known_safe(i, kind="ipv4")]

    return {
        "cves": dedupe(CVE_RE.findall(text)),
        "ips": ips,
        "domains": domains,
        "md5": dedupe(HASH_MD5_RE.findall(text)),
        "sha1": dedupe(HASH_SHA1_RE.findall(text)),
        "sha256": dedupe(HASH_SHA256_RE.findall(text)),
        "explicit_ttps": dedupe(ATTACK_RE.findall(text)),
    }


# Curated allowlist of legitimate-platform infrastructure. An article that
# mentions "the malware downloaded a file from google.com" doesn't mean we
# should ship google.com as an IOC — it's the dispenser, not the threat.
# Keep this list as small as possible; over-blocking risks dropping a real
# typosquat. Only include domains that NO real adversary would register.
_IOC_DOMAIN_ALLOWLIST = {
    # Mainstream user platforms
    "google.com", "www.google.com", "gmail.com", "youtube.com", "blogspot.com",
    "microsoft.com", "www.microsoft.com", "live.com", "outlook.com", "office.com",
    "office365.com", "onmicrosoft.com", "msn.com", "bing.com", "msftauth.net",
    "azure.com", "azurewebsites.net", "windows.net", "sharepoint.com",
    "apple.com", "icloud.com", "me.com", "mac.com", "appstoreios.apple.com",
    "amazon.com", "aws.amazon.com", "amazonaws.com", "amazonses.com",
    "cloudflare.com", "cloudflare-dns.com", "cdnjs.cloudflare.com",
    "facebook.com", "fb.com", "instagram.com", "whatsapp.com", "twitter.com",
    "x.com", "linkedin.com", "reddit.com", "pinterest.com", "tiktok.com",
    # Dev / package ecosystems
    "github.com", "raw.githubusercontent.com", "githubusercontent.com",
    "gist.github.com", "objects.githubusercontent.com",
    "gitlab.com", "bitbucket.org", "atlassian.net", "atlassian.com",
    "npmjs.org", "registry.npmjs.org", "yarnpkg.com", "pnpm.io",
    "pypi.org", "pythonhosted.org", "anaconda.org", "conda.anaconda.org",
    "rubygems.org", "crates.io", "packagist.org", "nuget.org",
    "docker.io", "hub.docker.com", "gcr.io", "ghcr.io", "quay.io", "mcr.microsoft.com",
    # Open-source / docs / standards
    "wikipedia.org", "stackoverflow.com", "stackexchange.com",
    "medium.com", "dev.to", "hackernoon.com",
    "rfc-editor.org", "ietf.org", "w3.org", "iana.org",
    "mozilla.org", "owasp.org",
    # Security-research / vendor reference (shouldn't be IOCs even when cited)
    "mitre.org", "attack.mitre.org", "cve.mitre.org", "nvd.nist.gov", "cisa.gov",
    "thehackernews.com", "bleepingcomputer.com", "krebsonsecurity.com",
    "talosintelligence.com", "blog.talosintelligence.com",
    "securelist.com", "sentinelone.com", "unit42.paloaltonetworks.com",
    "welivesecurity.com", "lab52.io", "cybersecuritynews.com",
    "checkmarx.com", "snyk.io", "socket.dev",
    "virustotal.com", "abuse.ch", "urlhaus.abuse.ch", "threatfox.abuse.ch",
    # Common legit dispensers (ARTICLE-CONTEXT only — these CAN be abused as
    # dead-drops by malware. We drop them from the IOC feed because alerting
    # on every pastebin URL would drown the SOC; analysts hunt these manually.)
    "pastebin.com", "ghostbin.com", "rentry.co", "snippet.host",
    # Generic test / example
    "example.com", "example.net", "example.org", "example.invalid",
    "localhost", "test.com", "yourorganisation.com",
    # Sample-data junk we've seen previously extracted
    "xxx.com", "appstoreios", "iosfc",
}

# Block IPv4s that are universally trusted, reserved, or non-routable.
def _is_reserved_or_safe_ipv4(ip: str) -> bool:
    try:
        a, b, c, d = (int(x) for x in ip.split("."))
    except Exception:
        return True  # malformed → treat as safe (drop)
    if a == 0:        return True   # 0.0.0.0/8
    if a == 10:       return True   # RFC1918
    if a == 127:      return True   # loopback
    if a == 169 and b == 254: return True  # link-local
    if a == 172 and 16 <= b <= 31: return True  # RFC1918
    if a == 192 and b == 168: return True  # RFC1918
    if a == 192 and b == 0 and c == 2: return True  # TEST-NET
    if a == 198 and (b == 18 or b == 19): return True
    if a == 198 and b == 51 and c == 100: return True  # TEST-NET
    if a == 203 and b == 0 and c == 113: return True  # TEST-NET
    if a >= 224:      return True   # multicast / reserved
    return False

_IOC_IPV4_ALLOWLIST = {
    # Public DNS providers — frequently cited in articles, never an IOC.
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
    "208.67.222.222", "208.67.220.220",
    # Microsoft / Cloudflare / Google sample IPs
    "20.20.20.20", "13.107.6.152",
}


def _ioc_is_known_safe(value: str, kind: str) -> bool:
    """Return True if the IOC should be dropped from the feed because it's
    known-good infrastructure. Used by extract_indicators() and the
    aggregator to keep `google.com` / `8.8.8.8` etc. out of intel/iocs.csv."""
    if not value:
        return True
    v = value.lower().strip()
    if kind == "domain":
        if v in _IOC_DOMAIN_ALLOWLIST:
            return True
        # Match subdomains of the allowlist (e.g. `cdn.cloudflare.com`)
        for safe in _IOC_DOMAIN_ALLOWLIST:
            if v == safe or v.endswith("." + safe):
                return True
        # Drop bare TLDs / single-label "domains" that slipped through
        if "." not in v:
            return True
        return False
    if kind == "ipv4":
        if v in _IOC_IPV4_ALLOWLIST:
            return True
        if _is_reserved_or_safe_ipv4(v):
            return True
        return False
    return False


# =============================================================================
# Article-mechanic extraction — pulls specific binaries / paths / cmdline
# fragments from the article body so we can emit a bespoke per-article UC
# that hunts THIS attack instead of just keyword-matching to a generic
# template. The output of extract_mechanics() drives _make_bespoke_uc().
# =============================================================================

# Binary names — limit to known-attacker-popular file extensions and reject
# common false positives like file extensions in URLs ("...example.com/foo.exe?dl=1").
_BINARY_RE = re.compile(
    r"(?<![/\w])([A-Za-z0-9_.\-]{2,40}\.(?:exe|dll|sys|bat|cmd|ps1|vbs|js|jse|hta|"
    r"scr|cpl|msi|msp|jar|py|sh|elf))(?![A-Za-z0-9])",
    re.IGNORECASE,
)
# Windows file paths — `C:\...\file.ext` or `%APPDATA%\...`, `\Users\Public\...` etc.
_WIN_PATH_RE = re.compile(
    r"(?<![\w])("
    r"(?:[A-Z]:\\|%[A-Za-z]+%\\|\\Users\\|\\Windows\\|\\ProgramData\\|"
    r"\\AppData\\|\\Temp\\|\\inetpub\\|\\System32\\|\\SysWOW64\\)"
    r"[A-Za-z0-9_.\-\\\\]{2,200}"
    r")",
)
# Unix file paths — start with /, common security-relevant prefixes.
_UNIX_PATH_RE = re.compile(
    r"(?<![\w])("
    r"/(?:tmp|var|etc|usr|opt|home|root|dev|Library|System|private)"
    r"/[A-Za-z0-9_./\-]{2,200}"
    r")",
)
# Registry keys (Run / RunOnce / Services / etc.).
_REGISTRY_RE = re.compile(
    r"(HK[LCU][MR]?\\[A-Za-z0-9_\\\\\.\-]{4,200})",
)
# Persistence container names commonly invoked verbatim.
_PERSISTENCE_KEYWORDS = {
    "scheduled task": "T1053.005",
    "schtasks": "T1053.005",
    "scheduled job": "T1053.005",
    "launchagent": "T1543.001",
    "launchdaemon": "T1543.004",
    "startup folder": "T1547.001",
    "run key": "T1547.001",
    "runonce": "T1547.001",
    "service create": "T1543.003",
    "windows service": "T1543.003",
    "wmi event": "T1546.003",
    "image file execution": "T1546.012",
}
# PowerShell / cmd flag fragments that almost always mean "this was attacker-run".
_CMDLINE_FRAGMENTS = [
    "-EncodedCommand", "-enc ", "FromBase64String", "DownloadString",
    "Invoke-Expression", "IEX(", "Net.WebClient", "-NoProfile -ExecutionPolicy Bypass",
    "-WindowStyle Hidden", "iwr -useb", "certutil -urlcache",
    "bitsadmin /transfer", "rundll32 javascript:", "regsvr32 /s /u /i:",
    "mshta http", "mshta vbscript:", "wmic process call create",
    "powershell -nop -w hidden", "wevtutil cl", "vssadmin delete shadows",
    "wbadmin delete", "bcdedit /set", "fsutil usn deletejournal",
    "/c Reg Add", "Add-MpPreference -ExclusionPath", "Set-MpPreference -DisableRealtime",
]


def extract_mechanics(title: str, body: str) -> dict:
    """Pull article-specific *attack mechanics* (not IOCs).

    What we collect:
      - binaries:   "qakbot.exe", "rclone.exe", "wwlib.dll", ...
      - win_paths:  "C:\\Users\\Public\\setup.exe", "%APPDATA%\\Microsoft\\..."
      - unix_paths: "/tmp/.X11/.malware", "/Library/LaunchAgents/com.evil.plist"
      - registry:   "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\..."
      - persistence: list of (keyword, mitre_tid) pairs found in narrative
      - cmdline_frags: which attacker-style flags / patterns were seen
    """
    text = f"{title}\n{body}"
    text_lower = text.lower()

    # Filter out binary noise (legit OS / utility binaries the article merely
    # mentions — including in CONTEXT). These would ruin signal in a hunt.
    NOISE_BINARIES = {
        # Core Windows
        "explorer.exe", "svchost.exe", "smss.exe", "csrss.exe", "wininit.exe",
        "lsass.exe", "winlogon.exe", "services.exe", "dwm.exe", "spoolsv.exe",
        "fontdrvhost.exe", "lsm.exe", "taskhostw.exe", "runtimebroker.exe",
        # Universal scripting / built-in utilities (almost always used in cmd
        # examples within an article — not a *named attacker tool*)
        "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
        "rundll32.exe", "regsvr32.exe", "mshta.exe", "wmic.exe",
        "certutil.exe", "bitsadmin.exe", "msiexec.exe", "regedit.exe",
        "tasklist.exe", "taskkill.exe", "net.exe", "net1.exe", "whoami.exe",
        "systeminfo.exe", "ipconfig.exe", "netsh.exe", "schtasks.exe",
        "sc.exe", "reg.exe", "find.exe", "findstr.exe", "where.exe",
        "ping.exe", "nslookup.exe", "tracert.exe", "ftp.exe", "tftp.exe",
        # Browsers + Office (common contextual mentions)
        "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "opera.exe",
        "brave.exe", "safari.exe", "outlook.exe", "winword.exe", "excel.exe",
        "powerpnt.exe", "onenote.exe", "teams.exe", "ms-teams.exe",
        # Common dev / sysadmin tools
        "code.exe", "cursor.exe", "git.exe", "python.exe", "python3.exe",
        "node.exe", "java.exe", "javaw.exe", "javac.exe", "go.exe",
        # Media / OS chrome
        "wmplayer.exe", "calc.exe", "notepad.exe", "mspaint.exe",
        # Generic short-name files we already filter by length but call out
        "setup.exe", "install.exe", "installer.exe", "update.exe", "uninstall.exe",
    }
    bins = [b.lower() for b in _BINARY_RE.findall(text)]
    bins = [b for b in bins if b not in NOISE_BINARIES and len(b) >= 6
              # Strip out doc-extension strings like "ftp.exe", which are
              # rarely article-specific. Article-specific bins typically have
              # a custom-looking stem (numbers, mixed case, underscores).
              ]
    bins = dedupe(bins)[:25]

    # Generic Windows paths that appear in nearly every Windows-mentioning
    # article. Hunting for "C:\Windows" alone is meaningless — every legit
    # process runs from there. These get filtered out below.
    NOISE_PATH_PREFIXES = (
        "c:\\windows", "c:\\program files", "c:\\users\\", "c:\\programdata",
        "c:\\users\\vagrant", "c:\\users\\analyst", "c:\\users\\sandbox",
        "c:\\users\\malware", "c:\\users\\test", "c:\\users\\admin",
        "c:\\users\\administrator", "c:\\users\\user",
    )
    GENERIC_WIN_PATHS = {
        # Exact-match paths that are almost always non-IOC narrative mentions
        "c:\\windows", "c:\\windows\\system32", "c:\\windows\\syswow64",
        "c:\\users", "c:\\users\\public", "c:\\programdata",
        "c:\\program files", "c:\\program files (x86)", "c:\\windows\\temp",
    }

    def _path_too_generic(p: str) -> bool:
        pl = p.lower().rstrip("\\")
        if pl in GENERIC_WIN_PATHS:
            return True
        # Researcher / VM artefact paths
        if any(pl.startswith(pref) and len(pl) - len(pref) < 18 for pref in (
            "c:\\users\\vagrant","c:\\users\\analyst","c:\\users\\sandbox",
            "c:\\users\\malware","c:\\users\\test","c:\\users\\admin",
            "c:\\users\\administrator","c:\\users\\user"
        )):
            return True
        # Reject paths that are just a top-level dir with one or zero subdirs
        depth = pl.count("\\")
        if depth <= 1:
            return True
        return False

    raw_win_paths = dedupe(p.replace("\\\\", "\\") for p in _WIN_PATH_RE.findall(text))
    win_paths = [p for p in raw_win_paths if not _path_too_generic(p)][:15]
    unix_paths = dedupe(_UNIX_PATH_RE.findall(text))[:15]
    registry = dedupe(_REGISTRY_RE.findall(text))[:15]

    persistence = []
    for kw, tid in _PERSISTENCE_KEYWORDS.items():
        if kw in text_lower:
            persistence.append({"keyword": kw, "technique": tid})

    cmdline_frags = []
    for f in _CMDLINE_FRAGMENTS:
        if f.lower() in text_lower:
            cmdline_frags.append(f)

    return {
        "binaries": bins,
        "win_paths": win_paths,
        "unix_paths": unix_paths,
        "registry": registry,
        "persistence": persistence,
        "cmdline_frags": cmdline_frags,
    }


# =============================================================================
# LLM-driven bespoke UC generation (opt-in via ANTHROPIC_API_KEY)
# =============================================================================
# Reads the article body with an LLM and emits structured detection content
# specific to the attack described — not a regex-extracted template. Called
# alongside _make_bespoke_uc() (regex). Both run; the LLM output is treated
# as a higher-confidence bespoke UC tier.
#
# Cost note: ~3-6K input tokens + ~1.5K output tokens per article. With
# claude-haiku-4-5 (cheapest current Claude) that's ~$0.005-0.01 per article,
# so ~$2-3 for a 300-article 180-day pipeline run. Cached per article URL
# so re-runs of the same articles are free.
LLM_UC_CACHE_DIR = Path(__file__).parent / "intel" / ".llm_uc_cache"
LLM_UC_MODEL = os.environ.get("USECASEINTEL_LLM_MODEL", "claude-haiku-4-5-20251001")
LLM_UC_MAX_BODY_CHARS = 15000  # cap body length sent to LLM


_LLM_UC_PROMPT = """You are a senior detection engineer at a SOC. You will be given a recent threat-intel article. Read it carefully and produce 1-3 high-quality detection use cases that hunt the SPECIFIC attack described — NOT a generic technique template.

You have WebSearch and WebFetch tools available. Before finalising your output, you SHOULD search the web for additional context that can corroborate or enrich the article's claims:
  - Vendor advisories (MSRC, Cisco PSIRT, Fortinet PSIRT) for any CVE mentioned
  - Other vendor write-ups of the same campaign / actor / malware family (Mandiant, CrowdStrike, Microsoft Threat Intel)
  - Public IOC bundles on the campaign (abuse.ch ThreatFox, AlienVault OTX, GitHub IOC-list repos)
  - MITRE ATT&CK group / software pages for any named actor or tool
  - Sigma rules or Splunk Security Content for the same TTPs (so we don't ship a duplicate)

Use what you find to:
  - Validate the IOCs / TTPs (only ship them if at least one second source confirms — drop if only the original article cites them)
  - Add mapped MITRE technique IDs you wouldn't have known from the article alone
  - Fill in actor / campaign / malware-family attribution when the article is vague
  - Note in `rationale` which external sources you cross-checked

Don't search for more than 2-3 things — keep it focused.


Output STRICT JSON matching this schema (no markdown fences, no prose, just one JSON object):

{
  "ucs": [
    {
      "title": "<concise behavioural title; e.g. 'Mustang Panda DLL side-load via signed Acrobat Reader' — under 100 chars>",
      "description": "<2-3 sentence operational summary; what this hunts and why it's article-specific>",
      "kill_chain": "<one of: recon, weapon, delivery, exploit, install, c2, actions>",
      "tier": "<alerting OR hunting — alerting only when query has named binaries / hashes / threshold / temporal correlation; default hunting>",
      "confidence": "<High, Medium, Low>",
      "fp_rate_estimate": "<low, medium, high, unknown>",
      "required_telemetry": ["<list of data sources e.g. 'Sysmon EID 1', 'Defender DeviceProcessEvents'>"],
      "techniques": [{"id":"T####.###","name":"<technique name>"}],
      "data_models": ["<Splunk CIM dataset names e.g. Endpoint.Processes, Network_Traffic.All_Traffic>"],
      "splunk_spl": "<full Splunk SPL using CIM tstats syntax. Reference SPECIFIC binaries/paths/cmdline strings from the article. Use macros like `summariesonly` and `drop_dm_object_name(<DM>)`.>",
      "defender_kql": "<full Microsoft Defender Advanced Hunting KQL. Use DeviceProcessEvents / DeviceFileEvents / DeviceNetworkEvents / DeviceRegistryEvents / EmailEvents / AADSignInEventsBeta etc. Reference the article's specific strings.>",
      "rationale": "<1-2 sentences: which strings/IOCs/behaviours from the article you used and why they're high-fidelity>",
      "corroborated_sources": ["<URLs of any external sources you cross-checked (vendor advisories, other articles, MITRE, abuse.ch). Empty list if you didn't search.>"]
    }
  ]
}

Hard rules:
- Use ACTUAL binaries / paths / hashes / cmdline patterns / domains named in the article. Do not invent or hallucinate.
- If the article describes the attack in narrative only (no specific strings), output {"ucs":[]} — silence beats a generic template.
- Splunk SPL must be CIM-conformant (tstats from datamodel=...).
- Defender KQL must be Advanced Hunting (real table + column names).
- Don't generate the same logic that would already be matched by these existing rules: phishing-link click+exec, LSASS access, PsExec lateral movement, Office spawning scripts, encoded PowerShell. Add ONLY genuinely article-specific detections.
- Maximum 3 UCs per article.

Article title: <<TITLE>>
Article URL: <<URL>>
Article body:
\"\"\"
<<BODY>>
\"\"\"

Pre-extracted IOCs from the article (use these in your queries where appropriate):
<<IOC_SUMMARY>>
"""


def _llm_call_via_oauth(prompt: str, enable_search: bool = True) -> str | None:
    """Call Claude through the user's Claude Code OAuth session via
    claude-agent-sdk. Returns the raw response text or None if the SDK
    isn't installed / the user isn't authenticated.

    When enable_search=True (default), Claude can use the WebSearch tool
    to cross-reference the article against other public sources before
    answering. This is what lets the LLM-emitted UCs reach genuinely
    high fidelity — multiple article sources confirm the IOCs / TTPs."""
    try:
        from claude_agent_sdk import query, ClaudeAgentOptions, AssistantMessage, TextBlock
    except ImportError:
        return None
    import asyncio
    async def _run():
        chunks = []
        if enable_search:
            # WebSearch lets Claude cross-check the article against vendor
            # advisories, MITRE attributions, public IOC dumps. max_turns=4
            # gives it room to do 1-2 search rounds + the final answer.
            options = ClaudeAgentOptions(
                max_turns=4,
                allowed_tools=["WebSearch", "WebFetch"],
            )
        else:
            options = ClaudeAgentOptions(max_turns=1, allowed_tools=[])
        async for msg in query(prompt=prompt, options=options):
            if isinstance(msg, AssistantMessage):
                for block in msg.content:
                    if isinstance(block, TextBlock):
                        chunks.append(block.text)
        return "".join(chunks)
    try:
        return asyncio.run(_run())
    except Exception as e:
        safe = str(e).encode("ascii","replace").decode("ascii")[:120]
        print(f"    [!] Claude Code OAuth call failed: {safe}")
        return None


def _llm_call_via_api_key(prompt: str, api_key: str) -> str | None:
    """Call Claude via api.anthropic.com with an x-api-key. Returns raw
    response text or None on error / library missing."""
    try:
        import anthropic
    except ImportError:
        print("    [!] anthropic library not installed — pip install anthropic")
        return None
    try:
        client = anthropic.Anthropic(api_key=api_key)
        msg = client.messages.create(
            model=LLM_UC_MODEL,
            max_tokens=4000,
            messages=[{"role": "user", "content": prompt}],
        )
        return "".join(block.text for block in msg.content if hasattr(block, "text"))
    except Exception as e:
        safe = str(e).encode("ascii","replace").decode("ascii")[:120]
        print(f"    [!] Anthropic API call failed: {safe}")
        return None


def _llm_should_process(article: dict, ind: dict) -> bool:
    """Filter — should this article go to the LLM at all?

    Each LLM call costs (token bill or subscription quota) and takes
    30-60s with web search enabled. Skip articles that won't yield
    useful UCs:
      - already-curated briefings (analyst overlay wins)
      - CISA KEV stubs (per-CVE only — IOC-substitution UC handles this)
      - very short bodies (RSS-only, no mechanics)
      - opinion / recap / webinar pieces with no attack mechanics
    """
    # Body length floor — RSS-only stubs are sub-300 chars
    body = article.get("raw_body", "") or ""
    if len(body) < 600:
        return False
    # CISA KEV entries are per-CVE; the asset-exposure template UC is
    # already a perfect match — LLM would just re-emit the same query.
    sources = article.get("sources") or [article.get("source", "")]
    if "CISA KEV" in sources and len(sources) == 1:
        return False
    title_lower = (article.get("title", "") or "").lower()
    body_lower = body.lower()
    # Skip non-attack content
    NON_ATTACK_TITLES = (
        "weekly recap", "this month in security", "in memoriam",
        "5 things to do", "ground zero", "5 places where",
        "what to look for", "webinar:", "webinar -", "podcast",
        "unlocked 403", "threatsday bulletin", "ai-powered defense",
        "making opportunistic", "the agentic soc",
    )
    if any(p in title_lower for p in NON_ATTACK_TITLES):
        return False
    # Want at least one attack-content keyword
    ATTACK_KEYWORDS = (
        "malware", "ransomware", "trojan", "stealer", "backdoor",
        "exploit", "vulnerab", "campaign", "actor", "apt", "cve-",
        "rce", "0-day", "zero-day", "phishing", "lateral", "dropper",
        "loader", "wiper", "rootkit", "implant", "botnet", "intrusion",
    )
    if not any(kw in title_lower or kw in body_lower[:2000] for kw in ATTACK_KEYWORDS):
        return False
    return True


def _llm_generate_ucs(article: dict, ind: dict):
    """Call Claude with the article body and parse a list of UseCase objects
    from the JSON response. Three auth paths, in priority order:
      1. USECASEINTEL_USE_CLAUDE_OAUTH=1 — claude-agent-sdk + user's
         Claude Code session (Pro / Max subscription)
      2. ANTHROPIC_API_KEY=... — direct API key (pay-per-token billing)
      3. neither set — skip cleanly, pipeline runs without LLM UCs
    Cached on disk by article URL hash so repeat runs cost nothing.
    Filtered to attack-content articles only — see _llm_should_process()."""
    use_oauth = os.environ.get("USECASEINTEL_USE_CLAUDE_OAUTH", "").lower() in ("1", "true", "yes")
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    url = article.get("link", "")
    if not url:
        return []
    # Cache is consulted regardless of auth-env state — cached responses are
    # free to read and represent past analyst-grade work that should keep
    # flowing into the site even when the operator runs without the LLM
    # creds set (e.g. a quick UI-only rebuild). Only NEW LLM calls require
    # auth; the env-var gate moved below the cache lookup.
    LLM_UC_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_key = hashlib.sha1(url.encode("utf-8", "replace")).hexdigest()
    cache_path = LLM_UC_CACHE_DIR / f"{cache_key[:2]}/{cache_key}.json"
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    if cache_path.exists():
        try:
            data = __import__("json").loads(cache_path.read_text(encoding="utf-8"))
            return [_uc_from_llm_dict(d) for d in data.get("ucs", []) if d]
        except Exception:
            pass
    # Cache miss — only proceed to make a new LLM call if auth is configured.
    if not use_oauth and not api_key:
        return []
    # USECASEINTEL_LLM_SKIP_FILTER=1 forces the LLM to process every
    # article regardless of attack-content heuristics. Useful for a
    # comprehensive corpus review; default-on filter saves tokens on
    # opinion / recap / webinar pieces.
    skip_filter = os.environ.get("USECASEINTEL_LLM_SKIP_FILTER", "").lower() in ("1", "true", "yes")
    if not skip_filter and not _llm_should_process(article, ind):
        return []
    body = (article.get("raw_body") or "")[:LLM_UC_MAX_BODY_CHARS]
    if len(body) < 200:
        return []  # not enough content for the LLM to ground on
    ioc_summary = []
    for k, label in [("cves","CVEs"),("ips","IPs"),("domains","Domains"),
                     ("sha256","SHA256"),("sha1","SHA1"),("md5","MD5")]:
        if ind.get(k):
            ioc_summary.append(f"  {label}: {', '.join(ind[k][:8])}")
    # Manual placeholder substitution — the prompt body contains literal
    # JSON `{...}` braces which would confuse str.format(), causing every
    # call to fail with a KeyError before ever reaching the LLM.
    prompt = (_LLM_UC_PROMPT
              .replace("<<TITLE>>",       article.get("title", "")[:200])
              .replace("<<URL>>",         url[:200])
              .replace("<<BODY>>",        body)
              .replace("<<IOC_SUMMARY>>", "\n".join(ioc_summary) or "  (none)"))
    raw = None
    if use_oauth:
        raw = _llm_call_via_oauth(prompt)
    if raw is None and api_key:
        raw = _llm_call_via_api_key(prompt, api_key)
    if raw is None:
        return []
    raw = raw.strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json)?\s*", "", raw)
        raw = re.sub(r"\s*```\s*$", "", raw)
    # The Agent SDK sometimes wraps the JSON in chatty prose. Try to
    # extract the first balanced { ... } block if a direct parse fails.
    json_lib = __import__("json")
    try:
        data = json_lib.loads(raw)
    except Exception:
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        if m:
            try:
                data = json_lib.loads(m.group(0))
            except Exception as e:
                print(f"    [!] LLM output JSON-parse failed: {str(e)[:80]}")
                return []
        else:
            print(f"    [!] LLM output had no JSON block: {raw[:80]!r}")
            return []
    cache_path.write_text(json_lib.dumps(data, indent=2), encoding="utf-8")
    return [_uc_from_llm_dict(d) for d in (data.get("ucs") or []) if d]


def _uc_from_llm_dict(d: dict):
    """Validate + coerce an LLM-emitted UC dict into a UseCase object."""
    if not isinstance(d, dict): return None
    title = (d.get("title") or "").strip()
    spl = d.get("splunk_spl") or ""
    kql = d.get("defender_kql") or ""
    if not title or not (spl or kql):
        return None
    techs = []
    for t in (d.get("techniques") or []):
        tid = (t or {}).get("id") if isinstance(t, dict) else t
        tname = (t or {}).get("name", "") if isinstance(t, dict) else ""
        if tid and re.match(r"^T\d{4}(\.\d{3})?$", str(tid)):
            techs.append((tid, tname or ""))
    tier = (d.get("tier") or "hunting").lower()
    if tier not in ("alerting", "hunting"):
        tier = "hunting"
    fp_rate = (d.get("fp_rate_estimate") or "unknown").lower()
    if fp_rate not in ("low", "medium", "high", "unknown"):
        fp_rate = "unknown"
    req_telem = d.get("required_telemetry") or []
    if not isinstance(req_telem, list):
        req_telem = [str(req_telem)]
    desc_parts = [(d.get("description") or "").strip()]
    if d.get("rationale"):
        desc_parts.append("\n\nRationale: " + (d.get("rationale") or "").strip())
    cs = d.get("corroborated_sources") or []
    if isinstance(cs, list) and cs:
        desc_parts.append("\n\nCross-checked against:")
        for u in cs[:6]:
            desc_parts.append(f"\n  • {u}")
    return UseCase(
        title=f"[LLM] {title[:140]}",
        description="".join(desc_parts),
        kill_chain=(d.get("kill_chain") or "actions"),
        techniques=techs,
        data_models=list(d.get("data_models") or []),
        splunk_spl=spl,
        defender_kql=kql,
        confidence=(d.get("confidence") or "Medium"),
        tier=tier,
        fp_rate_estimate=fp_rate,
        required_telemetry=[str(t) for t in req_telem][:8],
    )


def _make_bespoke_uc(article_title: str, mechanics: dict, ind: dict):
    """Assemble a *per-article* UseCase from the extracted mechanics.

    Returns None if there's not enough article-specific signal to build a
    meaningful detection — better silence than a query that fires on every
    `chrome.exe` execution. Threshold: at least one of (binary, win_path,
    unix_path, registry, cmdline_frag) must be present.
    """
    bins = mechanics.get("binaries") or []
    wpaths = mechanics.get("win_paths") or []
    upaths = mechanics.get("unix_paths") or []
    regs = mechanics.get("registry") or []
    cmdfrags = mechanics.get("cmdline_frags") or []
    persistence = mechanics.get("persistence") or []

    # Require a real article-specific anchor — otherwise we'd be emitting a
    # generic query that hunts on, e.g., the standard Run key alone, which is
    # neither novel nor article-specific.
    if not any([bins, wpaths, upaths, regs, cmdfrags]):
        return None

    safe_title = article_title[:80].strip()

    # Build SPL — a process / filesystem hunt scoped to the article's mechanics.
    spl_parts = []
    spl_parts.append(f'``` Article-specific bespoke detection — {safe_title} ```')

    proc_clauses = []
    if bins:
        bin_list = ",".join(f'"{b}"' for b in bins[:15])
        proc_clauses.append(f"Processes.process_name IN ({bin_list})")
    if cmdfrags:
        for f in cmdfrags[:6]:
            proc_clauses.append(f'Processes.process="*{f}*"')
    if wpaths:
        for p in wpaths[:5]:
            esc = p.replace('"', '\\"')
            proc_clauses.append(f'Processes.process_path="*{esc}*"')

    if proc_clauses:
        clauses = " OR ".join(proc_clauses)
        spl_parts.append(
            "| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime\n"
            "    from datamodel=Endpoint.Processes\n"
            f"    where ({clauses})\n"
            "    by Processes.dest, Processes.user, Processes.process_name,\n"
            "       Processes.process, Processes.parent_process_name, Processes.process_path\n"
            "| `drop_dm_object_name(Processes)`\n"
            "| `security_content_ctime(firstTime)`"
        )

    fs_clauses = []
    if wpaths or upaths:
        for p in (wpaths + upaths)[:8]:
            esc = p.replace('"', '\\"')
            fs_clauses.append(f'Filesystem.file_path="*{esc}*"')
    if bins:
        # Also surface filesystem-create events for the named binaries
        bin_filenames = ",".join(f'"{b}"' for b in bins[:15])
        fs_clauses.append(f"Filesystem.file_name IN ({bin_filenames})")
    if fs_clauses:
        clauses = " OR ".join(fs_clauses)
        if proc_clauses:
            spl_parts.append("| append [")
        spl_parts.append(
            "| tstats `summariesonly` count\n"
            "    from datamodel=Endpoint.Filesystem\n"
            f"    where Filesystem.action IN (\"created\",\"modified\")\n"
            f"      AND ({clauses})\n"
            "    by Filesystem.dest, Filesystem.user, Filesystem.process_name,\n"
            "       Filesystem.file_path, Filesystem.file_name\n"
            "| `drop_dm_object_name(Filesystem)`"
        )
        if proc_clauses:
            spl_parts.append("]")

    if regs:
        reg_clauses = []
        for r in regs[:6]:
            esc = r.replace('"', '\\"').replace("\\", "\\\\")
            reg_clauses.append(f'Registry.registry_path="*{esc}*"')
        clauses = " OR ".join(reg_clauses)
        spl_parts.append(
            "| append [\n"
            "  | tstats `summariesonly` count\n"
            "      from datamodel=Endpoint.Registry\n"
            f"      where Registry.action IN (\"created\",\"modified\")\n"
            f"        AND ({clauses})\n"
            "      by Registry.dest, Registry.process_name, Registry.registry_path,\n"
            "         Registry.registry_value_name, Registry.registry_value_data\n"
            "  | `drop_dm_object_name(Registry)`\n"
            "]"
        )

    spl = "\n".join(spl_parts)

    # Build KQL — same shape, Defender XDR tables.
    kql_lines = [
        f"// Article-specific bespoke detection — {safe_title}",
        f"// Hunts the actual binaries / paths / commandline fragments named",
        f"// in the article instead of a generic technique-class template.",
    ]
    proc_filters = []
    if bins:
        proc_filters.append(
            "FileName in~ (" + ", ".join(f'"{b}"' for b in bins[:15]) + ")")
    if cmdfrags:
        cf = ", ".join(f'"{f}"' for f in cmdfrags[:6])
        proc_filters.append(f"ProcessCommandLine has_any ({cf})")
    if wpaths:
        # KQL has_any expects no leading/trailing wildcards
        wp = ", ".join(f'"{p}"' for p in wpaths[:5])
        proc_filters.append(f"FolderPath has_any ({wp})")

    if proc_filters:
        kql_lines.append("DeviceProcessEvents")
        kql_lines.append("| where Timestamp > ago(30d)")
        kql_lines.append("| where (" + " or ".join(proc_filters) + ")")
        kql_lines.append("| project Timestamp, DeviceName, AccountName, FileName,")
        kql_lines.append("          FolderPath, ProcessCommandLine,")
        kql_lines.append("          InitiatingProcessFileName, InitiatingProcessCommandLine")
        kql_lines.append("| order by Timestamp desc")

    fs_filters = []
    if wpaths or upaths:
        all_paths = (wpaths + upaths)[:8]
        if all_paths:
            fp = ", ".join(f'"{p}"' for p in all_paths)
            fs_filters.append(f"FolderPath has_any ({fp})")
    if bins:
        bf = ", ".join(f'"{b}"' for b in bins[:15])
        fs_filters.append(f"FileName in~ ({bf})")
    if fs_filters:
        kql_lines.append("\n// File-creation events for the named binaries / paths")
        kql_lines.append("DeviceFileEvents")
        kql_lines.append("| where Timestamp > ago(30d)")
        kql_lines.append("| where ActionType in (\"FileCreated\",\"FileModified\")")
        kql_lines.append("| where (" + " or ".join(fs_filters) + ")")
        kql_lines.append("| project Timestamp, DeviceName, AccountName, FolderPath,")
        kql_lines.append("          FileName, ActionType, InitiatingProcessFileName,")
        kql_lines.append("          InitiatingProcessCommandLine")
        kql_lines.append("| order by Timestamp desc")

    if regs:
        rkql = ", ".join(f'"{r}"' for r in regs[:6])
        kql_lines.append("\n// Registry persistence locations named in the article")
        kql_lines.append("DeviceRegistryEvents")
        kql_lines.append("| where Timestamp > ago(30d)")
        kql_lines.append("| where ActionType in (\"RegistryValueSet\",\"RegistryKeyCreated\")")
        kql_lines.append(f"| where RegistryKey has_any ({rkql})")
        kql_lines.append("| project Timestamp, DeviceName, AccountName, RegistryKey,")
        kql_lines.append("          RegistryValueName, RegistryValueData,")
        kql_lines.append("          InitiatingProcessFileName, InitiatingProcessCommandLine")
        kql_lines.append("| order by Timestamp desc")

    kql = "\n".join(kql_lines)

    # Pick a kill-chain phase and a representative technique.
    if cmdfrags or bins:
        ph = "exploit"
    elif persistence:
        ph = "install"
    elif regs:
        ph = "install"
    elif wpaths or upaths:
        ph = "install"
    else:
        ph = "actions"

    techs = []
    if cmdfrags:
        techs.append(("T1059.001", "PowerShell"))
        techs.append(("T1027", "Obfuscated Files or Information"))
    if persistence:
        for p in persistence[:3]:
            techs.append((p["technique"], "Persistence (article-specific)"))
    if not techs:
        techs.append(("T1204.002", "User Execution: Malicious File"))

    # Tier: bespoke article UCs are HUNTING by default — they list rows
    # matching strings extracted from the article body. They lack
    # environment baselining (legit binary allowlist) and false-positive
    # suppression. An analyst should run them as hunts, then promote to
    # alerting after tuning + adding suppression.
    return UseCase(
        title=f"Article-specific behavioural hunt — {safe_title}",
        description=(
            "Auto-generated hunt targeting the specific binaries, paths, "
            "registry locations and command-line fragments named in this "
            "article. Hunting tier — needs analyst review and environment "
            "tuning before promotion to alerting."
        ),
        kill_chain=ph,
        techniques=techs,
        data_models=["Endpoint.Processes", "Endpoint.Filesystem", "Endpoint.Registry"],
        splunk_spl=spl,
        defender_kql=kql,
        confidence="High",
        tier="hunting",
    )


# =============================================================================
# Cyber Kill Chain (Lockheed Martin) phases
# =============================================================================

KILL_CHAIN_PHASES = [
    ("recon", "Reconnaissance", "Attacker researches the target — OSINT, scanning, enumeration."),
    ("weapon", "Weaponization", "Coupling exploit code with deliverable payload (e.g. weaponized PDF/Office doc, trojanized installer)."),
    ("delivery", "Delivery", "Transmitting the weapon (phishing email, USB, watering hole, drive-by, malicious ad)."),
    ("exploit", "Exploitation", "Triggering the exploit — vulnerability/macro/trust abuse to execute code."),
    ("install", "Installation", "Establishing persistence on the host — backdoor, service, scheduled task, registry key."),
    ("c2", "Command & Control", "Beacon to attacker infrastructure for control and tasking."),
    ("actions", "Actions on Objectives", "Lateral movement, credential dumping, data theft, ransomware, sabotage."),
]
PHASE_IDS = {p[0] for p in KILL_CHAIN_PHASES}


# =============================================================================
# UseCase + Rule data model
# =============================================================================

@dataclass
class UseCase:
    title: str
    description: str
    kill_chain: str
    techniques: list  # [(id, name)]
    data_models: list  # ["Endpoint.Processes", "Network_Traffic"]
    splunk_spl: str
    defender_kql: str
    confidence: str = "Medium"
    # Tier classification:
    #   "alerting" — high-fidelity. Specific IOCs, named binaries, threshold
    #                or temporal correlation, statistically anomalous. Safe
    #                to wire to a SIEM rule with normal triage SLA.
    #   "hunting"  — starter content. Returns rows that need analyst review;
    #                will produce false positives without environment tuning.
    # Default to hunting to keep the bar conservative — opt UCs into
    # alerting only when the logic clearly meets that bar.
    tier: str = "hunting"
    # Estimated false-positive rate. One of:
    #   "low"     — <1 fire per week per 10K endpoints in a tuned environment
    #   "medium"  — 1-10 fires per week (still actionable)
    #   "high"    — >10 fires per week (hunt only, do not alert)
    #   "unknown" — not yet measured (default; bias toward hunting)
    fp_rate_estimate: str = "unknown"
    # Required telemetry — UC will return zero rows without these data sources.
    # Helps SOC triage whether they have coverage before deploying. Free-form
    # list of strings, e.g. ["Sysmon EID 1", "Defender DeviceProcessEvents",
    # "EDR process telemetry", "M365 EmailEvents"].
    required_telemetry: list = field(default_factory=list)


def _infer_tier_from_query(spl: str, kql: str, confidence: str) -> str:
    """Heuristic tier classifier for UCs that don't set tier explicitly.

    Returns "alerting" if the query has any of: temporal correlation
    (between (T1 .. T1+Ns)), threshold (count > N / dcount > N), specific
    binary list, hash/IOC IN-list, or anomaly-detection language. Otherwise
    "hunting" — return-rows queries that need an analyst to triage.
    """
    blob = (spl or "") + "\n" + (kql or "")
    blob_l = blob.lower()
    alerting_signals = [
        # Temporal correlation
        " between (", "datetime_diff(", "earliest(_time)", "latest(_time)",
        # Thresholds
        "count > ", "count>=", "count >=", " sum(count) >",
        "dcount(", "dc(", "files > ", "events > ", "uniq",
        # Anomaly statistics
        "stdev(", "stdev_delta", "avg(delta", "avg_delta",
        # Specific IOC substitution slots (UC fires only when IOCs present)
        "__cve_list__", "__ip_list__", "__domain_list__", "__hash_list__",
        # Specific named-binary hunts
        " in (\"", " in~ (\"", "filename in~", "process_name in (",
        # MFA / brute-force rate
        "attempts > ", "logoncount", "mfaprompts >",
    ]
    if any(s in blob_l for s in alerting_signals):
        return "alerting"
    if (confidence or "").lower() == "high" and "data_models=endpoint.processes" in blob_l.replace(" ",""):
        return "alerting"
    return "hunting"


@dataclass
class Rule:
    name: str
    triggers: list  # list of substrings (case-insensitive). ANY-match.
    use_cases: list  # callables or dicts producing UseCase(s)


def _tech(*pairs):
    return [(t.split("|")[0], t.split("|")[1]) for t in pairs]


# =============================================================================
# Use case + rule loader — reads YAML files from use_cases/ and rules/
# =============================================================================

USE_CASES_DIR = Path(__file__).parent / "use_cases"
RULES_DIR = Path(__file__).parent / "rules"


def _load_uc_from_yaml(path):
    import yaml as _yaml
    doc = _yaml.safe_load(path.read_text(encoding="utf-8"))
    if not doc or not isinstance(doc, dict):
        return None
    impls = doc.get("implementations") or []
    dms = doc.get("data_models") or {}
    splunk_dms = dms.get("splunk") or []
    defender_tables = dms.get("defender") or []
    flat_dms = list(splunk_dms) + [t for t in defender_tables if t not in splunk_dms]
    techs = [(t["id"], t["name"]) for t in (doc.get("mitre_attack") or [])]
    spl = (doc.get("splunk_spl") or "") if "splunk" in impls else ""
    kql = (doc.get("defender_kql") or "") if "defender" in impls else ""
    confidence = doc.get("confidence", "Medium")
    # Tier: explicit field wins; otherwise infer from query shape.
    tier = (doc.get("tier") or "").strip().lower() or _infer_tier_from_query(spl, kql, confidence)
    if tier not in ("alerting", "hunting"):
        tier = "hunting"
    fp_rate = (doc.get("fp_rate_estimate") or "unknown").strip().lower()
    if fp_rate not in ("low", "medium", "high", "unknown"):
        fp_rate = "unknown"
    req_telemetry = doc.get("required_telemetry") or []
    if not isinstance(req_telemetry, list):
        req_telemetry = [str(req_telemetry)]
    return UseCase(
        title=doc.get("title", ""),
        description=(doc.get("description") or "").strip(),
        kill_chain=doc.get("kill_chain", "actions"),
        techniques=techs,
        data_models=flat_dms,
        splunk_spl=spl,
        defender_kql=kql,
        confidence=confidence,
        tier=tier,
        fp_rate_estimate=fp_rate,
        required_telemetry=[str(t) for t in req_telemetry],
    )


def _load_rule_from_yaml(path, uc_lookup):
    import yaml as _yaml
    doc = _yaml.safe_load(path.read_text(encoding="utf-8"))
    if not doc:
        return None
    fires = []
    for uc_id in doc.get("fires") or []:
        uc = uc_lookup.get(uc_id)
        if uc:
            fires.append(uc)
    return Rule(
        name=doc.get("name", path.stem),
        triggers=list(doc.get("triggers") or []),
        use_cases=fires,
    )


def _load_catalog():
    """Load all UseCases and Rules from YAML, expose them at module level."""
    if not USE_CASES_DIR.exists():
        print(f"[!] {USE_CASES_DIR} not found — using inline catalog (legacy mode)")
        return None, None
    use_cases = {}
    for path in sorted(USE_CASES_DIR.rglob("*.yml")):
        if path.name.startswith("_") or path.name == "SCHEMA.md":
            continue
        uc = _load_uc_from_yaml(path)
        if uc is None:
            continue
        uc_id = path.stem  # filename = id
        use_cases[uc_id] = uc
    rules = []
    if RULES_DIR.exists():
        for path in sorted(RULES_DIR.glob("*.yml")):
            r = _load_rule_from_yaml(path, use_cases)
            if r and r.use_cases:
                rules.append(r)
    return use_cases, rules


_LOADED_UCS, _LOADED_RULES = _load_catalog()
if _LOADED_UCS:
    # Expose every loaded use case as a module-level variable so the matrix
    # builder, validator, and renderer continue to work as before.
    for _uc_id, _uc in _LOADED_UCS.items():
        globals()[_uc_id] = _uc
    # Drop the loop variables — otherwise the leftover `_uc` lingers in
    # module globals and the matrix builder picks it up as an extra UseCase.
    del _uc_id, _uc
    print(f"[*] Loaded {len(_LOADED_UCS)} use cases from {USE_CASES_DIR}")
    print(f"[*] Loaded {len(_LOADED_RULES)} rules from {RULES_DIR}")


# =============================================================================
# Inline use case templates (legacy) — these get OVERRIDDEN at the end of the
# rules block by the YAML-loaded versions. Will be deleted entirely once we're
# fully on YAML and have git-committed the use_cases/ tree.
# =============================================================================

UC_PHISH_LINK = UseCase(
    title="Suspicious URL click in email — phishing landing page",
    description=(
        "User followed a link from an external email to an uncategorized / "
        "young-domain page. Pivots from the Email DM onto the Web DM to flag the "
        "click-through chain that typically precedes credential theft."
    ),
    kill_chain="delivery",
    techniques=_tech("T1566.002|Spearphishing Link", "T1204.001|User Execution: Malicious Link"),
    data_models=["Email.All_Email", "Web"],
    splunk_spl="""\
| tstats `summariesonly` count
    from datamodel=Email.All_Email
    where All_Email.action="delivered" AND All_Email.url!="-"
    by All_Email.src_user, All_Email.recipient, All_Email.url, All_Email.subject
| rex field=All_Email.url "https?://(?<email_domain>[^/]+)"
| join type=inner email_domain
    [| tstats `summariesonly` count
        from datamodel=Web
        where Web.action="allowed"
        by Web.src, Web.dest, Web.url, Web.user
     | rex field=Web.url "https?://(?<email_domain>[^/]+)"]
| stats values(All_Email.subject) as subject, values(Web.url) as clicked_url,
        earliest(_time) as first_seen, latest(_time) as last_seen
        by All_Email.recipient, email_domain
""",
    defender_kql="""\
let LookbackDays = 7d;
let DeliveredEmails = EmailEvents
    | where Timestamp > ago(LookbackDays)
    | where DeliveryAction == "Delivered"
    | project NetworkMessageId, Subject, SenderFromAddress, RecipientEmailAddress,
              EmailTimestamp = Timestamp;
EmailUrlInfo
| where Timestamp > ago(LookbackDays)
| join kind=inner DeliveredEmails on NetworkMessageId
| join kind=inner (
    UrlClickEvents
    | where Timestamp > ago(LookbackDays)
    | where ActionType == "ClickAllowed"
    | project Url, ClickTimestamp = Timestamp, AccountUpn, IPAddress
  ) on Url
| project ClickTimestamp, RecipientEmailAddress, SenderFromAddress,
          Subject, Url, UrlDomain, IPAddress
| order by ClickTimestamp desc
""",
    confidence="High",
)

UC_PHISH_ATTACH = UseCase(
    title="Email attachment opened from external sender",
    description="Attachment delivery + execution by recipient — most common malware initial access.",
    kill_chain="delivery",
    techniques=_tech("T1566.001|Spearphishing Attachment", "T1204.002|User Execution: Malicious File"),
    data_models=["Email.All_Email", "Endpoint.Processes"],
    splunk_spl="""\
| tstats `summariesonly` count
    from datamodel=Email.All_Email
    where All_Email.file_name!="-"
    by All_Email.src_user, All_Email.recipient, All_Email.file_name, All_Email.subject
| rename All_Email.recipient as user
| join type=inner user
    [| tstats `summariesonly` count
        from datamodel=Endpoint.Processes
        where Processes.parent_process_name IN ("OUTLOOK.EXE","winword.exe","excel.exe","powerpnt.exe")
          AND Processes.process_name IN ("cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe")
        by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
     | rename Processes.user as user]
""",
    defender_kql="""\
let LookbackDays = 7d;
let MalAttachments = EmailAttachmentInfo
    | where Timestamp > ago(LookbackDays)
    | project NetworkMessageId, RecipientEmailAddress,
              AttachmentFileName = FileName, AttachmentSHA256 = SHA256;
DeviceProcessEvents
| where Timestamp > ago(LookbackDays)
| where InitiatingProcessFileName in~ ("OUTLOOK.EXE","winword.exe","excel.exe","powerpnt.exe")
| where FileName in~ ("cmd.exe","powershell.exe","wscript.exe","cscript.exe",
                      "mshta.exe","rundll32.exe","regsvr32.exe")
| join kind=inner MalAttachments on $left.AccountUpn == $right.RecipientEmailAddress
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, AttachmentFileName, AttachmentSHA256
""",
    confidence="High",
)

UC_OFFICE_CHILD = UseCase(
    title="Office app spawning script/LOLBin child process",
    description="Classic macro/exploit pattern — Office app launching cmd/powershell/wmic/regsvr32.",
    kill_chain="exploit",
    techniques=_tech("T1059.001|PowerShell", "T1059.005|Visual Basic", "T1218|System Binary Proxy Execution"),
    data_models=["Endpoint.Processes"],
    splunk_spl="""\
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe","mspub.exe","visio.exe")
      AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","wmic.exe","bitsadmin.exe","certutil.exe")
    by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
""",
    defender_kql="""\
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe","mspub.exe","visio.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","wmic.exe","bitsadmin.exe","certutil.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
""",
    confidence="High",
)

UC_PS_OBFUSCATED = UseCase(
    title="PowerShell encoded / obfuscated command",
    description="Encoded or obfuscated PowerShell — common across loaders, recon, and post-exploitation.",
    kill_chain="exploit",
    techniques=_tech("T1059.001|PowerShell", "T1027|Obfuscated Files or Information"),
    data_models=["Endpoint.Processes"],
    splunk_spl="""\
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("powershell.exe","pwsh.exe")
      AND (Processes.process="*-enc *" OR Processes.process="*EncodedCommand*"
        OR Processes.process="*FromBase64String*" OR Processes.process="*-nop*"
        OR Processes.process="*-w hidden*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*IEX(*" OR Processes.process="*DownloadString*"
        OR Processes.process="*Net.WebClient*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
""",
    defender_kql="""\
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)(-enc|encodedcommand|frombase64string|-nop|-w\s+hidden|invoke-expression|iex\s*\(|downloadstring|net\.webclient)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
""",
    confidence="High",
)

UC_LSASS = UseCase(
    title="LSASS process access / dump (credential theft)",
    description="Mimikatz, comsvcs.dll MiniDump, or any non-Windows process opening LSASS.",
    kill_chain="actions",
    techniques=_tech("T1003.001|LSASS Memory", "T1003|OS Credential Dumping"),
    data_models=["Endpoint.Processes"],
    splunk_spl="""\
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process="*lsass*" OR Processes.process="*sekurlsa*"
        OR Processes.process="*MiniDump*" OR Processes.process="*comsvcs.dll*MiniDump*"
        OR Processes.process="*procdump*lsass*")
       OR (Processes.process_name="rundll32.exe" AND Processes.process="*comsvcs*MiniDump*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
""",
    defender_kql="""\
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsSense.exe","MsMpEng.exe","csrss.exe",
                                          "svchost.exe","wininit.exe","services.exe",
                                          "lsm.exe","SearchProtocolHost.exe")
| project Timestamp, DeviceName, ActionType, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, AccountName
| order by Timestamp desc
""",
    confidence="High",
)

UC_BEACONING = UseCase(
    title="Beaconing — periodic outbound to small set of destinations",
    description="C2 channel detection via inter-beacon-time stddev / fan-out to single dest.",
    kill_chain="c2",
    techniques=_tech("T1071.001|Web Protocols", "T1071.004|DNS"),
    data_models=["Network_Traffic.All_Traffic"],
    splunk_spl="""\
| tstats `summariesonly` count, values(All_Traffic.dest_port) AS ports
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.action="allowed" AND All_Traffic.dest_category!="internal"
    by _time span=10s, All_Traffic.src, All_Traffic.dest
| `drop_dm_object_name(All_Traffic)`
| streamstats current=f last(_time) AS prev_time by src, dest
| eval delta = _time - prev_time
| stats avg(delta) AS avg_delta stdev(delta) AS sd_delta count by src, dest
| where count > 30 AND sd_delta < 5 AND avg_delta>=30 AND avg_delta<=600
| sort - count
""",
    defender_kql="""\
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteIPType == "Public" and ActionType == "ConnectionSuccess"
| project DeviceName, RemoteIP, RemotePort, Timestamp
| sort by DeviceName asc, RemoteIP asc, RemotePort asc, Timestamp asc
| extend prev_dev = prev(DeviceName, 1), prev_ip = prev(RemoteIP, 1),
         prev_port = prev(RemotePort, 1), prev_ts = prev(Timestamp, 1)
| where DeviceName == prev_dev and RemoteIP == prev_ip and RemotePort == prev_port
| extend delta_sec = datetime_diff('second', Timestamp, prev_ts)
| summarize conn_count = count(), avg_delta = avg(delta_sec), stdev_delta = stdev(delta_sec)
    by DeviceName, RemoteIP, RemotePort
| where conn_count > 30 and avg_delta between (30.0 .. 600.0) and stdev_delta < 5.0
| order by conn_count desc
""",
    confidence="Medium",
)

UC_DNS_TUNNEL = UseCase(
    title="DNS tunneling / TXT-heavy domain queries",
    description="Long subdomain labels + frequent queries to a single 2LD = DNS C2/exfil.",
    kill_chain="c2",
    techniques=_tech("T1071.004|DNS", "T1048.003|Exfiltration Over Unencrypted Non-C2 Protocol"),
    data_models=["Network_Resolution.DNS"],
    splunk_spl="""\
| tstats `summariesonly` count from datamodel=Network_Resolution.DNS
    where DNS.message_type="QUERY"
    by DNS.src, DNS.query
| `drop_dm_object_name(DNS)`
| eval qlen=len(query)
| where qlen > 50
| rex field=query "(?<second_level_domain>[\\w-]+\\.[\\w-]+)$"
| stats sum(count) AS qcount, dc(query) AS unique_subs, max(qlen) AS max_label
    by src, second_level_domain
| where qcount > 100 AND unique_subs > 20
| sort - qcount
""",
    defender_kql="""\
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemotePort == 53 and isnotempty(RemoteUrl)
| extend qlen = strlen(RemoteUrl)
| where qlen > 50
| extend SecondLevelDomain = extract(@"([\w-]+\.[a-zA-Z]{2,})$", 1, RemoteUrl)
| summarize qcount = count(), uniqueSubs = dcount(RemoteUrl), maxLabel = max(qlen)
    by DeviceName, SecondLevelDomain
| where qcount > 100 and uniqueSubs > 20
| order by qcount desc
""",
    confidence="Medium",
)

UC_SCHEDULED_TASK = UseCase(
    title="Scheduled task created with suspicious image / encoded args",
    description="schtasks.exe /create or Microsoft-Windows-TaskScheduler EventID 4698 with LOLBin actions.",
    kill_chain="install",
    techniques=_tech("T1053.005|Scheduled Task"),
    data_models=["Endpoint.Processes"],
    splunk_spl="""\
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name="schtasks.exe" AND Processes.process="*/create*"
      AND (Processes.process="*powershell*" OR Processes.process="*cmd.exe*"
        OR Processes.process="*rundll32*" OR Processes.process="*-enc*"
        OR Processes.process="*FromBase64*" OR Processes.process="*\\Users\\Public*"
        OR Processes.process="*\\AppData\\*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
""",
    defender_kql="""\
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has_any ("powershell","cmd.exe","rundll32","-enc","FromBase64","\\Users\\Public","\\AppData\\")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
""",
    confidence="High",
)

UC_SERVICE_PERSIST = UseCase(
    title="Service install for persistence — sc.exe / new service registry write",
    description=(
        "Service install with binPath pointing to user-writeable path or LOLBin. "
        "Detects via process telemetry (sc.exe create) and registry "
        "(HKLM\\SYSTEM\\CurrentControlSet\\Services\\* writes)."
    ),
    kill_chain="install",
    techniques=_tech("T1543.003|Windows Service"),
    data_models=["Endpoint.Processes", "Endpoint.Registry"],
    splunk_spl="""\
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name="sc.exe" AND Processes.process="*create*"
      AND (Processes.process="*\\Users\\*" OR Processes.process="*\\AppData\\*"
        OR Processes.process="*\\ProgramData\\*" OR Processes.process="*\\Temp\\*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| append
    [| tstats `summariesonly` count from datamodel=Endpoint.Registry
        where Registry.registry_path="*\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\*"
          AND Registry.registry_value_name="ImagePath"
          AND (Registry.registry_value_data="*\\Users\\*"
            OR Registry.registry_value_data="*\\AppData\\*"
            OR Registry.registry_value_data="*\\Temp\\*")
        by Registry.dest, Registry.registry_path, Registry.registry_value_data, Registry.user
     | `drop_dm_object_name(Registry)`]
""",
    defender_kql="""\
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "sc.exe" and ProcessCommandLine has "create"
| where ProcessCommandLine matches regex @"(?i)(\\Users\\|\\AppData\\|\\ProgramData\\|\\Temp\\)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
""",
    confidence="High",
)

UC_VULN_EXPOSURE = UseCase(
    title="Asset exposure — vulnerability matches article CVE(s)",
    description="Match vulnerability scanner output to the CVE(s) named in the article.",
    kill_chain="recon",
    techniques=_tech("T1190|Exploit Public-Facing Application"),
    data_models=["Vulnerabilities"],
    splunk_spl="""\
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Vulnerabilities
    where Vulnerabilities.signature IN (__CVE_LIST__)
    by Vulnerabilities.dest, Vulnerabilities.signature, Vulnerabilities.severity, Vulnerabilities.cve
| `drop_dm_object_name(Vulnerabilities)`
| sort - severity
""",
    defender_kql="""\
DeviceTvmSoftwareVulnerabilities
| where CveId in~ (__CVE_LIST__)
| join kind=inner DeviceInfo on DeviceId
| project DeviceName, OSPlatform, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
""",
    confidence="High",
)

UC_NETWORK_IOC = UseCase(
    title="Network connections to article IPs / domains",
    description="Outbound traffic to attacker infrastructure named in the article.",
    kill_chain="c2",
    techniques=_tech("T1071|Application Layer Protocol"),
    data_models=["Network_Traffic.All_Traffic", "Web", "Network_Resolution.DNS"],
    splunk_spl="""\
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.dest IN (__IP_LIST__)
    by All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port
| `drop_dm_object_name(All_Traffic)`
| append
    [| tstats `summariesonly` count from datamodel=Web
        where Web.dest IN (__DOMAIN_LIST__)
        by Web.src, Web.dest, Web.url, Web.user
     | `drop_dm_object_name(Web)`]
| append
    [| tstats `summariesonly` count from datamodel=Network_Resolution.DNS
        where DNS.query IN (__DOMAIN_LIST__)
        by DNS.src, DNS.query, DNS.answer
     | `drop_dm_object_name(DNS)`]
""",
    defender_kql="""\
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIP in (__IP_LIST__) or RemoteUrl has_any (__DOMAIN_LIST__)
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl,
          InitiatingProcessFileName, InitiatingProcessCommandLine
""",
    confidence="High",
)

UC_HASH_IOC = UseCase(
    title="File hash IOCs — endpoint file/process match",
    description="Match SHA256/SHA1/MD5 named in the article against EDR file/process telemetry.",
    kill_chain="install",
    techniques=_tech("T1027|Obfuscated Files or Information"),
    data_models=["Endpoint.Filesystem", "Endpoint.Processes"],
    splunk_spl="""\
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where Filesystem.file_hash IN (__HASH_LIST__)
    by Filesystem.dest, Filesystem.user, Filesystem.file_path, Filesystem.file_name, Filesystem.file_hash
| `drop_dm_object_name(Filesystem)`
| append
    [| tstats `summariesonly` count from datamodel=Endpoint.Processes
        where Processes.process_hash IN (__HASH_LIST__)
        by Processes.dest, Processes.user, Processes.process_name, Processes.process_hash
     | `drop_dm_object_name(Processes)`]
""",
    defender_kql="""\
union DeviceFileEvents, DeviceProcessEvents
| where Timestamp > ago(7d)
| where SHA256 in~ (__HASH_LIST__) or SHA1 in~ (__HASH_LIST__) or MD5 in~ (__HASH_LIST__)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
""",
    confidence="High",
)

UC_RANSOM_ENCRYPT = UseCase(
    title="Ransomware-style mass file rename / extension change",
    description="Threshold detection: many files renamed in short window, often with new extension.",
    kill_chain="actions",
    techniques=_tech("T1486|Data Encrypted for Impact"),
    data_models=["Endpoint.Filesystem"],
    splunk_spl="""\
| tstats `summariesonly` count, dc(Filesystem.file_name) AS files
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("modified","renamed")
    by Filesystem.dest, Filesystem.user, _time span=1m
| `drop_dm_object_name(Filesystem)`
| where files > 200
| sort - files
""",
    defender_kql="""\
DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType in ("FileRenamed","FileModified")
| summarize files = dcount(FileName) by DeviceName, AccountName, bin(Timestamp, 1m)
| where files > 200
| order by files desc
""",
    confidence="Medium",
)

UC_LATERAL_PSEXEC = UseCase(
    title="Remote service execution — PsExec / SMB lateral movement",
    description="psexec / paexec / smbexec / wmic /node — service install over SMB from remote host.",
    kill_chain="actions",
    techniques=_tech("T1021.002|SMB/Windows Admin Shares", "T1569.002|Service Execution"),
    data_models=["Endpoint.Processes"],
    splunk_spl="""\
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
       OR (Processes.process_name="wmic.exe" AND Processes.process="*/node:*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
""",
    defender_kql="""\
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
   or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
""",
    confidence="High",
)

UC_OAUTH_ABUSE = UseCase(
    title="OAuth consent / suspicious app grant",
    description="Cloud identity abuse: app gets high-priv scopes, often via consent phishing.",
    kill_chain="actions",
    techniques=_tech("T1528|Steal Application Access Token", "T1098.001|Account Manipulation: Additional Cloud Credentials"),
    data_models=["Authentication.Authentication"],
    splunk_spl="""\
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Authentication.Authentication
    where Authentication.action="success"
      AND Authentication.signature IN (
        "Consent to application",
        "Add app role assignment grant to user",
        "Add OAuth2PermissionGrant",
        "Add delegated permission grant")
    by Authentication.user, Authentication.app, Authentication.src, Authentication.signature
| `drop_dm_object_name(Authentication)`
""",
    defender_kql="""\
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("Consent to application.","Add OAuth2PermissionGrant.","Add delegated permission grant.")
| project Timestamp, AccountObjectId, AccountDisplayName, ActivityType,
          ActivityObjects, IPAddress, UserAgent
""",
    confidence="High",
)

UC_MFA_FATIGUE = UseCase(
    title="MFA fatigue / push-bombing",
    description="Many MFA pushes to same user in short window — suggests adversary attempting approval-fatigue.",
    kill_chain="actions",
    techniques=_tech("T1621|Multi-Factor Authentication Request Generation"),
    data_models=["Authentication.Authentication"],
    splunk_spl="""\
| tstats `summariesonly` count from datamodel=Authentication.Authentication
    where Authentication.action="failure" AND Authentication.signature="*MFA*"
    by _time span=5m, Authentication.user, Authentication.src
| `drop_dm_object_name(Authentication)`
| where count > 10
""",
    defender_kql="""\
AADSignInEventsBeta
| where Timestamp > ago(1d)
| where ErrorCode in (50074, 50076, 50158, 50125, 50097)
| extend MfaPrompt = AuthenticationRequirement == "multiFactorAuthentication"
| where MfaPrompt
| summarize attempts = count(), distinct_ips = dcount(IPAddress)
    by AccountUpn, bin(Timestamp, 5m)
| where attempts > 10
| order by attempts desc
""",
    confidence="High",
)

UC_SUPPLY_CHAIN = UseCase(
    title="Trusted vendor binary / installer launching unusual children",
    description="Supply-chain trojan signal: legitimate signed binary spawning script interpreters or exotic LOLBins.",
    kill_chain="exploit",
    techniques=_tech("T1195.002|Compromise Software Supply Chain"),
    data_models=["Endpoint.Processes"],
    splunk_spl="""\
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN (__VENDOR_BINS__)
      AND Processes.process_name IN ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
    by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
""",
    defender_kql="""\
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ (__VENDOR_BINS__)
| where FileName in~ ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
""",
    confidence="Medium",
)

UC_FAKECAPTCHA = UseCase(
    title="Fake CAPTCHA / clipboard-injected PowerShell (ClickFix / FakeCaptcha)",
    description="Browser-pasted PowerShell launched from explorer/Run dialog — ClickFix social engineering.",
    kill_chain="exploit",
    techniques=_tech("T1204.004|User Execution: Malicious Copy and Paste", "T1059.001|PowerShell"),
    data_models=["Endpoint.Processes"],
    splunk_spl="""\
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("explorer.exe","RuntimeBroker.exe")
      AND Processes.process_name IN ("powershell.exe","pwsh.exe","mshta.exe")
      AND (Processes.process="*iex*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*FromBase64*" OR Processes.process="*DownloadString*"
        OR Processes.process="*hxxp*" OR Processes.process="*curl*" OR Processes.process="*wget*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
""",
    defender_kql="""\
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("explorer.exe","RuntimeBroker.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","mshta.exe")
| where ProcessCommandLine matches regex @"(?i)(iex|invoke-expression|frombase64|downloadstring|hxxp|curl |wget )"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
""",
    confidence="High",
)

UC_BROWSER_STEALER = UseCase(
    title="Infostealer — non-browser process accessing browser cookie/login DBs",
    description="Stealers (RedLine, Lumma, Vidar, Atomic) read Login Data / cookies SQLite from Chrome/Edge/Firefox.",
    kill_chain="actions",
    techniques=_tech("T1539|Steal Web Session Cookie", "T1555.003|Credentials from Web Browsers"),
    data_models=["Endpoint.Filesystem"],
    splunk_spl="""\
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\\Google\\Chrome\\User Data\\*\\Login Data*"
        OR Filesystem.file_path="*\\Google\\Chrome\\User Data\\*\\Cookies*"
        OR Filesystem.file_path="*\\Microsoft\\Edge\\User Data\\*\\Login Data*"
        OR Filesystem.file_path="*\\Mozilla\\Firefox\\Profiles\\*\\logins.json*"
        OR Filesystem.file_path="*\\Mozilla\\Firefox\\Profiles\\*\\cookies.sqlite*")
      AND NOT Filesystem.process_name IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
""",
    defender_kql="""\
DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath has_any ("\\Google\\Chrome\\User Data\\","\\Microsoft\\Edge\\User Data\\","\\Mozilla\\Firefox\\Profiles\\")
| where FileName in~ ("Login Data","Cookies","logins.json","cookies.sqlite")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
""",
    confidence="High",
)

UC_TEAMS_VISHING = UseCase(
    title="Microsoft Teams external-tenant chat from unverified IT-helpdesk impersonator",
    description="External Teams chat where displayName contains 'helpdesk' or 'IT support' — common 2024+ vishing pattern (Storm-1811, Black Basta, UNC6692). No CIM data model maps to Teams chats; uses raw O365 audit logs.",
    kill_chain="delivery",
    techniques=_tech("T1566.004|Phishing: Spearphishing Voice", "T1566|Phishing"),
    data_models=["O365 audit (raw)"],
    splunk_spl="""\
`o365_management_activity`
  Workload=MicrosoftTeams Operation=MessageSent
  ExternalParticipants=*
| where match(SenderDisplayName, "(?i)(help.?desk|it.?support|service.?desk|tech.?support|admin)")
| stats count, earliest(_time) as firstTime, latest(_time) as lastTime
    by SenderUpn, SenderDisplayName, RecipientUpn, ChatId
""",
    defender_kql="""\
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Microsoft Teams"
| where ActionType == "MessageSent"
| where RawEventData has "ExternalParticipants"
| extend SenderDisplayName = tostring(parse_json(RawEventData).SenderDisplayName)
| where SenderDisplayName matches regex @"(?i)(help.?desk|it.?support|service.?desk|tech.?support|admin)"
| project Timestamp, AccountDisplayName, IPAddress, ActivityType, SenderDisplayName, RawEventData
""",
    confidence="High",
)

UC_RMM_TOOLS = UseCase(
    title="RMM tool installed by non-IT user — remote-access utility for hands-on-keyboard",
    description="ConnectWise / AnyDesk / TeamViewer / ScreenConnect / Atera installed outside IT change windows = common tradecraft for ransomware affiliates and IT-helpdesk impersonators.",
    kill_chain="install",
    techniques=_tech("T1219|Remote Access Software"),
    data_models=["Endpoint.Processes"],
    splunk_spl="""\
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe","kaseya*.exe")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
""",
    defender_kql="""\
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe")
   or FileName matches regex @"(?i)kaseya.*\.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
""",
    confidence="High",
)

UC_BROWSER_EXT = UseCase(
    title="Suspicious browser extension installation",
    description="Side-loaded / unsigned extensions, often masquerading as wallets, productivity tools.",
    kill_chain="install",
    techniques=_tech("T1176|Browser Extensions"),
    data_models=["Endpoint.Registry"],
    splunk_spl="""\
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Registry
    where (Registry.registry_path="*\\Software\\Google\\Chrome\\Extensions\\*"
        OR Registry.registry_path="*\\Software\\Microsoft\\Edge\\Extensions\\*"
        OR Registry.registry_path="*\\Software\\Mozilla\\Firefox\\Extensions\\*")
    by Registry.dest, Registry.registry_path, Registry.registry_value_data, Registry.registry_value_name, Registry.user
| `drop_dm_object_name(Registry)`
""",
    defender_kql="""\
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where RegistryKey has_any ("\\Software\\Google\\Chrome\\Extensions\\","\\Software\\Microsoft\\Edge\\Extensions\\","\\Software\\Mozilla\\Firefox\\Extensions\\")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessAccountName
""",
    confidence="Medium",
)

UC_CRYPTO_WALLET = UseCase(
    title="Crypto-wallet file/keystore access by non-wallet process",
    description="Stealers / wallet drainers read keystore.json, MetaMask, Exodus, Atomic, Phantom data.",
    kill_chain="actions",
    techniques=_tech("T1005|Data from Local System"),
    data_models=["Endpoint.Filesystem"],
    splunk_spl="""\
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\\Ethereum\\keystore\\*"
        OR Filesystem.file_path="*\\Bitcoin\\wallet.dat"
        OR Filesystem.file_path="*\\Exodus\\exodus.wallet*"
        OR Filesystem.file_path="*\\Electrum\\wallets\\*"
        OR Filesystem.file_path="*\\MetaMask\\*"
        OR Filesystem.file_path="*\\Phantom\\*"
        OR Filesystem.file_path="*\\Atomic\\Local Storage\\*")
      AND NOT Filesystem.process_name IN ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
""",
    defender_kql="""\
DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath has_any ("\\Ethereum\\keystore\\","\\Bitcoin\\","\\Exodus\\","\\Electrum\\wallets\\","\\MetaMask\\","\\Phantom\\","\\Atomic\\Local Storage\\")
| where InitiatingProcessFileName !in~ ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
""",
    confidence="High",
)


# =============================================================================
# Rules — link narrative phrases to use cases
# =============================================================================

RULES = [
    Rule("Phishing — link",
         ["phishing email", "phishing link", "spear-phishing", "spearphishing", "spear phishing",
          "credential harvest", "credential phishing", "fake login", "fake captcha",
          "clickfix", "click-fix", "click fix"],
         [UC_PHISH_LINK, UC_FAKECAPTCHA]),

    Rule("Phishing — attachment",
         ["malicious attachment", "weaponized document", "weaponised document",
          "macro-laden", "vba macro", "office macro", "malicious doc"],
         [UC_PHISH_ATTACH, UC_OFFICE_CHILD]),

    Rule("Generic phishing — assume both modes",
         ["phishing", "phish "],
         [UC_PHISH_LINK, UC_PHISH_ATTACH, UC_OFFICE_CHILD]),

    Rule("PowerShell / scripting",
         ["powershell", "encoded command", "obfuscated", "iex", "invoke-expression"],
         [UC_PS_OBFUSCATED]),

    Rule("Office / macro",
         ["macro", "office document", "word document", "excel macro", "office attachment"],
         [UC_OFFICE_CHILD]),

    Rule("Credential dumping / LSASS",
         ["credential dumping", "lsass", "mimikatz", "sekurlsa", "comsvcs"],
         [UC_LSASS]),

    Rule("Beaconing / C2",
         ["c2 ", "command and control", "command-and-control", "beacon", "cobalt strike",
          "sliver", "brute ratel", "havoc framework"],
         [UC_BEACONING, UC_NETWORK_IOC]),

    Rule("DNS C2 / tunneling",
         ["dns tunneling", "dns tunnel", "dns-based c2", "dns exfil"],
         [UC_DNS_TUNNEL]),

    Rule("Persistence — scheduled task",
         ["scheduled task", "schtasks", "task scheduler"],
         [UC_SCHEDULED_TASK]),

    Rule("Persistence — service",
         ["new service", "service install", "service registry"],
         [UC_SERVICE_PERSIST]),

    Rule("CVE / vulnerability",
         ["cve-", "vulnerability", "exploited flaw", "kev catalog", "patched flaw",
          "rce ", "remote code execution", "exploit chain", "zero-day", "zero day", "0-day"],
         [UC_VULN_EXPOSURE]),

    Rule("Ransomware",
         ["ransomware", "encrypts files", "ransom note", "double extortion",
          "lockbit", "blackcat", "alphv", "akira", "play ransomware", "rhysida",
          "ransomhub", "qilin", "8base", "medusa ransomware", "clop", "cl0p",
          "black basta", "blackbasta"],
         [UC_RANSOM_ENCRYPT, UC_LSASS, UC_LATERAL_PSEXEC]),

    Rule("Lateral movement",
         ["lateral movement", "psexec", "smbexec", "wmic /node", "remote service"],
         [UC_LATERAL_PSEXEC]),

    Rule("OAuth / consent abuse",
         ["oauth", "consent phishing", "illicit consent", "token theft", "app registration"],
         [UC_OAUTH_ABUSE]),

    Rule("MFA bombing",
         ["mfa fatigue", "mfa bombing", "push bombing", "push fatigue", "mfa-bombing"],
         [UC_MFA_FATIGUE]),

    Rule("Supply chain",
         ["supply chain", "supply-chain", "trojanized installer", "trojanised installer",
          "compromised software", "package compromise", "trojanized sumatrapdf",
          "trojanised sumatrapdf", "weaponized installer"],
         [UC_SUPPLY_CHAIN]),

    Rule("Browser stealer / cookie theft",
         ["infostealer", "info stealer", "stealer malware", "redline stealer",
          "lumma stealer", "vidar stealer", "atomic stealer", "stealc", "risepro",
          "browser cookies", "session cookie", "session hijack", "browser session"],
         [UC_BROWSER_STEALER]),

    Rule("Microsoft Teams vishing / IT-helpdesk impersonation",
         ["microsoft teams", "teams chat", "it help desk", "it helpdesk",
          "help desk impersonat", "service desk impersonat", "tech support impersonat",
          "impersonating it"],
         [UC_TEAMS_VISHING, UC_RMM_TOOLS]),

    Rule("RMM abuse",
         ["anydesk", "teamviewer", "screenconnect", "connectwise", "atera",
          "splashtop", "rustdesk", "ninjarmm", "ninjaone", "kaseya", "remote access tool",
          "rmm tool", "rmm software"],
         [UC_RMM_TOOLS]),

    Rule("Browser extensions",
         ["malicious extension", "browser extension", "fake wallet", "fake extension",
          "chrome extension", "edge extension", "rogue extension"],
         [UC_BROWSER_EXT, UC_BROWSER_STEALER]),

    Rule("Crypto wallet",
         ["crypto wallet", "wallet drainer", "metamask", "phantom wallet",
          "exodus wallet", "fakewallet", "fake wallet", "cryptocurrency theft"],
         [UC_CRYPTO_WALLET, UC_BROWSER_STEALER]),
]

# --- YAML override --------------------------------------------------------
# If use_cases/ and rules/ YAML are present, they win over the inline
# definitions above. Going forward, edit YAML files only — the inline block
# is kept as a runtime fallback / git-blame reference.
if _LOADED_UCS:
    for _uc_id, _uc in _LOADED_UCS.items():
        globals()[_uc_id] = _uc
    del _uc_id, _uc
    if _LOADED_RULES:
        RULES = list(_LOADED_RULES)


# =============================================================================
# Article narrative inference
# =============================================================================

NARRATIVE_KILLCHAIN = [
    # text -> set of phases
    (re.compile(r"\bphishing|spear-?phish|email|smis?hing|vishing\b", re.I), {"delivery"}),
    (re.compile(r"\bsupply.?chain|trojanized|trojanised|installer\b", re.I), {"delivery", "exploit"}),
    (re.compile(r"\bcve-|exploit|0-?day|zero-?day|rce|public-?facing\b", re.I), {"exploit"}),
    (re.compile(r"\bmacro|office\s+(?:doc|file)|vbs\b", re.I), {"exploit"}),
    (re.compile(r"\bdll|rundll32|regsvr32|mshta|powershell|cmd\.exe\b", re.I), {"exploit"}),
    (re.compile(r"\bscheduled\s+task|service\s+install|registry\s+run|persistence\b", re.I), {"install"}),
    (re.compile(r"\bbackdoor|implant|rat\b|remote\s+access\s+trojan", re.I), {"install", "c2"}),
    (re.compile(r"\bbeacon|c2|command\s*and\s*control|callback\b", re.I), {"c2"}),
    (re.compile(r"\bcredential|lsass|mimikatz|kerberos|ntds\b", re.I), {"actions"}),
    (re.compile(r"\blateral\s*movement|psexec|smb\s*exec|wmi\b", re.I), {"actions"}),
    (re.compile(r"\bransom|encrypt(?:s|ed)?\s*files\b", re.I), {"actions"}),
    (re.compile(r"\bdata\s*theft|exfiltrat|stealer\b", re.I), {"actions"}),
    (re.compile(r"\brecon|scan|enumerat\b", re.I), {"recon"}),
    (re.compile(r"\bweaponized|weaponised|weaponi[sz]ation\b", re.I), {"weapon"}),
]

# Common attacker chain implication: if Initial Access (delivery) is detected,
# attackers will typically execute, install, beacon, and act on objectives.
INFER_FROM_PHASE = {
    "delivery": {"exploit", "install", "c2"},
    "exploit": {"install", "c2"},
    "install": {"c2", "actions"},
    "c2": {"actions"},
}


def detect_kill_chain(text: str):
    text_l = text.lower()
    found = set()
    for rx, phases in NARRATIVE_KILLCHAIN:
        if rx.search(text):
            found |= phases
    inferred = set()
    for ph in list(found):
        inferred |= INFER_FROM_PHASE.get(ph, set())
    return found, inferred - found


# =============================================================================
# Threat profile — pulls together a richer summary per article
# =============================================================================

ATTACK_KEYWORD_TO_TID = {
    "powershell": ("T1059.001", "PowerShell"),
    "cmd.exe": ("T1059.003", "Windows Command Shell"),
    "wmi": ("T1047", "Windows Management Instrumentation"),
    "scheduled task": ("T1053.005", "Scheduled Task"),
    "lsass": ("T1003.001", "LSASS Memory"),
    "ntds": ("T1003.003", "NTDS"),
    "kerberoast": ("T1558.003", "Kerberoasting"),
    "kerberos": ("T1558", "Steal or Forge Kerberos Tickets"),
    "pass-the-hash": ("T1550.002", "Pass the Hash"),
    "pass-the-ticket": ("T1550.003", "Pass the Ticket"),
    "rdp": ("T1021.001", "Remote Desktop Protocol"),
    "smb": ("T1021.002", "SMB/Windows Admin Shares"),
    "winrm": ("T1021.006", "Windows Remote Management"),
    "psexec": ("T1021.002", "SMB/Windows Admin Shares"),
    "registry run key": ("T1547.001", "Registry Run Keys / Startup Folder"),
    "dll sideloading": ("T1574.002", "DLL Side-Loading"),
    "rundll32": ("T1218.011", "Rundll32"),
    "regsvr32": ("T1218.010", "Regsvr32"),
    "mshta": ("T1218.005", "Mshta"),
    "office macro": ("T1059.005", "Visual Basic"),
    "phishing email": ("T1566.001", "Spearphishing Attachment"),
    "phishing link": ("T1566.002", "Spearphishing Link"),
    "phishing": ("T1566", "Phishing"),
    "spearphishing": ("T1566.002", "Spearphishing Link"),
    "credential dumping": ("T1003", "OS Credential Dumping"),
    "ransomware": ("T1486", "Data Encrypted for Impact"),
    "supply chain": ("T1195.002", "Compromise Software Supply Chain"),
    "browser cookies": ("T1539", "Steal Web Session Cookie"),
    "session cookie": ("T1539", "Steal Web Session Cookie"),
    "ad cs": ("T1649", "Steal or Forge Authentication Certificates"),
    "service install": ("T1543.003", "Windows Service"),
    "rce": ("T1190", "Exploit Public-Facing Application"),
    "remote code execution": ("T1190", "Exploit Public-Facing Application"),
    "exploit public-facing": ("T1190", "Exploit Public-Facing Application"),
    "encoded command": ("T1027", "Obfuscated Files or Information"),
    "obfuscat": ("T1027", "Obfuscated Files or Information"),
    "mfa fatigue": ("T1621", "Multi-Factor Authentication Request Generation"),
    "consent phishing": ("T1528", "Steal Application Access Token"),
    "oauth": ("T1528", "Steal Application Access Token"),
    "infostealer": ("T1555.003", "Credentials from Web Browsers"),
    "stealer": ("T1555.003", "Credentials from Web Browsers"),
    "anydesk": ("T1219", "Remote Access Software"),
    "teamviewer": ("T1219", "Remote Access Software"),
    "screenconnect": ("T1219", "Remote Access Software"),
    "rmm tool": ("T1219", "Remote Access Software"),
    "browser extension": ("T1176", "Browser Extensions"),
    "fake captcha": ("T1204.004", "User Execution: Malicious Copy and Paste"),
    "clickfix": ("T1204.004", "User Execution: Malicious Copy and Paste"),
    "smishing": ("T1660", "Phishing"),
    "trojan": ("T1204.002", "Malicious File"),
}


def infer_techniques(text: str, explicit: list) -> list:
    found = {}  # id -> name
    for tid in explicit:
        found[tid] = tid
    text_l = text.lower()
    for kw, (tid, name) in ATTACK_KEYWORD_TO_TID.items():
        if kw in text_l:
            found[tid] = name
    return sorted(found.items())


# =============================================================================
# Render: substitute placeholders in templated SPL/KQL
# =============================================================================

def fmt_list(values, sep=", ", quote='"'):
    return sep.join(f"{quote}{v}{quote}" for v in values)


def parameterize(text: str, ind: dict) -> str:
    """Substitute IOC placeholders. Returns empty string if the query
    references an IOC class the article doesn't have — caller-side
    suppression is preferred (see select_use_cases) but this is a
    safety net so we never ship `IN ("-")` placeholder queries."""
    cves = ind["cves"]
    ips = ind["ips"]
    domains = ind["domains"][:10]
    hashes = ind["sha256"] + ind["sha1"] + ind["md5"]
    if "__CVE_LIST__" in text and not cves: return ""
    if "__IP_LIST__" in text and not ips and "__DOMAIN_LIST__" not in text: return ""
    if "__DOMAIN_LIST__" in text and not domains and "__IP_LIST__" not in text: return ""
    if "__IP_LIST__" in text and "__DOMAIN_LIST__" in text and not (ips or domains): return ""
    if "__HASH_LIST__" in text and not hashes: return ""
    text = text.replace("__CVE_LIST__", fmt_list(cves))
    text = text.replace("__IP_LIST__", fmt_list(ips) if ips else '""')
    text = text.replace("__DOMAIN_LIST__", fmt_list(domains) if domains else '""')
    text = text.replace("__HASH_LIST__", fmt_list(hashes))
    text = text.replace("__VENDOR_BINS__", '"setup.exe","installer.exe","update.exe"')
    return text


def select_use_cases(article_text: str, ind: dict) -> list:
    activated = []
    seen_titles = set()
    text_l = article_text.lower()
    has_cve = bool(ind.get("cves"))
    has_netioc = bool(ind.get("ips") or ind.get("domains"))
    has_hash = bool(ind.get("sha256") or ind.get("sha1") or ind.get("md5"))
    # Rule-fired UCs only get added when their target IOC class is actually
    # present. We never want to ship a vuln-exposure / network-IOC / hash-IOC
    # use case with placeholder values like "-" or "0.0.0.0" — better to say
    # "no actionable hunt for this category" by leaving the UC out entirely.
    iocless_titles = {
        UC_VULN_EXPOSURE.title: has_cve,
        UC_NETWORK_IOC.title:   has_netioc,
        UC_HASH_IOC.title:      has_hash,
    }
    for rule in RULES:
        if any(t in text_l for t in rule.triggers):
            for uc in rule.use_cases:
                if uc.title in iocless_titles and not iocless_titles[uc.title]:
                    continue  # would render placeholder query — skip
                if uc.title not in seen_titles:
                    activated.append(uc)
                    seen_titles.add(uc.title)
    if has_cve and UC_VULN_EXPOSURE.title not in seen_titles:
        activated.append(UC_VULN_EXPOSURE)
        seen_titles.add(UC_VULN_EXPOSURE.title)
    if has_netioc and UC_NETWORK_IOC.title not in seen_titles:
        activated.append(UC_NETWORK_IOC)
        seen_titles.add(UC_NETWORK_IOC.title)
    if has_hash and UC_HASH_IOC.title not in seen_titles:
        activated.append(UC_HASH_IOC)
        seen_titles.add(UC_HASH_IOC.title)
    return activated


# =============================================================================
# HTML render
# =============================================================================

HTML_HEAD = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Clankerusecase — Splunk &amp; Defender Use Cases from threat-intel articles</title>
<link rel="icon" type="image/png" href="logo.png">
<link rel="apple-touch-icon" href="logo.png">
<meta name="description" content="Threat-intel-driven Splunk and Defender use cases, mapped to MITRE ATT&amp;CK with tier-tagged alerting and hunting detections.">
<meta property="og:title" content="Clankerusecase — Threat-Intel-Driven Detection Catalogue">
<meta property="og:description" content="2,175 use cases · 596 IOCs · 392/691 ATT&CK techniques covered. Splunk SPL + Defender KQL, tier-tagged.">
<meta property="og:image" content="logo.png">
<meta property="og:type" content="website">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:image" content="logo.png">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
/* =====================================================================
   Theme: Linear-inspired dark UI
   - Flat near-black background; subtle top-of-page accent wash only
   - Inter typography with tight tracking, small body scale
   - Indigo (#5e6ad2) signature accent; purple secondary
   - Hairline 1px borders (rgba white 0.07) instead of heavy frames
   - Restrained shadows — Linear leans on borders, not depth
   - Compact radii (4 / 6 / 8px) for that precision feel
   ===================================================================== */
:root {
  /* Backgrounds — near-black with three elevation steps */
  --bg:#08090a; --bg-grad-1:#0d0e10; --bg-grad-2:#08090a;
  --panel:#16171b; --panel-elev:#1f2024; --panel2:#26272b;
  /* Text — high-contrast on dark; Linear keeps body text very legible */
  --text:#f7f8f8; --muted:#8a8f98; --muted-2:#62656a;
  /* Accent — Linear signature indigo, with a purple+green for variety */
  --accent:#7170ff; --accent-2:#9b8afb; --accent-3:#4cb782;
  /* Borders — hairlines, not frames */
  --border:rgba(255,255,255,0.07); --border-2:rgba(255,255,255,0.12);
  --hairline:rgba(255,255,255,0.04);
  /* Status colors — calmer than the previous neon */
  --good:#4cb782; --warn:#e2a93f; --bad:#eb5757; --crit:#f25555;
  --code-bg:#1a1b1e;
  /* Shadows — barely there; structure comes from borders */
  --shadow-sm:0 1px 2px rgba(0,0,0,0.30);
  --shadow-md:0 8px 24px rgba(0,0,0,0.18),0 2px 4px rgba(0,0,0,0.16);
  --shadow-lg:0 16px 48px rgba(0,0,0,0.32),0 4px 12px rgba(0,0,0,0.20);
  --shadow-glow:0 0 0 1px rgba(113,112,255,0.45),0 0 16px rgba(113,112,255,0.18);
  /* Radii — Linear is precise, not rounded */
  --r-sm:4px; --r-md:6px; --r-lg:8px;
  --mono:"JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;
}
*{box-sizing:border-box;}
html,body{margin:0;}
body{
  /* Flat near-black with a single subtle indigo wash from the top — the
     restrained Linear backdrop. No competing gradients from multiple
     directions; the eye should land on content, not chrome. */
  background:
    radial-gradient(1200px 500px at 50% -10%, rgba(113,112,255,0.06), transparent 60%),
    var(--bg);
  background-attachment:fixed;
  color:var(--text);
  font-family:"Inter",-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
  font-size:14px; line-height:1.55;
  font-feature-settings:"cv11","ss01","ss03";
  letter-spacing:-0.003em;
  -webkit-font-smoothing:antialiased; -moz-osx-font-smoothing:grayscale;
  letter-spacing:-0.005em;
}
::selection{background:rgba(113,112,255,0.32);color:#fff;}

/* ----- Header / Top bar ---------------------------------------------- */
.topbar{
  position:sticky; top:0; z-index:50;
  background:rgba(8,9,10,0.72);
  backdrop-filter:blur(16px) saturate(160%);
  -webkit-backdrop-filter:blur(16px) saturate(160%);
  border-bottom:1px solid var(--border);
}
.topbar-inner{
  margin:0; padding:12px 28px;
  display:flex; gap:24px; align-items:center; flex-wrap:wrap;
}
.brand{display:flex;align-items:center;gap:14px;font-weight:600;font-size:22px;letter-spacing:-0.018em;}
.brand .logo{
  width:64px; height:64px; border-radius:12px;
  display:flex; align-items:center; justify-content:center;
  position:relative; overflow:hidden;
  /* Reset default button chrome so the <button> wrapper looks
     identical to the previous <div>. */
  padding:0; cursor:pointer; outline:none;
  /* Soft radial wash that picks up Clanker's pink + the Linear indigo
     accent — gives the mascot a glow without being neon, and keeps the
     logo readable on the near-black topbar. */
  background:
    radial-gradient(circle at 35% 30%, rgba(244,114,182,0.18), transparent 65%),
    radial-gradient(circle at 70% 80%, rgba(113,112,255,0.16), transparent 65%),
    var(--panel-elev);
  border:1px solid var(--border-2);
  box-shadow:0 1px 2px rgba(0,0,0,0.4), inset 0 1px 0 rgba(255,255,255,0.06);
  transition:transform 0.22s cubic-bezier(0.2,0.8,0.2,1), border-color 0.18s;
}
.brand .logo:focus-visible{
  outline:2px solid var(--accent); outline-offset:2px;
}
.brand:hover .logo{
  transform:rotate(-4deg) scale(1.04);
  border-color:rgba(244,114,182,0.35);
}
/* Logo lightbox — click the topbar logo to see Clanker full-size.
   Backdrop blurs the page; image animates in with a small bounce.
   Click backdrop, ESC, or close button to dismiss. */
.logo-lightbox{
  position:fixed; inset:0; z-index:200; display:none;
  align-items:center; justify-content:center;
  background:rgba(8,9,10,0.78);
  backdrop-filter:blur(12px) saturate(140%);
  -webkit-backdrop-filter:blur(12px) saturate(140%);
  animation:lbFade 0.22s ease;
  cursor:zoom-out;
}
.logo-lightbox.open{display:flex;}
.logo-lightbox img{
  max-width:min(80vw, 720px);
  max-height:min(80vh, 720px);
  width:auto; height:auto;
  border-radius:24px;
  background:
    radial-gradient(circle at 35% 30%, rgba(244,114,182,0.20), transparent 65%),
    radial-gradient(circle at 70% 80%, rgba(113,112,255,0.18), transparent 65%),
    var(--panel-elev);
  border:1px solid var(--border-2);
  padding:24px;
  box-shadow:0 24px 64px rgba(0,0,0,0.55), 0 0 0 1px rgba(255,255,255,0.04);
  filter:drop-shadow(0 6px 16px rgba(0,0,0,0.5));
  animation:lbZoom 0.32s cubic-bezier(0.2,0.8,0.2,1);
  cursor:default;
}
.logo-lightbox-close{
  position:absolute; top:24px; right:24px;
  width:36px; height:36px; border-radius:50%;
  background:var(--panel-elev); border:1px solid var(--border);
  color:var(--text); font-size:18px; cursor:pointer;
  display:flex; align-items:center; justify-content:center;
  transition:border-color 0.12s, background-color 0.12s;
}
.logo-lightbox-close:hover{
  background:var(--panel2); border-color:var(--border-2);
}
.logo-lightbox-caption{
  position:absolute; bottom:48px; left:50%; transform:translateX(-50%);
  color:var(--muted); font-size:13px; letter-spacing:-0.005em;
}
.logo-lightbox-caption strong{color:var(--text); font-weight:600;}
@keyframes lbFade{
  from{opacity:0;}
  to{opacity:1;}
}
@keyframes lbZoom{
  from{opacity:0; transform:scale(0.85) rotate(-3deg);}
  to{opacity:1; transform:scale(1) rotate(0);}
}
/* logo.png — Clanker the mascot. Drop-shadow lifts the pig-robot off
   the gradient panel; padding-3 keeps a touch of breathing room
   around the trotters. */
.brand .logo .logo-img{
  display:block; width:100%; height:100%;
  object-fit:contain; padding:3px;
  position:relative; z-index:1;
  filter:drop-shadow(0 2px 6px rgba(0,0,0,0.45));
}
.brand .logo svg{width:32px;height:32px;color:var(--accent);position:relative;z-index:1;}
.brand-text{display:flex;flex-direction:column;line-height:1.2;}
.brand-text > span:first-child{font-size:20px; font-weight:600; letter-spacing:-0.018em;}

/* All three stats bars share ONE centred slot — they overlap via
   absolute positioning inside .stats-wrap so the visible one always
   sits dead-centre regardless of which tab is active. Without this
   they'd be flex siblings each claiming 1/3 of the row width. */
.stats-wrap{
  flex:1; position:relative;
  display:flex; justify-content:center; align-items:center;
  min-height:64px;
}
.stats{
  position:absolute; left:50%; top:50%;
  transform:translate(-50%, -50%);
  display:flex; gap:16px; flex-wrap:nowrap;
  white-space:nowrap;
  /* Hidden by default — body class shows the active tab's bar. Same
     fade + slide animation; just no longer fighting siblings for space. */
  transition:opacity 0.25s ease, transform 0.3s cubic-bezier(0.2,0.8,0.2,1);
  opacity:0; pointer-events:none;
}
body.view-articles-active .stats-articles,
body.view-matrix-active   .stats-matrix,
body.view-intel-active    .stats-intel{
  opacity:1; transform:translate(-50%, -50%); pointer-events:auto;
}
/* Subtle entry animation — slide up from below as it fades in */
body:not(.view-articles-active) .stats-articles,
body:not(.view-matrix-active)   .stats-matrix,
body:not(.view-intel-active)    .stats-intel{
  transform:translate(-50%, calc(-50% + 8px));
}
@media(max-width:780px){
  .stats{ flex-wrap:wrap; white-space:normal; }
  .stats-wrap{ min-height:auto; }
}
/* Workflow tab: no stats bar — purposeful blank space, the diagram speaks */
.stat{
  display:flex; flex-direction:column; align-items:center;
  padding:6px 12px; min-width:64px;
}
.stat .v{font-size:18px;font-weight:600;color:var(--text);font-variant-numeric:tabular-nums;letter-spacing:-0.014em;}
.stat .l{font-size:10.5px;color:var(--muted);text-transform:uppercase;letter-spacing:0.06em;font-weight:500;margin-top:2px;}

.search-trigger{
  display:flex; align-items:center; gap:10px;
  background:var(--panel); border:1px solid var(--border);
  padding:8px 14px; border-radius:var(--r-md);
  color:var(--muted); cursor:pointer; transition:all 0.15s;
  min-width:240px; font-family:inherit; font-size:13px;
}
.search-trigger:hover{border-color:var(--border-2);color:var(--text);}
.search-placeholder{flex:1; min-width:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;}
.search-shortcut{display:inline-flex; gap:4px; flex-shrink:0; margin-left:14px;}
.search-trigger kbd{
  padding:2px 7px; font-size:10.5px; font-family:inherit; line-height:1;
  background:var(--panel2); border:1px solid var(--border-2); border-radius:4px;
  color:var(--muted); font-weight:600;
}

/* ----- Filter bar ---------------------------------------------------- */
.filter-row{
  margin:0; padding:14px 28px 0;
  display:flex; gap:8px; flex-wrap:wrap; align-items:center;
}
.filter-label{font-size:11px; color:var(--muted); text-transform:uppercase;
  letter-spacing:0.08em; margin-right:6px; font-weight:600;}
.fchip{
  background:var(--panel); border:1px solid var(--border);
  padding:5px 12px; border-radius:999px; font-size:12px; cursor:pointer;
  color:var(--muted); transition:all 0.15s; font-family:inherit;
  display:inline-flex; align-items:center; gap:6px;
}
.fchip:hover{color:var(--text);border-color:var(--border-2);}
.fchip.on{
  color:var(--text); border-color:transparent;
  background:linear-gradient(135deg, rgba(95,182,255,0.25), rgba(180,141,255,0.18));
  box-shadow:0 0 0 1px rgba(95,182,255,0.4) inset;
}
.fchip .x{display:none;font-size:14px;line-height:1;opacity:0.6;}
.fchip.on .x{display:inline;}
.fchip .dot{width:6px;height:6px;border-radius:50%;background:var(--muted);}
.fchip.on .dot{background:var(--accent);}

/* ----- Main layout --------------------------------------------------- */
/* Width-mode is user-selectable via the toolbar in #articles. Default is
   "wide" so the article column uses most of the viewport on large monitors
   without sprawling on ultrawides. localStorage key: usecaseintel:width. */
main{
  margin:0; padding:18px 28px 28px;
  display:grid; gap:20px;
}
main.width-compact{grid-template-columns:260px minmax(0, 1180px);}
main.width-wide   {grid-template-columns:260px minmax(0, 1700px);}
main.width-full   {grid-template-columns:260px minmax(0, 1fr);}
main:not(.width-compact):not(.width-wide):not(.width-full){
  /* fallback if JS hasn't applied a class yet */
  grid-template-columns:260px minmax(0, 1700px);
}
@media(max-width:1280px){
  main, main.width-compact, main.width-wide, main.width-full{
    grid-template-columns:240px minmax(0, 1fr); gap:16px;
  }
}
@media(max-width:980px){
  main, main.width-compact, main.width-wide, main.width-full{
    grid-template-columns:1fr; padding:18px;
  }
}

/* Width toolbar — matches view-tab segmented style */
.width-toggle{
  display:inline-flex; gap:2px; margin-left:auto;
  background:var(--panel); border:1px solid var(--border);
  border-radius:var(--r-md); padding:2px;
}
.width-toggle button{
  background:transparent; border:0; color:var(--muted);
  padding:4px 10px; border-radius:calc(var(--r-md) - 2px);
  font-size:10.5px; font-family:inherit; font-weight:500;
  text-transform:uppercase; letter-spacing:0.05em;
  cursor:pointer; transition:color 0.12s, background-color 0.12s;
}
.width-toggle button:hover{color:var(--text); background:rgba(255,255,255,0.03);}
.width-toggle button.on{
  background:var(--panel-elev); color:var(--text);
  box-shadow:inset 0 0 0 1px var(--border);
}

nav.toc{
  background:var(--panel); border:1px solid var(--border); border-radius:var(--r-lg);
  padding:10px; position:sticky; top:90px; max-height:calc(100vh - 110px);
  overflow:auto; box-shadow:var(--shadow-sm);
}
nav.toc::-webkit-scrollbar{width:6px;}
nav.toc::-webkit-scrollbar-thumb{background:var(--border-2);border-radius:3px;}
nav.toc h3{font-size:10.5px;color:var(--muted);text-transform:uppercase;letter-spacing:0.08em;
  margin:6px 10px 8px;font-weight:600;}
.nav-item{
  display:flex; gap:10px; padding:9px 10px; border-radius:var(--r-md);
  color:var(--text); text-decoration:none; font-size:12.5px; line-height:1.35;
  margin-bottom:2px; align-items:flex-start; cursor:pointer;
  transition:all 0.12s ease;
  position:relative;
}
.nav-item:hover{background:var(--panel-elev);}
.nav-item.active{
  background:var(--panel2);
  box-shadow:inset 2px 0 0 var(--accent);
}
.nav-item .num{
  flex:0 0 24px; font-variant-numeric:tabular-nums; color:var(--muted);
  font-weight:600; font-size:11px;
}
.nav-item .ttl{flex:1;}
.nav-item .sev{
  flex:0 0 6px; height:6px; border-radius:50%; margin-top:7px;
  background:var(--good);
}
.nav-item .sev.med{background:var(--warn);}
.nav-item .sev.high{background:var(--bad);}
.nav-item .sev.crit{background:var(--crit);}

/* ----- Source filter bar (Articles tab) ------------------------------ */
.src-filter-bar{
  display:flex; gap:6px; flex-wrap:wrap; align-items:center;
  padding:10px 14px; margin-bottom:8px;
  background:var(--panel); border:1px solid var(--border);
  border-radius:var(--r-md);
}
.src-filter-bar .lg-label{flex:0 0 auto; min-width:72px;}
/* Source filter chips — Linear style. All chips share the same neutral
   panel + hairline; the only difference between sources is a 2px coloured
   left border in the active state. No saturated bg fills.  */
.src-chip{
  padding:5px 11px; border-radius:var(--r-md);
  background:var(--panel-elev); border:1px solid var(--border);
  color:var(--muted); cursor:pointer; font-family:inherit; font-size:12px;
  font-weight:500; letter-spacing:-0.003em;
  transition:color 0.12s, border-color 0.12s, background-color 0.12s;
  display:inline-flex; align-items:center; gap:6px;
}
.src-chip:hover{color:var(--text); border-color:var(--border-2);}
.src-chip.active{
  color:var(--text); background:var(--panel2);
  border-color:var(--border-2);
  box-shadow:inset 2px 0 0 var(--accent);
}
/* Per-source active accent — a 2px coloured stripe on the left. */
.src-chip.active.thn{box-shadow:inset 2px 0 0 #7170ff;}
.src-chip.active.bc{box-shadow:inset 2px 0 0 #eb5757;}
.src-chip.active.ms{box-shadow:inset 2px 0 0 #9b8afb;}
.src-chip.active.kev{box-shadow:inset 2px 0 0 #e2a93f;}
.src-chip.active.talos{box-shadow:inset 2px 0 0 #4cb782;}
.src-chip.active.securelist{box-shadow:inset 2px 0 0 #4cb782;}
.src-chip.active.sentinel{box-shadow:inset 2px 0 0 #9b8afb;}
.src-chip.active.unit42{box-shadow:inset 2px 0 0 #e2a93f;}
.src-chip.active.eset{box-shadow:inset 2px 0 0 #7170ff;}
.src-chip.active.lab52{box-shadow:inset 2px 0 0 #4cb782;}
.src-chip.active.csn{box-shadow:inset 2px 0 0 #f25555;}
.src-chip .cnt{
  font-variant-numeric:tabular-nums; color:var(--muted-2);
  font-size:10.5px; font-weight:500;
}
article.card.src-hidden{display:none;}

/* ----- Article cards -------------------------------------------------
   Linear card: flat panel bg, hairline border, no gradient, no
   transform on hover. Hover lifts only the border + a subtle inner
   highlight — that's the look that makes the matrix and articles feel
   refined rather than vibe-coded. */
section#articles{display:flex; flex-direction:column; gap:18px;}
article.card{
  background:var(--panel);
  border:1px solid var(--border);
  border-radius:var(--r-lg);
  padding:24px 26px;
  font-size:14px; line-height:1.6;
  position:relative;
  /* Sticky header is ~90-110px tall (brand row + tabs row). Without this,
     anchor jumps from the sidebar TOC scroll the article's top under the
     header and crop the title / severity ribbon. */
  scroll-margin-top:120px;
  transition:border-color 0.15s ease, background-color 0.15s ease;
}
article.card:hover{
  border-color:var(--border-2);
  background:var(--panel-elev);
}
article.card.hidden{display:none;}
article.card .sev-ribbon{
  position:absolute; top:0; left:24px; padding:3px 10px 4px;
  font-size:10px; font-weight:600; text-transform:uppercase; letter-spacing:0.08em;
  border-radius:0 0 6px 6px;
  background:rgba(76,183,130,0.16); color:var(--good);
  border:1px solid rgba(76,183,130,0.28); border-top:none;
}
article.card .sev-ribbon.med{background:rgba(226,169,63,0.14); color:var(--warn); border-color:rgba(226,169,63,0.30);}
article.card .sev-ribbon.high{background:rgba(235,87,87,0.14); color:var(--bad); border-color:rgba(235,87,87,0.30);}
article.card .sev-ribbon.crit{
  background:rgba(242,85,85,0.18); color:var(--crit);
  border-color:rgba(242,85,85,0.36);
}
article.card h2{margin:14px 0 8px 0;font-size:20px;line-height:1.25;letter-spacing:-0.018em;font-weight:600;}
article.card h2 a{color:var(--text);text-decoration:none;
  transition:color 0.12s ease;}
article.card h2 a:hover{color:var(--accent);}
article.card .pubmeta{color:var(--muted);font-size:12px;margin-bottom:14px;display:flex;gap:12px;flex-wrap:wrap;}
article.card .pubmeta span:not(:first-child)::before{content:"·";margin-right:12px;color:var(--muted-2);}
article.card p.summary{color:var(--muted);margin:8px 0 16px 0;font-size:13.5px;line-height:1.6;}

.action-row{display:flex;gap:8px;flex-wrap:wrap;margin:6px 0 14px 0;align-items:center;}
/* Linear button style — flat panel bg, hairline border, slight bg
   shift on hover (no transform). Primary is solid accent on dark, no
   gradient (Linear keeps buttons calm). */
.btn{
  background:var(--panel-elev); border:1px solid var(--border);
  color:var(--text); padding:6px 12px; border-radius:var(--r-md);
  font-size:12.5px; cursor:pointer; font-family:inherit; font-weight:500;
  display:inline-flex; align-items:center; gap:6px;
  transition:background-color 0.12s, border-color 0.12s, color 0.12s;
  letter-spacing:-0.003em; line-height:1.4;
}
.btn:hover{background:var(--panel2); border-color:var(--border-2);}
.btn:active{background:var(--panel);}
.btn-kc{display:inline-flex;align-items:center;gap:6px;}
.kc-chev{transition:transform 0.18s ease;flex-shrink:0;opacity:0.7;}
.btn-kc.primary .kc-chev{transform:rotate(180deg);}
.btn.primary{
  background:var(--accent); color:#fff; border-color:transparent;
  font-weight:500;
}
.btn.primary:hover{background:#7e7dff; box-shadow:none;}
.btn-meta{color:var(--muted);font-size:11.5px;margin-left:auto;}

/* ----- Indicator pills ----------------------------------------------- */
.ind-group{display:flex;flex-wrap:wrap;gap:6px;margin:8px 0;align-items:center;}
.ind-label{color:var(--muted);font-size:10.5px;text-transform:uppercase;letter-spacing:0.08em;
  margin-right:6px;font-weight:600;}
/* Linear pill — flat panel-elev background, hairline border, mono
   text in a near-neutral colour. Variants get a tinted *colour* on
   the text only, never a saturated bg fill. */
.ind{
  background:var(--panel-elev); border:1px solid var(--border); border-radius:4px;
  padding:2px 7px; font-size:11px; font-family:var(--mono);
  color:var(--text); transition:border-color 0.12s, color 0.12s;
  cursor:default; line-height:1.5; font-weight:500;
}
.ind.cve{color:#e2a93f;}
.source-badges{display:flex; gap:6px; flex-wrap:wrap; margin:6px 0 2px;}
.source-badge{
  font-size:10.5px; font-weight:500; letter-spacing:0.01em;
  padding:2px 8px; border-radius:4px;
  background:var(--panel-elev); border:1px solid var(--border);
  color:var(--muted); display:inline-flex; align-items:center; gap:4px;
}
/* Source badges — colour the text only; keep the bg/border neutral.
   Linear style avoids saturated colour blocks; the eye should land
   on text content, not chrome. */
.source-badge.thn{color:#7170ff;}
.source-badge.bc{color:#eb5757;}
.source-badge.ms{color:#9b8afb;}
.source-badge.kev{color:#e2a93f;}
.source-badge.talos{color:#4cb782;}
.source-badge.securelist{color:#4cb782;}
.source-badge.sentinel{color:#9b8afb;}
.source-badge.unit42{color:#e2a93f;}
.source-badge.eset{color:#7170ff;}
.source-badge.lab52{color:#4cb782;}
.source-badge.csn{color:#f25555;}
.ind.tech{color:#9b8afb; cursor:pointer;}
.ind.tech:hover{border-color:rgba(155,138,251,0.4); color:#b4a4ff;}
.ind.malware{color:#eb5757;}

/* ----- 3D Kill Chain ------------------------------------------------- */
.killchain{
  display:none; padding:20px; margin:14px 0 20px 0;
  background:linear-gradient(180deg, rgba(0,0,0,0.25), rgba(0,0,0,0.05));
  border:1px solid var(--border);
  border-radius:var(--r-lg);
  perspective:1400px;
  animation:fadeUp 0.35s cubic-bezier(0.2,0.8,0.2,1);
}
.killchain.active{display:block;}
@keyframes fadeUp{from{opacity:0;transform:translateY(-6px);}to{opacity:1;transform:translateY(0);}}

.kc3d{
  display:grid; grid-template-columns:repeat(7, minmax(0,1fr));
  gap:10px; transform-style:preserve-3d;
  transform:rotateX(8deg);
  margin:6px 0 22px 0;
}
.kc3d .kc-cell{
  position:relative; padding:14px 10px 12px;
  border-radius:10px;
  background:linear-gradient(180deg, #1a2230 0%, #0e1420 100%);
  border:1px solid #2a3445;
  text-align:center; min-height:96px;
  display:flex; flex-direction:column; justify-content:center; align-items:center;
  transform-style:preserve-3d; transition:transform 0.25s cubic-bezier(0.2,0.8,0.2,1);
  box-shadow:0 6px 14px rgba(0,0,0,0.45), inset 0 1px 0 rgba(255,255,255,0.04);
}
.kc3d .kc-cell:hover{transform:translateZ(12px) rotateX(-4deg);}
.kc3d .kc-cell::before{
  content:""; position:absolute; inset:1px; border-radius:9px; pointer-events:none;
  background:linear-gradient(180deg, rgba(255,255,255,0.04), transparent 30%);
}
.kc3d .kc-cell .num{
  font-size:9.5px; color:var(--muted); font-weight:700;
  letter-spacing:0.12em; text-transform:uppercase;
}
.kc3d .kc-cell .name{
  font-size:12px; font-weight:700; margin-top:4px; letter-spacing:-0.01em;
}
.kc3d .kc-cell .marker{
  font-size:9.5px; color:var(--muted-2); margin-top:6px;
  text-transform:uppercase; letter-spacing:0.1em; font-weight:700;
}
.kc3d .kc-cell.hit{
  background:linear-gradient(180deg, #3a1820 0%, #20111a 100%);
  border-color:#ff5d6d;
  box-shadow:
    0 8px 22px rgba(255,93,109,0.32),
    0 0 0 1px rgba(255,93,109,0.45) inset,
    inset 0 1px 0 rgba(255,255,255,0.06);
  animation:hit-glow 2.4s ease-in-out infinite;
}
@keyframes hit-glow{
  0%,100%{box-shadow:0 8px 22px rgba(255,93,109,0.28),0 0 0 1px rgba(255,93,109,0.4) inset, inset 0 1px 0 rgba(255,255,255,0.06);}
  50%{box-shadow:0 8px 32px rgba(255,93,109,0.5),0 0 0 1px rgba(255,93,109,0.7) inset, inset 0 1px 0 rgba(255,255,255,0.08);}
}
.kc3d .kc-cell.hit .marker{color:var(--bad);}
.kc3d .kc-cell.inferred{
  background:linear-gradient(180deg, #322218 0%, #1a1410 100%);
  border-color:#cc8a4d;
  box-shadow:0 6px 18px rgba(255,176,96,0.18), 0 0 0 1px rgba(255,176,96,0.35) inset,
    inset 0 1px 0 rgba(255,255,255,0.04);
}
.kc3d .kc-cell.inferred .marker{color:var(--warn);}

.kc-detail{font-size:12.5px;color:var(--muted);}
.kc-detail .phase-line{
  margin:6px 0; padding:8px 12px; border-radius:8px;
  background:rgba(255,255,255,0.015); border:1px solid var(--hairline);
}
.kc-detail .phase-line strong{color:var(--text);font-weight:700;}
.kc-detail .phase-line.hit{
  background:linear-gradient(90deg, rgba(255,93,109,0.08), transparent);
  border-color:rgba(255,93,109,0.3);
}
.kc-detail .phase-line.hit strong{color:var(--bad);}
.kc-detail .phase-line.inferred{
  background:linear-gradient(90deg, rgba(255,176,96,0.06), transparent);
  border-color:rgba(255,176,96,0.25);
}
.kc-detail .phase-line.inferred strong{color:var(--warn);}
.kc-detail .phase-line em{color:var(--accent-2);font-style:normal;font-size:11.5px;}

/* ----- Use case accordion ------------------------------------------- */
.usecases{display:flex;flex-direction:column;gap:12px;}
details.uc{
  background:var(--panel-elev); border:1px solid var(--border);
  border-radius:var(--r-md); transition:border-color 0.15s, box-shadow 0.15s;
  overflow:hidden;
}
details.uc[open]{border-color:var(--border-2);box-shadow:var(--shadow-sm);}
details.uc summary{
  cursor:pointer; padding:14px 16px; list-style:none;
  display:flex; flex-wrap:wrap; align-items:center; gap:10px;
  transition:background 0.12s;
}
details.uc summary:hover{background:rgba(255,255,255,0.02);}
details.uc summary::-webkit-details-marker{display:none;}
details.uc summary::before{
  content:"›"; color:var(--muted); font-size:18px; line-height:1;
  margin-right:4px; transition:transform 0.18s; display:inline-block;
}
details.uc[open] summary::before{transform:rotate(90deg);}
.uc-title{font-weight:600; font-size:13.5px; flex:1; min-width:200px;letter-spacing:-0.012em;}
.uc-phase, .uc-conf, .uc-dm{
  font-size:10px; text-transform:uppercase; letter-spacing:0.05em;
  padding:2px 8px; border-radius:4px; font-weight:500;
  background:var(--panel-elev); border:1px solid var(--border);
  color:var(--muted);
}
.uc-phase{color:#9b8afb;}
.uc-conf.high{color:#4cb782;}
.uc-conf.medium{color:#e2a93f;}
.uc-conf.low{color:var(--muted);}
.uc-body{padding:0 16px 16px 16px;}
.uc-desc{color:var(--text);opacity:0.88;font-size:12.8px;margin:6px 0 12px 0;line-height:1.6;}
.uc-meta{display:flex;flex-wrap:wrap;gap:6px;margin:8px 0;}

.tabs{
  display:flex; gap:2px; padding:3px;
  background:var(--panel); border:1px solid var(--border);
  border-radius:var(--r-md); margin:12px 0 0 0; width:fit-content;
}
.tab-btn{
  padding:5px 12px; background:transparent; border:none; border-radius:4px;
  color:var(--muted); cursor:pointer; font-family:inherit; font-size:12px;
  font-weight:500; transition:color 0.12s, background-color 0.12s; letter-spacing:-0.003em;
}
.tab-btn:hover{color:var(--text); background:rgba(255,255,255,0.03);}
.tab-btn.active{
  color:var(--text);
  background:var(--panel-elev);
  box-shadow:inset 0 0 0 1px var(--border);
}
.tab-content{display:none;}
.tab-content.active{display:block;animation:fadeIn 0.2s ease;}
@keyframes fadeIn{from{opacity:0;}to{opacity:1;}}

pre{
  background:var(--code-bg); border:1px solid var(--border);
  border-radius:var(--r-md); padding:14px 16px; overflow:auto;
  font-size:12.5px; font-family:var(--mono);
  line-height:1.65; margin:10px 0;
  position:relative;
  font-feature-settings:"calt" off;
}
pre::-webkit-scrollbar{height:8px;width:8px;}
pre::-webkit-scrollbar-thumb{background:var(--border-2);border-radius:4px;}
pre code{color:var(--text);white-space:pre;font-family:inherit;}
.copy-btn{
  position:absolute; top:10px; right:10px;
  background:var(--panel-elev); border:1px solid var(--border);
  color:var(--muted); padding:3px 10px; border-radius:var(--r-sm);
  font-size:10.5px; font-weight:500; cursor:pointer; font-family:inherit;
  transition:color 0.12s, border-color 0.12s; opacity:0.75; letter-spacing:0.02em;
}
.copy-btn:hover{color:var(--text); border-color:var(--border-2); opacity:1;}
pre:hover .copy-btn{opacity:1;}
.copy-btn:hover{background:var(--accent);color:#04111d;border-color:transparent;}
.copy-btn.copied{background:var(--good);color:#04130a;border-color:transparent;}

/* ----- Search overlay (Cmd/Ctrl+K) ----------------------------------- */
.search-overlay{
  display:none; position:fixed; inset:0; z-index:200;
  background:rgba(4,7,12,0.78); backdrop-filter:blur(8px);
  align-items:flex-start; justify-content:center; padding-top:14vh;
  animation:fadeIn 0.15s ease;
}
.search-overlay.open{display:flex;}
.search-modal{
  width:min(620px, 90%);
  background:var(--panel-elev); border:1px solid var(--border-2);
  border-radius:var(--r-lg); box-shadow:var(--shadow-lg);
  overflow:hidden;
}
.search-modal input{
  width:100%; padding:18px 22px; background:transparent; border:none;
  border-bottom:1px solid var(--hairline); color:var(--text);
  font-size:16px; font-family:inherit; outline:none;
}
.search-modal input::placeholder{color:var(--muted-2);}
.search-results{max-height:50vh;overflow:auto;padding:8px;}
.search-results::-webkit-scrollbar{width:6px;}
.search-results::-webkit-scrollbar-thumb{background:var(--border-2);border-radius:3px;}
.search-result{
  padding:10px 14px; border-radius:var(--r-md); cursor:pointer;
  display:flex; gap:10px; align-items:flex-start; transition:background 0.1s;
}
.search-result:hover, .search-result.sel{background:var(--panel2);}
.search-result .sr-num{color:var(--muted);font-variant-numeric:tabular-nums;
  font-size:11px;font-weight:700;flex:0 0 24px;margin-top:2px;}
.search-result .sr-title{font-weight:600;font-size:13.5px;margin-bottom:2px;}
.search-result .sr-meta{color:var(--muted);font-size:11.5px;}
.search-empty{padding:20px;text-align:center;color:var(--muted);font-size:13px;}

/* ----- Footer -------------------------------------------------------- */
footer{
  padding:32px 28px; text-align:center;
  color:var(--muted); font-size:11.5px;
  border-top:1px solid var(--hairline);
  margin-top:24px;
}
footer code{background:var(--panel2);padding:2px 6px;border-radius:4px;font-size:11px;}

/* ----- View tabs (Articles / ATT&CK Matrix) ----------------------------
   Linear's segmented-tab style: pill-on-pill, 1px border on the parent,
   active state is a slightly elevated panel with a subtle inner ring.
   Smaller padding, tighter type than the previous flashy version. */
.view-tabs{
  display:flex; gap:2px; padding:3px;
  background:var(--panel); border:1px solid var(--border);
  border-radius:var(--r-md); width:fit-content;
}
.view-tab{
  padding:6px 14px; background:transparent; border:none; border-radius:4px;
  color:var(--muted); cursor:pointer; font-family:inherit; font-size:13px;
  font-weight:500; transition:color 0.12s, background-color 0.12s;
  letter-spacing:-0.005em;
  display:inline-flex; align-items:center; gap:6px;
}
.view-tab:hover{color:var(--text); background:rgba(255,255,255,0.03);}
.view-tab.active{
  color:var(--text);
  background:var(--panel-elev);
  box-shadow:inset 0 0 0 1px var(--border);
}
.view{display:none;}
.view.active{display:block;}

/* ----- ATT&CK Matrix view ------------------------------------------- */
.matrix-wrap{max-width:none; padding:18px 28px 28px;}
.matrix-toolbar{
  display:flex; gap:12px; align-items:center; flex-wrap:wrap;
  margin-bottom:14px; padding:12px 14px;
  background:var(--panel); border:1px solid var(--border);
  border-radius:var(--r-md);
}
.matrix-toolbar input{
  flex:1; min-width:240px; padding:8px 12px;
  background:var(--bg); border:1px solid var(--border);
  border-radius:var(--r-sm); color:var(--text);
  font-family:inherit; font-size:13px; outline:none;
}
.matrix-toolbar input:focus{border-color:var(--accent);}
.matrix-toolbar select{
  min-width:240px; max-width:340px; padding:8px 10px;
  background:var(--bg); border:1px solid var(--border);
  border-radius:var(--r-sm); color:var(--text);
  font-family:inherit; font-size:12.5px; outline:none;
  cursor:pointer;
}
.matrix-toolbar select:focus,
.matrix-toolbar select:hover{border-color:var(--accent);}
.matrix-toolbar select option{background:var(--panel-elev); color:var(--text);}
.matrix-legend{
  background:var(--panel); border:1px solid var(--border);
  border-radius:var(--r-md); padding:10px 14px; margin-bottom:14px;
  display:flex; flex-direction:column; gap:8px;
}
.lg-row{display:flex; flex-wrap:wrap; gap:8px; align-items:center;
  font-size:11.5px; line-height:1.4;}
.lg-label{
  flex:0 0 auto; min-width:108px;
  font-size:10px; font-weight:700; letter-spacing:0.08em;
  color:var(--muted); text-transform:uppercase;
}
.lg-swatch{
  display:inline-flex; align-items:center; gap:6px;
  padding:4px 10px; border-radius:6px;
  font-size:11px; font-weight:600;
  background:var(--panel2); border:1px solid var(--border);
  color:var(--text);
}
.lg-swatch.cov-0{background:var(--panel2); color:var(--muted-2);}
.lg-swatch.cov-1{background:linear-gradient(180deg, rgba(54,224,192,0.10), rgba(54,224,192,0.02));}
.lg-swatch.cov-2{background:linear-gradient(180deg, rgba(54,224,192,0.18), rgba(54,224,192,0.04));}
.lg-swatch.cov-3{background:linear-gradient(180deg, rgba(54,224,192,0.30), rgba(54,224,192,0.06));
  border-color:rgba(54,224,192,0.35);}
.lg-swatch.cov-4{background:linear-gradient(180deg, rgba(54,224,192,0.45), rgba(54,224,192,0.10));
  border-color:rgba(54,224,192,0.55);}
.lg-swatch.heat-1{background:linear-gradient(180deg, rgba(255,176,96,0.10), rgba(255,176,96,0.02));}
.lg-swatch.heat-2{background:linear-gradient(180deg, rgba(255,93,93,0.18), rgba(255,93,93,0.04));
  border-color:rgba(255,93,93,0.4);}
.lg-swatch.heat-3{background:linear-gradient(180deg, rgba(255,50,96,0.30), rgba(255,50,96,0.06));
  border-color:rgba(255,50,96,0.55);}
.lg-chip{
  padding:3px 9px; background:var(--panel2); border:1px solid var(--border);
  border-radius:6px; font-size:11px; color:var(--text);
}
.lg-note{
  margin-left:auto; color:var(--muted-2); font-size:10.5px; font-style:italic;
}
.matrix-stats{display:flex; gap:18px; font-size:12px;}
.matrix-stats span{color:var(--muted);}
.matrix-stats span b{color:var(--text); font-variant-numeric:tabular-nums;}

/* ----- Workflow tab -------------------------------------------------- */
.workflow-wrap{
  max-width:1280px; margin:0 auto; padding:20px 28px 60px; line-height:1.65;
}
.wf-title{
  font-size:24px; font-weight:700; letter-spacing:-0.012em;
  margin:0 0 10px 0; color:var(--text);
}
.wf-lede{
  color:var(--muted); font-size:14px; max-width:880px; margin:0 0 24px 0;
}
.wf-diagram{
  background:var(--panel); border:1px solid var(--border); border-radius:var(--r-lg);
  padding:14px; margin:18px 0 28px 0; box-shadow:var(--shadow-sm);
  overflow:auto;
}
.wf-diagram svg{display:block; width:100%; height:auto; min-width:1100px;}
.wf-section-title{
  font-size:16px; font-weight:700; letter-spacing:-0.005em;
  color:var(--accent); margin:24px 0 8px 0;
  padding-bottom:6px; border-bottom:1px solid var(--border);
}
.wf-step{
  background:var(--panel); border:1px solid var(--border); border-radius:var(--r-md);
  padding:14px 18px; margin-bottom:14px; font-size:13.5px; color:var(--text);
  line-height:1.65;
}
.wf-step ul, .wf-step ol{padding-left:22px; margin:6px 0;}
.wf-step li{margin-bottom:4px;}
.wf-step code{
  background:var(--panel-elev); padding:1px 6px; border-radius:4px;
  font-size:12px; color:var(--accent-3);
}
.wf-step a{color:var(--accent); text-decoration:none;}
.wf-step a:hover{text-decoration:underline;}

/* About tab cards — richer than wf-step, used for the platform-coverage
   table, Discord CTA, and how-a-UC-lands-here sections. Single column on
   narrow viewports, no internal grid. Generous padding so headings and
   body copy aren't crammed. */
.wf-card{
  background:var(--panel); border:1px solid var(--border); border-radius:var(--r-lg);
  padding:22px 26px; margin-bottom:18px; color:var(--text);
  line-height:1.65; font-size:14px;
  box-shadow:var(--shadow-sm);
}
.wf-card h3{
  margin:0 0 12px 0; font-size:17px; font-weight:700;
  letter-spacing:-0.005em; color:var(--text);
  padding-bottom:10px; border-bottom:1px solid var(--border);
}
.wf-card p{margin:0 0 12px 0;}
.wf-card p:last-child{margin-bottom:0;}
.wf-card ul, .wf-card ol{padding-left:22px; margin:6px 0 12px 0;}
.wf-card li{margin-bottom:6px;}
.wf-card code{
  background:var(--panel-elev); padding:1px 6px; border-radius:4px;
  font-size:12.5px; color:var(--accent-3);
}
.wf-card a{color:var(--accent); text-decoration:none;}
.wf-card a:hover{text-decoration:underline;}
.wf-card em{color:var(--muted);}

/* About tab platform-coverage table */
.wf-table{
  width:100%; border-collapse:separate; border-spacing:0;
  font-size:13.5px; line-height:1.55;
  border:1px solid var(--border); border-radius:var(--r-md);
  overflow:hidden;
}
.wf-table thead th{
  background:var(--panel-elev); color:var(--muted);
  text-align:left; padding:10px 14px;
  font-weight:600; font-size:11.5px;
  text-transform:uppercase; letter-spacing:0.06em;
  border-bottom:1px solid var(--border);
}
.wf-table tbody td{
  padding:14px; vertical-align:top;
  border-bottom:1px solid var(--border);
  color:var(--text);
}
.wf-table tbody tr:last-child td{border-bottom:none;}
.wf-table tbody tr:nth-child(even) td{background:rgba(255,255,255,0.012);}
.wf-table tbody td:first-child{
  white-space:nowrap; min-width:180px;
  font-weight:600;
}
.wf-table tbody td:nth-child(2){
  white-space:nowrap; width:1%;
}
.wf-table code{
  background:var(--panel-elev); padding:1px 5px; border-radius:3px;
  font-size:11.5px; color:var(--accent-3);
}
@media(max-width:780px){
  .wf-table thead{display:none;}
  .wf-table tbody td{display:block; border-bottom:none;}
  .wf-table tbody tr{
    display:block; padding:10px 0;
    border-bottom:1px solid var(--border);
  }
  .wf-table tbody td:first-child{font-size:15px; padding-bottom:4px;}
  .wf-table tbody td:nth-child(2){padding:4px 14px 8px;}
}

/* ----- Drawer use-case list (paginated for large drawers) ------------ */
.drawer-uc-toolbar{
  display:flex; gap:8px; align-items:center; margin-bottom:10px; flex-wrap:wrap;
}
.drawer-uc-toolbar input{
  flex:1; min-width:160px;
  background:var(--panel-elev); border:1px solid var(--border); color:var(--text);
  padding:6px 10px; border-radius:var(--r-md); font-size:12px; font-family:inherit;
}
.drawer-uc-toolbar input:focus{border-color:var(--accent);}
.drawer-uc-toolbar select{
  background:var(--panel-elev); border:1px solid var(--border); color:var(--text);
  padding:6px 10px; border-radius:var(--r-md); font-size:12px; font-family:inherit;
}
.drawer-uc-pager{
  margin-top:10px; padding:8px;
  background:var(--panel); border:1px dashed var(--border); border-radius:var(--r-md);
  text-align:center; font-size:11.5px; color:var(--muted);
  cursor:pointer;
}
.drawer-uc-pager:hover{border-color:var(--accent); color:var(--accent);}
.uc-card-row .uc-src-pill{
  font-size:9.5px; padding:1px 6px; border-radius:4px;
  background:var(--panel2); color:var(--muted-2);
  text-transform:uppercase; letter-spacing:0.06em; font-weight:600;
}
.uc-card-row .uc-src-pill.escu{color:var(--accent-3);}
.uc-card-row .uc-src-pill.internal{color:var(--accent);}
/* Tier pills: alerting (production-ready) vs hunting (needs tuning).
   Alerting has a strong colour stop so high-fidelity content stands out
   in a long drawer list; hunting is muted to signal "needs review". */
.uc-card-row .uc-tier-pill{
  font-size:9.5px; padding:1px 7px; border-radius:4px;
  text-transform:uppercase; letter-spacing:0.06em; font-weight:700;
  flex:0 0 auto;
}
.uc-card-row .uc-tier-pill.alerting{
  background:rgba(46,213,99,0.18); color:var(--good);
  border:1px solid rgba(46,213,99,0.4);
}
.uc-card-row .uc-tier-pill.hunting{
  background:rgba(255,176,96,0.10); color:var(--warn);
  border:1px solid rgba(255,176,96,0.3);
}
.uc-card-row.tier-alerting{
  border-left:3px solid rgba(46,213,99,0.55);
}
.uc-card-row.tier-hunting{
  border-left:3px solid rgba(255,176,96,0.45);
}
.uc-card-row{transition:border-color 0.15s, background 0.15s;}
.uc-card-row:hover{border-color:var(--accent); background:var(--panel-elev);}
.uc-card-row .uc-card-chev{transition:transform 0.15s ease;}
.matrix-mode{display:flex; gap:4px;
  padding:3px; background:var(--bg); border:1px solid var(--border);
  border-radius:var(--r-sm);}
.matrix-mode button{
  padding:5px 12px; background:transparent; border:none; border-radius:4px;
  color:var(--muted); cursor:pointer; font-family:inherit; font-size:11.5px;
  font-weight:600; letter-spacing:0.04em; text-transform:uppercase;
  transition:all 0.12s;
}
.matrix-mode button.on{background:var(--accent); color:#04111d;}

.matrix-grid{
  display:grid; grid-template-columns:repeat(14, minmax(150px, 1fr));
  gap:8px;
  overflow-x:auto; padding-bottom:24px;
}
.tactic-col{display:flex; flex-direction:column; min-width:150px;}
.tactic-header{
  position:sticky; top:0; z-index:5;
  background:var(--panel-elev); border:1px solid var(--border);
  border-radius:6px 6px 0 0;
  padding:9px 8px 7px; text-align:center;
  font-size:11px; font-weight:700; letter-spacing:0.02em;
}
.tactic-header .tactic-name{color:var(--text); display:block; line-height:1.25;}
.tactic-header .tactic-count{color:var(--muted); font-size:10px; font-weight:500;}
.tactic-techs{display:flex; flex-direction:column; gap:2px; padding-top:2px;}
.tech-cell{
  background:var(--panel); border:1px solid var(--border);
  border-radius:0; padding:5px 7px;
  font-size:11px; line-height:1.3; cursor:pointer;
  position:relative; transition:all 0.1s;
  display:flex; flex-direction:column; gap:2px;
}
.tech-cell:hover{border-color:var(--accent); transform:translateY(-1px);
  box-shadow:0 4px 10px rgba(0,0,0,0.4); z-index:2;}
.tech-cell .tech-name{color:var(--text); white-space:nowrap; overflow:hidden;
  text-overflow:ellipsis; font-weight:500;}
.tech-cell .tech-meta{display:flex; gap:6px; align-items:center; font-size:9.5px;
  color:var(--muted-2); font-variant-numeric:tabular-nums;}
.tech-cell .sub-marker{color:var(--accent-2); font-size:9px; font-weight:700;}
.tech-cell .uc-count{color:var(--accent-3); font-weight:700;}
.tech-cell.has-uc{background:linear-gradient(180deg, rgba(54,224,192,0.07), rgba(54,224,192,0.02));}
.tech-cell.cov-1{background:linear-gradient(180deg, rgba(54,224,192,0.10), rgba(54,224,192,0.02));}
.tech-cell.cov-2{background:linear-gradient(180deg, rgba(54,224,192,0.18), rgba(54,224,192,0.04));}
.tech-cell.cov-3{background:linear-gradient(180deg, rgba(54,224,192,0.30), rgba(54,224,192,0.06));
  border-color:rgba(54,224,192,0.35);}
.tech-cell.cov-4{background:linear-gradient(180deg, rgba(54,224,192,0.45), rgba(54,224,192,0.10));
  border-color:rgba(54,224,192,0.55);}
.tech-cell.heat-1{background:linear-gradient(180deg, rgba(255,176,96,0.10), rgba(255,176,96,0.02));}
.tech-cell.heat-2{background:linear-gradient(180deg, rgba(255,93,93,0.15), rgba(255,93,93,0.04));
  border-color:rgba(255,93,93,0.4);}
.tech-cell.heat-3{background:linear-gradient(180deg, rgba(255,50,96,0.30), rgba(255,50,96,0.05));
  border-color:rgba(255,50,96,0.55);}
.tech-cell.dim{opacity:0.35;}
.tech-cell.is-sub{padding-left:14px; border-left:2px solid var(--accent-2);
  background:var(--panel2);}
.tech-cell.expanded{border-color:var(--accent);}

/* ----- Threat Intel table -------------------------------------------- */
.intel-types{display:flex; gap:4px; padding:3px;
  background:var(--bg); border:1px solid var(--border); border-radius:var(--r-sm);}
.intel-types button{
  padding:5px 11px; background:transparent; border:none; border-radius:4px;
  color:var(--muted); cursor:pointer; font-family:inherit; font-size:11.5px;
  font-weight:600; letter-spacing:0.04em; text-transform:uppercase;
  transition:all 0.12s;
}
.intel-types button.on{background:var(--accent); color:#04111d;}
.intel-table-wrap{
  overflow-x:auto; border:1px solid var(--border); border-radius:var(--r-md);
  background:var(--panel);
}
.intel-table{width:100%; border-collapse:collapse; font-size:12.5px;}
.intel-table thead th{
  position:sticky; top:0; background:var(--panel-elev);
  text-align:left; padding:10px 12px; border-bottom:1px solid var(--border);
  font-size:10.5px; text-transform:uppercase; letter-spacing:0.08em;
  color:var(--muted); font-weight:700;
}
.intel-table tbody tr{transition:background 0.12s;}
.intel-table tbody tr:hover{background:rgba(95,182,255,0.04);}
.intel-table tbody tr.dim{display:none;}
.intel-table td{padding:9px 12px; border-bottom:1px solid var(--hairline); vertical-align:top;}
.intel-table .ioc-val{
  font-family:"JetBrains Mono",ui-monospace,monospace;
  color:var(--accent-2); word-break:break-all;
}
.intel-table .type-pill, .intel-table .sev-pill{
  font-size:10px; font-weight:700; letter-spacing:0.06em; text-transform:uppercase;
  padding:2px 8px; border-radius:6px;
  background:var(--panel2); border:1px solid var(--border);
  color:var(--muted); display:inline-block;
}
.intel-table .type-pill.cve{color:var(--warn); border-color:#5a3b1f;}
.intel-table .type-pill.ipv4{color:var(--accent); border-color:rgba(95,182,255,0.3);}
.intel-table .type-pill.domain{color:var(--accent-3); border-color:rgba(54,224,192,0.3);}
.intel-table .type-pill.sha256, .intel-table .type-pill.sha1, .intel-table .type-pill.md5{
  color:var(--accent-2); border-color:rgba(180,141,255,0.3);
}
.intel-table .sev-pill.crit{color:var(--crit); border-color:rgba(255,50,96,0.55);}
.intel-table .sev-pill.high{color:var(--bad); border-color:rgba(255,93,93,0.4);}
.intel-table .sev-pill.med{color:var(--warn); border-color:rgba(255,176,96,0.4);}
.intel-table .sev-pill.low{color:var(--good); border-color:rgba(92,216,122,0.4);}
.intel-table .sources{display:flex; gap:4px; flex-wrap:wrap;}
.intel-table .article-link{color:var(--accent); text-decoration:none;
  display:inline-block; max-width:300px; overflow:hidden; text-overflow:ellipsis;
  white-space:nowrap; vertical-align:bottom;}
.intel-table .article-link:hover{text-decoration:underline;}
.intel-empty{padding:40px; text-align:center; color:var(--muted-2);}

/* ----- Intel "About this feed" expandable panel ---------------------- */
details.intel-about{
  background:linear-gradient(135deg, rgba(95,182,255,0.06), rgba(180,141,255,0.04));
  border:1px solid var(--border);
  border-radius:var(--r-md);
  margin-bottom:14px;
  overflow:hidden;
}
details.intel-about[open]{
  border-color:rgba(95,182,255,0.3);
  background:var(--panel);
}
details.intel-about summary{
  padding:14px 18px; cursor:pointer; list-style:none;
  display:flex; align-items:center; gap:14px;
}
details.intel-about summary::-webkit-details-marker{display:none;}
details.intel-about summary::after{
  content:"▾"; color:var(--muted); font-size:14px; margin-left:auto;
  transition:transform 0.2s;
}
details.intel-about[open] summary::after{transform:rotate(180deg);}
.intel-about-title{font-weight:700; font-size:14px; color:var(--text);}
.intel-about-sub{color:var(--muted); font-size:12px;}
.intel-about-body{padding:0 24px 22px; line-height:1.55;}
.intel-about-body h4{
  margin:18px 0 8px; font-size:11px;
  text-transform:uppercase; letter-spacing:0.08em; color:var(--accent-2);
}
.intel-mission{
  margin:6px 0 18px;
  padding:12px 16px;
  border-left:3px solid var(--accent);
  background:rgba(95,182,255,0.04);
  border-radius:0 6px 6px 0;
}
.intel-sources{display:flex; gap:8px; flex-wrap:wrap; align-items:center; margin-bottom:8px;}
.intel-urls{display:grid; grid-template-columns:repeat(auto-fit, minmax(280px,1fr));
  gap:6px; margin:8px 0 14px;}
.intel-urls code{
  display:block; padding:8px 10px;
  background:var(--code-bg); border:1px solid var(--border); border-radius:6px;
  font-size:11.5px; word-break:break-all;
}
.intel-urls code a{color:var(--accent); text-decoration:none;}
.intel-urls code a:hover{text-decoration:underline;}
table.intel-cols-doc{
  width:100%; border-collapse:collapse; font-size:12px; margin-top:6px;
}
table.intel-cols-doc th{
  text-align:left; padding:8px 10px;
  background:var(--panel2); border-bottom:1px solid var(--border);
  font-size:10.5px; text-transform:uppercase; letter-spacing:0.08em;
  color:var(--muted);
}
table.intel-cols-doc td{
  padding:8px 10px; border-bottom:1px solid var(--hairline);
  vertical-align:top;
}
table.intel-cols-doc code{
  background:var(--panel2); padding:2px 6px; border-radius:4px;
  font-size:11px; color:var(--accent-3);
}
ul.intel-types-doc{padding-left:20px; margin:8px 0; font-size:13px;}
ul.intel-types-doc li{margin:6px 0; line-height:1.55;}
ul.intel-types-doc code{
  background:var(--panel2); padding:1px 6px; border-radius:4px;
  font-size:11px; color:var(--accent-3);
}
.quality-bar{
  background:rgba(255,176,96,0.06); border:1px solid rgba(255,176,96,0.25);
  border-left:3px solid var(--warn); border-radius:0 6px 6px 0;
  padding:12px 16px; margin:6px 0;
}
.quality-bar p{margin:0 0 6px;}
.quality-bar ul.intel-types-doc{margin:6px 0;}

/* Drawer — centred modal covering most of the screen */
.drawer-bg{
  position:fixed; inset:0; z-index:60;
  background:rgba(0,0,0,0.65); backdrop-filter:blur(6px);
  display:none;
}
.drawer-bg.open{display:block; animation:fadeIn 0.15s;}
.drawer{
  position:fixed;
  top:50%; left:50%;
  /* Centred at ~78% of viewport, capped so it never sprawls. */
  width:min(1200px, 78vw);
  height:min(880px, 86vh);
  transform:translate(-50%, -50%) scale(0.96);
  background:var(--panel-elev);
  border:1px solid var(--border-2); border-radius:14px;
  z-index:61;
  opacity:0; pointer-events:none;
  transition:transform 0.22s cubic-bezier(0.2,0.8,0.2,1), opacity 0.18s ease;
  display:flex; flex-direction:column;
  box-shadow:0 32px 80px rgba(0,0,0,0.55), 0 0 0 1px rgba(255,255,255,0.04) inset;
  overflow:hidden;
}
.drawer.open{
  transform:translate(-50%, -50%) scale(1);
  opacity:1; pointer-events:auto;
}
@media(max-width:768px){
  .drawer{ width:96vw; height:94vh; }
}
.drawer-head{padding:18px 20px; border-bottom:1px solid var(--hairline);}
.drawer-head .tid{color:var(--accent); font-family:ui-monospace,monospace; font-size:13px;
  font-weight:700; letter-spacing:0.02em;}
.drawer-head h3{margin:6px 0 4px; font-size:18px; font-weight:700; line-height:1.25;}
.drawer-head .tactics{display:flex; flex-wrap:wrap; gap:5px; margin-top:8px;}
.drawer-head .tactic-pill{font-size:10px; padding:2px 8px; border-radius:10px;
  background:rgba(180,141,255,0.12); color:var(--accent-2);
  border:1px solid rgba(180,141,255,0.3); text-transform:uppercase;
  letter-spacing:0.04em; font-weight:700;}
.drawer-head .ext-link{display:inline-flex; align-items:center; gap:4px;
  color:var(--accent); text-decoration:none; font-size:12px; margin-top:8px;}
.drawer-head .ext-link:hover{text-decoration:underline;}
.drawer-close{position:absolute; top:14px; right:14px;
  background:transparent; border:none; color:var(--muted);
  font-size:22px; cursor:pointer; line-height:1; padding:4px 8px;
  border-radius:4px;}
.drawer-close:hover{background:var(--panel2); color:var(--text);}
.drawer-body{flex:1; overflow-y:auto; padding:14px 20px 20px;}
.drawer-body::-webkit-scrollbar{width:6px;}
.drawer-body::-webkit-scrollbar-thumb{background:var(--border-2); border-radius:3px;}
.drawer-section{margin-bottom:18px;}
.drawer-section h4{font-size:10.5px; text-transform:uppercase; letter-spacing:0.08em;
  color:var(--muted); margin:0 0 8px 0; font-weight:700;}
.drawer-list{display:flex; flex-direction:column; gap:6px;}
.drawer-list a{
  display:block; padding:8px 10px; background:var(--panel); border:1px solid var(--border);
  border-radius:6px; color:var(--text); text-decoration:none;
  font-size:12.5px; line-height:1.3; transition:all 0.12s;
}
.drawer-list a:hover{border-color:var(--accent); transform:translateX(2px);}
.drawer-list .meta{display:flex; gap:6px; margin-top:4px; font-size:10px; color:var(--muted-2);
  text-transform:uppercase; letter-spacing:0.04em; font-weight:600;}
.drawer-list .pill{padding:1px 7px; border-radius:8px;
  background:var(--panel2); border:1px solid var(--border);}
.drawer-list .pill.high{color:var(--bad); border-color:rgba(255,93,93,0.4);}
.drawer-list .pill.crit{color:var(--crit); border-color:rgba(255,50,96,0.55);}
.drawer-list .pill.med{color:var(--warn); border-color:rgba(255,176,96,0.4);}
.drawer-list .pill.low{color:var(--good); border-color:rgba(92,216,122,0.4);}
.drawer-list .pill.confhigh{color:var(--good);}
.drawer-list .pill.confmedium{color:var(--warn);}
.drawer-empty{color:var(--muted-2); font-size:12px; font-style:italic; padding:8px 0;}

/* ----- Reduced motion ------------------------------------------------ */
@media (prefers-reduced-motion: reduce){
  *,*::before,*::after{animation:none !important;transition:none !important;}
}
</style>
</head>
<body>
<!-- Logo lightbox — click logoButton to open, click backdrop or ESC to close. -->
<div class="logo-lightbox" id="logoLightbox" role="dialog" aria-modal="true" aria-labelledby="lbCaption" hidden>
  <button class="logo-lightbox-close" id="logoLightboxClose" aria-label="Close">×</button>
  <img src="logo.png" alt="Clanker the Clankerusecase mascot">
  <div class="logo-lightbox-caption" id="lbCaption"><strong>Clanker</strong> · the Clankerusecase mascot</div>
</div>
<header class="topbar">
  <div class="topbar-inner">
    <div class="brand">
      <button type="button" class="logo" id="logoButton"
              aria-label="View Clanker the mascot at full size"
              title="Meet Clanker">
        <!-- logo.png in repo root → SVG fallback if file missing -->
        <img src="logo.png" alt="Clankerusecase" class="logo-img"
             onerror="this.style.display='none';this.nextElementSibling.style.display='block';">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round" style="display:none;">
          <path d="M12 2 L4 6 v6 c0 5 3.5 8 8 10 4.5-2 8-5 8-10 V6z"/>
          <path d="M9 12 l2 2 l4-4"/>
        </svg>
      </button>
      <div class="brand-text">
        <span>Clankerusecase</span>
      </div>
    </div>
    <div class="stats-wrap">
      <div class="stats stats-articles" id="topStats">
        <div class="stat"><div class="v">__ARTICLE_COUNT__</div><div class="l">Articles</div></div>
        <div class="stat"><div class="v">__USECASE_COUNT__</div><div class="l">Use Cases</div></div>
        <div class="stat"><div class="v">__TECH_COUNT__</div><div class="l">ATT&amp;CK</div></div>
        <div class="stat"><div class="v">__CVE_COUNT__</div><div class="l">CVEs</div></div>
        <div class="stat"><div class="v">__CRIT_COUNT__</div><div class="l">Critical</div></div>
      </div>
      <div class="stats stats-matrix" id="topStatsMatrix"></div>
      <div class="stats stats-intel" id="topStatsIntel"></div>
    </div>
    <div class="search-trigger" id="searchTrigger">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="M21 21 L16.65 16.65"/></svg>
      <span class="search-placeholder">Search articles, techniques, CVEs</span>
      <span class="search-shortcut"><kbd id="searchShortcutKey">Ctrl</kbd><kbd>K</kbd></span>
    </div>
  </div>
  <div class="topbar-inner" style="padding-top:0; gap:14px;">
    <div class="view-tabs" role="tablist">
      <button class="view-tab active" data-view="articles" role="tab">Articles</button>
      <button class="view-tab" data-view="matrix" role="tab">ATT&amp;CK Matrix</button>
      <button class="view-tab" data-view="intel" role="tab">Threat Intel</button>
      <button class="view-tab" data-view="workflow" role="tab">Workflow</button>
      <button class="view-tab" data-view="about" role="tab">About</button>
    </div>
  </div>
</header>

<div id="view-articles" class="view active">
<main class="width-wide">
  <nav class="toc">
    <h3>Articles</h3>
    <div id="navlist">__NAV__</div>
  </nav>
  <section id="articles">
    <div class="src-filter-bar" id="srcFilter">
      __SOURCE_CHIPS__
      <div class="width-toggle" id="widthToggle" title="Article column width">
        <button data-width="compact">Compact</button>
        <button data-width="wide" class="on">Wide</button>
        <button data-width="full">Full</button>
      </div>
    </div>
    __CARDS__
  </section>
</main>
</div>

<div id="view-matrix" class="view">
  <div class="matrix-wrap">
    <div class="matrix-toolbar">
      <input type="text" id="matrixSearch" placeholder="Filter by technique name or T-ID" autocomplete="off">
      <div class="matrix-mode" id="matrixModes">
        <button class="on" data-mode="coverage">Coverage</button>
        <button data-mode="heat">Heat</button>
        <button data-mode="all">All</button>
      </div>
      <div class="matrix-stats" id="matrixStats"></div>
    </div>
    <div class="matrix-legend" id="matrixLegend">
      <div class="lg-row">
        <span class="lg-label">Coverage mode</span>
        <span class="lg-swatch cov-0">none</span>
        <span class="lg-swatch cov-1">1 UC</span>
        <span class="lg-swatch cov-2">2 UCs</span>
        <span class="lg-swatch cov-3">3 UCs</span>
        <span class="lg-swatch cov-4">4+ UCs</span>
        <span class="lg-note">how many of our use cases map to that technique</span>
      </div>
      <div class="lg-row">
        <span class="lg-label">Heat mode</span>
        <span class="lg-swatch cov-0">none</span>
        <span class="lg-swatch heat-1">1 article</span>
        <span class="lg-swatch heat-2">2 articles</span>
        <span class="lg-swatch heat-3">3+ articles</span>
        <span class="lg-note">how many current articles cite that technique</span>
      </div>
      <div class="lg-row">
        <span class="lg-label">Cell badges</span>
        <span class="lg-chip"><b style="color:var(--accent-2);">▾4</b> = 4 sub-techniques</span>
        <span class="lg-chip"><b style="color:var(--accent-3);">3 UC</b> = 3 use cases mapped</span>
        <span class="lg-chip"><b style="color:var(--warn);">8 art</b> = 8 articles cite it</span>
        <span class="lg-note">click any cell for the full drawer</span>
      </div>
    </div>
    <div class="matrix-grid" id="matrixGrid"></div>
  </div>
</div>

<div id="view-intel" class="view">
  <div class="matrix-wrap">
    <details class="intel-about" id="intelAbout">
      <summary>
        <span class="intel-about-title">📡 About the Intel Feed</span>
        <span class="intel-about-sub">Real intel from the best threat articles · click to expand</span>
      </summary>
      <div class="intel-about-body">
        <p class="intel-mission">
          <strong>Mission:</strong> Provide actionable, contextualised threat intelligence drawn from the day's
          best security reporting — not a generic IOC firehose. Every indicator below has a story attached:
          who reported it, when, and which malware/actor/campaign it relates to.
        </p>

        <h4>Sources</h4>
        <div class="intel-sources">
          <span class="source-badge thn">The Hacker News</span>
          <span class="source-badge bc">BleepingComputer</span>
          <span class="source-badge ms">Microsoft Security Blog</span>
          <span class="source-badge kev">CISA KEV</span>
          <span class="lg-note">refreshed daily · deduplicated across publications</span>
        </div>

        <h4>Pull the feed (always current)</h4>
        <div class="intel-urls">
          <code><a href="https://raw.githubusercontent.com/Virtualhaggis/usecaseintel/main/intel/iocs.csv" target="_blank">intel/iocs.csv</a></code>
          <code><a href="https://raw.githubusercontent.com/Virtualhaggis/usecaseintel/main/intel/iocs.json" target="_blank">intel/iocs.json</a></code>
          <code><a href="https://raw.githubusercontent.com/Virtualhaggis/usecaseintel/main/intel/iocs.stix.json" target="_blank">intel/iocs.stix.json</a></code>
          <code><a href="https://raw.githubusercontent.com/Virtualhaggis/usecaseintel/main/intel/splunk_lookup_iocs.csv" target="_blank">splunk_lookup_iocs.csv</a></code>
          <code><a href="https://raw.githubusercontent.com/Virtualhaggis/usecaseintel/main/intel/iocs.rss.xml" target="_blank">📡 iocs.rss.xml (RSS 2.0)</a></code>
        </div>
        <p class="lg-note" style="margin-top:6px;">
          Drop the RSS URL into Feedly, Inoreader, Slack RSS, or your TIP's RSS connector to get
          notified the moment a new high-fidelity IOC lands. The feed shows the latest 100 items,
          newest first, with severity, source attribution and a click-through to the source article.
        </p>

        <h4>What each column tells you</h4>
        <table class="intel-cols-doc">
          <tr><th>Column</th><th>What it means</th><th>What to do with it</th></tr>
          <tr><td><code>value</code></td><td>The actual indicator (CVE-ID, IP, domain, hash)</td><td>Search your telemetry for matches</td></tr>
          <tr><td><code>type</code></td><td><code>cve</code> · <code>ipv4</code> · <code>domain</code> · <code>sha256</code> · <code>sha1</code> · <code>md5</code></td><td>Routes you to the right SIEM data model / Defender table</td></tr>
          <tr><td><code>severity</code></td><td><code>crit</code> / <code>high</code> / <code>med</code> / <code>low</code> — inherited from the article</td><td>Triage priority. <code>crit</code>+<code>high</code> get hunted today</td></tr>
          <tr><td><code>sources</code></td><td>Publication(s) that reported the IOC</td><td>2+ sources = stronger consensus</td></tr>
          <tr><td><code>first_seen</code></td><td>Earliest article publication date</td><td>Bounds your hunt window</td></tr>
          <tr><td><code>article</code> link</td><td>Direct URL to the source article</td><td>Click for full context — TTPs, additional IOCs</td></tr>
        </table>

        <h4>What you're looking at — by IOC type</h4>
        <ul class="intel-types-doc">
          <li><strong>CVE</strong> — a vulnerability identifier; match against your scanner output. <code>Splunk: Vulnerabilities.signature</code> · <code>Defender: DeviceTvmSoftwareVulnerabilities.CveId</code></li>
          <li><strong>IPv4</strong> — attacker-controlled C2/scanner IP. <code>Splunk: Network_Traffic.All_Traffic.dest</code> · <code>Defender: DeviceNetworkEvents.RemoteIP</code></li>
          <li><strong>Domain</strong> — attacker hostname (C2/phishing/download). <code>Splunk: Network_Resolution.DNS.query</code> · <code>Defender: DeviceNetworkEvents.RemoteUrl</code></li>
          <li><strong>SHA256 / SHA1 / MD5</strong> — malicious file hashes. <code>Splunk: Endpoint.Filesystem.file_hash</code> · <code>Defender: DeviceFileEvents.SHA256</code></li>
        </ul>

        <h4>How we earn the SOC's trust — high-fidelity extraction</h4>
        <div class="quality-bar">
          <p>A bad IOC feed makes an analyst block legitimate Outlook / GitHub / vendor traffic. So this pipeline is deliberately conservative:</p>
          <ul class="intel-types-doc">
            <li><strong>CVEs and hashes</strong> are extracted by regex — unambiguous format, low false-positive rate.</li>
            <li><strong>Domains and IPs</strong> are accepted <em>only when defanged</em> by the source author (e.g. <code>evil[.]com</code>, <code>1[.]2[.]3[.]4</code>, <code>hxxps://...</code>). That's the universal "I'm flagging this as malicious" convention.</li>
            <li><strong>Plain-text domain/IP mentions are rejected</strong>. In an RSS summary, a phrase like "Outlook users were affected" or "ASP.NET vulnerability" is the legitimate victim or platform — never an IOC. We don't ship false positives just to look busy.</li>
          </ul>
          <p style="margin-top:10px;color:var(--muted);">
            If today's feed shows mostly CVEs, that reflects an honest reality: KEV publishes structured exploited-CVE data daily; defanged IPs/hashes typically live in technical write-ups whose bodies we cannot scrape. Every IOC you see has earned its place.
          </p>
        </div>

        <h4>Severity meaning</h4>
        <ul class="intel-types-doc">
          <li><span class="sev-pill crit">CRIT</span> — multiple sources + zero-day + active exploitation → page on-call</li>
          <li><span class="sev-pill high">HIGH</span> — confirmed exploitation, named threat actor, or CISA KEV → hunt this shift</li>
          <li><span class="sev-pill med">MED</span> — reported activity, malware family identified → weekly hunt queue</li>
          <li><span class="sev-pill low">LOW</span> — background reporting → context only</li>
        </ul>

        <p class="lg-note" style="margin-top:14px;">
          Full docs and integration examples (Splunk, Defender, MISP, OpenCTI, Sentinel TAXII): see
          <a href="https://github.com/Virtualhaggis/usecaseintel/blob/main/intel/README.md" target="_blank" style="color:var(--accent);">intel/README.md on GitHub</a>.
        </p>
      </div>
    </details>

    <div class="matrix-toolbar">
      <input type="text" id="intelSearch" placeholder="Search IOC value, article title, or context" autocomplete="off">
      <div class="intel-types" id="intelTypes">
        <button class="on" data-type="">All</button>
        <button data-type="cve">CVE</button>
        <button data-type="ipv4">IP</button>
        <button data-type="domain">Domain</button>
        <button data-type="sha256">SHA256</button>
        <button data-type="sha1">SHA1</button>
        <button data-type="md5">MD5</button>
      </div>
      <div class="matrix-stats" id="intelStats"></div>
    </div>
    <div class="matrix-toolbar" style="margin-top:-6px;">
      <span class="lg-label">Export</span>
      <button class="src-chip" data-export="csv">📄 CSV</button>
      <button class="src-chip" data-export="json">{ } JSON</button>
      <button class="src-chip" data-export="stix">⚡ STIX 2.1</button>
      <button class="src-chip" data-export="splunk">🔎 Splunk lookup</button>
      <button class="src-chip" data-export="copy">📋 Copy CSV</button>
      <a class="src-chip" target="_blank" rel="noopener"
         href="https://raw.githubusercontent.com/Virtualhaggis/usecaseintel/main/intel/iocs.rss.xml"
         style="text-decoration:none;color:var(--warn);border-color:rgba(255,176,96,0.4);">
        📡 Subscribe via RSS
      </a>
      <span class="lg-note" style="margin-left:auto;">Exports reflect current filters · RSS feed auto-refreshes daily</span>
    </div>
    <div class="intel-table-wrap">
      <table class="intel-table" id="intelTable">
        <thead><tr>
          <th>Value</th><th>Type</th><th>Sev</th>
          <th>Sources</th><th>Article</th><th>First seen</th><th>Articles</th>
        </tr></thead>
        <tbody id="intelBody"></tbody>
      </table>
    </div>
  </div>
</div>

<div class="drawer-bg" id="drawerBg"></div>
<aside class="drawer" id="techDrawer" aria-hidden="true">
  <button class="drawer-close" id="drawerClose" aria-label="Close">×</button>
  <div class="drawer-head" id="drawerHead"></div>
  <div class="drawer-body" id="drawerBody"></div>
</aside>

<div class="search-overlay" id="searchOverlay">
  <div class="search-modal">
    <input type="text" id="searchInput" placeholder="Search by title, technique (T1566), CVE, malware name…" autocomplete="off">
    <div class="search-results" id="searchResults"></div>
  </div>
</div>

<div id="view-workflow" class="view">
  <div class="workflow-wrap">
    <h2 class="wf-title">From article to detection — the full pipeline</h2>
    <p class="wf-lede">
      How a fresh threat-intel article moves through this site: ingestion,
      extraction, mapping, export. Diagram first, then the per-step detail —
      including the actual prompts, regex, and heuristics behind each stage.
    </p>

    <!-- ============== DIAGRAM ============== -->
    <div class="wf-diagram">
      <svg viewBox="0 0 1280 480" preserveAspectRatio="xMidYMid meet" role="img" aria-label="Pipeline workflow">
        <defs>
          <marker id="wfArrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto">
            <path d="M 0 0 L 10 5 L 0 10 z" fill="#5fb6ff"/>
          </marker>
          <linearGradient id="wfFill1" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stop-color="#1a2840"/>
            <stop offset="1" stop-color="#0f1a2c"/>
          </linearGradient>
          <linearGradient id="wfFill2" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stop-color="#1f2a3f"/>
            <stop offset="1" stop-color="#13202f"/>
          </linearGradient>
          <linearGradient id="wfFill3" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stop-color="#1c2d2a"/>
            <stop offset="1" stop-color="#0e1f1c"/>
          </linearGradient>
        </defs>

        <!-- Stage 1: Sources -->
        <g class="wf-stage">
          <rect x="20" y="40" width="180" height="200" rx="12" fill="url(#wfFill1)" stroke="#2a3f5e" stroke-width="1.4"/>
          <text x="110" y="68" text-anchor="middle" fill="#5fb6ff" font-size="13" font-weight="700">1. SOURCES</text>
          <text x="35" y="100" fill="#cfd6e3" font-size="11">• The Hacker News</text>
          <text x="35" y="122" fill="#cfd6e3" font-size="11">• BleepingComputer</text>
          <text x="35" y="144" fill="#cfd6e3" font-size="11">• Microsoft Security Blog</text>
          <text x="35" y="166" fill="#36e0c0" font-size="11">• Cisco Talos</text>
          <text x="35" y="188" fill="#36e0c0" font-size="11">• Securelist (Kaspersky)</text>
          <text x="35" y="210" fill="#36e0c0" font-size="11">• SentinelLabs</text>
          <text x="35" y="232" fill="#36e0c0" font-size="11">• Unit 42 / ESET / KEV</text>
        </g>

        <!-- Stage 2: Ingest -->
        <g class="wf-stage">
          <rect x="240" y="40" width="200" height="200" rx="12" fill="url(#wfFill1)" stroke="#2a3f5e" stroke-width="1.4"/>
          <text x="340" y="68" text-anchor="middle" fill="#5fb6ff" font-size="13" font-weight="700">2. INGEST</text>
          <text x="255" y="100" fill="#cfd6e3" font-size="11" font-weight="600">RSS / KEV JSON</text>
          <text x="255" y="120" fill="#9aa3b2" font-size="10.5">→ feedparser pulls entries</text>
          <text x="255" y="138" fill="#9aa3b2" font-size="10.5">→ 180-day rolling window</text>
          <text x="255" y="160" fill="#cfd6e3" font-size="11" font-weight="600">Full body fetch</text>
          <text x="255" y="180" fill="#9aa3b2" font-size="10.5">→ HTTPS GET with cache</text>
          <text x="255" y="198" fill="#9aa3b2" font-size="10.5">→ HTML→text + noise strip</text>
          <text x="255" y="216" fill="#cfd6e3" font-size="11" font-weight="600">Cross-source dedupe</text>
          <text x="255" y="234" fill="#9aa3b2" font-size="10.5">→ Jaccard ≥ 0.55 on titles</text>
        </g>

        <!-- Stage 3: Extraction -->
        <g class="wf-stage">
          <rect x="480" y="40" width="220" height="200" rx="12" fill="url(#wfFill2)" stroke="#3a2a5a" stroke-width="1.4"/>
          <text x="590" y="68" text-anchor="middle" fill="#b48dff" font-size="13" font-weight="700">3. EXTRACT</text>
          <text x="495" y="100" fill="#cfd6e3" font-size="11" font-weight="600">High-fidelity IOCs</text>
          <text x="495" y="120" fill="#9aa3b2" font-size="10.5">CVEs (regex)</text>
          <text x="495" y="138" fill="#9aa3b2" font-size="10.5">Hashes MD5/SHA1/SHA256</text>
          <text x="495" y="156" fill="#9aa3b2" font-size="10.5">Defanged IPs / domains</text>
          <text x="495" y="174" fill="#9aa3b2" font-size="10.5">hxxps:// URLs</text>
          <text x="495" y="196" fill="#cfd6e3" font-size="11" font-weight="600">Article mechanics</text>
          <text x="495" y="214" fill="#9aa3b2" font-size="10.5">Binaries / paths / cmd flags</text>
          <text x="495" y="230" fill="#9aa3b2" font-size="10.5">Registry / persistence keys</text>
        </g>

        <!-- Stage 4: Use cases -->
        <g class="wf-stage">
          <rect x="740" y="40" width="240" height="200" rx="12" fill="url(#wfFill2)" stroke="#3a2a5a" stroke-width="1.4"/>
          <text x="860" y="68" text-anchor="middle" fill="#b48dff" font-size="13" font-weight="700">4. USE CASES</text>
          <text x="755" y="100" fill="#cfd6e3" font-size="11" font-weight="600">Rule matching</text>
          <text x="755" y="120" fill="#9aa3b2" font-size="10.5">→ keyword triggers fire UC</text>
          <text x="755" y="142" fill="#cfd6e3" font-size="11" font-weight="600">Bespoke generation</text>
          <text x="755" y="162" fill="#9aa3b2" font-size="10.5">→ SPL/KQL hunts THIS</text>
          <text x="755" y="180" fill="#9aa3b2" font-size="10.5">  attack's specific bins/paths</text>
          <text x="755" y="200" fill="#cfd6e3" font-size="11" font-weight="600">IOC-driven hunts</text>
          <text x="755" y="220" fill="#9aa3b2" font-size="10.5">→ shared template + IOC list</text>
        </g>

        <!-- Stage 5: Outputs -->
        <g class="wf-stage">
          <rect x="1020" y="40" width="240" height="200" rx="12" fill="url(#wfFill3)" stroke="#2a5a4f" stroke-width="1.4"/>
          <text x="1140" y="68" text-anchor="middle" fill="#36e0c0" font-size="13" font-weight="700">5. OUTPUTS</text>
          <text x="1035" y="100" fill="#cfd6e3" font-size="11" font-weight="600">Articles tab</text>
          <text x="1035" y="118" fill="#9aa3b2" font-size="10.5">→ per-article cards + briefings</text>
          <text x="1035" y="138" fill="#cfd6e3" font-size="11" font-weight="600">ATT&amp;CK Matrix</text>
          <text x="1035" y="156" fill="#9aa3b2" font-size="10.5">→ 691 techniques × 2,236 UCs</text>
          <text x="1035" y="176" fill="#cfd6e3" font-size="11" font-weight="600">Threat Intel</text>
          <text x="1035" y="194" fill="#9aa3b2" font-size="10.5">→ CSV / JSON / STIX / RSS</text>
          <text x="1035" y="214" fill="#cfd6e3" font-size="11" font-weight="600">Briefings (markdown)</text>
          <text x="1035" y="232" fill="#9aa3b2" font-size="10.5">→ analyst-curated overlays</text>
        </g>

        <!-- Connectors -->
        <line x1="200" y1="140" x2="240" y2="140" stroke="#5fb6ff" stroke-width="2" marker-end="url(#wfArrow)"/>
        <line x1="440" y1="140" x2="480" y2="140" stroke="#5fb6ff" stroke-width="2" marker-end="url(#wfArrow)"/>
        <line x1="700" y1="140" x2="740" y2="140" stroke="#5fb6ff" stroke-width="2" marker-end="url(#wfArrow)"/>
        <line x1="980" y1="140" x2="1020" y2="140" stroke="#5fb6ff" stroke-width="2" marker-end="url(#wfArrow)"/>

        <!-- Bottom rail: analyst loop -->
        <g class="wf-loop">
          <rect x="20" y="320" width="1240" height="100" rx="12" fill="rgba(255,176,96,0.06)" stroke="#5a4a2a" stroke-width="1.4" stroke-dasharray="4 4"/>
          <text x="640" y="350" text-anchor="middle" fill="#ffb060" font-size="13" font-weight="700">Analyst loop (continuous)</text>
          <text x="100" y="378" fill="#cfd6e3" font-size="11">📖 Read article →</text>
          <text x="280" y="378" fill="#cfd6e3" font-size="11">✏ Curate briefing &lt;!-- curated:true --&gt; →</text>
          <text x="600" y="378" fill="#cfd6e3" font-size="11">🛠 Tune triggers / write new YAML UC →</text>
          <text x="950" y="378" fill="#cfd6e3" font-size="11">💾 Commit → next pipeline run picks up</text>
          <text x="640" y="402" text-anchor="middle" fill="#9aa3b2" font-size="10.5">Curated briefings get the &lt;!-- curated:true --&gt; marker and are preserved across runs.</text>
        </g>

        <line x1="640" y1="240" x2="640" y2="320" stroke="#ffb060" stroke-width="2" stroke-dasharray="4 4" marker-end="url(#wfArrow)"/>
      </svg>
    </div>

    <!-- ============== DETAILED STEPS ============== -->
    <h3 class="wf-section-title">1. Sources</h3>
    <div class="wf-step">
      <p>The pipeline pulls from <strong>9 feeds</strong> on every run:</p>
      <ul>
        <li><strong>News</strong> — The Hacker News, BleepingComputer, Microsoft Security Blog. Broad coverage, light on technical IOC tables.</li>
        <li><strong>IOC-rich vendor research</strong> — Cisco Talos, Securelist (Kaspersky), SentinelLabs, Unit 42 (Palo Alto), ESET WeLiveSecurity. Where the hash / IP / domain tables live.</li>
        <li><strong>CISA KEV</strong> — authoritative exploited-vulnerability feed (JSON, not RSS).</li>
      </ul>
      <p>Adding a source is a 3-line entry in <code>SOURCES</code>. The fetcher detects RSS vs JSON automatically.</p>
    </div>

    <h3 class="wf-section-title">2. Ingest</h3>
    <div class="wf-step">
      <p>For each entry in the rolling <strong>180-day window</strong>:</p>
      <ol>
        <li><code>feedparser.parse()</code> reads the RSS preview.</li>
        <li><code>_fetch_full_body(url)</code> issues an HTTPS GET with a polite <code>User-Agent</code>, caches the HTML to <code>intel/.article_cache/</code>, and converts to plain text. <strong>Without this step the IOC feed only has CVEs</strong> — RSS previews don't include hash tables.</li>
        <li>Cross-source <strong>Jaccard dedupe</strong> on title token sets (threshold 0.55) merges "Chinese Silk Typhoon hacker extradited" (THN) with "Alleged Silk Typhoon hacker extradited" (BleepingComputer) into a single entry with two source attributions.</li>
      </ol>
    </div>

    <h3 class="wf-section-title">3. Extract</h3>
    <div class="wf-step">
      <p>Two parallel extractors run on every article body:</p>
      <p><strong>High-fidelity IOCs</strong> (<code>extract_indicators</code>):</p>
      <ul>
        <li>CVE — <code>CVE-\d{4}-\d{4,7}</code> regex.</li>
        <li>SHA256 / SHA1 / MD5 — fixed-width hex regexes.</li>
        <li>IPs / domains — <strong>defanged-only</strong>: <code>1[.]2[.]3[.]4</code>, <code>evil[.]com</code>, <code>hxxps://...</code>. Plain-text mentions are rejected because they're almost always the victim or platform, not the attacker.</li>
      </ul>
      <p><strong>Article mechanics</strong> (<code>extract_mechanics</code>):</p>
      <ul>
        <li>Binaries: regex on <code>*.exe / .dll / .sys / .ps1 / .vbs / ...</code> filtered through a noise list (chrome.exe, cmd.exe, etc.).</li>
        <li>Windows paths: <code>C:\</code> / <code>%APPDATA%</code> / <code>\Users\</code> / <code>\System32\</code> patterns, generic top-level paths filtered out.</li>
        <li>Unix paths: <code>/tmp</code>, <code>/var</code>, <code>/Library</code>, <code>/etc</code> patterns.</li>
        <li>Registry keys: <code>HK[LCU][MR]?\...</code> patterns.</li>
        <li>Persistence keywords ("scheduled task", "launchagent", "run key", etc.) → linked to MITRE technique IDs.</li>
        <li>Command-line fragments — <code>-EncodedCommand</code>, <code>FromBase64String</code>, <code>vssadmin delete shadows</code>, etc.</li>
      </ul>
    </div>

    <h3 class="wf-section-title">4. Use cases</h3>
    <div class="wf-step">
      <p>Three classes of use case fire per article:</p>
      <p><strong>(a) Rule-fired generic UCs</strong> — <code>rules/*.yml</code> contain trigger keyword lists. If the article body matches any trigger, the rule's pre-built use case (in <code>use_cases/*.yml</code>) is added to the briefing. Example: any article mentioning "psexec" fires <code>UC_LATERAL_PSEXEC</code>.</p>
      <p><strong>(b) Bespoke article-specific UCs</strong> — <em>new this session</em>. <code>extract_mechanics</code> output drives <code>_make_bespoke_uc</code>, which assembles a per-article SPL+KQL searching for the <strong>actual binaries / paths / commandline fragments</strong> named in the article. Threshold: at least one mechanic anchor must be present, otherwise no bespoke UC is emitted (silence beats noise).</p>
      <p><strong>(c) IOC-substitution UCs</strong> — when the article has a CVE / IP / domain / hash, the matching boilerplate UC fires with the actual IOC list substituted in. Canonical SPL/KQL bodies live once in <a href="briefings/_TEMPLATES.md">briefings/_TEMPLATES.md</a>; the briefing inlines only the IOC values.</p>
    </div>

    <h3 class="wf-section-title">5. Outputs</h3>
    <div class="wf-step">
      <ul>
        <li><strong>Articles tab</strong> — per-article cards (this <code>index.html</code>) + per-article markdown briefings under <code>briefings/&lt;date&gt;/</code>.</li>
        <li><strong>ATT&amp;CK Matrix tab</strong> — 14 tactics × 691 techniques. Coverage drawn from 23 internal UCs + <strong>2,213 synced Splunk ESCU detections</strong>. Click any technique cell, then any UC card to expand it inline with full SPL/KQL — backed by <code>catalog/use_cases_full.js</code>.</li>
        <li><strong>Threat Intel tab</strong> — IOC feed exports: CSV, JSON, STIX 2.1, RSS, Splunk lookup. Aggregated across every article in the window with source attribution.</li>
      </ul>
      <p>All outputs commit to <a href="https://github.com/Virtualhaggis/usecaseintel">github.com/Virtualhaggis/usecaseintel</a>; <code>run_daily.bat</code> runs validate → generate → digest → auto-commit on a schedule.</p>
    </div>

    <h3 class="wf-section-title">LLM-driven UC generation (opt-in)</h3>
    <div class="wf-step">
      <p>When <code>ANTHROPIC_API_KEY</code> is set in the environment, the pipeline sends each article body to an LLM with a structured detection-engineer prompt, parses the response as JSON, validates the techniques (<code>T####.###</code> format) + tier (alerting/hunting) + KQL/SPL fields, and emits the resulting UseCase objects alongside the regex bespoke UCs.</p>
      <p>The LLM is told: use the actual binaries/paths/cmdlines named in the article, not invented ones; if the article describes the attack only narratively, return no UCs. Output is cached per article URL hash so repeat runs cost nothing.</p>
      <p>Cost: ~$0.005-0.01 per article on <code>claude-haiku-4-5</code> (configurable via <code>USECASEINTEL_LLM_MODEL</code>). 300-article 180-day run ≈ $2-3.</p>
      <p>Each LLM-emitted UC is title-prefixed <code>[LLM]</code> and shows up in the matrix drawer alongside the rule-fired and regex-bespoke variants. Failures (no API key, parse error, network timeout) are logged but never fail the pipeline.</p>
    </div>

    <h3 class="wf-section-title">IOC enrichment (opt-in)</h3>
    <div class="wf-step">
      <p>When <code>ABUSECH_API_KEY</code> is set, every IOC in <code>intel/iocs.csv</code> is cross-referenced against:</p>
      <ul>
        <li><strong>ThreatFox (abuse.ch)</strong> — malware family attribution + first-seen + reporter for IPs / domains / hashes / CVEs / URLs.</li>
        <li><strong>URLhaus (abuse.ch)</strong> — URL counts + blacklist memberships for hosts.</li>
      </ul>
      <p>Free auth keys at <a href="https://auth.abuse.ch/" target="_blank" rel="noopener">auth.abuse.ch</a> — abuse.ch added auth in 2024-2025 to control abuse. New CSV columns: <code>threatfox_malware</code>, <code>threatfox_threat_type</code>, <code>urlhaus_url_count</code>, <code>urlhaus_blacklists</code>, <code>enrichment_url</code>. Cache lives in <code>intel/.enrich_cache/</code>; if no key is set the columns stay blank and the pipeline runs unchanged.</p>
      <p>Practical impact when enabled: an IOC the SOC sees in our feed is flanked by "is this on abuse.ch's known-bad list and what malware family is it linked to?" — turning a list of values into intel with attribution.</p>
    </div>

    <h3 class="wf-section-title">Per-platform rule packs</h3>
    <div class="wf-step">
      <p>Every internal UC is now exported to multiple SIEM-native formats under <code>rule_packs/</code>:</p>
      <ul>
        <li><code>splunk/savedsearches.conf</code> — drop-in Splunk app config. Each saved search is <code>enableSched = 0</code> by default — review-then-enable.</li>
        <li><code>sentinel/&lt;uc&gt;.json</code> — Microsoft Sentinel ARM analytics rule template.</li>
        <li><code>elastic/&lt;uc&gt;.json</code> — Elastic detection rule (KQL embedded in note for analyst port-over to ECS/EQL).</li>
        <li><code>sigma/&lt;uc&gt;.yml</code> — Sigma format. Convert with <code>sigma-cli</code> to your SIEM dialect.</li>
      </ul>
      <p>All exports tier-aware: alerting runs hourly, hunting runs daily; severity high vs low; tier + fp_rate + MITRE attached to custom-details.</p>
    </div>

    <h3 class="wf-section-title">Quality gates — tier &amp; IOC allowlist</h3>
    <div class="wf-step">
      <p>Two filters keep the output honest:</p>
      <p><strong>UC tier — alerting vs hunting.</strong> Every use case is tagged:</p>
      <ul>
        <li><strong style="color:var(--good);">ALERTING</strong> — high-fidelity. Specific IOCs, threshold or temporal correlation (<code>between (T .. T+60s)</code>), named-binary hunt, anomaly logic. Safe to wire to a SIEM rule with normal triage SLA.</li>
        <li><strong style="color:var(--warn);">HUNTING</strong> — starter content. Returns rows that need analyst review; will produce false positives without environment tuning. Use as a hunt query first; promote to alerting after baselining + adding suppression for legitimate use.</li>
      </ul>
      <p>How it's set: explicit <code>tier:</code> field in the UC YAML wins. Otherwise <code>_infer_tier_from_query()</code> looks for alerting signals (temporal joins, thresholds, named-binary <code>IN</code>-lists, anomaly stats) and defaults to hunting if none are present. Splunk ESCU detections inherit tier from the upstream <code>type</code> — TTP/Correlation → alerting, Anomaly/Hunting → hunting. Bespoke article-generated UCs default to hunting.</p>
      <p>Filter the drawer by tier (Alerting / Hunting) using the dropdown in the Use cases mapped section.</p>

      <p style="margin-top:14px;"><strong>IOC allowlist — drop platform / reserved infrastructure.</strong> No SOC wants <code>google.com</code> or <code>192.168.0.1</code> in their block list. <code>_ioc_is_known_safe()</code> drops:</p>
      <ul>
        <li>Mainstream platform domains (Google, Microsoft, Apple, Amazon, Cloudflare, GitHub, npm, PyPI, Docker Hub, Wikipedia, Stack Overflow, social platforms).</li>
        <li>Security-vendor self-references (THN, BleepingComputer, Talos, Securelist, etc.).</li>
        <li>Common dead-drop dispensers (pastebin, ghostbin) — which CAN be abused but should be hunted manually rather than block-listed.</li>
        <li>Reserved IPv4 ranges: RFC1918 (<code>10/8</code>, <code>172.16/12</code>, <code>192.168/16</code>), loopback (<code>127/8</code>), link-local (<code>169.254/16</code>), TEST-NETs, multicast.</li>
        <li>Public DNS providers (<code>8.8.8.8</code>, <code>1.1.1.1</code>, etc.).</li>
      </ul>
      <p>Internal IPs aren't useless — they're just useless <em>standalone</em>. A bespoke UC describing lateral movement <em>can</em> reference them as part of a broader chain, but they don't belong in the IOC feed where the value is "block this on the perimeter".</p>
    </div>

    <h3 class="wf-section-title">Analyst loop</h3>
    <div class="wf-step">
      <p>Curated briefings get a <code>&lt;!-- curated:true --&gt;</code> HTML comment as line 1. The briefing writer skips any file with that marker so analyst overlays are preserved across pipeline runs. The pattern:</p>
      <ol>
        <li>Pipeline emits an auto-generated briefing.</li>
        <li>Analyst reads the article, rewrites the briefing with attribution / actor context / sector implications / bespoke detection logic, adds <code>&lt;!-- curated:true --&gt;</code>.</li>
        <li>Commits. Future pipeline runs see the marker and leave the file alone.</li>
      </ol>
      <p>For new use cases the analyst writes a YAML file under <code>use_cases/&lt;phase&gt;/UC_X.yml</code>; the loader at module-load time auto-registers it and the matrix builder picks it up on the next run.</p>
    </div>

    <h3 class="wf-section-title">Commands cheat-sheet</h3>
    <div class="wf-step">
      <pre style="background:var(--panel-elev);border:1px solid var(--border);border-radius:6px;padding:14px;font-size:12px;overflow:auto;">
# Daily run (Windows)
run_daily.bat                                   # validate → generate → digest → auto-commit

# Manual one-shot
python validate.py                              # YAML schema + SPL/KQL field checks
python generate.py                              # rebuild index.html + intel/ + briefings/
python digest.py                                # daily_digest.md summary

# Disable body fetch (offline / debug)
THN_FETCH_FULL_BODY=0 python generate.py        # IOC feed loses hash/IP/domain coverage
THN_FETCH_DELAY=0.1 python generate.py          # speed up (less polite to sources)
      </pre>
    </div>
  </div>
</div>

<div id="view-about" class="view">
  <div class="workflow-wrap" style="max-width:1180px;">
    <h2 class="wf-title" style="font-size:28px;">About Clankerusecase</h2>
    <p class="wf-lede" style="font-size:15px;max-width:760px;">
      Detection content for SOC analysts, generated from threat-intel articles
      the day they break. Free, open-source, and community-shaped.
    </p>

    <div class="wf-card" style="margin-bottom:14px;">
      <h3 style="margin-top:0;">What this is</h3>
      <p>
        Clankerusecase reads recent threat-intel articles (The Hacker News,
        BleepingComputer, Microsoft Security Blog, Cisco Talos, Securelist,
        SentinelLabs, Unit 42, ESET, Lab52, Cyber Security News, CISA KEV) and produces detection use
        cases an analyst can drop into their SIEM. Every use case is mapped
        to MITRE ATT&amp;CK, tagged with a tier (alerting vs hunting) and
        a false-positive estimate, and — for the article-bespoke ones —
        written by an LLM that's actually <em>read</em> the article rather
        than spat out a generic technique template.
      </p>
    </div>

    <div class="wf-card" style="margin-bottom:14px;">
      <h3 style="margin-top:0;">The goal</h3>
      <ul style="line-height:1.6;">
        <li><strong>Hand analysts ready-to-run detection content</strong> the
            day a campaign breaks — not three weeks later when the vendor
            blog post has been turned into a "rule pack" behind a paywall.</li>
        <li><strong>Cover the platforms analysts actually use.</strong>
            Pick a vendor, get the same detection rendered for it.</li>
        <li><strong>Be community-driven.</strong> The platforms covered, the
            tier thresholds, the FP estimates, the per-source filters — all
            decided by people doing detection engineering and threat hunting
            day-to-day, not by a marketing team.</li>
      </ul>
    </div>

    <div class="wf-card" style="margin-bottom:14px;">
      <h3 style="margin-top:0;">Platform coverage today</h3>
      <table class="wf-table">
        <thead><tr><th>Platform</th><th>Status</th><th>Notes</th></tr></thead>
        <tbody>
          <tr>
            <td><strong>Microsoft Defender</strong> (Advanced Hunting / KQL)</td>
            <td><span class="pill tier-alerting" style="background:rgba(34,197,94,.15);color:#86efac;border:1px solid rgba(34,197,94,.4);padding:2px 8px;border-radius:4px;font-size:11px;">Working well</span></td>
            <td>Every use case has a hand-checked KQL query against the
                <code>DeviceProcessEvents</code> / <code>EmailEvents</code> /
                <code>UrlClickEvents</code> / <code>AADSignInEventsBeta</code>
                tables. Pre-deployed table validation against the Defender
                schema. This is the most mature path on the site today.</td>
          </tr>
          <tr>
            <td><strong>Splunk</strong> (CIM / ESCU)</td>
            <td><span class="pill" style="background:rgba(234,179,8,.15);color:#fde047;border:1px solid rgba(234,179,8,.4);padding:2px 8px;border-radius:4px;font-size:11px;">In progress</span></td>
            <td>SPL queries emitted against <code>Endpoint</code>,
                <code>Network_Traffic</code>, <code>Email</code>,
                <code>Vulnerabilities</code>, <code>Web</code> data models;
                CIM-validated. 2,200+ Splunk ESCU detections synced into the
                ATT&amp;CK matrix. Field-level tuning for production deployment
                is the next focus area.</td>
          </tr>
          <tr>
            <td><strong>Sentinel ARM / Elastic / Sigma</strong></td>
            <td><span class="pill" style="background:rgba(148,163,184,.15);color:#cbd5e1;border:1px solid rgba(148,163,184,.4);padding:2px 8px;border-radius:4px;font-size:11px;">Rule-pack export</span></td>
            <td>Rule packs are emitted to <code>rule_packs/</code> on every
                build (all <code>enabled=false</code> by default — read,
                review, then enable). Validation against each platform's
                native schema is on the roadmap.</td>
          </tr>
          <tr>
            <td><strong>Anything else?</strong></td>
            <td><span class="pill" style="background:rgba(125,211,252,.15);color:#7dd3fc;border:1px solid rgba(125,211,252,.4);padding:2px 8px;border-radius:4px;font-size:11px;">Tell us</span></td>
            <td>CrowdStrike NG-SIEM? Chronicle / Google SecOps? Sumo? OpenSearch?
                Drop a request in Discord (link below) and if there's interest
                from the community we'll wire it in.</td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="wf-card" style="margin-bottom:14px;">
      <h3 style="margin-top:0;">Community &amp; Discord</h3>
      <p>
        We're spinning up a Discord for analysts and detection engineers
        using the site. The space is for:
      </p>
      <ul style="line-height:1.6;">
        <li>Suggesting new platforms to add (KQL → SPL is done; what's next?).</li>
        <li>Sharing tuning notes for the FP rate on specific use cases in
            your environment.</li>
        <li>Flagging articles you'd like covered (the feed-fetcher is fast
            but not exhaustive — analyst-curated tips help).</li>
        <li>Posting your own detection ideas — if they fit the site's
            criteria they'll get added with attribution.</li>
      </ul>
      <div id="discord-cta" style="margin-top:14px;padding:14px 16px;background:rgba(88,101,242,.08);border:1px solid rgba(88,101,242,.3);border-radius:8px;display:flex;align-items:center;gap:14px;flex-wrap:wrap;">
        <div style="font-size:24px;">💬</div>
        <div style="flex:1;min-width:200px;">
          <div style="font-weight:600;color:var(--text);margin-bottom:2px;">Join the Clankerusecase Discord</div>
          <div style="color:var(--muted);font-size:13px;">Detection engineers, threat hunters, SOC analysts — all welcome.</div>
        </div>
        <a id="discord-link" href="https://discord.gg/6KSXVrC3Kr" target="_blank" rel="noopener"
           style="padding:8px 16px;background:#5865f2;color:#fff;text-decoration:none;border-radius:6px;font-weight:600;font-size:13px;">
          Open Discord →
        </a>
      </div>
      <p style="font-size:12px;color:var(--muted-2);margin-top:8px;">
        <em>Permanent invite:</em>
        <a href="https://discord.gg/6KSXVrC3Kr" target="_blank" rel="noopener"
           style="color:var(--accent);font-family:var(--mono);">https://discord.gg/6KSXVrC3Kr</a>
        — never expires, no member cap. Channels: <code>#welcome</code>,
        <code>#use-case-requests</code>, <code>#platform-requests</code>,
        <code>#detection-engineering</code>, <code>#threat-hunting</code>,
        <code>#site-feedback</code>. Verified-email + AutoMod spam protection
        on by default.
      </p>
    </div>

    <div class="wf-card" style="margin-bottom:14px;">
      <h3 style="margin-top:0;">How a use case lands here</h3>
      <ol style="line-height:1.7;">
        <li>Article published by a covered intel source.</li>
        <li>Pipeline fetches the full body (not just the RSS preview), pulls
            IOCs (defanged-aware, with allowlists for legitimate platforms),
            and infers MITRE techniques from narrative keywords.</li>
        <li>Rule-fired generic UCs from <code>use_cases/*.yml</code> attach
            based on trigger keywords.</li>
        <li>An LLM (your Claude Code OAuth session, or an
            <code>ANTHROPIC_API_KEY</code>) reads the article body and
            generates 1–3 <em>article-specific</em> bespoke UCs with their
            own SPL/KQL — these get the <code>[LLM]</code> prefix and sort
            to the top of every list because they're the highest-fidelity
            detection content on the page.</li>
        <li>WebSearch corroboration: the LLM cross-checks vendor advisories
            (Microsoft Threat Intel, Mandiant, CrowdStrike, MITRE, abuse.ch)
            and links them in the briefing as <em>"Cross-checked against:"</em>.</li>
        <li>Validation pass: every SPL field is checked against the CIM spec
            and ESCU production references; every KQL table/column against
            the Defender schema. Fail validation → don't ship.</li>
      </ol>
      <p style="font-size:12.5px;color:var(--muted);margin-top:8px;">
        See the <strong>Workflow</strong> tab for the full diagram and
        per-stage prompt detail.
      </p>
    </div>

    <div class="wf-card" style="margin-bottom:14px;">
      <h3 style="margin-top:0;">Repo &amp; licence</h3>
      <p>
        Source:
        <a href="https://github.com/Virtualhaggis/usecaseintel" target="_blank" style="color:var(--accent);">github.com/Virtualhaggis/usecaseintel</a>.
        MIT-licensed. Contributions welcome — open an issue or PR. The site
        is rebuilt by <code>generate.py</code> on every run; the catalog
        lives in <code>catalog/use_cases_full.json</code> for non-browser
        consumers (TIPs, scripts, your SIEM's API).
      </p>
    </div>
  </div>
</div>

<footer>
  Splunk SPL conforms to the <a href="https://help.splunk.com/en/data-management/common-information-model/8.5/introduction/overview-of-the-splunk-common-information-model" style="color:var(--accent);" target="_blank">Splunk Common Information Model (CIM)</a> — uses
  <code>tstats</code> against accelerated data models with the canonical <code>Processes.dest</code>,
  <code>All_Email.recipient</code>, <code>All_Traffic.dest</code> field paths.
  Macros: <code>`summariesonly`</code> · <code>`drop_dm_object_name()`</code> · <code>`security_content_ctime()`</code> ship with Splunk ESCU.
  <br>Defender KQL targets <a href="https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables" style="color:var(--accent);" target="_blank">Advanced Hunting schema</a>.
  Kill chain follows the Lockheed Martin 7-phase model.
</footer>

<!-- Per-UC detail sidecar. Sets window.__UC_DETAILS__ = { ucId: {...} }
     so clicking a UC card in the matrix drawer can render full SPL/KQL.
     Loaded async; the drawer code handles the case where it hasn't arrived. -->
<script src="catalog/use_cases_full.js" async></script>

<script>
// ----- Tab switching --------------------------------------------------
document.addEventListener('click', e => {
  const btn = e.target.closest('.tab-btn');
  if (!btn) return;
  const parent = btn.closest('.uc-body, .killchain, article.card');
  if (!parent) return;
  parent.querySelectorAll(':scope > .tabs > .tab-btn, :scope .tabs > .tab-btn').forEach(b => {
    if (b.closest('.uc-body, .killchain, article.card') === parent) b.classList.remove('active');
  });
  parent.querySelectorAll(':scope > .tab-content').forEach(c => c.classList.remove('active'));
  btn.classList.add('active');
  const tgt = parent.querySelector('#' + btn.dataset.target);
  if (tgt) tgt.classList.add('active');
});

// ----- Toggle kill chain ----------------------------------------------
document.querySelectorAll('.btn[data-target]').forEach(btn => {
  btn.addEventListener('click', () => {
    const target = document.getElementById(btn.dataset.target);
    if (!target) return;
    target.classList.toggle('active');
    btn.classList.toggle('primary');
    const lbl = btn.querySelector('.kc-label');
    if (lbl) lbl.textContent = target.classList.contains('active') ? 'Hide kill chain' : 'Show kill chain';
  });
});

// ----- Copy code block ------------------------------------------------
document.addEventListener('click', e => {
  const btn = e.target.closest('.copy-btn');
  if (!btn) return;
  e.stopPropagation();
  const code = btn.parentElement.querySelector('code').innerText;
  navigator.clipboard.writeText(code).then(() => {
    const orig = btn.textContent;
    btn.textContent = 'Copied';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = orig; btn.classList.remove('copied'); }, 1300);
  });
});

// ----- Active nav highlighting on scroll ------------------------------
const navItems = document.querySelectorAll('#navlist .nav-item');
const cards = document.querySelectorAll('article.card');
// During programmatic scroll (nav click) the IntersectionObserver fires for
// every article the viewport passes through, which lands the "active" state
// on the next short card. Suspend the observer briefly during click-driven
// scrolls so the explicit click always wins.
let scrollLockUntil = 0;
const observer = new IntersectionObserver(entries => {
  if (Date.now() < scrollLockUntil) return;
  entries.forEach(en => {
    if (en.isIntersecting) {
      navItems.forEach(n => n.classList.remove('active'));
      const el = document.querySelector(`#navlist .nav-item[data-jump="${en.target.id}"]`);
      if (el) el.classList.add('active');
    }
  });
}, { rootMargin: '-30% 0px -55% 0px' });
cards.forEach(c => observer.observe(c));

// ----- Nav click jumps -----------------------------------------------
navItems.forEach(item => {
  item.addEventListener('click', () => {
    const id = item.dataset.jump;
    const target = document.getElementById(id);
    if (!target) return;
    // Set the active state immediately and lock the observer for ~700ms
    // so the smooth-scroll animation can't re-flip it to the next card.
    navItems.forEach(n => n.classList.remove('active'));
    item.classList.add('active');
    scrollLockUntil = Date.now() + 700;
    target.scrollIntoView({behavior:'smooth', block:'start'});
  });
});

// ----- Filter chips: phase, severity ----------------------------------
const activeFilters = { phase: null, sev: null, tech: null };
function applyFilters() {
  cards.forEach(c => {
    const phases = (c.dataset.phases || '').split(',');
    const sev = c.dataset.sev || '';
    const techs = (c.dataset.techs || '').split(',');
    let show = true;
    if (activeFilters.phase && !phases.includes(activeFilters.phase)) show = false;
    if (activeFilters.sev && sev !== activeFilters.sev) show = false;
    if (activeFilters.tech && !techs.includes(activeFilters.tech)) show = false;
    c.classList.toggle('hidden', !show);
    const navEl = document.querySelector(`#navlist .nav-item[data-jump="${c.id}"]`);
    if (navEl) navEl.style.display = show ? '' : 'none';
  });
}
document.querySelectorAll('.fchip').forEach(chip => {
  chip.addEventListener('click', () => {
    const k = chip.dataset.key;
    const v = chip.dataset.val;
    if (activeFilters[k] === v) {
      activeFilters[k] = null;
      chip.classList.remove('on');
    } else {
      document.querySelectorAll(`.fchip[data-key="${k}"]`).forEach(c => c.classList.remove('on'));
      activeFilters[k] = v;
      chip.classList.add('on');
    }
    applyFilters();
  });
});

// ----- Click ATT&CK technique pill to filter -------------------------
document.addEventListener('click', e => {
  const t = e.target.closest('.ind.tech');
  if (!t) return;
  const tid = t.textContent.trim();
  if (activeFilters.tech === tid) {
    activeFilters.tech = null;
  } else {
    activeFilters.tech = tid;
  }
  applyFilters();
  // Highlight active filter visually:
  document.querySelectorAll('.ind.tech').forEach(el => {
    el.style.outline = (activeFilters.tech && el.textContent.trim() === activeFilters.tech) ? '2px solid var(--accent-3)' : 'none';
  });
});

// ----- Search overlay -------------------------------------------------
const overlay = document.getElementById('searchOverlay');
const input = document.getElementById('searchInput');
const results = document.getElementById('searchResults');
const trigger = document.getElementById('searchTrigger');
let resultEls = [];
let selIndex = 0;

function openSearch() {
  overlay.classList.add('open');
  input.value = '';
  renderResults('');
  setTimeout(() => input.focus(), 30);
}
function closeSearch() { overlay.classList.remove('open'); }
trigger.addEventListener('click', openSearch);
document.addEventListener('keydown', e => {
  if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
    e.preventDefault(); openSearch();
  } else if (e.key === 'Escape' && overlay.classList.contains('open')) {
    closeSearch();
  } else if (overlay.classList.contains('open')) {
    if (e.key === 'ArrowDown') { e.preventDefault(); selIndex = Math.min(selIndex+1, resultEls.length-1); renderSel(); }
    if (e.key === 'ArrowUp')   { e.preventDefault(); selIndex = Math.max(selIndex-1, 0); renderSel(); }
    if (e.key === 'Enter' && resultEls[selIndex]) { resultEls[selIndex].click(); }
  }
});
overlay.addEventListener('click', e => { if (e.target === overlay) closeSearch(); });

function renderResults(q) {
  q = q.toLowerCase().trim();
  results.innerHTML = '';
  resultEls = [];
  selIndex = 0;
  let count = 0;
  cards.forEach(c => {
    const blob = (c.dataset.search || '').toLowerCase();
    if (q && !blob.includes(q)) return;
    const id = c.id;
    const title = c.querySelector('h2 a')?.innerText || id;
    const num = parseInt(id.replace('art-','')) + 1;
    const techs = c.dataset.techs || '';
    const sev = c.dataset.sev || '';
    const div = document.createElement('div');
    div.className = 'search-result' + (count === 0 ? ' sel' : '');
    div.innerHTML = `<div class="sr-num">${String(num).padStart(2,'0')}</div>
      <div><div class="sr-title">${title}</div><div class="sr-meta">${sev.toUpperCase()} · ${techs.split(',').slice(0,3).join(', ')}</div></div>`;
    div.addEventListener('click', () => {
      closeSearch();
      document.getElementById(id).scrollIntoView({behavior:'smooth', block:'start'});
    });
    results.appendChild(div);
    resultEls.push(div);
    count++;
  });
  if (count === 0) {
    const e = document.createElement('div');
    e.className = 'search-empty';
    e.textContent = q ? `No matches for "${q}"` : 'Type to search…';
    results.appendChild(e);
  }
}
function renderSel() {
  resultEls.forEach((el,i) => el.classList.toggle('sel', i === selIndex));
  resultEls[selIndex]?.scrollIntoView({block:'nearest'});
}
input.addEventListener('input', () => renderResults(input.value));

// =================================================================
// Source filter (Articles tab) — multi-select
// =================================================================
// Click a source chip to toggle its filter on/off. Multiple chips can be
// active at once; a card is shown if it matches ANY active source.
// "All" deselects every other chip and shows everything.
function applySourceFilter() {
  const activeChips = document.querySelectorAll('#srcFilter .src-chip.active:not(.all)');
  const activeSources = Array.from(activeChips).map(c => c.dataset.source).filter(Boolean);
  const cards = document.querySelectorAll('#view-articles article.card');
  cards.forEach(card => {
    const sources = (card.dataset.sources || '').split('|');
    const show = activeSources.length === 0
                 || activeSources.some(s => sources.includes(s));
    card.classList.toggle('src-hidden', !show);
  });
  document.querySelectorAll('#navlist .nav-item').forEach(n => {
    const card = document.getElementById(n.dataset.jump);
    n.style.display = card && card.classList.contains('src-hidden') ? 'none' : '';
  });
  // Keep the "All" chip's active state in sync (active iff no other source picked)
  const allChip = document.querySelector('#srcFilter .src-chip.all');
  if (allChip) allChip.classList.toggle('active', activeSources.length === 0);
}
document.querySelectorAll('#srcFilter .src-chip').forEach(chip => {
  chip.addEventListener('click', () => {
    if (chip.classList.contains('all')) {
      // "All" clears every other chip
      document.querySelectorAll('#srcFilter .src-chip').forEach(c => c.classList.remove('active'));
      chip.classList.add('active');
    } else {
      chip.classList.toggle('active');
      // any non-All click means "All" is no longer the implicit selection
      document.querySelector('#srcFilter .src-chip.all')?.classList.remove('active');
    }
    applySourceFilter();
  });
});

// =================================================================
// Width toggle (Articles tab)
// =================================================================
(function(){
  const STORAGE_KEY = 'usecaseintel:width';
  const main = document.querySelector('#view-articles main');
  const toggle = document.getElementById('widthToggle');
  if (!main || !toggle) return;
  function setWidth(mode) {
    main.classList.remove('width-compact','width-wide','width-full');
    main.classList.add('width-' + mode);
    toggle.querySelectorAll('button').forEach(b => {
      b.classList.toggle('on', b.dataset.width === mode);
    });
    try { localStorage.setItem(STORAGE_KEY, mode); } catch(e) {}
  }
  // Restore saved preference (default = 'wide', applied via class on <main>)
  let saved = null;
  try { saved = localStorage.getItem(STORAGE_KEY); } catch(e) {}
  if (saved && ['compact','wide','full'].includes(saved)) setWidth(saved);
  toggle.querySelectorAll('button').forEach(btn => {
    btn.addEventListener('click', () => setWidth(btn.dataset.width));
  });
})();

// =================================================================
// Platform-aware shortcut hint (Cmd on Mac, Ctrl elsewhere)
// =================================================================
(function () {
  const isMac = /Mac|iPhone|iPad|iPod/.test(navigator.platform || navigator.userAgent || '');
  const el = document.getElementById('searchShortcutKey');
  if (el) el.textContent = isMac ? '\u2318' : 'Ctrl';   // ⌘ on Mac
})();

// =================================================================
// View tab switching (Articles / ATT&CK Matrix)
// =================================================================
const viewTabs = document.querySelectorAll('.view-tab');
const views = document.querySelectorAll('.view');
function showView(name) {
  viewTabs.forEach(b => b.classList.toggle('active', b.dataset.view === name));
  views.forEach(v => v.classList.toggle('active', v.id === 'view-' + name));
  // Each tab has its own top-bar stats area. Body class drives the
  // CSS visibility transition; only the active tab's stats are shown.
  document.body.classList.toggle('view-articles-active', name === 'articles');
  document.body.classList.toggle('view-matrix-active',   name === 'matrix');
  document.body.classList.toggle('view-intel-active',    name === 'intel');
  if (name === 'matrix' && !window._matrixRendered) {
    renderMatrix();
    window._matrixRendered = true;
  }
  if (name === 'intel' && !window._intelRendered) {
    renderIntel();
    window._intelRendered = true;
  }
}
// Apply default state on page load — Articles tab starts active.
document.body.classList.add('view-articles-active');
viewTabs.forEach(b => b.addEventListener('click', () => showView(b.dataset.view)));

// =================================================================
// Logo lightbox — click the topbar Clanker to see him full size.
// Backdrop click, ESC, or close-button all dismiss. Re-renders cleanly
// every open (no stale animation state).
// =================================================================
(() => {
  const btn = document.getElementById('logoButton');
  const lb = document.getElementById('logoLightbox');
  const close = document.getElementById('logoLightboxClose');
  if (!btn || !lb) return;
  function open() {
    lb.removeAttribute('hidden');
    lb.classList.add('open');
  }
  function dismiss() {
    lb.classList.remove('open');
    setTimeout(() => lb.setAttribute('hidden', ''), 220);
  }
  btn.addEventListener('click', e => { e.preventDefault(); open(); });
  close.addEventListener('click', dismiss);
  lb.addEventListener('click', e => {
    // Click on the backdrop (not the image itself) closes the lightbox.
    if (e.target === lb) dismiss();
  });
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && lb.classList.contains('open')) dismiss();
  });
})();

// =================================================================
// ATT&CK Matrix
// =================================================================
const MATRIX = __MATRIX_DATA__;
let matrixMode = 'coverage';

function covClassFor(n) {
  if (!n) return '';
  if (n >= 4) return 'cov-4';
  if (n >= 3) return 'cov-3';
  if (n >= 2) return 'cov-2';
  return 'cov-1';
}
function heatClassFor(n) {
  if (!n) return '';
  if (n >= 3) return 'heat-3';
  if (n >= 2) return 'heat-2';
  return 'heat-1';
}

function tidCellHtml(tid, isSub) {
  const tinfo = MATRIX.techniques[tid];
  if (!tinfo) return '';
  const ucs = MATRIX.tech_ucs[tid] || [];
  const arts = MATRIX.tech_arts[tid] || [];
  const subCount = (tinfo.subs || []).length;
  let cls = 'tech-cell';
  if (isSub) cls += ' is-sub';
  if (matrixMode === 'coverage') cls += ' ' + covClassFor(ucs.length);
  else if (matrixMode === 'heat') cls += ' ' + heatClassFor(arts.length);
  return `<div class="${cls}" data-tid="${tid}" tabindex="0">
    <div class="tech-name" title="${tid}: ${escapeHtml(tinfo.name)}">${escapeHtml(tinfo.name)}</div>
    <div class="tech-meta">
      <span style="color:var(--muted)">${tid}</span>
      ${subCount ? `<span class="sub-marker">▾${subCount}</span>` : ''}
      ${ucs.length ? `<span class="uc-count">${ucs.length} UC</span>` : ''}
      ${arts.length ? `<span style="color:var(--warn)">${arts.length} art</span>` : ''}
    </div>
  </div>`;
}
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"})[c]);
}

function renderMatrix() {
  if (!MATRIX) {
    document.getElementById('matrixGrid').innerHTML =
      '<div style="padding:40px;color:var(--muted);">Matrix data not available — run sync.py to fetch ATT&CK.</div>';
    return;
  }
  const grid = document.getElementById('matrixGrid');
  const cols = MATRIX.tactics.map(tac => {
    const cellsHtml = tac.tids.map(tid => tidCellHtml(tid, false)).join('');
    return `<div class="tactic-col" data-tactic="${tac.short}">
      <div class="tactic-header">
        <span class="tactic-name">${escapeHtml(tac.name)}</span>
        <span class="tactic-count">${tac.tids.length} techniques</span>
      </div>
      <div class="tactic-techs" data-techs>${cellsHtml}</div>
    </div>`;
  }).join('');
  grid.innerHTML = cols;

  // Mirror the matrix counts into the top-bar slot so the stats float
  // up next to the brand the same way the Articles bar does. Same DOM
  // shape as #topStats so the .stat / .v / .l styling kicks in.
  const topMatrix = document.getElementById('topStatsMatrix');
  if (topMatrix) {
    topMatrix.innerHTML =
      `<div class="stat"><div class="v">${MATRIX.stats.total_techs.toLocaleString()}</div><div class="l">Techniques</div></div>` +
      `<div class="stat"><div class="v">${MATRIX.stats.total_subs.toLocaleString()}</div><div class="l">Sub-Techniques</div></div>` +
      `<div class="stat"><div class="v">${MATRIX.stats.covered_techs.toLocaleString()}</div><div class="l">Covered</div></div>` +
      `<div class="stat"><div class="v">${MATRIX.stats.ucs.toLocaleString()}</div><div class="l">Use Cases</div></div>`;
  }
  // Hide the in-tab matrix-stats element since the same numbers now
  // live in the top-bar; redundant on screen.
  const inTabStats = document.getElementById('matrixStats');
  if (inTabStats) inTabStats.style.display = 'none';
}

// Mode toggle
document.getElementById('matrixModes').addEventListener('click', e => {
  const btn = e.target.closest('button');
  if (!btn) return;
  matrixMode = btn.dataset.mode;
  document.querySelectorAll('#matrixModes button').forEach(b => b.classList.toggle('on', b === btn));
  document.querySelectorAll('#matrixGrid .tech-cell').forEach(cell => {
    const tid = cell.dataset.tid;
    const tinfo = MATRIX.techniques[tid];
    cell.classList.remove('cov-1','cov-2','cov-3','cov-4','heat-1','heat-2','heat-3');
    const ucs = MATRIX.tech_ucs[tid] || [];
    const arts = MATRIX.tech_arts[tid] || [];
    if (matrixMode === 'coverage' && ucs.length) cell.classList.add(covClassFor(ucs.length));
    else if (matrixMode === 'heat' && arts.length) cell.classList.add(heatClassFor(arts.length));
  });
});

// Search filter
document.getElementById('matrixSearch')?.addEventListener('input', e => {
  const q = e.target.value.trim().toLowerCase();
  document.querySelectorAll('#matrixGrid .tech-cell').forEach(cell => {
    if (!q) { cell.classList.remove('dim'); return; }
    const tid = cell.dataset.tid;
    const tinfo = MATRIX.techniques[tid];
    const match = tid.toLowerCase().includes(q) || tinfo.name.toLowerCase().includes(q);
    cell.classList.toggle('dim', !match);
  });
});

// Cell click → drawer
document.addEventListener('click', e => {
  const cell = e.target.closest('.tech-cell');
  if (!cell) return;
  openDrawerFor(cell.dataset.tid);
});

function openDrawerFor(tid) {
  if (!MATRIX || !MATRIX.techniques[tid]) return;
  // Switch to matrix view if we're not already there
  if (!document.getElementById('view-matrix').classList.contains('active')) {
    showView('matrix');
  }
  const tinfo = MATRIX.techniques[tid];
  const ucs = (MATRIX.tech_ucs[tid] || []).map(i => MATRIX.ucs[i]);
  const arts = (MATRIX.tech_arts[tid] || []).map(i => MATRIX.arts[i]);
  const tactics = (tinfo.tactics || []).map(t => `<span class="tactic-pill">${escapeHtml(t.replace(/-/g,' '))}</span>`).join('');
  const parent = tinfo.parent;
  const parentBlock = parent && MATRIX.techniques[parent]
    ? `<div style="margin-top:10px;font-size:12px;color:var(--muted)">Sub-technique of <a href="#" data-tid="${parent}" class="parent-link" style="color:var(--accent)">${parent} ${escapeHtml(MATRIX.techniques[parent].name)}</a></div>`
    : '';
  document.getElementById('drawerHead').innerHTML = `
    <span class="tid">${tid}</span>
    <h3>${escapeHtml(tinfo.name)}</h3>
    <div class="tactics">${tactics}</div>
    <a class="ext-link" href="https://attack.mitre.org/techniques/${tid.replace('.', '/')}/" target="_blank" rel="noopener">
      View on attack.mitre.org →
    </a>
    ${parentBlock}
  `;
  let body = '';
  // Sub-techniques
  if (tinfo.subs && tinfo.subs.length) {
    body += `<div class="drawer-section"><h4>Sub-techniques (${tinfo.subs.length})</h4><div class="drawer-list">`;
    body += tinfo.subs.map(stid => {
      const stinfo = MATRIX.techniques[stid];
      const stUCs = (MATRIX.tech_ucs[stid] || []).length;
      return `<a href="#" data-tid="${stid}" class="sub-link">
        <div><b>${stid}</b> ${escapeHtml(stinfo.name)}</div>
        <div class="meta">${stUCs ? '<span class="pill">' + stUCs + ' UC</span>' : '<span style="color:var(--muted-2)">no use case</span>'}</div>
      </a>`;
    }).join('');
    body += '</div></div>';
  }
  // Mapped use cases — paginated. With 2150 ESCU detections in the matrix,
  // popular techniques can have hundreds of UCs. Order:
  //   1. LLM-generated article-bespoke UCs (rank-0 — these read the actual
  //      threat-intel article and tailor a detection to the specific TTP)
  //   2. Internal hand-curated UCs
  //   3. Splunk ESCU detections
  // Within each group: alphabetical by title.
  const ucRank = (uc) => {
    if ((uc.t || '').startsWith('[LLM]') || uc.src === 'llm') return 0;
    return uc.src === 'internal' ? 1 : 2;
  };
  const ucsSorted = ucs.slice().sort((a, b) => {
    const ra = ucRank(a), rb = ucRank(b);
    if (ra !== rb) return ra - rb;
    return (a.t || '').localeCompare(b.t || '');
  });
  body += `<div class="drawer-section"><h4>Use cases mapped (${ucs.length})</h4>`;
  if (ucs.length) {
    body += `<div class="drawer-uc-toolbar">
      <input type="text" id="drawerUcSearch" placeholder="Filter use cases…" autocomplete="off">
      <select id="drawerUcSrc">
        <option value="">All sources</option>
        <option value="internal">Internal only</option>
        <option value="escu">Splunk ESCU only</option>
      </select>
      <select id="drawerUcTier">
        <option value="">All tiers</option>
        <option value="alerting">Alerting (high-fidelity)</option>
        <option value="hunting">Hunting (needs tuning)</option>
      </select>
    </div>
    <div class="drawer-list" id="drawerUcList" data-all='${JSON.stringify(ucsSorted).replace(/'/g, "&#39;")}'></div>
    <div class="drawer-uc-pager" id="drawerUcPager" style="display:none;"></div>`;
  } else {
    body += '<div class="drawer-list"><div class="drawer-empty">No use cases reference this technique yet.</div></div>';
  }
  body += '</div>';
  // Articles citing
  body += `<div class="drawer-section"><h4>Articles citing this technique (${arts.length})</h4><div class="drawer-list">`;
  if (arts.length) {
    body += arts.map(art => `<a href="#${art.id}" data-jump="${art.id}" class="art-jump">
      <div>${escapeHtml(art.title)}</div>
      <div class="meta"><span class="pill ${art.sev}">${art.sev.toUpperCase()}</span></div>
    </a>`).join('');
  } else {
    body += '<div class="drawer-empty">No current articles mention this technique.</div>';
  }
  body += '</div></div>';
  document.getElementById('drawerBody').innerHTML = body;
  document.getElementById('techDrawer').classList.add('open');
  document.getElementById('drawerBg').classList.add('open');
  document.getElementById('techDrawer').setAttribute('aria-hidden','false');
  initDrawerUcList();
}

// Render-on-demand UC list inside the drawer. Reads the JSON-encoded
// data-all blob from #drawerUcList, renders 30 at a time with a "load more"
// pager, and wires the search + source-filter inputs.
function initDrawerUcList() {
  const list = document.getElementById('drawerUcList');
  const pager = document.getElementById('drawerUcPager');
  const search = document.getElementById('drawerUcSearch');
  const srcSel = document.getElementById('drawerUcSrc');
  if (!list || !pager) return;
  let allUcs = [];
  try { allUcs = JSON.parse(list.dataset.all); } catch(e) { allUcs = []; }
  let renderedCount = 0;
  const PAGE = 30;
  function ucCardHtml(uc) {
    const artLinks = (uc.arts || []).map(ai => MATRIX.arts[ai] && `<a href="#${MATRIX.arts[ai].id}" data-jump="${MATRIX.arts[ai].id}" class="art-jump" style="color:var(--accent);text-decoration:none;font-size:11px;">→ ${escapeHtml(MATRIX.arts[ai].title.slice(0, 60))}</a>`).filter(Boolean).join('<br>');
    const srcCls = uc.src === 'escu' ? 'escu' : 'internal';
    const srcLabel = uc.src === 'escu' ? 'ESCU' : 'Internal';
    const tier = (uc.tier || 'hunting');
    const tierLabel = tier === 'alerting' ? 'ALERTING' : 'HUNTING';
    return `<div class="uc-card-row tier-${tier}" data-uc-key="${escapeHtml(uc.n)}" data-tier="${tier}" style="padding:8px 10px;background:var(--panel);border:1px solid var(--border);border-radius:6px;margin-bottom:6px;cursor:pointer;">
      <div style="display:flex;align-items:center;gap:8px;">
        <div class="uc-card-title" style="font-weight:600;font-size:12.5px;flex:1;">${escapeHtml(uc.t)}</div>
        <span class="uc-tier-pill ${tier}" title="${tier === 'alerting' ? 'High-fidelity — safe to alert on' : 'Hunting — needs analyst review and tuning'}">${tierLabel}</span>
        <span class="uc-src-pill ${srcCls}">${srcLabel}</span>
        <span class="uc-card-chev" style="color:var(--muted);font-size:11px;">▸</span>
      </div>
      <div class="meta">
        <span class="pill">${escapeHtml(uc.ph || '-')}</span>
        <span class="pill conf${(uc.conf||'').toLowerCase()}">${escapeHtml(uc.conf || '-')}</span>
        <span style="color:var(--muted-2);font-size:10.5px;">${escapeHtml(uc.n)}</span>
      </div>
      ${artLinks ? '<div style="margin-top:6px;line-height:1.4;">' + artLinks + '</div>' : ''}
      <div class="uc-card-detail" style="display:none;"></div>
    </div>`;
  }
  function renderUcDetail(detail) {
    if (!detail) {
      return '<div style="padding:10px;color:var(--muted);font-size:11.5px;">Detection logic not available — sidecar (catalog/use_cases_full.js) is still loading or this UC is missing from it.</div>';
    }
    const techPills = (detail.techniques || []).map(t => {
      const tid = (t && t.id) || t;
      const tname = (t && t.name) || (MATRIX.techniques[tid] && MATRIX.techniques[tid].name) || '';
      return `<span class="pill" style="cursor:pointer;" data-jump-tid="${escapeHtml(tid)}">${escapeHtml(tid)}${tname ? ' ' + escapeHtml(tname) : ''}</span>`;
    }).join(' ');
    const dms = (detail.data_models || []).map(d => `<span class="pill">${escapeHtml(d)}</span>`).join(' ');
    const phPill = detail.kill_chain ? `<span class="pill">${escapeHtml(detail.kill_chain)}</span>` : '';
    let html = `<div style="margin-top:10px;padding-top:10px;border-top:1px dashed var(--border);">`;
    // Tier banner explains alerting vs hunting up-front. Honest framing
    // beats the alternative of users assuming every UC is alert-grade.
    const dt = (detail.tier || 'hunting');
    if (dt === 'alerting') {
      html += `<div style="background:rgba(46,213,99,0.08);border:1px solid rgba(46,213,99,0.35);border-radius:6px;padding:8px 12px;margin-bottom:10px;font-size:11.5px;line-height:1.5;"><b style="color:var(--good);">ALERTING TIER</b> — high-fidelity logic. Specific IOCs, threshold or temporal correlation, or named-binary hunt. Safe to wire to a SIEM rule with normal triage SLA. Still validate with a 7-day backfill in your environment first.</div>`;
    } else {
      html += `<div style="background:rgba(255,176,96,0.08);border:1px solid rgba(255,176,96,0.35);border-radius:6px;padding:8px 12px;margin-bottom:10px;font-size:11.5px;line-height:1.5;"><b style="color:var(--warn);">HUNTING TIER</b> — starter content. Returns rows that need analyst review; will produce false positives without environment tuning. Use as a hunt query first; promote to alerting after baselining + adding suppression for legitimate use.</div>`;
    }
    if (detail.description) {
      html += `<div style="font-size:12px;color:var(--text);opacity:0.92;line-height:1.55;margin-bottom:10px;">${escapeHtml(detail.description)}</div>`;
    }
    // FP-rate + required-telemetry annotations help the SOC decide whether
    // a UC fits their telemetry coverage and noise budget before deploying.
    const fpr = detail.fp_rate_estimate || 'unknown';
    const reqTelem = detail.required_telemetry || [];
    if (fpr !== 'unknown' || reqTelem.length) {
      html += `<div style="display:flex;flex-wrap:wrap;gap:8px;font-size:11px;margin-bottom:10px;">`;
      if (fpr !== 'unknown') {
        const fprColor = {low:'var(--good)', medium:'var(--warn)', high:'var(--bad)'}[fpr] || 'var(--muted)';
        html += `<span style="padding:3px 10px;border-radius:4px;background:var(--panel2);color:${fprColor};border:1px solid var(--border);"><b>FP rate:</b> ${escapeHtml(fpr)}</span>`;
      }
      reqTelem.slice(0, 6).forEach(t => {
        html += `<span style="padding:3px 10px;border-radius:4px;background:var(--panel2);color:var(--muted);border:1px solid var(--border);"><b>Needs:</b> ${escapeHtml(t)}</span>`;
      });
      html += `</div>`;
    }
    if (techPills || phPill || dms) {
      html += `<div class="meta" style="margin-bottom:10px;">${phPill}${techPills}${dms}</div>`;
    }
    if (detail.splunk_spl) {
      html += `<div style="font-size:10.5px;color:var(--muted);text-transform:uppercase;letter-spacing:0.06em;font-weight:600;margin:8px 0 4px 0;">Splunk SPL</div>`;
      html += `<pre style="background:var(--panel-elev);border:1px solid var(--border);border-radius:4px;padding:8px 10px;overflow:auto;font-size:11px;line-height:1.5;color:var(--text);max-height:340px;"><code>${escapeHtml(detail.splunk_spl)}</code></pre>`;
    }
    if (detail.defender_kql) {
      html += `<div style="font-size:10.5px;color:var(--muted);text-transform:uppercase;letter-spacing:0.06em;font-weight:600;margin:8px 0 4px 0;">Defender KQL</div>`;
      html += `<pre style="background:var(--panel-elev);border:1px solid var(--border);border-radius:4px;padding:8px 10px;overflow:auto;font-size:11px;line-height:1.5;color:var(--text);max-height:340px;"><code>${escapeHtml(detail.defender_kql)}</code></pre>`;
    }
    if (detail.source_url) {
      const src = detail.source === 'splunk_escu' ? 'Splunk Security Content (GitHub)' : 'usecaseintel (GitHub)';
      html += `<a href="${escapeHtml(detail.source_url)}" target="_blank" rel="noopener" style="color:var(--accent);font-size:11px;">↗ View source — ${escapeHtml(src)}</a>`;
    }
    html += `</div>`;
    return html;
  }
  function getFiltered() {
    const q = (search?.value || '').trim().toLowerCase();
    const srcF = srcSel?.value || '';
    const tierF = (document.getElementById('drawerUcTier')?.value || '');
    return allUcs.filter(uc => {
      if (srcF && uc.src !== srcF) return false;
      if (tierF && (uc.tier || 'hunting') !== tierF) return false;
      if (!q) return true;
      const blob = ((uc.t || '') + ' ' + (uc.n || '') + ' ' + (uc.techs || []).join(' ')).toLowerCase();
      return blob.includes(q);
    });
  }
  function renderPage(reset) {
    const filtered = getFiltered();
    if (reset) { list.innerHTML = ''; renderedCount = 0; }
    const slice = filtered.slice(renderedCount, renderedCount + PAGE);
    list.insertAdjacentHTML('beforeend', slice.map(ucCardHtml).join(''));
    renderedCount += slice.length;
    const remaining = filtered.length - renderedCount;
    if (remaining > 0) {
      pager.style.display = 'block';
      pager.textContent = `Show next ${Math.min(PAGE, remaining)} (of ${remaining} remaining)`;
    } else {
      pager.style.display = 'none';
    }
  }
  pager.addEventListener('click', () => renderPage(false));
  search?.addEventListener('input', () => renderPage(true));
  srcSel?.addEventListener('change', () => renderPage(true));
  document.getElementById('drawerUcTier')?.addEventListener('change', () => renderPage(true));
  // Click a UC card to expand inline with full SPL/KQL detail.
  list.addEventListener('click', e => {
    // Don't trigger expansion when clicking an embedded link or pill jump
    if (e.target.closest('a, [data-jump-tid]')) return;
    const card = e.target.closest('.uc-card-row');
    if (!card) return;
    const detail = card.querySelector('.uc-card-detail');
    const chev = card.querySelector('.uc-card-chev');
    if (detail.style.display === 'none' || !detail.style.display) {
      const key = card.dataset.ucKey;
      const data = (window.__UC_DETAILS__ || {})[key];
      detail.innerHTML = renderUcDetail(data);
      detail.style.display = '';
      if (chev) chev.textContent = '▾';
      // Wire technique-pill clicks to navigate
      detail.querySelectorAll('[data-jump-tid]').forEach(p => {
        p.addEventListener('click', ev => {
          ev.stopPropagation();
          openDrawerFor(p.dataset.jumpTid);
        });
      });
    } else {
      detail.style.display = 'none';
      if (chev) chev.textContent = '▸';
    }
  });
  renderPage(true);
}

function closeDrawer() {
  document.getElementById('techDrawer').classList.remove('open');
  document.getElementById('drawerBg').classList.remove('open');
  document.getElementById('techDrawer').setAttribute('aria-hidden','true');
}
document.getElementById('drawerClose')?.addEventListener('click', closeDrawer);
document.getElementById('drawerBg')?.addEventListener('click', closeDrawer);
document.addEventListener('keydown', e => {
  if (e.key === 'Escape' && document.getElementById('techDrawer').classList.contains('open')) {
    closeDrawer();
  }
});

// Sub-technique / parent click in drawer
document.getElementById('drawerBody').addEventListener('click', e => {
  const link = e.target.closest('a.sub-link, a.art-jump');
  if (!link) return;
  e.preventDefault();
  const subTid = link.dataset.tid;
  if (subTid) { openDrawerFor(subTid); return; }
  const jump = link.dataset.jump;
  if (jump) {
    closeDrawer();
    showView('articles');
    setTimeout(() => document.getElementById(jump)?.scrollIntoView({behavior:'smooth', block:'start'}), 150);
  }
});
document.getElementById('drawerHead').addEventListener('click', e => {
  const link = e.target.closest('a.parent-link');
  if (!link) return;
  e.preventDefault();
  openDrawerFor(link.dataset.tid);
});

// Make ATT&CK pills in articles deep-link to matrix drawer
document.querySelectorAll('.ind.tech').forEach(pill => {
  const tid = pill.textContent.trim();
  pill.style.cursor = 'pointer';
  pill.title = 'Click to open in ATT&CK Matrix';
  pill.addEventListener('click', e => {
    e.preventDefault(); e.stopPropagation();
    openDrawerFor(tid);
  }, true);
});

// =================================================================
// Threat Intel tab
// =================================================================
const INTEL = __INTEL_DATA__;
let intelTypeFilter = '';
let intelSearchQ = '';

const SRC_CLASS = {
  "The Hacker News":"thn", "BleepingComputer":"bc",
  "Microsoft Security Blog":"ms", "CISA KEV":"kev"
};

function renderIntel() {
  if (!INTEL || !INTEL.iocs) return;
  const tbody = document.getElementById('intelBody');
  if (INTEL.iocs.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" class="intel-empty">No IOCs extracted from current article window.</td></tr>';
    return;
  }
  const rows = INTEL.iocs.map((ioc, idx) => {
    const sources = (ioc.sources || []).map(s =>
      `<span class="source-badge ${SRC_CLASS[s] || ''}">${escapeHtml(s)}</span>`).join(' ');
    const a0 = (ioc.articles && ioc.articles[0]) || {title:'', link:'', id:''};
    const more = (ioc.articles || []).length > 1
      ? ` <span style="color:var(--muted-2);font-size:10.5px;">+${ioc.articles.length-1} more</span>` : '';
    return `<tr class="intel-row"
        data-type="${ioc.type}"
        data-search="${escapeHtml((ioc.value+' '+a0.title+' '+(ioc.sources||[]).join(' ')).toLowerCase())}">
      <td><span class="ioc-val ${ioc.type}">${escapeHtml(ioc.value)}</span></td>
      <td><span class="type-pill ${ioc.type}">${ioc.type}</span></td>
      <td><span class="sev-pill ${ioc.severity}">${ioc.severity.toUpperCase()}</span></td>
      <td><div class="sources">${sources}</div></td>
      <td><a class="article-link" href="${escapeHtml(a0.link)}" target="_blank" rel="noopener" title="${escapeHtml(a0.title)}">${escapeHtml(a0.title)}</a>${more}</td>
      <td>${escapeHtml(ioc.first_seen||'')}</td>
      <td><a class="article-link" href="#${a0.id}" data-jump="${a0.id}">view article</a></td>
    </tr>`;
  });
  tbody.innerHTML = rows.join('');
  applyIntelFilter();
  // Wire jump-to-article links
  tbody.querySelectorAll('a[data-jump]').forEach(a => {
    a.addEventListener('click', e => {
      e.preventDefault();
      showView('articles');
      setTimeout(() => document.getElementById(a.dataset.jump)?.scrollIntoView({behavior:'smooth'}), 100);
    });
  });
}

function applyIntelFilter() {
  let visible = 0;
  const counts = {cve:0, ipv4:0, domain:0, sha256:0, sha1:0, md5:0};
  document.querySelectorAll('#intelBody tr.intel-row').forEach(r => {
    const t = r.dataset.type;
    const blob = r.dataset.search || '';
    const matchType = !intelTypeFilter || t === intelTypeFilter;
    const matchSearch = !intelSearchQ || blob.includes(intelSearchQ);
    const show = matchType && matchSearch;
    r.classList.toggle('dim', !show);
    if (show) visible++;
    if (matchSearch && (t in counts)) counts[t]++;
  });
  const total = INTEL.iocs ? INTEL.iocs.length : 0;
  // In-tab stats — kept hidden because the same numbers are now in the
  // top bar. Left in the DOM in case any other code references it.
  const stats = document.getElementById('intelStats');
  if (stats) {
    stats.innerHTML =
      `<span><b>${visible}</b> of ${total} IOCs</span>` +
      `<span><b>${counts.cve}</b> CVEs</span>` +
      `<span><b>${counts.ipv4}</b> IPs</span>` +
      `<span><b>${counts.domain}</b> domains</span>` +
      `<span><b>${counts.sha256+counts.sha1+counts.md5}</b> hashes</span>`;
    stats.style.display = 'none';
  }
  // Top-bar mirror — same shape as #topStats so the .stat styling kicks in.
  const topIntel = document.getElementById('topStatsIntel');
  if (topIntel) {
    topIntel.innerHTML =
      `<div class="stat"><div class="v">${visible.toLocaleString()}</div><div class="l">Showing</div></div>` +
      `<div class="stat"><div class="v">${total.toLocaleString()}</div><div class="l">Total IOCs</div></div>` +
      `<div class="stat"><div class="v">${counts.cve.toLocaleString()}</div><div class="l">CVEs</div></div>` +
      `<div class="stat"><div class="v">${counts.ipv4.toLocaleString()}</div><div class="l">IPs</div></div>` +
      `<div class="stat"><div class="v">${counts.domain.toLocaleString()}</div><div class="l">Domains</div></div>` +
      `<div class="stat"><div class="v">${(counts.sha256+counts.sha1+counts.md5).toLocaleString()}</div><div class="l">Hashes</div></div>`;
  }
}

document.getElementById('intelTypes')?.addEventListener('click', e => {
  const btn = e.target.closest('button');
  if (!btn) return;
  document.querySelectorAll('#intelTypes button').forEach(b => b.classList.toggle('on', b === btn));
  intelTypeFilter = btn.dataset.type || '';
  applyIntelFilter();
});

document.getElementById('intelSearch')?.addEventListener('input', e => {
  intelSearchQ = e.target.value.trim().toLowerCase();
  applyIntelFilter();
});

// ----- Exports -----
function intelFiltered() {
  return (INTEL.iocs || []).filter(ioc => {
    if (intelTypeFilter && ioc.type !== intelTypeFilter) return false;
    if (intelSearchQ) {
      const blob = (ioc.value + ' ' + (ioc.articles?.[0]?.title || '') + ' ' + (ioc.sources||[]).join(' ')).toLowerCase();
      if (!blob.includes(intelSearchQ)) return false;
    }
    return true;
  });
}

function csvEscape(s) {
  s = String(s ?? '');
  return /[,"\n]/.test(s) ? '"' + s.replace(/"/g,'""') + '"' : s;
}

function iocsToCsv(iocs) {
  const head = ['value','type','severity','sources','first_seen','article_titles','article_links','source_count','article_count'];
  const lines = [head.join(',')];
  for (const i of iocs) {
    lines.push([
      i.value, i.type, i.severity,
      (i.sources||[]).join('; '),
      i.first_seen || '',
      (i.articles||[]).map(a => a.title).join('; '),
      (i.articles||[]).map(a => a.link).join('; '),
      (i.sources||[]).length,
      (i.articles||[]).length,
    ].map(csvEscape).join(','));
  }
  return lines.join('\n');
}

function iocsToSplunkLookup(iocs) {
  const head = ['indicator','indicator_type','severity','first_seen','description','source_url'];
  const lines = [head.join(',')];
  for (const i of iocs) {
    const a0 = i.articles?.[0] || {title:'', link:''};
    lines.push([i.value, i.type, i.severity, i.first_seen || '', a0.title, a0.link].map(csvEscape).join(','));
  }
  return lines.join('\n');
}

function stixPattern(t, v) {
  v = v.replace(/'/g,"\\'");
  if (t==='ipv4') return `[ipv4-addr:value = '${v}']`;
  if (t==='domain') return `[domain-name:value = '${v}']`;
  if (t==='sha256') return `[file:hashes.'SHA-256' = '${v}']`;
  if (t==='sha1') return `[file:hashes.'SHA-1' = '${v}']`;
  if (t==='md5') return `[file:hashes.MD5 = '${v}']`;
  if (t==='cve') return `[vulnerability:name = '${v}']`;
  return `[x-custom:value = '${v}']`;
}

function uuid4() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = Math.random()*16|0;
    return (c==='x' ? r : (r&0x3|0x8)).toString(16);
  });
}

function iocsToStix(iocs) {
  const ts = INTEL.generated || new Date().toISOString();
  return {
    type:'bundle', id:'bundle--'+uuid4(),
    objects: iocs.map(i => ({
      type:'indicator', spec_version:'2.1',
      id:'indicator--'+uuid4(),
      created:ts, modified:ts, valid_from:ts,
      name: i.type.toUpperCase()+': '+i.value,
      pattern: stixPattern(i.type, i.value), pattern_type:'stix',
      labels:['malicious-activity'],
      external_references: (i.articles||[]).slice(0,3).map(a => ({source_name:(a.title||'').slice(0,60), url:a.link})),
      x_severity: i.severity,
      x_sources: i.sources || [],
    }))
  };
}

function downloadFile(name, content, mime) {
  const blob = new Blob([content], {type:mime||'text/plain'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = name;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 300);
}

document.querySelectorAll('button[data-export]').forEach(btn => {
  btn.addEventListener('click', () => {
    const data = intelFiltered();
    const stamp = new Date().toISOString().slice(0,10);
    const kind = btn.dataset.export;
    if (kind === 'csv') {
      downloadFile(`iocs-${stamp}.csv`, iocsToCsv(data), 'text/csv');
    } else if (kind === 'json') {
      downloadFile(`iocs-${stamp}.json`,
        JSON.stringify({generated: INTEL.generated, count: data.length, iocs: data}, null, 2),
        'application/json');
    } else if (kind === 'stix') {
      downloadFile(`iocs-${stamp}.stix.json`, JSON.stringify(iocsToStix(data), null, 2), 'application/json');
    } else if (kind === 'splunk') {
      downloadFile(`splunk_lookup_iocs-${stamp}.csv`, iocsToSplunkLookup(data), 'text/csv');
    } else if (kind === 'copy') {
      navigator.clipboard.writeText(iocsToCsv(data)).then(() => {
        const orig = btn.textContent;
        btn.textContent = 'Copied!';
        setTimeout(() => btn.textContent = orig, 1300);
      });
    }
  });
});
</script>
<!-- Cloudflare Web Analytics — privacy-friendly, no cookies, no GDPR
     banner needed. Beacon script is loaded with `defer` so it never
     blocks the 8 MB index.html parse, and it's injected at the very
     end of <body> so analytics never get in the way of content load. -->
<script defer src='https://static.cloudflareinsights.com/beacon.min.js' data-cf-beacon='{"token": "93e5a6361d834ae2b95d7a90b539fe71"}'></script>
</body>
</html>
"""


def compute_severity(article_text: str, ind: dict, ucs: list, techs: list) -> str:
    """Return 'crit' | 'high' | 'med' | 'low' based on signals."""
    t = article_text.lower()
    score = 0
    if ind["cves"]:
        score += 2
    if any(k in t for k in ("zero-day", "0-day", "zero day", "actively exploited",
                              "kev", "in the wild", "supply chain", "supply-chain",
                              "ransomware", "wiper", "rce", "remote code execution")):
        score += 3
    if any(k in t for k in ("apt", "lazarus", "kimsuky", "fin7", "scattered spider",
                              "volt typhoon", "salt typhoon", "tropic trooper",
                              "muddywater", "fancy bear", "cozy bear", "cobalt strike",
                              "lockbit", "blackcat", "alphv", "akira", "rhysida",
                              "ransomhub", "qilin", "play ransomware")):
        score += 2
    score += min(len(ucs), 3)
    score += min(len(techs) // 3, 2)

    if score >= 9: return "crit"
    if score >= 6: return "high"
    if score >= 3: return "med"
    return "low"


SEV_LABEL = {"crit": "Critical", "high": "High", "med": "Medium", "low": "Low"}


def render_indicators(ind: dict, techniques: list) -> str:
    out = []
    def block(label, items, cls=""):
        if not items: return ""
        chips = " ".join(f'<span class="ind {cls}">{html.escape(str(i))}</span>' for i in items)
        return f'<div class="ind-group"><span class="ind-label">{label}</span>{chips}</div>'

    out.append(block("CVEs", ind["cves"], "cve"))
    if techniques:
        chips = " ".join(
            f'<span class="ind tech" title="{html.escape(name)}">{html.escape(tid)}</span>'
            for tid, name in techniques[:14]
        )
        out.append(f'<div class="ind-group"><span class="ind-label">ATT&amp;CK</span>{chips}</div>')
    out.append(block("Domains", ind["domains"][:10]))
    out.append(block("IPs", ind["ips"]))
    if ind["sha256"]: out.append(block("SHA256", [h[:16] + "…" for h in ind["sha256"][:5]]))
    if ind["sha1"]: out.append(block("SHA1", [h[:16] + "…" for h in ind["sha1"][:5]]))
    if ind["md5"]: out.append(block("MD5", [h[:16] + "…" for h in ind["md5"][:5]]))
    return "\n".join(b for b in out if b)


def render_killchain(art_id: str, hit: set, inferred: set,
                     uc_by_phase: dict) -> str:
    cells = []
    detail_lines = []
    for i, (pid, name, descr) in enumerate(KILL_CHAIN_PHASES):
        cls, marker = "", "—"
        if pid in hit:
            cls, marker = "hit", "Detected"
        elif pid in inferred:
            cls, marker = "inferred", "Likely"
        cells.append(f'''<div class="kc-cell {cls}">
  <div class="num">Phase {i+1}</div>
  <div class="name">{html.escape(name)}</div>
  <div class="marker">{marker}</div>
</div>''')
        ucs_here = uc_by_phase.get(pid, [])
        line_cls = "hit" if pid in hit else ("inferred" if pid in inferred else "")
        descr_html = html.escape(descr)
        if ucs_here:
            uc_titles = " · ".join(html.escape(u.title) for u in ucs_here)
            descr_html += f' <em>→ {uc_titles}</em>'
        detail_lines.append(
            f'<div class="phase-line {line_cls}"><strong>{html.escape(name)}.</strong> {descr_html}</div>'
        )
    track = "\n".join(cells)
    detail = "\n".join(detail_lines)
    return f"""
<div class="killchain" id="{art_id}-kc">
  <div class="kc3d">{track}</div>
  <div class="kc-detail">{detail}</div>
</div>
""".strip()


def render_use_case(art_id: str, idx: int, uc: UseCase, ind: dict) -> str:
    spl = parameterize(uc.splunk_spl, ind)
    kql = parameterize(uc.defender_kql, ind)
    techs = " ".join(
        f'<span class="ind tech" title="{html.escape(name)}">{html.escape(tid)}</span>'
        for tid, name in uc.techniques
    )
    dms = " ".join(
        f'<span class="ind">{html.escape(d)}</span>' for d in uc.data_models
    )
    uid = f"{art_id}-uc{idx}"
    phase_name = next((n for p, n, _ in KILL_CHAIN_PHASES if p == uc.kill_chain), uc.kill_chain)
    conf_cls = uc.confidence.lower()
    return f"""
<details class="uc"{ ' open' if idx == 0 else '' }>
  <summary>
    <span class="uc-title">{html.escape(uc.title)}</span>
    <span class="uc-phase">{html.escape(phase_name)}</span>
    <span class="uc-conf {conf_cls}">{html.escape(uc.confidence)}</span>
  </summary>
  <div class="uc-body">
    <div class="uc-desc">{html.escape(uc.description)}</div>
    <div class="uc-meta"><span class="ind-label">ATT&amp;CK</span>{techs}</div>
    <div class="uc-meta"><span class="ind-label">Data sources</span>{dms}</div>
    <div class="tabs">
      <button class="tab-btn active" data-target="{uid}-kql">Defender KQL</button>
      <button class="tab-btn" data-target="{uid}-spl">Splunk SPL (CIM)</button>
    </div>
    <div class="tab-content active" id="{uid}-kql">
      <pre><button class="copy-btn">COPY</button><code>{html.escape(kql)}</code></pre>
    </div>
    <div class="tab-content" id="{uid}-spl">
      <pre><button class="copy-btn">COPY</button><code>{html.escape(spl)}</code></pre>
    </div>
  </div>
</details>
""".strip()


def render_card(idx: int, article: dict, ind: dict,
                techniques: list, hit: set, inferred: set,
                use_cases: list, severity: str) -> str:
    aid = f"art-{idx:02d}"
    pubmeta = html.escape(article.get("published", ""))
    summary = html.escape(article.get("summary", ""))
    indicators_html = render_indicators(ind, techniques)
    # LLM-driven article-bespoke UCs (titles prefixed `[LLM]`) read the
    # actual threat-intel article and tailor a detection to the specific
    # TTP, so they're the highest-fidelity items on the card. Sort them
    # to the top of the per-article use-case list, then everything else
    # in the order rules fired them.
    use_cases = sorted(
        use_cases,
        key=lambda u: 0 if (u.title or "").startswith("[LLM]") else 1,
    )
    uc_by_phase = {}
    for uc in use_cases:
        uc_by_phase.setdefault(uc.kill_chain, []).append(uc)
    killchain_html = render_killchain(aid, hit, inferred, uc_by_phase)
    uc_html = "\n".join(render_use_case(aid, i, uc, ind) for i, uc in enumerate(use_cases))

    phases_attr = ",".join(sorted(hit | inferred))
    techs_attr = ",".join(t for t, _ in techniques)
    search_blob = " ".join([
        article["title"], article.get("summary", ""),
        " ".join(ind["cves"]),
        " ".join(t for t, _ in techniques),
        " ".join(uc.title for uc in use_cases),
    ])

    src_class_map = {
        "The Hacker News": "thn",
        "BleepingComputer": "bc",
        "Microsoft Security Blog": "ms",
        "CISA KEV": "kev",
        "Cisco Talos": "talos",
        "Securelist (Kaspersky)": "securelist",
        "SentinelLabs": "sentinel",
        "Unit 42 (Palo Alto)": "unit42",
        "ESET WeLiveSecurity": "eset",
        "Lab52": "lab52",
        "Cyber Security News": "csn",
    }
    sources = article.get("sources") or [article.get("source", "")]
    source_html = "".join(
        f'<span class="source-badge {src_class_map.get(s, "")}">{html.escape(s)}</span>'
        for s in sources if s
    )
    sources_attr = "|".join(sources)
    return f"""
<article class="card" id="{aid}"
  data-phases="{phases_attr}" data-sev="{severity}"
  data-techs="{html.escape(techs_attr)}"
  data-sources="{html.escape(sources_attr)}"
  data-search="{html.escape(search_blob)}">
  <div class="sev-ribbon {severity}">{SEV_LABEL[severity]}</div>
  <h2><a href="{html.escape(article['link'])}" target="_blank" rel="noopener">{html.escape(article['title'])}</a></h2>
  <div class="source-badges">{source_html}</div>
  <div class="pubmeta">
    <span>{pubmeta}</span>
    <span>{len(use_cases)} use case{'s' if len(use_cases)!=1 else ''}</span>
    <span>{len(techniques)} technique{'s' if len(techniques)!=1 else ''}</span>
    <span>{len(hit)} kill-chain phase{'s' if len(hit)!=1 else ''} detected</span>
  </div>
  <p class="summary">{summary}</p>
  {indicators_html}
  <div class="action-row">
    <button class="btn btn-kc" data-target="{aid}-kc"><svg class="kc-chev" width="11" height="11" viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="3 4.5 6 7.5 9 4.5"/></svg><span class="kc-label">Show kill chain</span></button>
    <span class="btn-meta">Click any ATT&amp;CK pill below to open it on the Matrix</span>
  </div>
  {killchain_html}
  <div class="usecases">{uc_html}</div>
</article>
""".strip()


def render_nav(articles_meta):
    items = []
    for i, m in enumerate(articles_meta, start=1):
        aid = f"art-{i-1:02d}"
        title = html.escape(m["title"])
        sev = m["sev"]
        items.append(
            f'<div class="nav-item" data-jump="{aid}">'
            f'<span class="num">{i:02d}</span>'
            f'<span class="ttl">{title}</span>'
            f'<span class="sev {sev}"></span>'
            f'</div>'
        )
    return "\n".join(items)


def render_filter_chips() -> str:
    chips = []
    for sev_key, sev_lbl in [("crit", "Critical"), ("high", "High"), ("med", "Medium"), ("low", "Low")]:
        chips.append(f'<button class="fchip" data-key="sev" data-val="{sev_key}"><span class="dot"></span>{sev_lbl}<span class="x">×</span></button>')
    chips.append('<span style="width:1px;height:18px;background:var(--border);margin:0 6px;"></span>')
    for pid, name, _ in KILL_CHAIN_PHASES:
        chips.append(f'<button class="fchip" data-key="phase" data-val="{pid}">{html.escape(name)}<span class="x">×</span></button>')
    return "\n".join(chips)


# =============================================================================
# ATT&CK Matrix data — designed for 10,000+ use cases (lean refs, no inline)
# =============================================================================

# Canonical ATT&CK Enterprise tactic order (left-to-right)
TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]
TACTIC_DISPLAY = {
    "reconnaissance": "Reconnaissance",
    "resource-development": "Resource Development",
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}

REGISTRY_PATH_FOR_MATRIX = Path(__file__).parent / "data_sources" / "registry.json"


def _load_attack_data():
    """Read MITRE ATT&CK techniques + tactics from registry.json."""
    if not REGISTRY_PATH_FOR_MATRIX.exists():
        return None
    try:
        return __import__("json").loads(REGISTRY_PATH_FOR_MATRIX.read_text(encoding="utf-8"))
    except Exception:
        return None


def build_matrix_data(articles_meta):
    """
    Build the compact data structure embedded into the matrix view.

    articles_meta is a list of {id, title, sev, link, ucs:[(name, UseCase),...], techs:[(tid, name)]}.

    Output structure (everything lean — IDs/refs, not full inline objects so
    the matrix can scale to 10K+ use cases without bloating the HTML):

      tactics:    [{short, name, tids:[...]}, ...]   ordered for matrix columns
      techniques: {tid: {name, parent, subs:[...], tactics:[...]}}
      ucs:        [{i:int, n:str, t:str, conf:str, ph:str, techs:[tid,...]}]
      arts:       [{i:int, id:str, title:str, sev:str, techs:[tid,...]}]
      tech_ucs:   {tid: [uc_index, ...]}
      tech_arts:  {tid: [art_index, ...]}
    """
    reg = _load_attack_data()
    if not reg:
        return None
    techs = reg.get("attack_techniques", {})
    if not techs:
        return None

    # 1. Walk every technique, build hierarchy + tactic membership
    by_tactic = {t: [] for t in TACTIC_ORDER}
    technique_view = {}
    for tid, info in techs.items():
        if info.get("deprecated"):
            continue
        parent = tid.rsplit(".", 1)[0] if "." in tid else None
        is_sub = parent is not None
        tactics_for = [t for t in (info.get("kill_chain_phases") or []) if t in by_tactic]
        technique_view[tid] = {
            "name": info.get("name", tid),
            "parent": parent,
            "subs": [],
            "tactics": tactics_for,
            "is_sub": is_sub,
        }
        if not is_sub:
            for tac in tactics_for:
                by_tactic[tac].append(tid)
    # Wire sub-techniques to their parents
    for tid, view in technique_view.items():
        if view["parent"] and view["parent"] in technique_view:
            technique_view[view["parent"]]["subs"].append(tid)

    # Sort techniques alphabetically per tactic (mirrors attack.mitre.org)
    for tac in by_tactic:
        by_tactic[tac].sort(key=lambda t: technique_view[t]["name"].lower())
    for tid, view in technique_view.items():
        view["subs"].sort(key=lambda t: technique_view[t]["name"].lower())

    # 2. Enumerate the entire UseCase catalog defined in this module —
    #    not just the ones today's articles triggered. The matrix is the
    #    canonical use-case-to-technique mapping; today's articles add
    #    article references to whatever use cases happened to fire.
    import sys as _sys
    this_module = _sys.modules[__name__]
    all_use_cases = []
    for name in dir(this_module):
        obj = getattr(this_module, name, None)
        if isinstance(obj, UseCase):
            all_use_cases.append((name, obj))
    all_use_cases.sort(key=lambda x: x[0])

    uc_records = []
    art_records = []
    tech_ucs = {}     # tid -> [uc_idx]
    tech_arts = {}    # tid -> [art_idx]
    seen_uc_ids = {}

    for name, uc in all_use_cases:
        idx = len(uc_records)
        seen_uc_ids[name] = idx
        uc_techs = [t for t, _ in uc.techniques]
        uc_records.append({
            "i": idx,
            "n": name,
            "t": uc.title,
            "conf": uc.confidence,
            "ph": uc.kill_chain,
            "src": "internal",
            "tier": getattr(uc, "tier", "hunting"),
            "techs": uc_techs,
            "arts": [],  # populated when articles cite this UC below
        })
        for tid in uc_techs:
            if tid in technique_view:
                tech_ucs.setdefault(tid, []).append(idx)

    # 2b. Pull synced ESCU detections (Splunk Security Content) into the matrix.
    #     Each is a use case mapped to MITRE techniques. This brings the matrix
    #     from ~24 hand-built UCs to thousands of reference detections.
    escu_list = reg.get("escu_detections") or []
    escu_added = 0
    for det in escu_list:
        tech_ids = []
        for t in (det.get("techniques") or []):
            tid = t.get("id") if isinstance(t, dict) else t
            if tid and tid in technique_view:
                tech_ids.append(tid)
        if not tech_ids:
            continue
        idx = len(uc_records)
        det_id = det.get("id") or f"escu_{idx}"
        # First kill_chain_phase if available (Splunk uses MITRE phase names)
        phases = det.get("kill_chain_phases") or []
        ph = phases[0] if phases else ""
        # Map MITRE phase short-names to our 7-stage kill-chain buckets
        ph_map = {
            "reconnaissance":"recon", "resource-development":"recon",
            "initial-access":"delivery", "execution":"exploit",
            "persistence":"install", "privilege-escalation":"install",
            "defense-evasion":"install", "credential-access":"actions",
            "discovery":"actions", "lateral-movement":"actions",
            "collection":"actions", "exfiltration":"actions",
            "command-and-control":"c2", "impact":"actions",
        }
        ph_short = ph_map.get(ph.lower() if ph else "", "actions")
        # ESCU detection types map to tiers as follows:
        #   TTP / Correlation       -> alerting (specific behaviour, deployable)
        #   Anomaly / Hunting       -> hunting  (needs tuning per environment)
        det_type = (det.get("type") or "").lower()
        if det_type in ("ttp", "correlation"):
            tier = "alerting"
        else:
            tier = "hunting"
        uc_records.append({
            "i": idx,
            "n": det_id[:36],
            "t": det.get("name", det_id)[:140],
            "conf": det.get("type", "Detection"),
            "ph": ph_short,
            "src": "escu",
            "tier": tier,
            "techs": tech_ids,
            "arts": [],
        })
        for tid in tech_ids:
            tech_ucs.setdefault(tid, []).append(idx)
        escu_added += 1
    if escu_added:
        print(f"[*] Matrix: added {escu_added} ESCU detections from registry")

    # Walk current articles, register article->technique and article->UC links
    for a in articles_meta:
        a_idx = len(art_records)
        art_techs = sorted({t for t, _ in a["techs"]})
        art_records.append({
            "i": a_idx,
            "id": a["id"],
            "title": a["title"][:140],
            "sev": a["sev"],
            "techs": art_techs,
        })
        for tid in art_techs:
            if tid in technique_view:
                tech_arts.setdefault(tid, []).append(a_idx)
        for uc_var, _uc in a["ucs"]:
            if uc_var in seen_uc_ids:
                uc_records[seen_uc_ids[uc_var]]["arts"].append(a_idx)

    # 3. Compose tactics array in canonical order
    tactics_out = []
    for short in TACTIC_ORDER:
        tactics_out.append({
            "short": short,
            "name": TACTIC_DISPLAY[short],
            "tids": by_tactic.get(short, []),
        })

    return {
        "tactics": tactics_out,
        "techniques": technique_view,
        "ucs": uc_records,
        "arts": art_records,
        "tech_ucs": tech_ucs,
        "tech_arts": tech_arts,
        "stats": {
            "total_techs": sum(1 for t, v in technique_view.items() if not v["is_sub"]),
            "total_subs": sum(1 for t, v in technique_view.items() if v["is_sub"]),
            "covered_techs": len(set(tech_ucs.keys()) | set(tech_arts.keys())),
            "ucs": len(uc_records),
            "arts": len(art_records),
        },
    }


# =============================================================================
# IOC aggregation + threat intel exports (CSV / JSON / STIX 2.1 / Splunk lookup)
# =============================================================================

import csv as _csv
import uuid as _uuid

INTEL_DIR = Path(__file__).parent / "intel"
CATALOG_DIR = Path(__file__).parent / "catalog"

_SEV_RANK = {"crit": 4, "high": 3, "med": 2, "low": 1}


def aggregate_iocs(articles_meta):
    """Dedupe IOCs across articles, attaching source attribution + context.

    Every IOC included here has passed the high-fidelity bar in
    `extract_indicators()`:
      - CVE & hash IOCs: regex-extracted (unambiguous format)
      - Domain/IP IOCs:  only present if the source author defanged them
                         (`evil[.]com`, `1[.]2[.]3[.]4`, `hxxps://...`)
    The `confidence` field below tells consumers which path each IOC took.
    """
    iocs = {}  # (type, value_lower) -> dict
    type_buckets = [
        ("cve", "cves", "regex"),
        ("ipv4", "ips", "defanged"),
        ("domain", "domains", "defanged"),
        ("sha256", "sha256", "regex"),
        ("sha1", "sha1", "regex"),
        ("md5", "md5", "regex"),
    ]
    for a in articles_meta:
        ind = a.get("ind") or {}
        sev = a.get("sev", "low")
        sources = a.get("sources") or []
        article_ref = {
            "id": a["id"],
            "title": a["title"],
            "link": a["link"],
            "published": a.get("published", ""),
            "sev": sev,
        }
        for ioc_type, ind_key, source_path in type_buckets:
            for value in ind.get(ind_key, []) or []:
                key = (ioc_type, str(value).lower())
                ent = iocs.get(key)
                if ent is None:
                    iocs[key] = {
                        "value": value,
                        "type": ioc_type,
                        "confidence": "high",  # everything that survives extraction is high-confidence by design
                        "extraction": source_path,  # "regex" or "defanged" — provenance of the extraction
                        "severity": sev,
                        "sources": list(sources),
                        "articles": [article_ref],
                        "first_seen": article_ref["published"] or "",
                    }
                else:
                    if article_ref not in ent["articles"]:
                        ent["articles"].append(article_ref)
                    for s in sources:
                        if s not in ent["sources"]:
                            ent["sources"].append(s)
                    if _SEV_RANK.get(sev, 0) > _SEV_RANK.get(ent["severity"], 0):
                        ent["severity"] = sev
    out = list(iocs.values())
    out.sort(key=lambda x: (-_SEV_RANK.get(x["severity"], 0), x["type"], x["value"].lower()))
    # Enrich each IOC with public-feed cross-references (ThreatFox / URLhaus).
    # Free, no API key, rate-limited but generous. Toggle off with
    # USECASEINTEL_ENRICH=0 if running offline.
    if os.environ.get("USECASEINTEL_ENRICH", "1") not in ("0", "false", "no", ""):
        _enrich_iocs(out)
    return out


# ----- IOC enrichment via free public threat-intel APIs ----------------
# ThreatFox (abuse.ch) — JSON API, free, no key. Returns malware family +
# first-seen + reporter for any IOC type. URLhaus is a sibling for URLs.
# We keep the call rate gentle (<= 1 req per 0.4s) and cache results to
# disk so re-runs reuse prior enrichment.
ENRICH_CACHE_DIR = Path(__file__).parent / "intel" / ".enrich_cache"
THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
URLHAUS_API   = "https://urlhaus-api.abuse.ch/v1/"


def _enrich_one(value, ioc_type, cache_dir, auth_key):
    """Look up a single IOC in ThreatFox + URLhaus. Returns dict or {}.

    abuse.ch APIs (ThreatFox + URLhaus) require an Auth-Key header as of
    2024-2025. If no key is supplied we never even call them — the
    enrichment columns just stay blank. Free auth keys are available at
    https://auth.abuse.ch/ — register and set ABUSECH_API_KEY."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^a-zA-Z0-9._-]+", "_", str(value))[:60]
    cache_path = cache_dir / f"{ioc_type}_{safe}.json"
    if cache_path.exists():
        try:
            return __import__("json").loads(cache_path.read_text(encoding="utf-8"))
        except Exception:
            pass
    if not auth_key:
        return {}
    out = {}
    headers = {
        "User-Agent": FETCH_USER_AGENT,
        "Auth-Key": auth_key,
    }
    try:
        import requests as _req
        time.sleep(0.4)
        tf_query_type = {
            "cve":"cve","ipv4":"ip","domain":"domain","md5":"md5",
            "sha1":"sha1","sha256":"sha256","url":"url",
        }.get(ioc_type)
        if tf_query_type:
            r = _req.post(THREATFOX_API,
                          json={"query": "search_ioc", "search_term": value},
                          headers=headers, timeout=15)
            if r.status_code == 200:
                d = r.json()
                if d.get("query_status") == "ok":
                    items = d.get("data") or []
                    if items:
                        first = items[0]
                        out["threatfox_malware"] = first.get("malware_printable") or first.get("malware") or ""
                        out["threatfox_threat_type"] = first.get("threat_type") or ""
                        out["threatfox_first_seen"] = first.get("first_seen") or ""
                        out["threatfox_reporter"] = first.get("reporter") or ""
                        out["threatfox_url"] = f"https://threatfox.abuse.ch/ioc/{first.get('id','')}"
                        out["threatfox_hits"] = len(items)
            elif r.status_code == 401:
                out["enrich_error"] = "ThreatFox: 401 unauthorized (set ABUSECH_API_KEY)"
        if ioc_type in ("domain","ipv4"):
            time.sleep(0.4)
            r = _req.post(URLHAUS_API + "host/",
                          data={"host": value},
                          headers=headers, timeout=15)
            if r.status_code == 200:
                d = r.json()
                if d.get("query_status") == "ok":
                    out["urlhaus_url_count"] = d.get("url_count") or 0
                    out["urlhaus_first_seen"] = d.get("firstseen") or ""
                    out["urlhaus_blacklists"] = ", ".join((d.get("blacklists") or {}).keys())
                    out["urlhaus_url"] = d.get("urlhaus_reference") or ""
            elif r.status_code == 401:
                out["enrich_error"] = "URLhaus: 401 unauthorized (set ABUSECH_API_KEY)"
    except Exception as e:
        out["enrich_error"] = str(e)[:80]
    try:
        cache_path.write_text(__import__("json").dumps(out), encoding="utf-8")
    except Exception:
        pass
    return out


def _enrich_iocs(iocs):
    """Annotate each IOC dict with ThreatFox / URLhaus enrichment in-place."""
    auth_key = os.environ.get("ABUSECH_API_KEY", "").strip()
    if not auth_key:
        # Don't even try — abuse.ch APIs require auth as of 2024-2025.
        # Log once so the user knows enrichment is disabled, then bail.
        print("[*] IOC enrichment skipped: set ABUSECH_API_KEY (free at https://auth.abuse.ch/) to enable ThreatFox/URLhaus cross-reference")
        return
    enriched = 0; auth_err = 0
    for i in iocs:
        meta = _enrich_one(i["value"], i["type"], ENRICH_CACHE_DIR, auth_key)
        if meta:
            i["enrichment"] = meta
            if meta.get("threatfox_malware") or meta.get("urlhaus_url_count"):
                enriched += 1
            elif "401" in (meta.get("enrich_error") or ""):
                auth_err += 1
    if auth_err:
        print(f"[!] IOC enrichment: {auth_err} 401-unauth responses — verify ABUSECH_API_KEY is correct")
    print(f"[*] IOC enrichment: {enriched} IOCs cross-referenced via ThreatFox/URLhaus")


def _iocs_to_csv_rows(iocs):
    rows = [[
        "value", "type", "severity", "sources", "first_seen",
        "article_titles", "article_links", "source_count", "article_count",
        "threatfox_malware", "threatfox_threat_type", "urlhaus_url_count",
        "urlhaus_blacklists", "enrichment_url"
    ]]
    for i in iocs:
        e = i.get("enrichment") or {}
        rows.append([
            i["value"], i["type"], i["severity"],
            "; ".join(i["sources"]),
            i.get("first_seen", ""),
            "; ".join(a["title"] for a in i["articles"]),
            "; ".join(a["link"] for a in i["articles"]),
            str(len(i["sources"])), str(len(i["articles"])),
            e.get("threatfox_malware",""),
            e.get("threatfox_threat_type",""),
            str(e.get("urlhaus_url_count","")),
            e.get("urlhaus_blacklists",""),
            e.get("threatfox_url") or e.get("urlhaus_url") or "",
        ])
    return rows


def _iocs_to_splunk_lookup_rows(iocs):
    rows = [["indicator", "indicator_type", "severity", "first_seen", "description", "source_url"]]
    for i in iocs:
        first = i["articles"][0] if i["articles"] else {"title": "", "link": ""}
        rows.append([
            i["value"], i["type"], i["severity"],
            i.get("first_seen", ""), first["title"], first["link"],
        ])
    return rows


def _stix_pattern(ioc_type, value):
    if ioc_type == "ipv4":
        return f"[ipv4-addr:value = '{value}']"
    if ioc_type == "domain":
        return f"[domain-name:value = '{value}']"
    if ioc_type == "sha256":
        return f"[file:hashes.'SHA-256' = '{value}']"
    if ioc_type == "sha1":
        return f"[file:hashes.'SHA-1' = '{value}']"
    if ioc_type == "md5":
        return f"[file:hashes.MD5 = '{value}']"
    if ioc_type == "cve":
        return f"[vulnerability:name = '{value}']"
    return f"[x-custom:value = '{value}']"


def _iocs_to_stix(iocs, generated_iso):
    bundle_id = f"bundle--{_uuid.uuid4()}"
    objects = []
    for i in iocs:
        first_link = i["articles"][0]["link"] if i["articles"] else ""
        first_title = i["articles"][0]["title"] if i["articles"] else ""
        ioc_id = f"indicator--{_uuid.uuid4()}"
        obj = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": ioc_id,
            "created": generated_iso,
            "modified": generated_iso,
            "name": f"{i['type'].upper()}: {i['value']}",
            "pattern": _stix_pattern(i["type"], i["value"]),
            "pattern_type": "stix",
            "valid_from": generated_iso,
            "labels": ["malicious-activity"],
            "external_references": (
                [{"source_name": s["title"][:60], "url": s["link"]} for s in i["articles"][:3]]
            ),
            "x_severity": i["severity"],
            "x_sources": i["sources"],
        }
        objects.append(obj)
    return {"type": "bundle", "id": bundle_id, "objects": objects}


def _xml_escape(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                  .replace('"', "&quot;").replace("'", "&apos;"))


def _iocs_to_rss(iocs, generated_iso, repo_url="https://github.com/Virtualhaggis/usecaseintel"):
    """RSS 2.0 feed of IOCs — newest-first, last 100 items."""
    sorted_iocs = sorted(
        iocs,
        key=lambda x: (x.get("first_seen") or "", x.get("type"), x.get("value", "").lower()),
        reverse=True,
    )[:100]

    def to_rfc2822(iso_date):
        try:
            d = dt.datetime.fromisoformat(iso_date + "T00:00:00+00:00") if len(iso_date) == 10 \
                else dt.datetime.fromisoformat(iso_date.replace("Z", "+00:00"))
            return d.strftime("%a, %d %b %Y %H:%M:%S +0000")
        except Exception:
            return ""

    items_xml = []
    for ioc in sorted_iocs:
        first_art = (ioc.get("articles") or [{}])[0]
        link = first_art.get("link") or repo_url
        title = f"[{ioc['type'].upper()}/{ioc['severity'].upper()}] {ioc['value']}"
        desc_html = (
            f"<p><strong>{_xml_escape(ioc['type'].upper())}:</strong> "
            f"<code>{_xml_escape(ioc['value'])}</code></p>"
            f"<p>Severity: <strong>{_xml_escape(ioc['severity'])}</strong> · "
            f"First seen: {_xml_escape(ioc.get('first_seen',''))} · "
            f"Sources: {_xml_escape(', '.join(ioc.get('sources', [])) or '—')}</p>"
            f"<p>Context: {_xml_escape(first_art.get('title',''))}</p>"
        )
        guid = f"usecaseintel:{ioc['type']}:{ioc['value']}"
        cats = "".join(
            f"\n      <category>{_xml_escape(s)}</category>"
            for s in ioc.get("sources", [])
        )
        items_xml.append(
            "    <item>\n"
            f"      <title>{_xml_escape(title)}</title>\n"
            f"      <link>{_xml_escape(link)}</link>\n"
            f"      <description>{_xml_escape(desc_html)}</description>\n"
            f"      <guid isPermaLink=\"false\">{_xml_escape(guid)}</guid>\n"
            f"      <pubDate>{to_rfc2822(ioc.get('first_seen',''))}</pubDate>"
            f"{cats}\n"
            "    </item>"
        )

    chan_pub = ""
    try:
        chan_pub = dt.datetime.fromisoformat(
            generated_iso.replace("Z", "+00:00")
        ).strftime("%a, %d %b %Y %H:%M:%S +0000")
    except Exception:
        pass
    self_url = f"https://raw.githubusercontent.com/Virtualhaggis/usecaseintel/main/intel/iocs.rss.xml"
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">\n'
        '  <channel>\n'
        '    <title>Use Case Intel — Threat Intel Feed</title>\n'
        '    <description>High-fidelity IOCs aggregated from The Hacker News, BleepingComputer, '
        'Microsoft Security Blog and CISA KEV. Refreshed daily. CVEs/hashes via regex; '
        'domains/IPs only when defanged by the source author.</description>\n'
        f'    <link>{repo_url}</link>\n'
        f'    <atom:link href="{self_url}" rel="self" type="application/rss+xml" />\n'
        '    <language>en-us</language>\n'
        f'    <pubDate>{chan_pub}</pubDate>\n'
        f'    <lastBuildDate>{chan_pub}</lastBuildDate>\n'
        '    <generator>usecaseintel/generate.py</generator>\n'
        + "\n".join(items_xml) +
        '\n  </channel>\n'
        '</rss>\n'
    )


def write_intel_files(iocs, generated_iso):
    INTEL_DIR.mkdir(exist_ok=True)
    # CSV
    with (INTEL_DIR / "iocs.csv").open("w", encoding="utf-8", newline="") as f:
        w = _csv.writer(f)
        for row in _iocs_to_csv_rows(iocs):
            w.writerow(row)
    # JSON
    payload = {"generated": generated_iso, "count": len(iocs), "iocs": iocs}
    (INTEL_DIR / "iocs.json").write_text(
        __import__("json").dumps(payload, indent=2, default=str),
        encoding="utf-8",
    )
    # STIX 2.1 bundle
    (INTEL_DIR / "iocs.stix.json").write_text(
        __import__("json").dumps(_iocs_to_stix(iocs, generated_iso), indent=2),
        encoding="utf-8",
    )
    # Splunk lookup CSV
    with (INTEL_DIR / "splunk_lookup_iocs.csv").open("w", encoding="utf-8", newline="") as f:
        w = _csv.writer(f)
        for row in _iocs_to_splunk_lookup_rows(iocs):
            w.writerow(row)
    # RSS 2.0
    (INTEL_DIR / "iocs.rss.xml").write_text(
        _iocs_to_rss(iocs, generated_iso),
        encoding="utf-8",
    )


def write_catalog_files(generated_iso):
    """Emit catalog/ JSON exports of the use-case catalog for programmatic consumers."""
    CATALOG_DIR.mkdir(exist_ok=True)
    json_lib = __import__("json")
    ucs_array = []
    coverage = {}
    if _LOADED_UCS:
        for uc_id, uc in sorted(_LOADED_UCS.items()):
            ucs_array.append({
                "id": uc_id,
                "title": uc.title,
                "kill_chain": uc.kill_chain,
                "confidence": uc.confidence,
                "description": uc.description,
                "implementations": [
                    p for p, q in (("splunk", uc.splunk_spl), ("defender", uc.defender_kql)) if q
                ],
                "mitre_attack": [{"id": t, "name": n} for t, n in uc.techniques],
                "data_models": uc.data_models,
                "splunk_spl": uc.splunk_spl or None,
                "defender_kql": uc.defender_kql or None,
            })
            for tid, _ in uc.techniques:
                coverage.setdefault(tid, []).append(uc_id)
    (CATALOG_DIR / "use_cases.json").write_text(
        json_lib.dumps({"generated": generated_iso, "count": len(ucs_array), "use_cases": ucs_array},
                       indent=2),
        encoding="utf-8",
    )
    rules_array = []
    if _LOADED_RULES:
        for r in _LOADED_RULES:
            rules_array.append({
                "name": r.name,
                "triggers": list(r.triggers),
                "fires": [k for k, v in (_LOADED_UCS or {}).items() if v in r.use_cases],
            })
    (CATALOG_DIR / "rules.json").write_text(
        json_lib.dumps({"generated": generated_iso, "count": len(rules_array), "rules": rules_array},
                       indent=2),
        encoding="utf-8",
    )
    (CATALOG_DIR / "attack_coverage.json").write_text(
        json_lib.dumps({"generated": generated_iso,
                        "tactics_count": len({uc.kill_chain for uc in (_LOADED_UCS or {}).values()}),
                        "technique_to_use_cases": coverage},
                       indent=2),
        encoding="utf-8",
    )
    # Full per-UC detail sidecar (loaded by index.html via <script src=...>).
    # This is the body of every detection — internal SPL+KQL plus the synced
    # Splunk ESCU search bodies. Kept out of the main HTML so the page weight
    # stays manageable and the browser can cache the heavy payload separately.
    full = {}
    # Internal UCs (full SPL + KQL from YAML)
    if _LOADED_UCS:
        for uc_id, uc in _LOADED_UCS.items():
            full[uc_id] = {
                "name": uc.title,
                "description": uc.description,
                "kill_chain": uc.kill_chain,
                "confidence": uc.confidence,
                "tier": getattr(uc, "tier", "hunting"),
                "fp_rate_estimate": getattr(uc, "fp_rate_estimate", "unknown"),
                "required_telemetry": list(getattr(uc, "required_telemetry", []) or []),
                "techniques": [{"id": t, "name": n} for t, n in uc.techniques],
                "data_models": list(uc.data_models or []),
                "splunk_spl": uc.splunk_spl or "",
                "defender_kql": uc.defender_kql or "",
                "source": "internal",
                "source_url": f"https://github.com/Virtualhaggis/usecaseintel/blob/main/use_cases/{uc.kill_chain}/{uc_id}.yml",
            }
    # ESCU detections (Splunk Security Content)
    try:
        reg = json_lib.loads(REGISTRY_PATH_FOR_MATRIX.read_text(encoding="utf-8"))
        for det in (reg.get("escu_detections") or []):
            det_id = det.get("id") or ""
            if not det_id: continue
            # Trim id used as JS key to first 36 chars to match matrix builder
            key = det_id[:36]
            det_type_lower = (det.get("type") or "").lower()
            tier = "alerting" if det_type_lower in ("ttp", "correlation") else "hunting"
            full[key] = {
                "name": det.get("name", ""),
                "description": det.get("description", ""),
                "kill_chain": (det.get("kill_chain_phases") or [""])[0],
                "confidence": det.get("type", "Detection"),
                "tier": tier,
                "techniques": det.get("techniques") or [],
                "data_models": det.get("data_models") or [],
                "splunk_spl": det.get("search", ""),
                "defender_kql": "",
                "source": "splunk_escu",
                "source_url": f"https://github.com/splunk/security_content/search?q={det_id}",
            }
    except Exception as _e:
        print(f"[!] Failed to embed ESCU details: {_e}")
    # Emit as JS so a plain <script src=...> include works for file:// + http
    js_payload = json_lib.dumps(full, separators=(",", ":"))
    (CATALOG_DIR / "use_cases_full.js").write_text(
        "/* auto-generated; do not edit by hand */\n"
        "window.__UC_DETAILS__ = " + js_payload + ";\n",
        encoding="utf-8",
    )
    # Also emit JSON for non-browser consumers
    (CATALOG_DIR / "use_cases_full.json").write_text(
        json_lib.dumps({"generated": generated_iso, "count": len(full),
                        "details": full}, separators=(",", ":")),
        encoding="utf-8",
    )
    print(f"[*] Use case detail sidecar: {len(full)} entries  ->  catalog/use_cases_full.js")
    # Per-platform rule packs (SIEM-native exports)
    _write_rule_packs(generated_iso)


def _write_rule_packs(generated_iso):
    """Emit per-platform rule packs for direct SIEM consumption.

    Outputs go to rule_packs/:
      - splunk/savedsearches.conf       — drop-in for Splunk app
      - sentinel/<uc>.json              — Sentinel analytics rule (ARM template)
      - elastic/<uc>.json               — Elastic detection rule
      - sigma/<uc>.yml                  — Sigma format (multi-vendor interchange)

    Only internal UCs are exported (not the 2150 ESCU detections — those
    already exist in their native Splunk Security Content repo).
    """
    if not _LOADED_UCS:
        return
    json_lib = __import__("json")
    rp_dir = Path(__file__).parent / "rule_packs"
    rp_dir.mkdir(exist_ok=True)
    splunk_dir = rp_dir / "splunk"; splunk_dir.mkdir(exist_ok=True)
    sentinel_dir = rp_dir / "sentinel"; sentinel_dir.mkdir(exist_ok=True)
    elastic_dir = rp_dir / "elastic"; elastic_dir.mkdir(exist_ok=True)
    sigma_dir = rp_dir / "sigma"; sigma_dir.mkdir(exist_ok=True)

    splunk_lines = [
        "# Splunk savedsearches.conf — auto-generated by usecaseintel",
        f"# Generated: {generated_iso}",
        f"# {len(_LOADED_UCS)} use cases. Drop into a Splunk app's local/",
        "# folder. Each saved search is disabled by default — enable per",
        "# environment after a 7-day backfill review.",
        "",
    ]

    for uc_id, uc in sorted(_LOADED_UCS.items()):
        tier = getattr(uc, "tier", "hunting")
        cron = "0 */6 * * *" if tier == "alerting" else "0 8 * * *"  # alerting hourly-ish, hunting daily
        # ---- Splunk savedsearches.conf stanza ----
        if uc.splunk_spl:
            splunk_lines.append(f"[usecaseintel - {uc.title}]")
            splunk_lines.append(f"description = {(uc.description or '').splitlines()[0] if uc.description else ''}")
            splunk_lines.append(f"search = {uc.splunk_spl.strip().splitlines()[0] if uc.splunk_spl else ''}")  # 1-line preview
            splunk_lines.append(f"# (full multi-line search below)")
            for line in uc.splunk_spl.strip().splitlines():
                splunk_lines.append(f"#   {line}")
            splunk_lines.append(f"cron_schedule = {cron}")
            splunk_lines.append(f"dispatch.earliest_time = -24h@h")
            splunk_lines.append(f"dispatch.latest_time = now")
            splunk_lines.append(f"enableSched = 0  # ENABLE AFTER REVIEW (tier={tier})")
            splunk_lines.append(f"action.notable = {1 if tier == 'alerting' else 0}")
            splunk_lines.append(f"action.notable.param.severity = high")
            splunk_lines.append(f"action.notable.param.security_domain = endpoint")
            techs = ",".join(t for t, _ in uc.techniques)
            splunk_lines.append(f"action.correlationsearch.annotations = {{\"mitre_attack\":[{techs}]}}")
            splunk_lines.append(f"# usecaseintel.tier = {tier}")
            splunk_lines.append(f"# usecaseintel.fp_rate = {getattr(uc, 'fp_rate_estimate', 'unknown')}")
            splunk_lines.append("")

        # ---- Sentinel analytics rule (Microsoft.SecurityInsights JSON) ----
        if uc.defender_kql:
            sentinel_rule = {
                "schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
                "contentVersion": "1.0.0.0",
                "resources": [{
                    "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules",
                    "apiVersion": "2022-12-01-preview",
                    "name": f"[concat(parameters('workspaceName'), '/Microsoft.SecurityInsights/{uc_id}')]",
                    "kind": "Scheduled",
                    "properties": {
                        "displayName": uc.title,
                        "description": uc.description or uc.title,
                        "severity": "High" if tier == "alerting" else "Low",
                        "enabled": False,  # ALWAYS off until reviewed
                        "query": uc.defender_kql,
                        "queryFrequency": "PT1H" if tier == "alerting" else "PT1D",
                        "queryPeriod": "PT24H",
                        "triggerOperator": "GreaterThan",
                        "triggerThreshold": 0,
                        "tactics": [],  # filled below
                        "techniques": [t for t, _ in uc.techniques],
                        "alertRuleTemplateName": uc_id,
                        "customDetails": {
                            "tier": tier,
                            "fp_rate_estimate": getattr(uc, "fp_rate_estimate", "unknown"),
                            "source_url": f"https://github.com/Virtualhaggis/usecaseintel/blob/main/use_cases/{uc.kill_chain}/{uc_id}.yml",
                        },
                    },
                }],
                "parameters": {
                    "workspaceName": {"type": "string"}
                }
            }
            (sentinel_dir / f"{uc_id}.json").write_text(
                json_lib.dumps(sentinel_rule, indent=2), encoding="utf-8")

        # ---- Elastic detection rule ----
        if uc.defender_kql or uc.splunk_spl:
            # Elastic accepts EQL / KQL — Defender KQL is closer in shape.
            elastic_rule = {
                "name": uc.title,
                "description": uc.description or uc.title,
                "risk_score": 73 if tier == "alerting" else 21,
                "severity": "high" if tier == "alerting" else "low",
                "type": "query",
                "language": "kuery",
                "enabled": False,  # OFF until reviewed
                "interval": "1h" if tier == "alerting" else "24h",
                "from": "now-24h",
                "index": ["logs-*", "winlogbeat-*", "endgame-*"],
                "query": "event.action:* AND _exists_:host.name",  # placeholder — analyst port-over needed
                "threat": [{
                    "framework": "MITRE ATT&CK",
                    "tactic": {"id": "", "name": uc.kill_chain, "reference": ""},
                    "technique": [{"id": t, "name": n, "reference": f"https://attack.mitre.org/techniques/{t}/"}
                                  for t, n in uc.techniques[:3]],
                }],
                "tags": ["usecaseintel", f"tier:{tier}", uc.kill_chain],
                "note": (
                    "**Auto-generated from usecaseintel — analyst port-over required.** "
                    "Original Splunk SPL / Defender KQL bodies preserved in the "
                    "`reference` URL. Translate the source query to Elastic's "
                    "ECS / EQL syntax before enabling.\n\n"
                    f"### Source query (Defender KQL)\n```\n{uc.defender_kql or '(none)'}\n```"
                ),
                "references": [
                    f"https://github.com/Virtualhaggis/usecaseintel/blob/main/use_cases/{uc.kill_chain}/{uc_id}.yml",
                ],
                "meta": {
                    "tier": tier,
                    "fp_rate_estimate": getattr(uc, "fp_rate_estimate", "unknown"),
                },
            }
            (elastic_dir / f"{uc_id}.json").write_text(
                json_lib.dumps(elastic_rule, indent=2), encoding="utf-8")

        # ---- Sigma rule (universal interchange) ----
        sigma_yaml = _emit_sigma(uc_id, uc, tier)
        if sigma_yaml:
            (sigma_dir / f"{uc_id}.yml").write_text(sigma_yaml, encoding="utf-8")

    (splunk_dir / "savedsearches.conf").write_text("\n".join(splunk_lines), encoding="utf-8")

    # README for the rule_packs/ directory
    readme = f"""# Rule packs — auto-generated SIEM-native exports

Generated: {generated_iso}

This directory contains per-platform versions of every internal use case
in the catalogue. Drop-in for the named SIEM, but **always disabled by
default** — review each rule against your environment before enabling.

| Directory | Format | Notes |
|---|---|---|
| `splunk/savedsearches.conf` | Splunk app config | Stanzas with full SPL embedded as comments. Enable per environment. |
| `sentinel/<uc>.json` | ARM template | Microsoft Sentinel analytics rule. Deploy with `az deployment group create`. |
| `elastic/<uc>.json` | Elastic detection rule | Translation TODO — KQL bodies need port to ECS/EQL. |
| `sigma/<uc>.yml` | Sigma | Universal interchange — convert with sigma-cli to your SIEM dialect. |

Tier-aware defaults:
- `alerting` UCs schedule hourly, severity High
- `hunting` UCs schedule daily, severity Low

All exports include `tier`, `fp_rate_estimate`, `mitre_attack` annotations.
"""
    (rp_dir / "README.md").write_text(readme, encoding="utf-8")
    print(f"[*] Rule packs: {len(_LOADED_UCS)} UCs  ->  rule_packs/{{splunk,sentinel,elastic,sigma}}/")


def _emit_sigma(uc_id, uc, tier):
    """Emit a Sigma rule. Sigma is multi-vendor — pretty-prints fields and
    leaves the heavy logic translation to sigma-cli on the consumer side.
    The `detection.condition` is intentionally simple — analysts run sigma-cli
    against their backend SIEM to expand the patterns we put in `keywords`."""
    techs = [t for t, _ in uc.techniques]
    # Pull a few discriminating tokens from the SPL/KQL to seed Sigma keywords.
    blob = (uc.splunk_spl or "") + " " + (uc.defender_kql or "")
    tokens = []
    for m in re.finditer(r'"([A-Za-z0-9_.\\\-\/]{3,80})"', blob):
        tokens.append(m.group(1))
    tokens = list(dict.fromkeys(tokens))[:25]
    if not tokens:
        return ""
    yaml_lines = [
        f"title: {uc.title}",
        f"id: {uc_id}",
        f"status: experimental",
        f"description: {(uc.description or uc.title).splitlines()[0]}",
        f"references:",
        f"  - https://github.com/Virtualhaggis/usecaseintel/blob/main/use_cases/{uc.kill_chain}/{uc_id}.yml",
        f"author: usecaseintel auto-generator",
        f"tags:",
        f"  - usecaseintel.tier.{tier}",
        f"  - usecaseintel.kill_chain.{uc.kill_chain}",
    ]
    for t in techs:
        yaml_lines.append(f"  - attack.{t.lower().replace('.','_')}")
    yaml_lines.extend([
        f"logsource:",
        f"  category: process_creation",
        f"  product: windows",
        f"detection:",
        f"  selection:",
        f"    Image|contains:",
    ])
    for tok in tokens[:15]:
        # Sigma quoting — escape backslashes
        esc = tok.replace("\\", "\\\\")
        yaml_lines.append(f"      - '{esc}'")
    yaml_lines.extend([
        f"  condition: selection",
    ])
    yaml_lines.extend([
        f"falsepositives:",
        f"  - Legitimate use of any of the above strings on dev / admin hosts",
        f"  - Tune via known-good allowlist before alerting",
        f"level: {'high' if tier == 'alerting' else 'low'}",
    ])
    return "\n".join(yaml_lines) + "\n"


# =============================================================================
# Per-article briefings — Markdown files committed to briefings/YYYY-MM-DD/
# =============================================================================

BRIEFINGS_DIR = Path(__file__).parent / "briefings"


def _slug(s: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")
    return s[:60] or "untitled"


def _kev_briefing(article, ind, ucs):
    cves = ind.get("cves", []) or []
    cve = cves[0] if cves else "CVE-UNKNOWN"
    title = article["title"]
    sev = article.get("sev", "high")
    src = ", ".join(article.get("sources", []) or [article.get("source", "")])
    pub = article.get("published", "")
    body = article.get("raw_body", "")
    vendor = ""
    if "—" in title:
        rest = title.split("—", 1)[1].strip()
        vendor = rest.rsplit(" Vulnerability", 1)[0].strip() if " Vulnerability" in rest else rest

    return f"""# [{sev.upper()}] {title}

**Source:** {src}
**Published:** {pub}
**Article:** {article.get('link', '')}

## Threat Profile

CISA KEV entry. The U.S. federal "Known Exploited Vulnerabilities" catalog only adds CVEs that have been **observed exploited in the wild**. Federal civilian agencies are required to remediate by the published due date; the same prioritisation logic applies to any sensible enterprise SOC.

{('Vendor / Product: **' + vendor + '**') if vendor else ''}

## Indicators of Compromise

- {cve} — match against your vulnerability scanner

## MITRE ATT&CK

- **T1190 — Exploit Public-Facing Application** (KEV implies active exploitation against exposed assets)

## Recommended hunts

Standard asset-exposure hunt — the canonical Splunk SPL and Defender KQL
live once in [`../_TEMPLATES.md#asset-exposure`](../_TEMPLATES.md#asset-exposure).
Substitute this CVE wherever the template references `<CVE>`:

- **CVE:** `{cve}`

## Why this matters

Anything in CISA KEV is *currently* being exploited. Even if your scanners say "not vulnerable" because of patches, it's worth one quick check across your fleet — patch lag is the silent killer. Federal due-date dates also frequently match the timing your organisation will be asked about by auditors / regulators.

## Source body

{body[:600]}{'…' if len(body) > 600 else ''}
"""


def _news_briefing(article, ind, ucs_pairs, techs, hit, sev):
    title = article["title"]
    src = ", ".join(article.get("sources", []) or [article.get("source", "")])
    pub = article.get("published", "")
    body = article.get("raw_body", "")
    link = article.get("link", "")

    ioc_lines = []
    for cve in ind.get("cves", []) or []:
        ioc_lines.append(f"- **CVE:** `{cve}`")
    for ip in ind.get("ips", []) or []:
        ioc_lines.append(f"- **IPv4 (defanged):** `{ip}`")
    for d in ind.get("domains", []) or []:
        ioc_lines.append(f"- **Domain (defanged):** `{d}`")
    for h in ind.get("sha256", []) or []:
        ioc_lines.append(f"- **SHA256:** `{h}`")
    for h in ind.get("sha1", []) or []:
        ioc_lines.append(f"- **SHA1:** `{h}`")
    for h in ind.get("md5", []) or []:
        ioc_lines.append(f"- **MD5:** `{h}`")
    if not ioc_lines:
        ioc_lines.append(
            "- _No high-fidelity IOCs in the RSS summary._ "
            "If the source publishes a technical write-up with defanged IOCs in the body, "
            "those would be picked up automatically on the next pipeline run."
        )

    tech_lines = []
    for tid, name in techs:
        tech_lines.append(f"- **{tid}**" + (f" — {name}" if name else ""))
    if not tech_lines:
        tech_lines.append("- _Narrative-keyword inference returned no technique mappings; review article for ATT&CK relevance manually._")

    # Compact rendering for the three IOC-substitution use cases. The full
    # SPL/KQL bodies are identical across hundreds of briefings — only the IOC
    # list differs. Inlining the full body on every briefing was redundant
    # noise. We emit a one-paragraph entry with the IOC list and link to the
    # canonical SPL/KQL in `briefings/_TEMPLATES.md`.
    BOILERPLATE_TITLES = {
        UC_VULN_EXPOSURE.title: ("asset-exposure", "cves",   "CVE(s)"),
        UC_NETWORK_IOC.title:   ("network-ioc",    "ipdom",  "IP / domain IOC(s)"),
        UC_HASH_IOC.title:      ("hash-ioc",       "hashes", "file hash IOC(s)"),
    }

    # Sort: LLM-driven article-bespoke UCs first (these read the actual
    # article and tailor a detection to the specific TTP, so they're the
    # highest-priority items for the analyst), then everything else in the
    # order rules fired them.
    def _llm_first(pair):
        _v, _u = pair
        return 0 if (_u.title or "").startswith("[LLM]") else 1
    ucs_pairs = sorted(ucs_pairs, key=_llm_first)

    uc_blocks = []
    boilerplate_seen = []
    for uc_var, uc in ucs_pairs:
        if uc.title in BOILERPLATE_TITLES:
            anchor, kind, label = BOILERPLATE_TITLES[uc.title]
            if kind == "cves":
                items = ind.get("cves", []) or []
            elif kind == "ipdom":
                items = (ind.get("ips", []) or []) + (ind.get("domains", []) or [])
            else:
                items = (ind.get("sha256", []) or []) + (ind.get("sha1", []) or []) + (ind.get("md5", []) or [])
            boilerplate_seen.append((uc, anchor, label, items))
            continue
        spl = parameterize(uc.splunk_spl, ind) if uc.splunk_spl else ""
        kql = parameterize(uc.defender_kql, ind) if uc.defender_kql else ""
        block = f"""### {uc.title}

`{uc_var}` · phase: **{uc.kill_chain}** · confidence: **{uc.confidence}**
"""
        if spl:
            block += f"\n**Splunk SPL (CIM):**\n```spl\n{spl.strip()}\n```\n"
        if kql:
            block += f"\n**Defender KQL:**\n```kql\n{kql.strip()}\n```\n"
        uc_blocks.append(block)

    boilerplate_seen = [bs for bs in boilerplate_seen if bs[3]]
    if boilerplate_seen:
        compact_lines = ["### IOC-driven hunts (use shared templates)\n"]
        compact_lines.append(
            "These are standard IOC-substitution hunts — the canonical SPL "
            "and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we "
            "don't repeat the same boilerplate on every CVE / hash / "
            "network-IOC briefing.\n"
        )
        for uc, anchor, label, items in boilerplate_seen:
            ioc_inline = ", ".join(f"`{i}`" for i in items[:8])
            more = f" _(+{len(items) - 8} more)_" if len(items) > 8 else ""
            compact_lines.append(
                f"- **{uc.title}** ([template](../_TEMPLATES.md#{anchor}))"
                f" — phase: **{uc.kill_chain}**, confidence: **{uc.confidence}**\n"
                f"  - {label}: {ioc_inline}{more}\n"
            )
        uc_blocks.append("\n".join(compact_lines))

    uc_section = "\n".join(uc_blocks) if uc_blocks else (
        "_No actionable hunts can be derived from the RSS summary alone. "
        "The article may still warrant manual review — open the source link "
        "for actor attribution, IOCs in the body, and TTP detail._\n"
    )

    return f"""# [{sev.upper()}] {title}

**Source:** {src}
**Published:** {pub}
**Article:** {link}

## Threat Profile

{(body[:500] + ('…' if len(body) > 500 else '')) if body else '_(no summary)_'}

## Indicators of Compromise (high-fidelity only)

{chr(10).join(ioc_lines)}

## MITRE ATT&CK Techniques

{chr(10).join(tech_lines)}

## Kill chain phases observed

{', '.join(sorted(hit)) or '_(none detected from narrative keywords)_'}

## Recommended hunts

{uc_section}

## Why this matters

Severity classified as **{sev.upper()}** based on: {('CVE present, ' if ind.get('cves') else '')}{'IOCs present, ' if any(ind.get(k) for k in ('ips','domains','sha256','sha1','md5')) else ''}{len(ucs_pairs)} use case(s) fired, {len(techs)} technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
"""


CURATED_MARKER = "<!-- curated:true -->"


def _write_briefing_templates():
    """Emit the canonical SPL/KQL for the three IOC-substitution use cases.

    These hunts are identical across hundreds of briefings — only the IOC
    list changes. Centralising them here keeps individual briefings focused
    on what's *unique* about each story (actor attribution, TTP detail,
    sector context) instead of repeating boilerplate.
    """
    md = """# Shared Detection Templates

Generic IOC-substitution hunts referenced from per-article briefings. Each
briefing lists the IOC values that fired (CVEs, defanged IPs / domains,
file hashes); the queries below are the canonical SPL / KQL bodies you'd
substitute those values into.

---

<a id="asset-exposure"></a>
## Asset Exposure — Vulnerability Matches Article CVE(s)

**Phase:** recon · **Confidence:** High · **Technique:** T1190 — Exploit Public-Facing Application

**When to use:** an article names one or more CVEs and you want to know
whether your estate has unpatched assets that match.

### Splunk SPL (CIM `Vulnerabilities`)

```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Vulnerabilities
    where Vulnerabilities.signature IN (<CVE_LIST>)
    by Vulnerabilities.dest, Vulnerabilities.signature, Vulnerabilities.severity, Vulnerabilities.cve
| `drop_dm_object_name(Vulnerabilities)`
| sort - severity
```

### Defender KQL (`DeviceTvmSoftwareVulnerabilities`)

```kql
DeviceTvmSoftwareVulnerabilities
| where CveId in~ (<CVE_LIST>)
| join kind=inner DeviceInfo on DeviceId
| project DeviceName, OSPlatform, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
| order by VulnerabilitySeverityLevel desc
```

---

<a id="network-ioc"></a>
## Network Connections to Article IPs / Domains

**Phase:** c2 · **Confidence:** High · **Technique:** T1071 — Application Layer Protocol

**When to use:** an article publishes defanged IPs or domains as
attacker C2 / staging infrastructure.

### Splunk SPL (CIM `Network_Traffic` / `Web` / `Network_Resolution`)

```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.dest IN (<IP_LIST>)
    by All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port
| `drop_dm_object_name(All_Traffic)`
| append
    [| tstats `summariesonly` count from datamodel=Web
        where Web.dest IN (<DOMAIN_LIST>)
        by Web.src, Web.dest, Web.url, Web.user
     | `drop_dm_object_name(Web)`]
| append
    [| tstats `summariesonly` count from datamodel=Network_Resolution.DNS
        where DNS.query IN (<DOMAIN_LIST>)
        by DNS.src, DNS.query, DNS.answer
     | `drop_dm_object_name(DNS)`]
```

### Defender KQL (`DeviceNetworkEvents`)

```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIP in (<IP_LIST>) or RemoteUrl has_any (<DOMAIN_LIST>)
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

---

<a id="hash-ioc"></a>
## File Hash IOCs — Endpoint File / Process Match

**Phase:** install · **Confidence:** High · **Technique:** T1027 — Obfuscated Files or Information

**When to use:** an article publishes SHA256 / SHA1 / MD5 hashes for
malicious binaries.

### Splunk SPL (CIM `Endpoint.Filesystem` + `Endpoint.Processes`)

```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where Filesystem.file_hash IN (<HASH_LIST>)
    by Filesystem.dest, Filesystem.user, Filesystem.file_path, Filesystem.file_name, Filesystem.file_hash
| `drop_dm_object_name(Filesystem)`
| append
    [| tstats `summariesonly` count from datamodel=Endpoint.Processes
        where Processes.process_hash IN (<HASH_LIST>)
        by Processes.dest, Processes.user, Processes.process_name, Processes.process_hash]
```

### Defender KQL (`DeviceFileEvents` + `DeviceProcessEvents`)

```kql
union DeviceFileEvents, DeviceProcessEvents
| where Timestamp > ago(7d)
| where SHA256 in~ (<HASH_LIST>) or SHA1 in~ (<HASH_LIST>) or MD5 in~ (<HASH_LIST>)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```

---

## Why these are split out

These three hunts fire on **most** briefings — every article that names
a CVE, an IP/domain, or a hash triggers one of them. The SPL / KQL bodies
don't change between articles; only the IOC list does.

Inlining the same boilerplate on every briefing was redundant noise that
made it harder to spot the *article-specific* detection content. Now
each briefing renders the IOC list inline (so you can copy-paste the
values straight into your search) and links here for the body once.

For machine consumption, the same IOC list is also exported to:

- `intel/iocs.csv` (one row per IOC with source attribution)
- `intel/splunk_lookup_iocs.csv` (Splunk lookup format)
- `intel/iocs.json` (JSON)
- `intel/iocs.stix.json` (STIX 2.1 bundle)
- `intel/iocs.rss.xml` (RSS feed)
"""
    (BRIEFINGS_DIR / "_TEMPLATES.md").write_text(md, encoding="utf-8")


def write_briefings(articles_meta, articles_raw_index):
    BRIEFINGS_DIR.mkdir(exist_ok=True)
    written = []
    skipped_curated = 0
    for am in articles_meta:
        a = articles_raw_index.get(am["id"])
        if not a:
            continue
        a["sev"] = am.get("sev", "low")
        a["sources"] = am.get("sources") or [a.get("source", "")]
        ind = am.get("ind") or {}
        pub = am.get("published") or "undated"
        day_dir = BRIEFINGS_DIR / (pub if re.match(r"^\d{4}-\d{2}-\d{2}$", pub) else "undated")
        day_dir.mkdir(parents=True, exist_ok=True)
        slug = _slug(am["title"])
        path = day_dir / f"{slug}.md"

        # If the briefing exists and is marked curated by an analyst, leave it alone.
        if path.exists():
            try:
                head = path.read_text(encoding="utf-8")[:500]
                if CURATED_MARKER in head:
                    skipped_curated += 1
                    written.append(path)
                    continue
            except Exception:
                pass

        if (am.get("sources") or [a.get("source", "")])[0] == "CISA KEV":
            md = _kev_briefing(a, ind, [u for _, u in am.get("ucs", [])])
        else:
            ucs_pairs = am.get("ucs", []) or []
            techs = []
            for _uc_var, uc in ucs_pairs:
                for tid, tname in uc.techniques:
                    if (tid, tname) not in techs:
                        techs.append((tid, tname))
            md = _news_briefing(a, ind, ucs_pairs, techs, set(), am.get("sev", "low"))
        path.write_text(md, encoding="utf-8")
        written.append(path)

    idx_lines = [
        "# Briefings — full archive\n",
        f"_{len(written)} per-article briefings — auto-generated from articles in the rolling {LOOKBACK_DAYS}-day window._\n",
        "",
        "**Shared detection templates:** generic IOC-substitution hunts ",
        "(asset exposure, network IOC, hash IOC) live once in [`_TEMPLATES.md`](./_TEMPLATES.md) ",
        "instead of being repeated on every briefing. Each briefing links to the relevant template.",
        "",
    ]
    by_day = {}
    for p in written:
        by_day.setdefault(p.parent.name, []).append(p)
    for day in sorted(by_day.keys(), reverse=True):
        idx_lines.append(f"\n## {day}")
        for p in sorted(by_day[day]):
            idx_lines.append(f"- [{p.stem.replace('-', ' ')}](./{day}/{p.name})")
    (BRIEFINGS_DIR / "INDEX.md").write_text("\n".join(idx_lines), encoding="utf-8")
    _write_briefing_templates()
    if skipped_curated:
        print(f"    {skipped_curated} curated briefings preserved (analyst-edited)")
    return written


# =============================================================================
# Main
# =============================================================================

def _parse_published(entry):
    if hasattr(entry, "published_parsed") and entry.published_parsed:
        try:
            return dt.datetime(*entry.published_parsed[:6], tzinfo=dt.timezone.utc)
        except Exception:
            pass
    s = entry.get("published") or entry.get("updated") or ""
    if not s:
        return None
    try:
        from email.utils import parsedate_to_datetime
        d = parsedate_to_datetime(s)
        if d.tzinfo is None:
            d = d.replace(tzinfo=dt.timezone.utc)
        return d
    except Exception:
        return None


# --- Full article body fetching (so IOC extraction sees more than the RSS preview) ---
ARTICLE_CACHE_DIR = Path(__file__).parent / "intel" / ".article_cache"
FETCH_FULL_BODY = os.environ.get("THN_FETCH_FULL_BODY", "1") not in ("0", "false", "no", "")
FETCH_DELAY_SEC = float(os.environ.get("THN_FETCH_DELAY", "1.2"))
FETCH_TIMEOUT_SEC = 25
FETCH_USER_AGENT = (
    "Mozilla/5.0 (compatible; usecaseintel-bot/1.0; "
    "+https://github.com/Virtualhaggis/usecaseintel) IOC-extractor"
)

# Tags whose content is noise for IOC extraction. Stripped before regex matching.
_NOISE_TAG_RE = re.compile(
    r"<(script|style|nav|header|footer|aside|form|button|svg|noscript)\b[^>]*>"
    r".*?</\1>",
    re.IGNORECASE | re.DOTALL,
)
# Inline elements / class hints that frame ads, comments, related-stories blocks.
_NOISE_BLOCK_RE = re.compile(
    r"<(div|section|aside)\b[^>]*"
    r"class=\"[^\"]*"
    r"(comment|related|advert|sidebar|share|social|newsletter|subscribe|popup|modal|cookie)"
    r"[^\"]*\"[^>]*>.*?</\1>",
    re.IGNORECASE | re.DOTALL,
)


def _cache_path_for(url: str) -> Path:
    h = hashlib.sha1(url.encode("utf-8", errors="replace")).hexdigest()
    return ARTICLE_CACHE_DIR / f"{h[:2]}" / f"{h}.html"


def _extract_main_html(html_doc: str) -> str:
    """Find the most-likely article-body region.

    Heuristic order — pick the LONGEST candidate above the threshold so
    sites that wrap only their header in <article> (Microsoft Security
    Blog) don't lose the body. Falls through to the whole doc if no
    container is large enough — IOC extraction is conservative anyway
    (regex-only or defanged-only), so noise tolerance is acceptable.
    """
    if not html_doc:
        return ""
    THRESHOLD = 2000
    candidates = []
    # 1. <article> tags — collect ALL, not just first.
    for m in re.finditer(r"<article\b[^>]*>(.*?)</article>", html_doc, re.IGNORECASE | re.DOTALL):
        candidates.append(m.group(1))
    # 2. common article-body class / id hints (THN, BC, Microsoft, etc.)
    body_class_re = re.compile(
        r"<(div|section|main)\b[^>]*"
        r"(?:class|id)=\"[^\"]*"
        r"(post-body|entry-content|articleBody|article-body|article__body|post__content|"
        r"post-content|article-content|story-content|content-body|articletext|"
        r"single-article|single-post|main-content|story-body|c-richtext|"
        r"rich-text|blog-post-content|wp-block-post-content)"
        r"[^\"]*\"[^>]*>(.*?)</\1>",
        re.IGNORECASE | re.DOTALL,
    )
    for m in body_class_re.finditer(html_doc):
        candidates.append(m.group(3))
    # 3. <main>
    m = re.search(r"<main\b[^>]*>(.*?)</main>", html_doc, re.IGNORECASE | re.DOTALL)
    if m:
        candidates.append(m.group(1))
    # Pick the longest candidate above threshold; otherwise fall back to whole doc.
    candidates = [c for c in candidates if len(c) > THRESHOLD]
    if candidates:
        return max(candidates, key=len)
    return html_doc


def _html_to_text_for_iocs(html_doc: str) -> str:
    """Convert article HTML to plain text suitable for IOC extraction.

    Preserves the textual content of <code>, <pre>, and table cells (where
    hashes / IPs / domains typically live in vendor write-ups) and strips
    obvious noise tags first.
    """
    if not html_doc:
        return ""
    body = _extract_main_html(html_doc)
    body = _NOISE_TAG_RE.sub(" ", body)
    body = _NOISE_BLOCK_RE.sub(" ", body)
    # <br> and </p> -> newline so multi-line IOCs aren't merged into one giant blob
    body = re.sub(r"<br\s*/?>", "\n", body, flags=re.IGNORECASE)
    body = re.sub(r"</p>", "\n", body, flags=re.IGNORECASE)
    body = re.sub(r"</li>", "\n", body, flags=re.IGNORECASE)
    body = re.sub(r"</tr>", "\n", body, flags=re.IGNORECASE)
    body = strip_html(body)
    body = html.unescape(body)
    body = re.sub(r"[ \t]+", " ", body)
    body = re.sub(r"\n[ \n]+", "\n", body)
    return body.strip()


def _fetch_full_body(url: str, fallback: str = "") -> str:
    """Fetch and clean an article body. Cached to disk; falls back on error."""
    if not FETCH_FULL_BODY or not url or not url.lower().startswith(("http://", "https://")):
        return fallback
    cache = _cache_path_for(url)
    html_doc = ""
    if cache.exists():
        try:
            html_doc = cache.read_text(encoding="utf-8", errors="replace")
        except Exception:
            html_doc = ""
    if not html_doc:
        try:
            import requests
            time.sleep(FETCH_DELAY_SEC)
            r = requests.get(
                url,
                headers={"User-Agent": FETCH_USER_AGENT, "Accept": "text/html,*/*"},
                timeout=FETCH_TIMEOUT_SEC,
                allow_redirects=True,
            )
            if r.status_code == 200 and r.text:
                html_doc = r.text
                cache.parent.mkdir(parents=True, exist_ok=True)
                try:
                    cache.write_text(html_doc, encoding="utf-8", errors="replace")
                except Exception:
                    pass
            else:
                return fallback
        except Exception as e:
            safe_err = str(e).encode("ascii", "replace").decode("ascii")
            print(f"    [!] body fetch failed for {url[:80]}: {safe_err}")
            return fallback
    text = _html_to_text_for_iocs(html_doc)
    if len(text) < 200:
        # extraction looks broken — better to keep the RSS summary than ship rubbish
        return fallback
    return text


def _fetch_rss(source, since):
    feed = feedparser.parse(source["url"])
    out = []
    fetched = 0
    for e in feed.entries[:MAX_PER_SOURCE]:
        pub = _parse_published(e)
        if since and pub and pub < since:
            continue
        rss_summary = strip_html(e.get("summary", "") or e.get("description", "") or "")
        rss_summary = re.sub(r"\s+", " ", rss_summary).strip()
        link = e.get("link", "")

        # Pull the full article body so IOC extraction sees hashes / defanged
        # IPs / domains that live below the RSS preview.
        full_body = _fetch_full_body(link, fallback=rss_summary)
        if full_body and full_body != rss_summary:
            fetched += 1

        out.append({
            "source": source["name"],
            "title": e.get("title", "(untitled)").strip(),
            "link": link,
            "published": e.get("published", ""),
            "published_dt": pub,
            # Display preview stays short; raw_body holds full text for IOC extraction.
            "summary": (rss_summary[:600] + "…") if len(rss_summary) > 600 else rss_summary,
            "raw_body": full_body or rss_summary,
        })
    if fetched:
        print(f"    -> fetched {fetched} full article bodies")
    return out


def _fetch_kev(source, since):
    import urllib.request as _ur
    req = _ur.Request(source["url"],
                      headers={"User-Agent": "Mozilla/5.0 (compatible; thn-usecases/1.0)"})
    try:
        with _ur.urlopen(req, timeout=30) as r:
            data = __import__("json").loads(r.read())
    except Exception as e:
        print(f"    [!] CISA KEV fetch failed: {e}")
        return []
    out = []
    for v in data.get("vulnerabilities", []):
        date_added = v.get("dateAdded", "")
        try:
            pub = dt.datetime.fromisoformat(date_added).replace(tzinfo=dt.timezone.utc)
        except Exception:
            pub = None
        if since and pub and pub < since:
            continue
        if len(out) >= MAX_PER_SOURCE:
            break
        cve = v.get("cveID", "") or ""
        vname = v.get("vulnerabilityName", "") or ""
        vendor = v.get("vendorProject", "") or ""
        product = v.get("product", "") or ""
        title = f"CISA KEV: {cve} — {vname}" if vname else f"CISA KEV: {cve}"
        bits = []
        if v.get("shortDescription"):
            bits.append(v["shortDescription"])
        if vendor or product:
            bits.append(f"Vendor: {vendor}, Product: {product}.")
        if v.get("knownRansomwareCampaignUse") and v["knownRansomwareCampaignUse"].lower() != "unknown":
            bits.append(f"Known ransomware use: {v['knownRansomwareCampaignUse']}.")
        if v.get("dueDate"):
            bits.append(f"Federal patch due: {v['dueDate']}.")
        body = " ".join(bits)
        out.append({
            "source": "CISA KEV",
            "title": title,
            "link": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "published": date_added,
            "published_dt": pub,
            "summary": body,
            "raw_body": body + " " + cve,
        })
    return out


_DEDUPE_STOPWORDS = {
    "the", "a", "an", "and", "or", "of", "in", "on", "to", "for", "with",
    "by", "as", "at", "from", "is", "was", "be", "been", "are", "this", "that",
    "after", "over", "via", "new", "amid", "into", "out", "up", "than",
}

def _title_tokens(title: str):
    """Lowercase, alphanumeric-only token set, minus stopwords + 1-char fragments."""
    return {t for t in re.findall(r"[a-z0-9]+", title.lower())
            if t not in _DEDUPE_STOPWORDS and len(t) > 1}


def _looks_same_story(a, b, threshold=0.55):
    """Jaccard similarity of significant title tokens."""
    if not a or not b:
        return False
    inter = a & b
    if not inter:
        return False
    union = a | b
    return (len(inter) / len(union)) >= threshold


def fetch_articles(limit: int = None, days: int = LOOKBACK_DAYS):
    """
    Pull articles from every configured source, filter to a rolling window
    of `days`, dedupe by normalised title (preserving multi-source attribution),
    and return newest first.
    """
    since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)
    print(f"[*] Lookback window: {days} days (since {since.strftime('%Y-%m-%d')})")
    raw = []
    for src in SOURCES:
        try:
            print(f"[*] {src['name']}…")
            if src["kind"] == "rss":
                items = _fetch_rss(src, since)
            elif src["kind"] == "kev":
                items = _fetch_kev(src, since)
            else:
                items = []
        except Exception as e:
            safe_err = str(e).encode('ascii','replace').decode('ascii')
            print(f"    [!] failed: {safe_err}")
            items = []
        print(f"    -> {len(items)} articles in window")
        raw.extend(items)

    # Pre-tokenize titles for word-set Jaccard dedupe across sources.
    for a in raw:
        a["_tokens"] = _title_tokens(a["title"])

    deduped = []
    for a in raw:
        a["sources"] = [a["source"]]
        match = None
        for existing in deduped:
            if _looks_same_story(a["_tokens"], existing["_tokens"]):
                match = existing
                break
        if match:
            for s in a["sources"]:
                if s not in match["sources"]:
                    match["sources"].append(s)
            # Prefer the earliest publication time
            if (a.get("published_dt")
                and (not match.get("published_dt")
                     or a["published_dt"] < match["published_dt"])):
                match["published_dt"] = a["published_dt"]
                match["published"] = a["published"]
            # Prefer the longest summary
            if len(a.get("raw_body","")) > len(match.get("raw_body","")):
                match["summary"] = a["summary"]
                match["raw_body"] = a["raw_body"]
        else:
            deduped.append(a)

    # Normalise `published` for every survivor to ISO YYYY-MM-DD (UTC). Mixed
    # RFC-2822 vs ISO is exactly the kind of inconsistency that ends up in
    # downstream CSV/JSON exports and confuses analysts.
    for a in deduped:
        a.pop("_tokens", None)
        if a.get("published_dt"):
            try:
                a["published"] = a["published_dt"].astimezone(dt.timezone.utc).strftime("%Y-%m-%d")
            except Exception:
                pass
    articles = deduped
    articles.sort(
        key=lambda a: a.get("published_dt") or dt.datetime.min.replace(tzinfo=dt.timezone.utc),
        reverse=True,
    )
    print(f"[*] After dedupe: {len(articles)} unique articles ({len(raw) - len(articles)} duplicates merged)")
    if limit:
        articles = articles[:limit]
    return articles


def main():
    articles = fetch_articles()
    if not articles:
        sys.exit("[!] No articles returned from any source.")
    print(f"[*] {len(articles)} articles total. Building deep analysis…")

    cards = []
    nav_meta = []
    articles_meta = []
    total_ucs = 0
    total_techs = set()
    total_cves = set()
    sev_counts = {"crit":0,"high":0,"med":0,"low":0}

    # Need a stable mapping from UseCase object -> python variable name (so
    # the matrix can dedupe across articles that share the same UC instance).
    uc_var_map = {id(obj): name
                  for name in dir(__import__(__name__))
                  for obj in [getattr(__import__(__name__), name, None)]
                  if isinstance(obj, UseCase)}

    bespoke_built = 0
    for i, a in enumerate(articles):
        text = f"{a['title']}\n{a['raw_body']}"
        ind = extract_indicators(a["title"], a["raw_body"])
        techniques = infer_techniques(text, ind["explicit_ttps"])
        ucs = select_use_cases(text, ind)
        # Article-specific bespoke UC built from the actual mechanics named
        # in this article. Augments rather than replaces the rule-fired UCs:
        # the generic templates still cover the technique class; the bespoke
        # UC adds detection logic targeting THIS attack's specific binaries
        # and paths and command-line patterns. None when the article doesn't
        # contain enough mechanic detail (e.g. RSS-only stub, opinion piece).
        try:
            mechanics = extract_mechanics(a["title"], a["raw_body"])
            bespoke = _make_bespoke_uc(a["title"], mechanics, ind)
            if bespoke is not None:
                ucs.append(bespoke)
                bespoke_built += 1
                a["_bespoke_uc"] = bespoke
                a["_mechanics"] = mechanics
        except Exception as _e:
            print(f"    [!] bespoke UC failed for article {i}: {_e}")
        # LLM-driven bespoke UCs — opt-in via ANTHROPIC_API_KEY env var.
        # Reads the article and emits per-attack SPL/KQL targeting the
        # specific binaries / domains / chain described, qualitatively
        # better than regex extraction. Cached per article URL.
        try:
            llm_ucs = _llm_generate_ucs(a, ind)
            for u in llm_ucs:
                if u is None: continue
                ucs.append(u)
                bespoke_built += 1
        except Exception as _e:
            print(f"    [!] LLM UC failed for article {i}: {_e}")
        narrative_hit, _ = detect_kill_chain(text)
        hit = narrative_hit | {uc.kill_chain for uc in ucs}
        inferred = set()
        for ph in list(hit):
            inferred |= INFER_FROM_PHASE.get(ph, set())
        inferred -= hit
        sev = compute_severity(text, ind, ucs, techniques)
        sev_counts[sev] += 1
        total_ucs += len(ucs)
        for tid, _ in techniques: total_techs.add(tid)
        for c in ind["cves"]: total_cves.add(c)
        cards.append(render_card(i, a, ind, techniques, hit, inferred, ucs, sev))
        nav_meta.append({"title": a["title"], "sev": sev})
        # For the matrix view: combine narrative-inferred techniques with the
        # techniques covered by any use case fired for this article. Otherwise
        # ~70% of articles look "uncovered" on the matrix purely because the
        # short RSS summary didn't trip the keyword-inference map.
        merged_techs = list(techniques)
        seen_t = {t for t, _ in techniques}
        for uc in ucs:
            for tid, tname in uc.techniques:
                if tid not in seen_t:
                    merged_techs.append((tid, tname))
                    seen_t.add(tid)
        # `published` was normalised to ISO YYYY-MM-DD by fetch_articles().
        articles_meta.append({
            "id": f"art-{i:02d}",
            "title": a["title"],
            "link": a["link"],
            "sev": sev,
            "sources": a.get("sources") or [a.get("source", "")],
            "published": a.get("published", ""),
            "techs": merged_techs,
            "ind": ind,
            "ucs": [(uc_var_map.get(id(uc), f"UC_{i}_{j}"), uc) for j, uc in enumerate(ucs)],
        })
        safe_title = a['title'][:55].encode('ascii', 'replace').decode('ascii')
        print(f"  [{i+1:02d}] {safe_title:55s} | sev={sev:4s} techs={len(techniques)} ucs={len(ucs)} kc-hit={len(hit)}")

    nav = render_nav(nav_meta)

    # IOC aggregation across all articles
    iocs = aggregate_iocs(articles_meta)
    generated_iso = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    write_intel_files(iocs, generated_iso)
    write_catalog_files(generated_iso)
    print(f"[*] IOCs aggregated: {len(iocs)} unique  ->  intel/")
    print(f"[*] Catalog exported: {len(_LOADED_UCS or {})} use cases  ->  catalog/")

    # Per-article briefings — committed to the repo so anyone pulling sees
    # operational content, not just aggregate exports
    raw_index = {f"art-{i:02d}": a for i, a in enumerate(articles)}
    briefing_paths = write_briefings(articles_meta, raw_index)
    print(f"[*] Briefings written: {len(briefing_paths)}  ->  briefings/")

    intel_json = __import__("json").dumps({"generated": generated_iso, "iocs": iocs}, default=str)

    # Source filter chips (Articles tab)
    src_class_map_chips = {
        "The Hacker News": "thn",
        "BleepingComputer": "bc",
        "Microsoft Security Blog": "ms",
        "CISA KEV": "kev",
        "Cisco Talos": "talos",
        "Securelist (Kaspersky)": "securelist",
        "SentinelLabs": "sentinel",
        "Unit 42 (Palo Alto)": "unit42",
        "ESET WeLiveSecurity": "eset",
        "Lab52": "lab52",
        "Cyber Security News": "csn",
    }
    src_counts = {}
    for a in articles:
        for s in (a.get("sources") or [a.get("source", "")]):
            src_counts[s] = src_counts.get(s, 0) + 1
    chip_html = [
        f'<span class="lg-label">Source</span>',
        f'<button class="src-chip all active" data-source="">All <span class="cnt">{len(articles)}</span></button>',
    ]
    for src in [s["name"] for s in SOURCES]:
        cnt = src_counts.get(src, 0)
        if cnt == 0: continue
        cls = src_class_map_chips.get(src, "")
        label = {"The Hacker News":"THN","BleepingComputer":"BleepingComputer",
                 "Microsoft Security Blog":"Microsoft","CISA KEV":"CISA KEV",
                 "Cisco Talos":"Talos","Securelist (Kaspersky)":"Securelist",
                 "SentinelLabs":"SentinelLabs","Unit 42 (Palo Alto)":"Unit 42",
                 "ESET WeLiveSecurity":"ESET"}.get(src, src)
        chip_html.append(
            f'<button class="src-chip {cls}" data-source="{html.escape(src)}">'
            f'{html.escape(label)} <span class="cnt">{cnt}</span></button>')
    source_chips_html = "\n".join(chip_html)

    matrix_data = build_matrix_data(articles_meta)
    if matrix_data:
        print(f"[*] Matrix: {matrix_data['stats']['total_techs']} techniques, "
              f"{matrix_data['stats']['total_subs']} sub-techniques, "
              f"{matrix_data['stats']['covered_techs']} with use-case or article coverage")
    matrix_json = __import__("json").dumps(matrix_data) if matrix_data else "null"

    page = (
        HTML_HEAD
        .replace("__GENERATED_AT__", dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"))
        .replace("__ARTICLE_COUNT__", str(len(articles)))
        .replace("__USECASE_COUNT__", str(total_ucs))
        .replace("__TECH_COUNT__", str(len(total_techs)))
        .replace("__CVE_COUNT__", str(len(total_cves)))
        .replace("__CRIT_COUNT__", str(sev_counts["crit"] + sev_counts["high"]))
        .replace("__NAV__", nav)
        .replace("__CARDS__", "\n".join(cards))
        .replace("__SOURCE_CHIPS__", source_chips_html)
        .replace("__MATRIX_DATA__", matrix_json)
        .replace("__INTEL_DATA__", intel_json)
    )
    OUT_HTML.write_text(page, encoding="utf-8")
    print(f"[*] Wrote {OUT_HTML} ({OUT_HTML.stat().st_size//1024} KB)")
    print(f"    Severity: crit={sev_counts['crit']} high={sev_counts['high']} med={sev_counts['med']} low={sev_counts['low']}")
    print(f"    Bespoke article-specific UCs built: {bespoke_built}")


if __name__ == "__main__":
    main()

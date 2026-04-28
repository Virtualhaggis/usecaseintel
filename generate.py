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
LOOKBACK_DAYS = 180       # 6-month rolling window
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

    return {
        "cves": dedupe(CVE_RE.findall(text)),
        "ips": ips,
        "domains": domains,
        "md5": dedupe(HASH_MD5_RE.findall(text)),
        "sha1": dedupe(HASH_SHA1_RE.findall(text)),
        "sha256": dedupe(HASH_SHA256_RE.findall(text)),
        "explicit_ttps": dedupe(ATTACK_RE.findall(text)),
    }


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
    return UseCase(
        title=doc.get("title", ""),
        description=(doc.get("description") or "").strip(),
        kill_chain=doc.get("kill_chain", "actions"),
        techniques=techs,
        data_models=flat_dms,
        splunk_spl=(doc.get("splunk_spl") or "") if "splunk" in impls else "",
        defender_kql=(doc.get("defender_kql") or "") if "defender" in impls else "",
        confidence=doc.get("confidence", "Medium"),
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
<title>THN Threat Atlas — Splunk &amp; Defender Use Cases</title>
<style>
/* ----- Theme ---------------------------------------------------------- */
:root {
  --bg:#070a10; --bg-grad-1:#0c1320; --bg-grad-2:#06080d;
  --panel:#10161f; --panel-elev:#161e2a; --panel2:#1c2533;
  --text:#e8eef5; --muted:#8b96a5; --muted-2:#5d6877;
  --accent:#5fb6ff; --accent-2:#b48dff; --accent-3:#36e0c0;
  --border:#222b39; --border-2:#2c384a; --hairline:rgba(255,255,255,0.06);
  --good:#5cd87a; --warn:#ffb060; --bad:#ff5d5d; --crit:#ff3260;
  --code-bg:#040608;
  --shadow-sm:0 1px 2px rgba(0,0,0,0.4);
  --shadow-md:0 4px 16px rgba(0,0,0,0.45),0 2px 4px rgba(0,0,0,0.4);
  --shadow-lg:0 24px 64px rgba(0,0,0,0.55),0 6px 16px rgba(0,0,0,0.5);
  --shadow-glow:0 0 0 1px rgba(95,182,255,0.4),0 0 24px rgba(95,182,255,0.18);
  --r-sm:6px; --r-md:10px; --r-lg:14px;
}
*{box-sizing:border-box;}
html,body{margin:0;}
body{
  background:
    radial-gradient(1200px 600px at 100% -10%, rgba(95,182,255,0.07), transparent 60%),
    radial-gradient(900px 600px at -10% 110%, rgba(180,141,255,0.06), transparent 60%),
    linear-gradient(180deg, var(--bg-grad-1) 0%, var(--bg) 60%, var(--bg-grad-2) 100%);
  background-attachment:fixed;
  color:var(--text);
  font-family:"Inter",-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
  font-size:14px; line-height:1.55;
  -webkit-font-smoothing:antialiased; -moz-osx-font-smoothing:grayscale;
  letter-spacing:-0.005em;
}
::selection{background:rgba(95,182,255,0.32);color:#fff;}

/* ----- Header / Top bar ---------------------------------------------- */
.topbar{
  position:sticky; top:0; z-index:50;
  background:rgba(10,14,21,0.78);
  backdrop-filter:blur(14px) saturate(140%);
  -webkit-backdrop-filter:blur(14px) saturate(140%);
  border-bottom:1px solid var(--hairline);
}
.topbar-inner{
  margin:0; padding:14px 28px;
  display:flex; gap:24px; align-items:center; flex-wrap:wrap;
}
.brand{display:flex;align-items:center;gap:12px;font-weight:700;font-size:16px;letter-spacing:-0.01em;}
.brand .logo{
  width:32px; height:32px; border-radius:8px;
  background:linear-gradient(135deg, var(--accent) 0%, var(--accent-2) 100%);
  display:flex; align-items:center; justify-content:center;
  box-shadow:var(--shadow-md), inset 0 1px 0 rgba(255,255,255,0.25);
  position:relative; overflow:hidden;
}
.brand .logo::after{
  content:"";position:absolute;inset:0;
  background:radial-gradient(circle at 30% 20%, rgba(255,255,255,0.45), transparent 50%);
}
.brand .logo svg{width:18px;height:18px;color:#0b1118;position:relative;z-index:1;}
.brand-text{display:flex;flex-direction:column;line-height:1.15;}
.brand-text .sub{color:var(--muted);font-size:11px;font-weight:500;letter-spacing:0.04em;text-transform:uppercase;}

.stats{display:flex;gap:16px;flex-wrap:wrap;flex:1;justify-content:center;}
.stat{
  display:flex; flex-direction:column; align-items:center;
  padding:6px 12px; min-width:64px;
}
.stat .v{font-size:20px;font-weight:700;color:var(--text);font-variant-numeric:tabular-nums;
  background:linear-gradient(135deg, var(--text) 0%, var(--accent) 100%);
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;}
.stat .l{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:0.08em;font-weight:600;}

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

/* Width toolbar (sits in the article-list filter bar) */
.width-toggle{
  display:inline-flex; gap:4px; margin-left:auto;
  background:var(--panel); border:1px solid var(--border);
  border-radius:var(--r-md); padding:3px;
}
.width-toggle button{
  background:transparent; border:0; color:var(--muted);
  padding:4px 10px; border-radius:calc(var(--r-md) - 3px);
  font-size:11px; font-family:inherit; font-weight:600;
  text-transform:uppercase; letter-spacing:0.06em;
  cursor:pointer; transition:all 0.15s;
}
.width-toggle button:hover{color:var(--text);}
.width-toggle button.on{
  background:var(--accent); color:#04111d;
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
.nav-item:hover{background:var(--panel2);}
.nav-item.active{
  background:linear-gradient(90deg, rgba(95,182,255,0.16), rgba(95,182,255,0.04));
  box-shadow:inset 3px 0 0 var(--accent);
}
.nav-item .num{
  flex:0 0 24px; font-variant-numeric:tabular-nums; color:var(--muted);
  font-weight:600; font-size:11px;
}
.nav-item .ttl{flex:1;}
.nav-item .sev{
  flex:0 0 10px; height:10px; border-radius:50%; margin-top:5px;
  background:var(--good); box-shadow:0 0 8px currentColor;
}
.nav-item .sev.med{background:var(--warn);}
.nav-item .sev.high{background:var(--bad);}
.nav-item .sev.crit{
  background:var(--crit);
  animation:pulse-crit 1.6s ease-in-out infinite;
}
@keyframes pulse-crit{
  0%,100%{box-shadow:0 0 6px var(--crit);}
  50%{box-shadow:0 0 14px var(--crit), 0 0 24px rgba(255,50,96,0.5);}
}

/* ----- Source filter bar (Articles tab) ------------------------------ */
.src-filter-bar{
  display:flex; gap:6px; flex-wrap:wrap; align-items:center;
  padding:10px 14px; margin-bottom:8px;
  background:var(--panel); border:1px solid var(--border);
  border-radius:var(--r-md);
}
.src-filter-bar .lg-label{flex:0 0 auto; min-width:72px;}
.src-chip{
  padding:6px 12px; border-radius:999px;
  background:var(--panel2); border:1px solid var(--border);
  color:var(--muted); cursor:pointer; font-family:inherit; font-size:12px;
  font-weight:600; letter-spacing:-0.005em; transition:all 0.12s;
  display:inline-flex; align-items:center; gap:6px;
}
.src-chip:hover{color:var(--text); border-color:var(--border-2);}
.src-chip.active{color:var(--text); transform:translateY(-1px);}
.src-chip.active.all{background:linear-gradient(135deg, rgba(95,182,255,0.25), rgba(180,141,255,0.18));
  border-color:transparent; box-shadow:0 0 0 1px rgba(95,182,255,0.4) inset;}
.src-chip.active.thn{background:rgba(95,182,255,0.18); border-color:var(--accent); color:var(--accent);}
.src-chip.active.bc{background:rgba(255,93,93,0.18); border-color:var(--bad); color:var(--bad);}
.src-chip.active.ms{background:rgba(180,141,255,0.18); border-color:var(--accent-2); color:var(--accent-2);}
.src-chip.active.kev{background:rgba(255,176,96,0.18); border-color:var(--warn); color:var(--warn);}
.src-chip.active.talos{background:rgba(54,224,192,0.18); border-color:var(--accent-3); color:var(--accent-3);}
.src-chip.active.securelist{background:rgba(46,213,99,0.18); border-color:var(--good); color:var(--good);}
.src-chip.active.sentinel{background:rgba(180,141,255,0.18); border-color:var(--accent-2); color:var(--accent-2);}
.src-chip.active.unit42{background:rgba(255,176,96,0.18); border-color:var(--warn); color:var(--warn);}
.src-chip.active.eset{background:rgba(95,182,255,0.18); border-color:var(--accent); color:var(--accent);}
.src-chip .cnt{
  font-variant-numeric:tabular-nums; opacity:0.7;
  background:rgba(0,0,0,0.25); padding:1px 6px; border-radius:999px;
  font-size:10.5px;
}
article.card.src-hidden{display:none;}

/* ----- Article cards ------------------------------------------------- */
section#articles{display:flex; flex-direction:column; gap:24px;}
article.card{
  background:linear-gradient(180deg, var(--panel-elev) 0%, var(--panel) 100%);
  border:1px solid var(--border);
  border-radius:var(--r-lg);
  padding:28px;
  font-size:15px; line-height:1.6;
  position:relative;
  box-shadow:var(--shadow-md);
  /* Sticky header is ~90-110px tall (brand row + tabs row). Without this,
     anchor jumps from the sidebar TOC scroll the article's top under the
     header and crop the title / severity ribbon. */
  scroll-margin-top:120px;
  transition:transform 0.25s cubic-bezier(0.2,0.8,0.2,1), box-shadow 0.25s ease, border-color 0.25s ease;
  transform-style:preserve-3d;
}
article.card:hover{
  transform:translateY(-2px);
  box-shadow:var(--shadow-lg);
  border-color:var(--border-2);
}
article.card.hidden{display:none;}
article.card .sev-ribbon{
  position:absolute; top:0; left:24px; padding:4px 12px 5px;
  font-size:10px; font-weight:700; text-transform:uppercase; letter-spacing:0.1em;
  border-radius:0 0 8px 8px;
  background:linear-gradient(180deg, var(--good), #2fa84a);
  color:#04130a;
  box-shadow:var(--shadow-sm);
}
article.card .sev-ribbon.med{background:linear-gradient(180deg, var(--warn), #e08a37);color:#1a0c00;}
article.card .sev-ribbon.high{background:linear-gradient(180deg, var(--bad), #c93a3a);color:#fff;}
article.card .sev-ribbon.crit{
  background:linear-gradient(180deg, var(--crit), #c40044);
  color:#fff;
  box-shadow:var(--shadow-sm), 0 0 16px rgba(255,50,96,0.5);
}
article.card h2{margin:16px 0 8px 0;font-size:22px;line-height:1.3;letter-spacing:-0.012em;font-weight:700;}
article.card h2 a{color:var(--text);text-decoration:none;background-image:linear-gradient(var(--accent),var(--accent));
  background-size:0% 1.5px;background-repeat:no-repeat;background-position:0 100%;
  transition:background-size 0.2s ease;}
article.card h2 a:hover{background-size:100% 1.5px;color:var(--accent);}
article.card .pubmeta{color:var(--muted);font-size:12.5px;margin-bottom:16px;display:flex;gap:14px;flex-wrap:wrap;}
article.card .pubmeta span:not(:first-child)::before{content:"•";margin-right:14px;color:var(--muted-2);}
article.card p.summary{color:var(--text);opacity:0.9;margin:10px 0 18px 0;font-size:14.5px;line-height:1.6;}

.action-row{display:flex;gap:8px;flex-wrap:wrap;margin:6px 0 14px 0;align-items:center;}
.btn{
  background:var(--panel2); border:1px solid var(--border);
  color:var(--text); padding:8px 14px; border-radius:var(--r-md);
  font-size:12px; cursor:pointer; font-family:inherit; font-weight:500;
  display:inline-flex; align-items:center; gap:6px;
  transition:all 0.15s;
}
.btn:hover{background:var(--border);border-color:var(--border-2);transform:translateY(-1px);}
.btn:active{transform:translateY(0);}
.btn-kc{display:inline-flex;align-items:center;gap:6px;}
.kc-chev{transition:transform 0.2s ease;flex-shrink:0;opacity:0.85;}
.btn-kc.primary .kc-chev{transform:rotate(180deg);}
.btn.primary{
  background:linear-gradient(135deg, var(--accent) 0%, #4a98e0 100%);
  color:#04111d; border-color:transparent; font-weight:600;
  box-shadow:0 2px 8px rgba(95,182,255,0.25);
}
.btn.primary:hover{
  background:linear-gradient(135deg, #79c2ff 0%, #5fb6ff 100%);
  box-shadow:0 4px 14px rgba(95,182,255,0.4);
}
.btn-meta{color:var(--muted);font-size:11.5px;margin-left:auto;}

/* ----- Indicator pills ----------------------------------------------- */
.ind-group{display:flex;flex-wrap:wrap;gap:6px;margin:8px 0;align-items:center;}
.ind-label{color:var(--muted);font-size:10.5px;text-transform:uppercase;letter-spacing:0.08em;
  margin-right:6px;font-weight:600;}
.ind{
  background:var(--panel2); border:1px solid var(--border); border-radius:6px;
  padding:3px 9px; font-size:11.5px; font-family:"JetBrains Mono",ui-monospace,monospace;
  color:var(--accent-2); transition:all 0.15s; cursor:default;
  box-shadow:inset 0 1px 0 rgba(255,255,255,0.02), var(--shadow-sm);
}
.ind.cve{color:var(--warn);border-color:#5a3b1f;}
.source-badges{display:flex; gap:6px; flex-wrap:wrap; margin:6px 0 2px;}
.source-badge{
  font-size:10px; font-weight:700; letter-spacing:0.06em;
  padding:3px 9px; border-radius:10px;
  background:var(--panel2); border:1px solid var(--border);
  color:var(--muted); display:inline-flex; align-items:center; gap:4px;
}
.source-badge.thn{background:rgba(95,182,255,0.10); border-color:rgba(95,182,255,0.30); color:var(--accent);}
.source-badge.bc{background:rgba(255,93,93,0.10); border-color:rgba(255,93,93,0.30); color:var(--bad);}
.source-badge.ms{background:rgba(180,141,255,0.10); border-color:rgba(180,141,255,0.30); color:var(--accent-2);}
.source-badge.kev{background:rgba(255,176,96,0.10); border-color:rgba(255,176,96,0.30); color:var(--warn);}
.ind.tech{color:var(--accent-3);border-color:#1d4f43;cursor:pointer;}
.ind.tech:hover{transform:translateY(-1px);box-shadow:0 4px 12px rgba(54,224,192,0.18), var(--shadow-sm);
  border-color:var(--accent-3);}
.ind.malware{color:var(--bad);border-color:#5a1f1f;}

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
.uc-title{font-weight:700; font-size:13.5px; flex:1; min-width:200px;letter-spacing:-0.01em;}
.uc-phase, .uc-conf, .uc-dm{
  font-size:10px; text-transform:uppercase; letter-spacing:0.1em;
  padding:3px 9px; border-radius:999px; font-weight:700;
  background:var(--panel2); border:1px solid var(--border);
}
.uc-phase{color:var(--accent-2); background:rgba(180,141,255,0.1); border-color:rgba(180,141,255,0.2);}
.uc-conf.high{color:var(--good);background:rgba(92,216,122,0.1);border-color:rgba(92,216,122,0.25);}
.uc-conf.medium{color:var(--warn);background:rgba(255,176,96,0.1);border-color:rgba(255,176,96,0.25);}
.uc-conf.low{color:var(--muted);}
.uc-body{padding:0 16px 16px 16px;}
.uc-desc{color:var(--text);opacity:0.88;font-size:12.8px;margin:6px 0 12px 0;line-height:1.6;}
.uc-meta{display:flex;flex-wrap:wrap;gap:6px;margin:8px 0;}

.tabs{
  display:flex; gap:0; padding:4px;
  background:var(--panel); border:1px solid var(--border);
  border-radius:var(--r-md); margin:12px 0 0 0; width:fit-content;
}
.tab-btn{
  padding:7px 14px; background:transparent; border:none; border-radius:6px;
  color:var(--muted); cursor:pointer; font-family:inherit; font-size:12px;
  font-weight:600; transition:all 0.15s; letter-spacing:-0.005em;
}
.tab-btn:hover{color:var(--text);}
.tab-btn.active{
  color:var(--text);
  background:linear-gradient(180deg, var(--panel2), var(--panel-elev));
  box-shadow:var(--shadow-sm), inset 0 1px 0 rgba(255,255,255,0.04);
}
.tab-content{display:none;}
.tab-content.active{display:block;animation:fadeIn 0.2s ease;}
@keyframes fadeIn{from{opacity:0;}to{opacity:1;}}

pre{
  background:var(--code-bg); border:1px solid var(--border);
  border-radius:var(--r-md); padding:14px 16px; overflow:auto;
  font-size:12px; font-family:"JetBrains Mono","Fira Code",ui-monospace,monospace;
  line-height:1.6; margin:10px 0;
  position:relative;
}
pre::-webkit-scrollbar{height:8px;width:8px;}
pre::-webkit-scrollbar-thumb{background:var(--border-2);border-radius:4px;}
pre code{color:var(--text);white-space:pre;}
.copy-btn{
  position:absolute; top:8px; right:8px;
  background:var(--panel2); border:1px solid var(--border);
  color:var(--text); padding:4px 12px; border-radius:6px;
  font-size:10.5px; font-weight:600; cursor:pointer; font-family:inherit;
  transition:all 0.15s; opacity:0.7; letter-spacing:0.04em;
}
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

/* ----- View tabs (Articles / ATT&CK Matrix) -------------------------- */
.view-tabs{
  display:flex; gap:4px; padding:4px;
  background:var(--panel); border:1px solid var(--border);
  border-radius:var(--r-md); width:fit-content;
}
.view-tab{
  padding:8px 18px; background:transparent; border:none; border-radius:6px;
  color:var(--muted); cursor:pointer; font-family:inherit; font-size:13px;
  font-weight:600; transition:all 0.15s; letter-spacing:-0.005em;
  display:inline-flex; align-items:center; gap:6px;
}
.view-tab:hover{color:var(--text);}
.view-tab.active{
  color:var(--text);
  background:linear-gradient(180deg, var(--panel2), var(--panel-elev));
  box-shadow:var(--shadow-sm), inset 0 1px 0 rgba(255,255,255,0.04);
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

/* Drawer (slide-in from right) */
.drawer-bg{
  position:fixed; inset:0; z-index:60;
  background:rgba(0,0,0,0.5); backdrop-filter:blur(4px);
  display:none;
}
.drawer-bg.open{display:block; animation:fadeIn 0.15s;}
.drawer{
  position:fixed; top:0; right:0; bottom:0; width:min(420px, 92%);
  background:var(--panel-elev); border-left:1px solid var(--border-2);
  z-index:61; transform:translateX(110%); transition:transform 0.25s cubic-bezier(0.2,0.8,0.2,1);
  display:flex; flex-direction:column; box-shadow:-12px 0 32px rgba(0,0,0,0.5);
}
.drawer.open{transform:translateX(0);}
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
<header class="topbar">
  <div class="topbar-inner">
    <div class="brand">
      <div class="logo">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 2 L4 6 v6 c0 5 3.5 8 8 10 4.5-2 8-5 8-10 V6z"/>
          <path d="M9 12 l2 2 l4-4"/>
        </svg>
      </div>
      <div class="brand-text">
        <span>Threat Atlas</span>
        <span class="sub">Splunk · Defender · Kill Chain</span>
      </div>
    </div>
    <div class="stats">
      <div class="stat"><div class="v">__ARTICLE_COUNT__</div><div class="l">Articles</div></div>
      <div class="stat"><div class="v">__USECASE_COUNT__</div><div class="l">Use Cases</div></div>
      <div class="stat"><div class="v">__TECH_COUNT__</div><div class="l">ATT&amp;CK</div></div>
      <div class="stat"><div class="v">__CVE_COUNT__</div><div class="l">CVEs</div></div>
      <div class="stat"><div class="v">__CRIT_COUNT__</div><div class="l">Critical</div></div>
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
  if (name === 'matrix' && !window._matrixRendered) {
    renderMatrix();
    window._matrixRendered = true;
  }
  if (name === 'intel' && !window._intelRendered) {
    renderIntel();
    window._intelRendered = true;
  }
}
viewTabs.forEach(b => b.addEventListener('click', () => showView(b.dataset.view)));

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

  document.getElementById('matrixStats').innerHTML =
    `<span><b>${MATRIX.stats.total_techs}</b> techniques</span>` +
    `<span><b>${MATRIX.stats.total_subs}</b> sub-techniques</span>` +
    `<span><b>${MATRIX.stats.covered_techs}</b> covered</span>` +
    `<span><b>${MATRIX.stats.ucs}</b> use cases</span>`;
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
  // popular techniques can have hundreds of UCs. Show internal first, then
  // page through ESCU. Search + source filter inside the drawer.
  // Internal UCs come first, then ESCU sorted alphabetically.
  const ucsSorted = ucs.slice().sort((a, b) => {
    if (a.src !== b.src) return a.src === 'internal' ? -1 : 1;
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
    return `<div class="uc-card-row" data-uc-key="${escapeHtml(uc.n)}" style="padding:8px 10px;background:var(--panel);border:1px solid var(--border);border-radius:6px;margin-bottom:6px;cursor:pointer;">
      <div style="display:flex;align-items:center;gap:8px;">
        <div class="uc-card-title" style="font-weight:600;font-size:12.5px;flex:1;">${escapeHtml(uc.t)}</div>
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
    if (detail.description) {
      html += `<div style="font-size:12px;color:var(--text);opacity:0.92;line-height:1.55;margin-bottom:10px;">${escapeHtml(detail.description)}</div>`;
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
    return allUcs.filter(uc => {
      if (srcF && uc.src !== srcF) return false;
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
  const stats = document.getElementById('intelStats');
  stats.innerHTML =
    `<span><b>${visible}</b> of ${total} IOCs</span>` +
    `<span><b>${counts.cve}</b> CVEs</span>` +
    `<span><b>${counts.ipv4}</b> IPs</span>` +
    `<span><b>${counts.domain}</b> domains</span>` +
    `<span><b>${counts.sha256+counts.sha1+counts.md5}</b> hashes</span>`;
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
        uc_records.append({
            "i": idx,
            "n": det_id[:36],
            "t": det.get("name", det_id)[:140],
            "conf": det.get("type", "Detection"),
            "ph": ph_short,
            "src": "escu",
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
    return out


def _iocs_to_csv_rows(iocs):
    rows = [[
        "value", "type", "severity", "sources", "first_seen",
        "article_titles", "article_links", "source_count", "article_count"
    ]]
    for i in iocs:
        rows.append([
            i["value"], i["type"], i["severity"],
            "; ".join(i["sources"]),
            i.get("first_seen", ""),
            "; ".join(a["title"] for a in i["articles"]),
            "; ".join(a["link"] for a in i["articles"]),
            str(len(i["sources"])), str(len(i["articles"])),
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
            full[key] = {
                "name": det.get("name", ""),
                "description": det.get("description", ""),
                "kill_chain": (det.get("kill_chain_phases") or [""])[0],
                "confidence": det.get("type", "Detection"),
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

    for i, a in enumerate(articles):
        text = f"{a['title']}\n{a['raw_body']}"
        ind = extract_indicators(a["title"], a["raw_body"])
        techniques = infer_techniques(text, ind["explicit_ttps"])
        ucs = select_use_cases(text, ind)
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


if __name__ == "__main__":
    main()

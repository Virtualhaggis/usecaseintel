# Intel Feed — IOC Threat Intelligence

**Real-time Indicator of Compromise feed, curated from the best security threat reporting.**

This folder contains an automatically-refreshed feed of Indicators of Compromise (IOCs) — CVEs, IPs, domains, file hashes — extracted from the day's most significant security articles. Built for SOC analysts, threat hunters, and detection engineers who want **signal, not noise**.

## Mission

Provide actionable, contextualised threat intelligence drawn from the day's best security reporting — not a generic IOC firehose. Every indicator in this feed has a real-world story attached: who reported it, when, what malware/actor it relates to, and a link back to the source so an analyst can drill in.

## Sources

| Publication | Why we pull it |
|---|---|
| **The Hacker News** | Independent security journalism — broad coverage of breaches, malware, threat actors |
| **BleepingComputer** | Fast incident reporting, malware family deep-dives, vendor advisories |
| **Microsoft Security Blog** | First-party Microsoft research on Windows/Azure/Defender threats |
| **CISA KEV** | The U.S. federal "patch this now" catalog — known-exploited CVEs only |

Sources are deduplicated: if THN and BleepingComputer both cover the same incident, the IOC appears once with both publications listed.

## How to consume

### Always-current raw URLs

| Format | URL | Best for |
|---|---|---|
| **CSV** | [`intel/iocs.csv`](https://raw.githubusercontent.com/Virtualhaggis/usecaseintel/main/intel/iocs.csv) | Spreadsheets, generic SIEM imports, Excel triage |
| **JSON** | [`intel/iocs.json`](https://raw.githubusercontent.com/Virtualhaggis/usecaseintel/main/intel/iocs.json) | Scripts, APIs, programmatic ingestion |
| **STIX 2.1** | [`intel/iocs.stix.json`](https://raw.githubusercontent.com/Virtualhaggis/usecaseintel/main/intel/iocs.stix.json) | Threat Intelligence Platforms (MISP, OpenCTI, Anomali, ThreatConnect) |
| **Splunk lookup** | [`intel/splunk_lookup_iocs.csv`](https://raw.githubusercontent.com/Virtualhaggis/usecaseintel/main/intel/splunk_lookup_iocs.csv) | Splunk Enterprise `inputlookup` |

Pull the latest at any time:

```bash
curl https://raw.githubusercontent.com/Virtualhaggis/usecaseintel/main/intel/iocs.csv -o iocs.csv
```

## What each column tells the analyst

| Column | What it means | What to do with it |
|---|---|---|
| `value` | The actual indicator — the CVE ID, IP address, domain, or file hash | Search your telemetry for matches |
| `type` | `cve` / `ipv4` / `domain` / `sha256` / `sha1` / `md5` | Routes you to the right Splunk data model or Defender table |
| `severity` | `crit` / `high` / `med` / `low` — inherited from the article reporting the IOC | Prioritises which to triage first |
| `sources` | Publication(s) that reported this IOC | Higher source count = stronger consensus on relevance |
| `first_seen` | Earliest article publication date | Lets you bound your hunt window — start from this date |
| `article_titles` | Headline(s) describing the IOC | Tells you the *story* — which malware/campaign/actor this came from |
| `article_links` | Direct URLs to the source articles | Click through for full context, attacker TTPs, additional IOCs |
| `source_count` | How many distinct publications reported it | Confidence signal — IOCs reported by 2+ sources are usually high-quality |
| `article_count` | How many distinct articles mention it | A frequently-cited IOC is a hot one |

## Severity levels — what they mean

| Level | Meaning | Triage action |
|---|---|---|
| `crit` | Multiple sources + zero-day language + active exploitation | Investigate immediately, page the on-call |
| `high` | Confirmed exploitation, named threat actor (APT/ransomware family), CISA KEV entry | Hunt during this shift |
| `med` | Reported activity, malware family identified, supply-chain incident | Add to your weekly hunt queue |
| `low` | Background reporting, no urgency signals | Optional — useful for context |

## What you're looking at — by IOC type

### CVE — vulnerability identifier
A specific software vulnerability (`CVE-2026-XXXXX`). Each CVE in this feed has been **reported as exploited** or actively researched, not theoretical.
- **Splunk**: search `Vulnerabilities.signature` against your vulnerability scanner data
- **Defender**: query `DeviceTvmSoftwareVulnerabilities | where CveId in (…)`
- **What it tells you**: which assets in your fleet are exposed *right now*

### IPv4 — attacker-controlled address
An IP address used as C2, scanner, redirector, or exfiltration endpoint. Article context tells you whether it's a beacon, a phishing landing host, or part of a botnet.
- **Splunk**: search `Network_Traffic.All_Traffic` for outbound to these destinations
- **Defender**: `DeviceNetworkEvents | where RemoteIP in (…)`
- **What it tells you**: who in your environment talked to attacker infrastructure

### Domain — attacker-owned hostname
Used for command-and-control, phishing, or malware distribution. Often more durable than IPs (attackers rotate IPs, retain domains).
- **Splunk**: search `Network_Resolution.DNS` and `Web.url` for these domains
- **Defender**: `DeviceNetworkEvents | where RemoteUrl has_any (…)`
- **What it tells you**: which users tried to resolve a malicious hostname

### Hashes (SHA256 / SHA1 / MD5)
Cryptographic fingerprints of malicious files. SHA256 is the strongest; MD5 is included for legacy IOC compatibility.
- **Splunk**: search `Endpoint.Filesystem.file_hash` and `Endpoint.Processes.process_hash`
- **Defender**: `DeviceFileEvents | where SHA256 in (…)` (or SHA1 / MD5 columns)
- **What it tells you**: whether a known-malicious file ever touched a host

## Refresh cadence

| When | What runs |
|---|---|
| **Daily 08:00 UTC** | `run_daily.bat` — re-extracts IOCs from the last 30 days of articles; auto-commits the changed `intel/*.{csv,json}` files to `main` |
| **Weekly Mon 06:00 UTC** | `run_weekly.bat` — also refreshes Splunk ESCU + Defender Hunting Queries + MITRE ATT&CK registries |

The CSV/JSON/STIX files in this folder are **always the most recent successful run**. If the daily job didn't run (network/error), the file timestamp tells you the last good refresh.

## Quality signals to watch

- **`source_count >= 2`** — at least two independent publications reported it. Stronger signal of relevance.
- **`severity = high|crit`** — high-priority. Likely exploited or KEV-listed.
- **`first_seen` within the last 7 days** — fresh; attackers may still be using it.

A low-severity IOC reported by one source 25 days ago is almost certainly stale — feel free to deprioritise.

## Pipeline integrations

### Splunk

```spl
| inputlookup splunk_lookup_iocs.csv WHERE indicator_type="ipv4" AND severity IN ("high","crit")
| rename indicator AS dest
| join type=inner dest [
    | tstats `summariesonly` count earliest(_time) AS first_contact
            from datamodel=Network_Traffic.All_Traffic
            by All_Traffic.dest, All_Traffic.src
  ]
| table _time src dest count first_contact severity description source_url
```

### Defender XDR (Advanced Hunting)

```kql
let badIPs = externaldata(IP:string) [@"https://raw.githubusercontent.com/Virtualhaggis/usecaseintel/main/intel/iocs.csv"]
    with(format="csv", ignoreFirstRecord=true);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIP in (badIPs | project IP)
| project Timestamp, DeviceName, RemoteIP, RemoteUrl, InitiatingProcessFileName
```

### Microsoft Sentinel

Use the [Threat Intelligence — TAXII data connector](https://learn.microsoft.com/en-us/azure/sentinel/connect-threat-intelligence-taxii) and point it at the STIX 2.1 file URL.

### TIPs (MISP / OpenCTI / Anomali)

Import `iocs.stix.json` directly — it's a STIX 2.1 bundle of `indicator` objects with proper patterns, severity tags (`x_severity`), source attribution (`x_sources`), and external references back to source articles.

## How we earn the SOC's trust — high-fidelity extraction only

A bad IOC feed will make an analyst block legitimate Microsoft / Google / GitHub traffic. Trust is earned by being honest about what we can and cannot reliably extract from RSS article summaries.

### What we extract (and why we trust it)

| Type | How | Why it's reliable |
|---|---|---|
| `cve` | Regex `CVE-\d{4}-\d{4,7}` | Unambiguous format. CVEs in articles are about the CVE — they're never coincidental. CISA KEV in particular is the federal "exploited in the wild" gold standard. |
| `sha256` / `sha1` / `md5` | Regex (32 / 40 / 64 hex chars) | High entropy, low false-positive rate. A hex string of this length appearing in a security article is almost always being called out as malicious. |
| `ipv4` | **Defanged form only** — `1[.]2[.]3[.]4` | Researchers explicitly mark IOCs as defanged so URLs don't auto-link. This is a strong "I, the author, am tagging this as malicious" signal. |
| `domain` | **Defanged form only** — `evil[.]com`, or `hxxps://evil-c2.io/path` | Same reasoning. Plain-text domain mentions like "outlook.com" or "github.com" are almost always the legitimate target / platform / vendor — NOT IOCs. |

### What we deliberately do NOT extract

Plain-text domain or IP mentions in article summaries.

A previous version of this pipeline did extract them and produced false positives like:
- `outlook.com` — from "Microsoft asks iPhone users to reauthenticate after **Outlook** outage"
- `asp.net` — from "Microsoft Patches Critical **ASP.NET** Core CVE"
- `context.ai` — from "Vercel breach exposes **Context.ai** customer data"

A SOC analyst running these through their proxy logs would block all their organisation's legitimate Outlook / ASP.NET / Context.ai traffic. Catastrophic.

The correct behaviour for a SOC feed is: **if the source author hasn't taken the small step of defanging their IOCs, we cannot tell programmatically whether a domain is the attacker's infrastructure or the victim's**. RSS summaries just don't carry the context. So we don't pretend.

### Defanged IOC examples

These would be picked up — researcher convention for sharing IOCs safely:

```
The implant beaconed to 185[.]220[.]101[.]50 on port 443.
Phishing emails linked to hxxps://drive-share[.]xyz/auth.html
Watering-hole infrastructure observed at evil-corp[.]io
```

These would NOT be picked up — too ambiguous for a feed:

```
"… users with outlook.com accounts were affected …"      (legitimate target)
"… exploited via ASP.NET deserialisation …"              (technology mention)
"… first reported by bleepingcomputer.com …"             (news source)
```

### Confidence model

Every IOC carries a `confidence` field:

| Value | Meaning |
|---|---|
| `high` | Default — passed the extraction quality bar |
| `medium` / `low` | Reserved for future LLM-augmented enrichment paths; not currently emitted |

Every IOC also carries an `extraction` field telling you the path it took:

| Value | Meaning |
|---|---|
| `regex` | CVE or hash matched by literal regex |
| `defanged` | Domain or IP matched only because it appeared in defanged form |

If you want to widen the funnel (e.g. pull plain-text domains too) for some specific consumer, fork this pipeline and adjust `extract_indicators()` — but understand the FP risk you're accepting.

## What this means in practice today

Today's feed has **36 IOCs** — all CVEs from CISA KEV. That's not a bug; it reflects the fact that:
- KEV is a clean, structured, authoritative feed
- The RSS summaries from THN / BleepingComputer / Microsoft Security Blog rarely contain defanged IOCs (those live in the body of the technical write-ups, which we cannot scrape)

So this feed is **complementary** to whatever paid TI you have, not a replacement. Where it shines:
- KEV CVE-to-asset matching (`Vulnerabilities.signature` / `DeviceTvmSoftwareVulnerabilities.CveId`)
- News-driven prioritisation: "what should my team be hunting for THIS week"
- Free, public, transparent provenance for every IOC

If a future article publishes defanged IPs/hashes, those will appear here automatically and inherit the same high-confidence classification.

## Contributing

If you spot a missing IOC type, want to add a new source, or improve the extractor, see [CONTRIBUTING.md](../CONTRIBUTING.md). PRs welcome.

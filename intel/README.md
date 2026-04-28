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

## Limitations & honesty

- IOCs are extracted from RSS article **summaries** (~400 chars each). Most articles only embed CVEs in the summary; raw IPs/hashes/domains often live deep in article bodies that aren't in the RSS feed.
- THN and other publishers block server-side scraping (HTTP 403), so we don't fetch full article bodies.
- **CVE coverage is comprehensive** thanks to CISA KEV (a clean JSON feed).
- **IP/domain/hash coverage is intentionally conservative** — we'd rather underreport than ship false positives.

If you have access to richer feeds (paid TI providers, internal SOC observations), this feed is best used as a *starting point* — not a replacement.

## Contributing

If you spot a missing IOC type, want to add a new source, or improve the extractor, see [CONTRIBUTING.md](../CONTRIBUTING.md). PRs welcome.

# [CRIT] Coruna: the framework used in Operation Triangulation

**Source:** Securelist (Kaspersky)
**Published:** 2026-03-26
**Article:** https://securelist.com/coruna-framework-updated-operation-triangulation-exploit/119228/

## Threat Profile

Table of Contents
Introduction 
Technical details 
Safari 
Payload 
Kernel exploits 
Launcher 
Conclusions 
Authors
Boris Larin 
Introduction 
On March 4, 2026, Google and iVerify published reports about a highly sophisticated exploit kit targeting Apple iPhone devices. According to Google, the exploit kit was first discovered in targeted attacks conducted by a customer of an unnamed surveillance vendor. It was later used by other attackers in watering-hole attacks in Ukraine and in financially …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2023-32434`
- **CVE:** `CVE-2023-38606`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1189** — Drive-by Compromise
- **T1583.001** — Acquire Infrastructure: Domains
- **T1203** — Exploitation for Client Execution
- **T1059.007** — Command and Scripting Interpreter: JavaScript

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Coruna iOS exploit kit delivery domain callouts (UNC6353/UNC6691 watering-holes)

`UC_159_1` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.user_agent) as user_agent values(Web.src) as src values(Web.dest) as dest from datamodel=Web where Web.url IN ("*b27.icu*","*7p.game*","*mxbc-v2.tjbjdod.cn*","*cdn.uacounter.com*","*tjbjdod.cn*","*uacounter.com*") OR Web.dest IN ("b27.icu","7p.game","mxbc-v2.tjbjdod.cn","cdn.uacounter.com") by Web.src Web.dest Web.http_method | `drop_dm_object_name(Web)` | append [| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(DNS.src) as src values(DNS.query) as query from datamodel=Network_Resolution where DNS.query IN ("b27.icu","7p.game","mxbc-v2.tjbjdod.cn","cdn.uacounter.com","*.tjbjdod.cn","*.uacounter.com") by DNS.src DNS.query | `drop_dm_object_name(DNS)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let coruna_domains = dynamic(["b27.icu","7p.game","mxbc-v2.tjbjdod.cn","tjbjdod.cn","cdn.uacounter.com","uacounter.com"]);
DeviceNetworkEvents
| where Timestamp > ago(90d)
| where ActionType in ("ConnectionSuccess","HttpConnectionInspected","DnsConnectionInspected")
| where RemoteUrl has_any (coruna_domains) or RemoteIPType == "Public" and tostring(AdditionalFields) has_any (coruna_domains)
| project Timestamp, DeviceName, DeviceId, OSPlatform, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort, ActionType, AdditionalFields
| order by Timestamp desc
```

### [LLM] Coruna stager URI '/static/analytics.html' fetched by mobile Safari

`UC_159_2` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.http_referrer) as referrer values(Web.dest) as dest values(Web.http_user_agent) as ua from datamodel=Web where Web.url="*/static/analytics.html*" by Web.src Web.dest Web.http_user_agent | `drop_dm_object_name(Web)` | where match(ua,"(?i)iPhone|iPad|CPU OS|Mobile/.*Safari") AND NOT match(dest,"(?i)(google-analytics\.com|googletagmanager\.com|doubleclick\.net|cloudflareinsights\.com)$") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(60d)
| where OSPlatform in ("iOS","iPadOS") or InitiatingProcessFileName in~ ("MobileSafari","SafariViewService","com.apple.WebKit.WebContent")
| where RemoteUrl endswith "/static/analytics.html" or RemoteUrl contains "/static/analytics.html?"
| where not(RemoteUrl has_any ("google-analytics.com","googletagmanager.com","doubleclick.net","cloudflareinsights.com"))
| project Timestamp, DeviceName, DeviceId, OSPlatform, InitiatingProcessFileName, RemoteUrl, RemoteIP, ActionType
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2023-32434`, `CVE-2023-38606`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 3 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

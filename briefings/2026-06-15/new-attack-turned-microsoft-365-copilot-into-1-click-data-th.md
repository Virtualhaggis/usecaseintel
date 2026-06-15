# [HIGH] New attack turned Microsoft 365 Copilot into 1-click data theft tool

**Source:** BleepingComputer, Cyber Security News
**Published:** 2026-06-15
**Article:** https://www.bleepingcomputer.com/news/security/new-attack-turned-microsoft-365-copilot-into-1-click-data-theft-tool/

## Threat Profile

New attack turned Microsoft 365 Copilot into 1-click data theft tool 
By Bill Toulas 
June 15, 2026
09:00 AM
0 
A critical vulnerability chain dubbed SearchLeak in Microsoft 365 Copilot Enterprise could allow attackers to steal sensitive data from a target's mailbox, OneDrive, or SharePoint account through a specially crafted URL.
The exfiltrated information could be email content (e.g., access codes, passwords), calendar events and meeting details, documents, and other content accessible throug…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-42824`
- **Domain (defanged):** `attacker.com`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1071** — Application Layer Protocol
- **T1566.002** — Phishing: Spearphishing Link
- **T1059** — Command and Scripting Interpreter
- **T1213** — Data from Information Repositories
- **T1204.001** — User Execution: Malicious Link
- **T1567** — Exfiltration Over Web Service
- **T1090.002** — Proxy: External Proxy

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### SearchLeak: Inbound email carrying crafted M365 Copilot Search URL with prompt-injection q parameter (CVE-2026-42824)

`UC_1_2` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, min(_time) as firstTime, max(_time) as lastTime, values(All_Email.subject) as subject, values(All_Email.src_user) as sender, values(All_Email.recipient) as recipient, values(All_Email.url) as url from datamodel=Email where (All_Email.url IN ("*m365.cloud.microsoft*","*copilot.cloud.microsoft*","*copilot.microsoft.com*","*office.com/chat*")) AND (All_Email.url IN ("*?q=*","*&q=*","*%3Fq%3D*")) AND (All_Email.url IN ("*extract*","*embed*","*imgurl*","*%3Cimg*","*search%20the%20user*","*search the user*","*mailbox*","*calendar*","*sharepoint*","*onedrive*")) by All_Email.message_id, All_Email.src_user, All_Email.recipient | `drop_dm_object_name(All_Email)` | convert ctime(firstTime), ctime(lastTime)
```

**Defender KQL:**
```kql
let CopilotDomains = dynamic(["m365.cloud.microsoft","copilot.cloud.microsoft","copilot.microsoft.com","office.com"]);
let InjectionMarkers = dynamic(["extract","embed","imgurl","%3cimg","<img","search the user","search%20the%20user","mailbox","calendar","sharepoint","onedrive"]);
EmailUrlInfo
| where Timestamp > ago(14d)
| where UrlDomain has_any (CopilotDomains)
| where Url has_any ("?q=","&q=","%3Fq%3D","%26q%3D")
| where Url has_any (InjectionMarkers) or strlen(Url) > 1200
| join kind=inner (
    EmailEvents
    | where Timestamp > ago(14d)
    | where EmailDirection == "Inbound"
  ) on NetworkMessageId
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderFromDomain, RecipientEmailAddress, Subject, Url, UrlDomain, DeliveryAction, DeliveryLocation
| order by Timestamp desc
```

### SearchLeak: User click of M365 Copilot Search URL with prompt-injection q parameter (CVE-2026-42824)

`UC_1_3` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, min(_time) as firstTime, max(_time) as lastTime, values(Web.url) as url from datamodel=Web where (Web.url IN ("*m365.cloud.microsoft*","*copilot.cloud.microsoft*","*copilot.microsoft.com*")) AND (Web.url IN ("*?q=*","*&q=*","*%3Fq%3D*")) AND (Web.url IN ("*extract*","*embed*","*imgurl*","*%3Cimg*","*search the user*","*mailbox*","*calendar*","*sharepoint*","*onedrive*")) by Web.src, Web.user, Web.dest, Web.http_referrer | `drop_dm_object_name(Web)` | convert ctime(firstTime), ctime(lastTime)
```

**Defender KQL:**
```kql
let CopilotDomains = dynamic(["m365.cloud.microsoft","copilot.cloud.microsoft","copilot.microsoft.com"]);
let InjectionMarkers = dynamic(["extract","embed","imgurl","%3cimg","<img","search the user","search%20the%20user","mailbox","calendar","sharepoint","onedrive"]);
UrlClickEvents
| where Timestamp > ago(14d)
| where Url has_any (CopilotDomains)
| where Url has_any ("?q=","&q=","%3Fq%3D","%26q%3D")
| where Url has_any (InjectionMarkers) or strlen(Url) > 1200
| where ActionType in ("ClickAllowed","ClickedThrough","UrlScanInProgress")
| project Timestamp, AccountUpn, Url, Workload, ActionType, IPAddress, UrlChain, NetworkMessageId
| order by Timestamp desc
```

### SearchLeak: Bing image-search SSRF carrier with imgurl exfil parameter (CVE-2026-42824)

`UC_1_4` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, min(_time) as firstTime, max(_time) as lastTime, values(Web.url) as url, values(Web.http_referrer) as referrer from datamodel=Web where (Web.dest IN ("www.bing.com","bing.com","*.bing.com")) AND (Web.url IN ("*images/search*")) AND (Web.url IN ("*iss=sbi*","*sbisrc=urlpaste*","*sbisrc=UrlPaste*","*imgurl%3a*","*imgurl=*","*form=sbivsp*","*form=SBIVSP*")) by Web.src, Web.user, Web.dest, Web.http_user_agent | `drop_dm_object_name(Web)` | eval url_len = len(mvindex(url,0)) | where url_len > 300 | rex field=url "imgurl(?:=|%3a)(?<exfil_url>[^&\s]+)" | convert ctime(firstTime), ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteUrl has "bing.com/images/search"
| where RemoteUrl has_any ("iss=sbi","sbisrc=urlpaste","imgurl%3a","imgurl=","form=sbivsp")
| where strlen(RemoteUrl) > 300
| where InitiatingProcessFileName in~ ("msedge.exe","chrome.exe","firefox.exe","brave.exe","iexplore.exe","opera.exe")
| extend ExfilCandidate = extract(@"imgurl(?:=|%3[aA])([^&\s]+)", 1, RemoteUrl)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessParentFileName, RemoteIP, RemoteUrl, UrlLen=strlen(RemoteUrl), ExfilCandidate
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-42824`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `attacker.com`


## Why this matters

Severity classified as **HIGH** based on: CVE present, IOCs present, 5 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

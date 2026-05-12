# [MED] Instructure confirms hackers used Canvas flaw to deface portals

**Source:** BleepingComputer
**Published:** 2026-05-11
**Article:** https://www.bleepingcomputer.com/news/security/instructure-confirms-hackers-used-canvas-flaw-to-deface-portals/

## Threat Profile

Instructure confirms hackers used Canvas flaw to deface portals 
By Ionut Ilascu 
May 11, 2026
11:26 AM
0 
Education technology giant Instructure has confirmed that a security vulnerability allowed hackers to modify Canvas login portals and leave an extortion message.
BleepingComputer has learned that both the breach and defacements involved multiple cross-site scripting (XSS) vulnerabilities that enabled the attacker to obtain authenticated admin sessions.
The second hack was to draw attention …

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1189** — Drive-by Compromise
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1190** — Exploit Public-Facing Application
- **T1219** — Remote Access Software
- **T1102** — Web Service
- **T1573.002** — Encrypted Channel: Asymmetric Cryptography

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Canvas LMS access during ShinyHunters XSS defacement window (May 7–9 2026)

`UC_69_0` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count earliest=1746576000 latest=1746835200 from datamodel=Web.Web where (Web.url="*canvas.instructure.com*" OR Web.url="*.instructure.com*" OR Web.dest="canvas.instructure.com" OR Web.dest="*.instructure.com") by Web.src, Web.user, Web.user_agent, Web.dest, Web.url, _time | `drop_dm_object_name("Web")` | stats min(_time) as FirstSeen max(_time) as LastSeen values(url) as URLs count by src, user, user_agent, dest | sort - LastSeen
```

**Defender KQL:**
```kql
// ShinyHunters Canvas defacement window: 2026-05-07 → 2026-05-09
DeviceNetworkEvents
| where Timestamp between (datetime(2026-05-07 00:00:00) .. datetime(2026-05-09 23:59:59))
| where RemoteUrl has "instructure.com"
   or RemoteUrl has "canvas.instructure.com"
| where InitiatingProcessFileName in~ (
    "chrome.exe","msedge.exe","firefox.exe","brave.exe",
    "safari.exe","iexplore.exe","opera.exe","arc.exe")
| where InitiatingProcessAccountName !endswith "$"
| summarize FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp),
            ConnectionCount = count(),
            URLs = make_set(RemoteUrl, 25),
            RemoteIPs = make_set(RemoteIP, 10)
            by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName
| order by FirstSeen asc
```

### [LLM] Tox / qTox messenger presence — ShinyHunters Canvas extortion contact channel

`UC_69_1` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Endpoint.Processes where (Processes.process_name IN ("qtox.exe","qTox.exe","QTOX.EXE","qtox-setup.exe","qTox-setup.exe","utox.exe","uTox.exe","uTox_64.exe","utox_64.exe","toxic.exe","tox-node.exe") OR Processes.process IN ("*qtox.exe*","*utox.exe*","*toxic*")) by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process, _time | `drop_dm_object_name("Processes")` | append [ | tstats summariesonly=true count from datamodel=Network_Resolution.DNS where (DNS.query="*tox.chat*" OR DNS.query="qtox.github.io" OR DNS.query="jenkins.tox.chat" OR DNS.query="nodes.tox.chat") by DNS.src, DNS.query, _time | `drop_dm_object_name("DNS")` ] | append [ | tstats summariesonly=true count from datamodel=Web.Web where (Web.url="*tox.chat*" OR Web.url="*qtox.github.io*") by Web.src, Web.user, Web.url, _time | `drop_dm_object_name("Web")` ] | sort - _time
```

**Defender KQL:**
```kql
// Hunt: Tox messenger artefacts — file drop, process exec, or network egress.
// ShinyHunters' May 2026 Canvas defacement message instructed victims to negotiate via TOX.
let _tox_binaries = dynamic(["qtox.exe","qtox-setup.exe","utox.exe","utox_64.exe","toxic.exe","tox-node.exe"]);
let _tox_domains = dynamic(["tox.chat","qtox.github.io","jenkins.tox.chat","nodes.tox.chat"]);
union isfuzzy=true
  ( DeviceFileEvents
    | where Timestamp > ago(14d)
    | where FileName in~ (_tox_binaries)
       or FileName matches regex @"(?i)^q?tox.*\.exe$"
    | where InitiatingProcessAccountName !endswith "$"
    | project Timestamp, Signal = "FileWrite", DeviceName, Account = InitiatingProcessAccountName,
              FileName, FolderPath, SHA256,
              Parent = InitiatingProcessFileName, ParentCmd = InitiatingProcessCommandLine ),
  ( DeviceProcessEvents
    | where Timestamp > ago(14d)
    | where FileName in~ (_tox_binaries)
       or ProcessCommandLine has_any ("qtox.exe","utox.exe","toxic.exe","--tox-id")
    | where AccountName !endswith "$"
    | project Timestamp, Signal = "ProcessExec", DeviceName, Account = AccountName,
              FileName, FolderPath = InitiatingProcessFolderPath, SHA256,
              Parent = InitiatingProcessFileName, ParentCmd = ProcessCommandLine ),
  ( DeviceNetworkEvents
    | where Timestamp > ago(14d)
    | where RemoteUrl has_any (_tox_domains)
       or RemoteUrl matches regex @"(?i)(^|\.)tox\.chat$"
    | where InitiatingProcessAccountName !endswith "$"
    | project Timestamp, Signal = "NetworkEgress", DeviceName, Account = InitiatingProcessAccountName,
              FileName = InitiatingProcessFileName, FolderPath = InitiatingProcessFolderPath, SHA256 = InitiatingProcessSHA256,
              Parent = RemoteUrl, ParentCmd = strcat(RemoteIP, ":", tostring(RemotePort)) )
| order by Timestamp desc
```


## Why this matters

Severity classified as **MED** based on: 2 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

# [HIGH] Legitimate-Looking Codex Remote UI Steals OpenAI Codex Authentication Tokens

**Source:** Cyber Security News
**Published:** 2026-05-29
**Article:** https://cybersecuritynews.com/legitimate-looking-codex-remote-ui/

## Threat Profile

Home Cyber Security News 
Legitimate-Looking Codex Remote UI Steals OpenAI Codex Authentication Tokens 
By Tushar Subhra Dutta 
May 29, 2026 
A polished, fully functional npm package has been caught secretly stealing OpenAI Codex authentication tokens from developers who trusted it. 
The package, named codexui-android, presented itself as a remote web UI for OpenAI Codex with no obvious signs of being malicious. 
It built a genuine user base, amassed 27,000 weekly downloads, and maintained an ac…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `sentry.anyclaw.store`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1204.002** — User Execution: Malicious File
- **T1041** — Exfiltration Over C2 Channel
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1567** — Exfiltration Over Web Service
- **T1132.001** — Data Encoding: Standard Encoding
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1195.002** — Supply Chain Compromise
- **T1027.002** — Obfuscated Files or Information: Software Packing

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Outbound traffic to BrutalStrike Codex stealer C2 (anyclaw.store /startlog)

`UC_24_4` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src) as src values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.app) as app from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="sentry.anyclaw.store" OR All_Traffic.dest="*.anyclaw.store" OR All_Traffic.dest="anyclaw.store" OR All_Traffic.url="*anyclaw.store/startlog*") by All_Traffic.src All_Traffic.dest All_Traffic.url host | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let c2_domains = dynamic(["sentry.anyclaw.store","anyclaw.store"]);
union isfuzzy=true
( DeviceNetworkEvents
  | where Timestamp > ago(30d)
  | where RemoteUrl has_any (c2_domains) or RemoteUrl has "anyclaw.store/startlog"
  | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, ActionType),
( DeviceEvents
  | where Timestamp > ago(30d)
  | where ActionType == "DnsQueryResponse" or ActionType == "ConnectionSuccess"
  | where RemoteUrl has_any (c2_domains) or AdditionalFields has "anyclaw.store"
  | project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, ActionType)
| order by Timestamp desc
```

### [LLM] HTTP POST to /startlog with XOR+base64 stealer beacon shape

`UC_24_5` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.src) as src values(Web.user) as user values(Web.http_user_agent) as ua from datamodel=Web.Web where Web.http_method="POST" AND (Web.url="*/startlog*" OR Web.uri_path="/startlog") by Web.src Web.dest Web.url Web.http_method host | `drop_dm_object_name(Web)` | where match(url,"(?i)/startlog") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where ActionType in ("ConnectionSuccess","HttpConnectionInspected")
| where RemoteUrl has "/startlog" or RemoteUrl endswith "anyclaw.store"
| where InitiatingProcessFileName in~ ("node.exe","npm.exe","npx.exe","electron.exe","chrome.exe","msedge.exe","java.exe","adb.exe","qemu-system-x86_64.exe")
   or InitiatingProcessCommandLine has_any ("codexui-android","chunk-PUR7OUAG","dist-cli/index.js")
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### [LLM] codexui-android npm package install or chunk-PUR7OUAG.js write on developer host

`UC_24_6` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.user) as user values(Filesystem.process_name) as process from datamodel=Endpoint.Filesystem where (Filesystem.file_name="chunk-PUR7OUAG.js" OR Filesystem.file_path="*node_modules*codexui-android*" OR Filesystem.file_path="*codexui-android*dist-cli*index.js") by Filesystem.dest Filesystem.file_path Filesystem.file_name host | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| where FileName == "chunk-PUR7OUAG.js"
   or FolderPath has @"node_modules\codexui-android"
   or FolderPath has "node_modules/codexui-android"
   or (FolderPath has "codexui-android" and FileName =~ "index.js" and FolderPath has "dist-cli")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName, SHA256
| order by Timestamp desc
```

### [LLM] Codex auth.json read followed by outbound HTTP within 60s (token theft pattern)

`UC_24_7` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Endpoint.Filesystem where Filesystem.file_name="auth.json" AND (Filesystem.file_path="*\\.codex\\*" OR Filesystem.file_path="*/.codex/*") by Filesystem.dest Filesystem.process_name Filesystem.user Filesystem.file_path _time | `drop_dm_object_name(Filesystem)` | rename _time as readTime | join type=inner dest process_name [| tstats summariesonly=true count from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port=443 AND All_Traffic.direction="outbound" by All_Traffic.src All_Traffic.dest All_Traffic.app _time | `drop_dm_object_name(All_Traffic)` | rename _time as netTime src as dest app as process_name] | where netTime>=readTime AND netTime<=readTime+60 | table readTime netTime dest process_name user file_path
```

**Defender KQL:**
```kql
let lookback = 30d;
let auth_reads = DeviceFileEvents
  | where Timestamp > ago(lookback)
  | where FileName =~ "auth.json"
  | where FolderPath has @"\.codex\" or FolderPath has "/.codex/" or FolderPath has "codex\auth.json" or FolderPath has "codex/auth.json"
  | where InitiatingProcessFileName in~ ("node.exe","electron.exe","npm.exe","npx.exe","java.exe","adb.exe")
  | project ReadTime=Timestamp, DeviceId, DeviceName, AuthFolderPath=FolderPath, InitiatingProcessFileName, InitiatingProcessId, InitiatingProcessAccountName, InitiatingProcessCommandLine;
let net_egress = DeviceNetworkEvents
  | where Timestamp > ago(lookback)
  | where ActionType == "ConnectionSuccess"
  | where RemoteIPType == "Public" and RemotePort in (443,80)
  | where InitiatingProcessFileName in~ ("node.exe","electron.exe","npm.exe","npx.exe","java.exe","adb.exe")
  | project NetTime=Timestamp, DeviceId, InitiatingProcessId, RemoteUrl, RemoteIP, RemotePort;
auth_reads
| join kind=inner net_egress on DeviceId, InitiatingProcessId
| where NetTime between (ReadTime .. ReadTime + 60s)
| extend DelaySec = datetime_diff('second', NetTime, ReadTime)
| project ReadTime, NetTime, DelaySec, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, AuthFolderPath, RemoteUrl, RemoteIP
| order by ReadTime desc
```

### [LLM] Android emulator / WSL extracts Linux rootfs and runs node.exe pulling unpinned npm

`UC_24_8` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where Processes.process_name="node.exe" AND (Processes.process="*npm install codexui-android*" OR Processes.process="*npx*codexui-android*" OR Processes.process="*codexui-android*" OR Processes.parent_process="*rootfs.tar.zst.bin*") by Processes.dest Processes.user Processes.process_name Processes.parent_process_name host | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
union isfuzzy=true
( DeviceFileEvents
  | where Timestamp > ago(30d)
  | where FileName =~ "rootfs.tar.zst.bin" or FileName endswith ".tar.zst.bin"
  | project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName, EventKind="rootfs-drop"),
( DeviceProcessEvents
  | where Timestamp > ago(30d)
  | where FileName =~ "node.exe" or FileName =~ "npm.exe" or FileName =~ "npx.exe"
  | where ProcessCommandLine has "codexui-android"
     or InitiatingProcessFolderPath has "app.anyclaw"
     or InitiatingProcessCommandLine has "gptos.intelligence.assistant"
     or InitiatingProcessCommandLine has "codex.app"
  | project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, EventKind="node-pulls-codexui")
| order by Timestamp desc
```

### Beaconing — periodic outbound to small set of destinations

`UC_BEACONING` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
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
```

**Defender KQL:**
```kql
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
```

### OAuth consent / suspicious app grant

`UC_OAUTH_ABUSE` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
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
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("Consent to application.","Add OAuth2PermissionGrant.","Add delegated permission grant.")
| project Timestamp, AccountObjectId, AccountDisplayName, ActivityType,
          ActivityObjects, IPAddress, UserAgent
```

### Article-specific behavioural hunt — Legitimate-Looking Codex Remote UI Steals OpenAI Codex Authentication Tokens

`UC_24_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Legitimate-Looking Codex Remote UI Steals OpenAI Codex Authentication Tokens ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("chunk-pur7ouag.js","node.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("chunk-pur7ouag.js","node.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Legitimate-Looking Codex Remote UI Steals OpenAI Codex Authentication Tokens
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("chunk-pur7ouag.js", "node.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("chunk-pur7ouag.js", "node.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `sentry.anyclaw.store`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 9 use case(s) fired, 16 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

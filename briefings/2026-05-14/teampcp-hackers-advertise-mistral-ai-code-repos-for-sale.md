# [HIGH] TeamPCP hackers advertise Mistral AI code repos for sale

**Source:** BleepingComputer
**Published:** 2026-05-14
**Article:** https://www.bleepingcomputer.com/news/security/teampcp-hackers-advertise-mistral-ai-code-repos-for-sale/

## Threat Profile

TeamPCP hackers advertise Mistral AI code repos for sale 
By Ionut Ilascu 
May 14, 2026
06:50 PM
0 
The TeamPCP hacker group is threatening to leak source code from the Mistral AI project unless a buyer is found for the data.
In a post on a hacker forum, the threat actor is asking $25,000 for a set of nearly 450 repositories.
Mistral AI is a French artificial intelligence company founded by former researchers from Google's DeepMind and Meta, which provides open-weight large language models (LLMs…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-45321`
- **IPv4 (defanged):** `83.142.209.194`
- **Domain (defanged):** `git-tanstack.com`
- **Domain (defanged):** `filev2.getsession.org`
- **Domain (defanged):** `api.masscan.cloud`
- **SHA256:** `ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c`
- **SHA256:** `2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96`
- **SHA256:** `2258284d65f63829bd67eaba01ef6f1ada2f593f9bbe41678b2df360bd90d3df`
- **SHA1:** `820fa07a7328b6cf2b417078e103721d4d8f2e79`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1546** — Event Triggered Execution
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1543.001** — Create or Modify System Process: Launch Agent
- **T1543.002** — Create or Modify System Process: Systemd Service
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1041** — Exfiltration Over C2 Channel
- **T1568** — Dynamic Resolution

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Mini Shai-Hulud npm worm persistence via .claude/ payload drop (router_runtime.js / setup.mjs)

`UC_38_4` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action IN ("created","modified") AND (Filesystem.file_path="*/.claude/router_runtime.js" OR Filesystem.file_path="*\\.claude\\router_runtime.js" OR Filesystem.file_path="*/.claude/setup.mjs" OR Filesystem.file_path="*\\.claude\\setup.mjs") by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.process_name Filesystem.process_guid | `drop_dm_object_name(Filesystem)` | where NOT match(file_path, "(?i)\\\\anthropic\\\\") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FileName in~ ("router_runtime.js","setup.mjs")
| where FolderPath has_any (@"\.claude\", "/.claude/")     // payload drops itself into a project-local .claude/
| where InitiatingProcessFileName in~ ("node.exe","node","npm.cmd","npm","npx.cmd","npx","pnpm.exe","pnpm","yarn.exe","yarn","python.exe","python","python3","pip.exe","pip","pip3") or InitiatingProcessCommandLine has_any ("postinstall","lifecycle","--unsafe-perm")
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          FolderPath, FileName, SHA256, InitiatingProcessFolderPath
| order by Timestamp desc
```

### [LLM] TeamPCP gh-token-monitor persistence daemon (macOS LaunchAgent / Linux systemd user unit)

`UC_38_5` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action IN ("created","modified") AND (Filesystem.file_path="*/Library/LaunchAgents/*gh-token-monitor*" OR Filesystem.file_path="*/.config/systemd/user/*gh-token-monitor*" OR Filesystem.file_name="com.user.gh-token-monitor.plist" OR Filesystem.file_name="gh-token-monitor.service") by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where (FolderPath contains "/Library/LaunchAgents/" and FileName has "gh-token-monitor")    // macOS
   or (FolderPath contains "/.config/systemd/user/" and FileName has "gh-token-monitor")     // Linux
   or FileName in~ ("com.user.gh-token-monitor.plist","gh-token-monitor.service")
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          FolderPath, FileName, SHA256
| order by Timestamp desc
```

### [LLM] Mini Shai-Hulud C2 callout to git-tanstack[.]com / *.getsession.org / api.masscan.cloud / 83.142.209.194

`UC_38_6` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_port) as dest_ports values(All_Traffic.app) as app values(All_Traffic.process_name) as process_name from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="83.142.209.194" OR All_Traffic.dest_host IN ("git-tanstack.com","*.git-tanstack.com","api.masscan.cloud","filev2.getsession.org","*.getsession.org") OR All_Traffic.url IN ("*git-tanstack.com*","*getsession.org*","*api.masscan.cloud*")) by All_Traffic.src All_Traffic.user All_Traffic.dest All_Traffic.dest_host | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime) | append [| tstats summariesonly=true count from datamodel=Network_Resolution.DNS where (DNS.query="*git-tanstack.com" OR DNS.query="*getsession.org" OR DNS.query="*masscan.cloud") by DNS.src DNS.query | `drop_dm_object_name(DNS)`]
```

**Defender KQL:**
```kql
let _c2_domains = dynamic(["git-tanstack.com","filev2.getsession.org","getsession.org","api.masscan.cloud","masscan.cloud"]);
let _c2_ips = dynamic(["83.142.209.194"]);
union isfuzzy=true
  ( DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteIP in (_c2_ips)
         or RemoteUrl has_any (_c2_domains)
    | project Timestamp, Source="DeviceNetworkEvents", DeviceName,
              InitiatingProcessAccountName, InitiatingProcessFileName,
              InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort ),
  ( DeviceEvents
    | where Timestamp > ago(30d)
    | where ActionType == "DnsQueryResponse"
    | extend Q = tolower(tostring(parse_json(AdditionalFields).QueryName))
    | where Q endswith "git-tanstack.com" or Q endswith "getsession.org" or Q endswith "masscan.cloud"
    | project Timestamp, Source="DnsQueryResponse", DeviceName,
              InitiatingProcessAccountName, InitiatingProcessFileName,
              InitiatingProcessCommandLine, RemoteUrl=Q,
              RemoteIP=tostring(parse_json(AdditionalFields).IPAddresses), RemotePort=int(null) )
| order by Timestamp desc
```

### Trusted vendor binary / installer launching unusual children

`UC_SUPPLY_CHAIN` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("setup.exe","installer.exe","update.exe")
      AND Processes.process_name IN ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
    by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("setup.exe","installer.exe","update.exe")
| where FileName in~ ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-45321`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `83.142.209.194`, `git-tanstack.com`, `filev2.getsession.org`, `api.masscan.cloud`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c`, `2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96`, `2258284d65f63829bd67eaba01ef6f1ada2f593f9bbe41678b2df360bd90d3df`, `820fa07a7328b6cf2b417078e103721d4d8f2e79`


## Why this matters

Severity classified as **HIGH** based on: CVE present, IOCs present, 7 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

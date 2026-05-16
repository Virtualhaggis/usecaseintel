# [HIGH] TeamPCP hackers advertise Mistral AI code repos for sale

**Source:** BleepingComputer
**Published:** 2026-05-14
**Article:** https://www.bleepingcomputer.com/news/security/teampcp-hackers-advertise-mistral-ai-code-repos-for-sale/

## Threat Profile

OpenAI confirms security breach in TanStack supply chain attack 
By Lawrence Abrams 
May 14, 2026
03:07 PM
0 
OpenAI says two employees' devices were breached in the recent TanStack supply chain attack that impacted hundreds of npm and PyPI packages, causing the company to rotate code-signing certificates for its applications as a precaution.
In a security advisory published today, the company said the incident did not impact customer data, production systems, intellectual property, or deployed …

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
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

`UC_27_1` · phase: **install** · confidence: **High**

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

`UC_27_2` · phase: **install** · confidence: **High**

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

`UC_27_3` · phase: **c2** · confidence: **High**

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


## Why this matters

Severity classified as **HIGH** based on: 4 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

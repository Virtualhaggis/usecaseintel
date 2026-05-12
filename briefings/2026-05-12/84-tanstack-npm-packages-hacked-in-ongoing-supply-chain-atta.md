# [HIGH] 84 TanStack npm Packages Hacked in Ongoing Supply-Chain Attack Targeting CI Credentials

**Source:** Cyber Security News
**Published:** 2026-05-12
**Article:** https://cybersecuritynews.com/tanstack-npm-packages-hacked/

## Threat Profile

Home Cyber Security 
84 TanStack npm Packages Hacked in Ongoing Supply-Chain Attack Targeting CI Credentials 
By Guru Baran 
May 12, 2026 
A significant supply-chain compromise affecting 84 npm package artifacts across the TanStack namespace.
The malicious versions, published to the npm registry at approximately 19:20 and 19:26 UTC, contain a suspected credential-stealing payload targeting CI systems, including GitHub Actions.
According to Socket , the compromise spans 42 TanStack packages — two…

## Indicators of Compromise (high-fidelity only)

- **SHA1:** `79ac49eedf774dd4b0cfa308722bc463cfe5885c`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1546.016** — Event Triggered Execution: Installer Packages
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1105** — Ingress Tool Transfer

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] TanStack Mini Shai-Hulud prepare hook executes tanstack_runner.js via bun/node

`UC_11_4` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("bun.exe","bun","node.exe","node")) AND Processes.process="*tanstack_runner.js*" by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_path | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("bun.exe","bun","node.exe","node")
| where ProcessCommandLine has "tanstack_runner.js"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessCommandLine, InitiatingProcessFolderPath, SHA256
| order by Timestamp desc
```

### [LLM] TanStack supply-chain payload router_init.js dropped inside @tanstack/* node_modules

`UC_11_5` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name="router_init.js" AND (Filesystem.file_path="*@tanstack*" OR Filesystem.file_path="*node_modules*") by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.process_name Filesystem.action | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FileName =~ "router_init.js"
| where FolderPath has "@tanstack" or FolderPath has "node_modules"
| where InitiatingProcessFileName in~ ("npm.exe","npm-cli.js","pnpm.exe","yarn.exe","yarn","pnpm","bun.exe","bun","node.exe","node")
    or InitiatingProcessCommandLine has_any ("npm install","pnpm install","yarn install","bun install")
    or FolderPath has "@tanstack"
| project Timestamp, DeviceName, FolderPath, FileName, FileSize, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessParentFileName
| order by Timestamp desc
```

### [LLM] npm install or git fetch references TanStack orphan commit 79ac49eedf774dd4b0cfa308722bc463cfe5885c

`UC_11_6` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process="*79ac49eedf774dd4b0cfa308722bc463cfe5885c*" OR Processes.process="*tanstack/router#79ac49ee*" by Processes.dest Processes.user Processes.process_name Processes.parent_process_name Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | append [ | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where Web.url="*79ac49eedf774dd4b0cfa308722bc463cfe5885c*" OR (Web.dest="codeload.github.com" AND Web.url="*tanstack/router*79ac49ee*") by Web.src Web.user Web.dest Web.url | `drop_dm_object_name(Web)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` ]
```

**Defender KQL:**
```kql
let MaliciousCommit = "79ac49eedf774dd4b0cfa308722bc463cfe5885c";
union isfuzzy=true
( DeviceProcessEvents
    | where Timestamp > ago(14d)
    | where ProcessCommandLine has MaliciousCommit
         or ProcessCommandLine has "tanstack/router#79ac49ee"
    | project Timestamp, DeviceName, AccountName, Source = "Process",
              Detail = ProcessCommandLine, ProcImage = FolderPath,
              ParentImage = InitiatingProcessFileName ),
( DeviceNetworkEvents
    | where Timestamp > ago(14d)
    | where RemoteUrl has MaliciousCommit
         or (RemoteUrl has "codeload.github.com" and RemoteUrl has "79ac49ee")
    | project Timestamp, DeviceName,
              AccountName = InitiatingProcessAccountName,
              Source = "Network", Detail = RemoteUrl,
              ProcImage = InitiatingProcessFolderPath,
              ParentImage = InitiatingProcessParentFileName )
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

### Article-specific behavioural hunt — 84 TanStack npm Packages Hacked in Ongoing Supply-Chain Attack Targeting CI Cred

`UC_11_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — 84 TanStack npm Packages Hacked in Ongoing Supply-Chain Attack Targeting CI Cred ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("router_init.js","tanstack_runner.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("router_init.js","tanstack_runner.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — 84 TanStack npm Packages Hacked in Ongoing Supply-Chain Attack Targeting CI Cred
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("router_init.js", "tanstack_runner.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("router_init.js", "tanstack_runner.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `79ac49eedf774dd4b0cfa308722bc463cfe5885c`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 7 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

# [HIGH] Official SAP npm packages compromised to steal credentials

**Source:** BleepingComputer
**Published:** 2026-04-29
**Article:** https://www.bleepingcomputer.com/news/security/official-sap-npm-packages-compromised-to-steal-credentials/

## Threat Profile

Official SAP npm packages compromised to steal credentials 
By Lawrence Abrams 
April 29, 2026
06:43 PM
0 
Multiple official SAP npm packages were compromised in what is believed to be a TeamPCP supply-chain attack to steal credentials and authentication tokens from developers' systems.
Security researchers report that the compromise impacted four packages, with the versions now deprecated on NPM:
@cap-js/sqlite – v2.2.2
@cap-js/postgres – v2.2.2
@cap-js/db-service – v2.10.1
mbt – v1.2.48
These …

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1105** — Ingress Tool Transfer
- **T1003.007** — OS Credential Dumping: Proc Filesystem
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1552.007** — Unsecured Credentials: Container API / CI Variables
- **T1546** — Event Triggered Execution

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] npm preinstall script drops setup.mjs/execution.js and fetches Bun runtime (Mini Shai-Hulud)

`UC_30_3` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.parent_process) as parent_cmd from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("node.exe","node","npm.exe","npm","npm-cli.js","yarn","pnpm.exe","pnpm")) AND (Processes.process IN ("*setup.mjs*","*execution.js*") OR (Processes.process="*bun*" AND Processes.process IN ("*github.com/oven-sh/bun*","*oven-sh/bun/releases*"))) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process_id _time | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let droppers = dynamic(["setup.mjs","execution.js"]);
let bunHosts = dynamic(["github.com/oven-sh/bun","oven-sh/bun/releases","bun.sh/install"]);
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("node.exe","node","npm.exe","npm","npm-cli.js","yarn","pnpm.exe","pnpm")
   or ProcessCommandLine has_any ("@cap-js/sqlite","@cap-js/postgres","@cap-js/db-service","mbt@1.2.48")
| where ProcessCommandLine has_any (droppers)
   or (ProcessCommandLine has "bun" and ProcessCommandLine has_any (bunHosts))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath
| join kind=leftouter (DeviceNetworkEvents | where Timestamp > ago(14d) | where RemoteUrl has_any (bunHosts) | project NetTime=Timestamp, DeviceName, RemoteUrl, RemoteIP) on DeviceName
```

### [LLM] Linux CI runner: process reading /proc/<pid>/mem of Runner.Worker (Mini Shai-Hulud secret scraper)

`UC_30_4` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths values(Filesystem.process_name) as procs from datamodel=Endpoint.Filesystem where Filesystem.file_path IN ("/proc/*/maps","/proc/*/mem") AND Filesystem.process_name IN ("python","python3","bun","node") by Filesystem.dest Filesystem.user Filesystem.process_id _time | `drop_dm_object_name(Filesystem)` | join type=inner Filesystem.dest [| tstats `summariesonly` count from datamodel=Endpoint.Processes where Processes.process_name="Runner.Worker" by Processes.dest Processes.process_id | rename Processes.dest as Filesystem.dest Processes.process_id as worker_pid | `drop_dm_object_name(Processes)`] | where like(paths, "%/".worker_pid."/maps") OR like(paths, "%/".worker_pid."/mem") | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
let runners = DeviceProcessEvents
  | where Timestamp > ago(14d)
  | where FileName == "Runner.Worker" or ProcessCommandLine has "Runner.Worker"
  | project DeviceId, RunnerWorkerPid = ProcessId, RunnerStart = Timestamp;
DeviceFileEvents
| where Timestamp > ago(14d)
| where FolderPath matches regex @"^/proc/\d+/(mem|maps)$"
| where InitiatingProcessFileName in~ ("python","python3","bun","node")
| extend TargetPid = toint(extract(@"/proc/(\d+)/", 1, FolderPath))
| join kind=inner runners on $left.DeviceId == $right.DeviceId and $left.TargetPid == $right.RunnerWorkerPid
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, TargetPid, RunnerStart
| union (DeviceProcessEvents
  | where Timestamp > ago(14d)
  | where ProcessCommandLine matches regex @"/proc/\d+/(mem|maps)" and ProcessCommandLine has "isSecret")
```

### [LLM] Compromised SAP CAP / mbt package files written under node_modules (pinned malicious versions)

`UC_30_5` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths from datamodel=Endpoint.Filesystem where Filesystem.file_name IN ("setup.mjs","execution.js") AND (Filesystem.file_path IN ("*node_modules*@cap-js/sqlite*","*node_modules*@cap-js/postgres*","*node_modules*@cap-js/db-service*","*node_modules*mbt*","*node_modules\\@cap-js\\sqlite*","*node_modules\\@cap-js\\postgres*","*node_modules\\@cap-js\\db-service*","*node_modules\\mbt*")) by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_name Filesystem.file_path _time | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let badPkgPaths = dynamic(["node_modules/@cap-js/sqlite","node_modules/@cap-js/postgres","node_modules/@cap-js/db-service","node_modules/mbt","node_modules\\@cap-js\\sqlite","node_modules\\@cap-js\\postgres","node_modules\\@cap-js\\db-service","node_modules\\mbt"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where FileName in~ ("setup.mjs","execution.js","package.json")
| where FolderPath has_any (badPkgPaths)
| join kind=leftouter (
    DeviceFileEvents
    | where Timestamp > ago(30d)
    | where FileName == "package.json"
    | where FolderPath has_any (badPkgPaths)
    | extend pkgVer = extract(@"""version""\s*:\s*""([0-9\.]+)""", 1, tostring(AdditionalFields))
  ) on DeviceId, FolderPath
| project Timestamp, DeviceName, AccountName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| extend SuspectVersion = case(
    FolderPath has "@cap-js/sqlite" or FolderPath has "@cap-js\\sqlite", "2.2.2",
    FolderPath has "@cap-js/postgres" or FolderPath has "@cap-js\\postgres", "2.2.2",
    FolderPath has "@cap-js/db-service" or FolderPath has "@cap-js\\db-service", "2.10.1",
    FolderPath has "mbt", "1.2.48",
    "unknown")
```

### PowerShell encoded / obfuscated command

`UC_PS_OBFUSCATED` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
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
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)(-enc|encodedcommand|frombase64string|-nop|-w\s+hidden|invoke-expression|iex\s*\(|downloadstring|net\.webclient)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
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
| where InitiatingProcessFileName in~ ("setup.exe","installer.exe","update.exe")
| where FileName in~ ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### Article-specific behavioural hunt — Official SAP npm packages compromised to steal credentials

`UC_30_2` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Official SAP npm packages compromised to steal credentials ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("execution.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("execution.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Official SAP npm packages compromised to steal credentials
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("execution.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("execution.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 6 use case(s) fired, 11 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

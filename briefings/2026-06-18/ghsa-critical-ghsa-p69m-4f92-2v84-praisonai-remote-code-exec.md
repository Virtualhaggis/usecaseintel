# [CRIT] [GHSA / CRITICAL] GHSA-p69m-4f92-2v84: PraisonAI: Remote Code Execution via Sandbox Escape in `codeMode` Tool

**Source:** GitHub Security Advisories
**Published:** 2026-06-18
**Article:** https://github.com/advisories/GHSA-p69m-4f92-2v84

## Threat Profile

PraisonAI: Remote Code Execution via Sandbox Escape in `codeMode` Tool

## Summary

The `codeMode` tool in `src/praisonai-ts/src/tools/builtins/code-mode.ts` uses `new Function()` with a `with(sandbox)` pattern to execute LLM-generated code. The blocklist-based "sandbox" can be trivially bypassed via `Function('return this')()` to recover the global object, followed by `global.require()` with string concatenation to evade the blocklist regex. This allows full arbitrary code execution on the host…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1219** — Remote Access Software
- **T1204.002** — User Execution: Malicious File
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1082** — System Information Discovery
- **T1033** — System Owner/User Discovery
- **T1190** — Exploit Public-Facing Application
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Node.js spawning shell with reconnaissance commands (PraisonAI codeMode sandbox escape)

`UC_52_2` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdlines from datamodel=Endpoint.Processes where (Processes.parent_process_name="node.exe" OR Processes.parent_process_name="node") AND (Processes.process_name IN ("sh","bash","dash","zsh","cmd.exe","powershell.exe","pwsh.exe")) AND (Processes.process="*whoami*" OR Processes.process="*uname*" OR Processes.process="*/etc/passwd*" OR Processes.process="*/etc/shadow*" OR Processes.process="*~/.ssh*" OR Processes.process="*ifconfig*" OR Processes.process="*ip addr*" OR Processes.process="*hostname*" OR Processes.process="*cat /root/*") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node.exe", "node")
| where FileName in~ ("sh","bash","dash","zsh","cmd.exe","powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)\b(whoami|uname|hostname|ifconfig)\b"
   or ProcessCommandLine has_any ("/etc/passwd", "/etc/shadow", "~/.ssh", "/root/.ssh", "ip addr", "cat /root/", "id;", "id |", "id&&")
| where InitiatingProcessCommandLine has_any ("praisonai", "code-mode", "codeMode", "new Function", "Function('return this')") 
   or AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd   = InitiatingProcessCommandLine,
          ChildImage  = FolderPath,
          ChildCmd    = ProcessCommandLine,
          SHA256, ProcessId, InitiatingProcessId
| order by Timestamp desc
```

### Vulnerable PraisonAI-TS package (<=1.7.1) installed — GHSA-p69m-4f92-2v84

`UC_52_3` · phase: **weapon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Endpoint.Filesystem where Filesystem.file_path="*node_modules*praisonai*package.json*" OR Filesystem.file_path="*node_modules*praisonai-ts*package.json*" by Filesystem.dest Filesystem.file_path Filesystem.user | `drop_dm_object_name(Filesystem)` | rex field=file_path "(?<package_dir>.+praisonai(?:-ts)?)[\\\\/]package\.json" | dedup dest, package_dir | table dest, user, package_dir, count
```

**Defender KQL:**
```kql
// Inventory pass — vulnerable versions per Defender TVM
let vuln = DeviceTvmSoftwareInventory
  | where SoftwareName has "praisonai"
  | where SoftwareVersion matches regex @"^(0\.|1\.[0-6]\.|1\.7\.[01](?:$|[^0-9]))"
  | project Timestamp, DeviceName, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion;
// Filesystem fallback — catches manual / non-managed installs TVM missed
let fileEvidence = DeviceFileEvents
  | where Timestamp > ago(30d)
  | where FolderPath matches regex @"(?i)node_modules[\\/]praisonai(?:-ts)?[\\/]"
  | where FileName =~ "package.json"
  | summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Paths=make_set(FolderPath, 25) by DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName;
union isfuzzy=true vuln, fileEvidence
| order by DeviceName asc
```

### RMM tool installed by non-IT user — remote-access utility for hands-on-keyboard

`UC_RMM_TOOLS` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe","kaseya*.exe")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe")
   or FileName matches regex @"(?i)kaseya.*\.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-p69m-4f92-2v84: PraisonAI: Remote Code Execution via Sand

`UC_52_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-p69m-4f92-2v84: PraisonAI: Remote Code Execution via Sand ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js","python_tools.py"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("node.js","python_tools.py"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-p69m-4f92-2v84: PraisonAI: Remote Code Execution via Sand
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js", "python_tools.py"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("node.js", "python_tools.py"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **CRIT** based on: 4 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

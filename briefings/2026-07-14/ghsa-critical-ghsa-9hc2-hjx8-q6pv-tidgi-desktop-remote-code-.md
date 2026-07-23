# [CRIT] [GHSA / CRITICAL] GHSA-9hc2-hjx8-q6pv: TidGi Desktop Remote Code Execution via Malicious TiddlyWiki Repository Import — Tiddler Startup Module Auto-Execution

**Source:** GitHub Security Advisories
**Published:** 2026-07-14
**Article:** https://github.com/advisories/GHSA-9hc2-hjx8-q6pv

## Threat Profile

TidGi Desktop Remote Code Execution via Malicious TiddlyWiki Repository Import — Tiddler Startup Module Auto-Execution

## Description

TidGi Desktop through 0.13.0 contains a critical remote code execution vulnerability exploitable via a single Git repository import. The vulnerability leverages TiddlyWiki's module system, which automatically discovers and executes JavaScript code embedded in `.tid` files placed in the wiki's `tiddlers/` directory:

1. **Auto-loading of `.tid` files** (`src/serv…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1059.001** — PowerShell
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1543.001** — Persistence (article-specific)
- **T1203** — Exploitation for Client Execution
- **T1059** — Command and Scripting Interpreter
- **T1218.015** — System Binary Proxy Execution: Electron Applications
- **T1204.002** — User Execution: Malicious File
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1195.001** — Supply Chain Compromise: Compromise Software Dependencies and Development Tools

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### TidGi Desktop wiki worker spawning a command interpreter (TiddlyWiki startup-module RCE)

`UC_130_2` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name="TidGi.exe" OR (Processes.parent_process_name="node.exe" AND Processes.parent_process_path="*TidGi*")) AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","bitsadmin.exe","certutil.exe","curl.exe","calc.exe") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("TidGi.exe","node.exe")
| where InitiatingProcessFolderPath has "TidGi"
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","bitsadmin.exe","certutil.exe","curl.exe","calc.exe")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, FileName, FolderPath, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Malicious startup-module tiddler (.js.tid) written into a TiddlyWiki tiddlers/ directory

`UC_130_3` · phase: **delivery** · confidence: **Low** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Endpoint.Filesystem.file_name="*.js.tid" AND Endpoint.Filesystem.file_path="*\\tiddlers\\*" by Endpoint.Filesystem.dest Endpoint.Filesystem.file_name Endpoint.Filesystem.file_path Endpoint.Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated"
| where FolderPath has "\\tiddlers\\"
| where FileName endswith ".js.tid"
| where InitiatingProcessFileName in~ ("git.exe","TidGi.exe","node.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, FolderPath
| order by Timestamp desc
```

### Office app spawning script/LOLBin child process

`UC_OFFICE_CHILD` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe","mspub.exe","visio.exe")
      AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","wmic.exe","bitsadmin.exe","certutil.exe")
    by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe","mspub.exe","visio.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","wmic.exe","bitsadmin.exe","certutil.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-9hc2-hjx8-q6pv: TidGi Desktop Remote Code Execution via M

`UC_130_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-9hc2-hjx8-q6pv: TidGi Desktop Remote Code Execution via M ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js","boot.js","__plugins__poc__startup.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/tmp/TidGi-RCE-PoC.txt*" OR Filesystem.file_path="*/tmp/evil-wiki*" OR Filesystem.file_name IN ("node.js","boot.js","__plugins__poc__startup.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-9hc2-hjx8-q6pv: TidGi Desktop Remote Code Execution via M
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js", "boot.js", "__plugins__poc__startup.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/tmp/TidGi-RCE-PoC.txt", "/tmp/evil-wiki") or FileName in~ ("node.js", "boot.js", "__plugins__poc__startup.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **CRIT** based on: 4 use case(s) fired, 10 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

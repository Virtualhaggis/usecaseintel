# [CRIT] [GHSA / CRITICAL] GHSA-vmmj-pfw7-fjwp: npm PraisonAI codeMode sandbox escape via Function constructor

**Source:** GitHub Security Advisories
**Published:** 2026-06-18
**Article:** https://github.com/advisories/GHSA-vmmj-pfw7-fjwp

## Threat Profile

npm PraisonAI codeMode sandbox escape via Function constructor

## Summary

The published npm package `praisonai` exports a TypeScript built-in tool named `codeMode`. The package describes this tool as executing code in a sandboxed environment, marks its capability as `sandbox: true`, and registers it through the public tools facade.

The implementation does not create an isolation boundary. It applies a small regular-expression blocklist, sets `process` and `require` to `undefined` inside a pla…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File
- **T1195.002** — Compromise Software Supply Chain
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1480** — Execution Guardrails
- **T1211** — Exploitation for Defense Evasion
- **T1059** — Command and Scripting Interpreter
- **T1059.001** — PowerShell
- **T1059.003** — Windows Command Shell
- **T1059.004** — Unix Shell
- **T1212** — Exploitation for Credential Access

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Installation of vulnerable npm praisonai package (GHSA-vmmj-pfw7-fjwp)

`UC_24_1` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("npm.exe","npm.cmd","yarn.exe","yarn.cmd","pnpm.exe","pnpm.cmd","node.exe") AND Processes.process="*praisonai*" AND (Processes.process="*install*" OR Processes.process="* add *" OR Processes.process="* i *") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("npm.exe","npm.cmd","yarn.exe","yarn.cmd","pnpm.exe","pnpm.cmd","node.exe")
    or InitiatingProcessFileName in~ ("npm.exe","yarn.exe","pnpm.exe")
| where ProcessCommandLine has "praisonai"
| where ProcessCommandLine has_any ("install"," add "," i ","add praisonai","install praisonai")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### PraisonAI codeMode Function-constructor sandbox escape payload

`UC_24_2` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*constructor.constructor*" OR Processes.process="*process.mainModule.require*" OR Processes.process="*return process*constructor*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let escape_patterns = dynamic(["constructor.constructor","process.mainModule.require","return process","with (sandbox)"]);
(union isfuzzy=true
    (DeviceProcessEvents
     | where Timestamp > ago(30d)
     | where ProcessCommandLine has_any (escape_patterns)
        or InitiatingProcessCommandLine has_any (escape_patterns)
     | project Timestamp, DeviceName, AccountName, Source="Process", FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine),
    (DeviceFileEvents
     | where Timestamp > ago(30d)
     | where ActionType in ("FileCreated","FileModified")
     | where FileName endswith ".js" or FileName endswith ".ts" or FileName endswith ".mjs" or FileName endswith ".cjs" or FileName endswith ".json"
     | where InitiatingProcessFileName in~ ("node.exe","npm.exe","pnpm.exe","yarn.exe")
     | where InitiatingProcessCommandLine has_any (escape_patterns)
        or FolderPath has "praisonai"
     | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, Source="File", FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine)
)
| order by Timestamp desc
```

### node.exe spawning shell or LOLBin child — post-codeMode-escape execution

`UC_24_3` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd_lines from datamodel=Endpoint.Processes where Processes.parent_process_name="node.exe" AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","wmic.exe","certutil.exe","bitsadmin.exe","curl.exe","wget.exe","sh","bash","dash","zsh","mshta.exe","rundll32.exe","regsvr32.exe") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.parent_process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "node.exe"
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wmic.exe","certutil.exe","bitsadmin.exe","curl.exe","wget.exe","sh","bash","dash","zsh","mshta.exe","rundll32.exe","regsvr32.exe","whoami.exe","net.exe","reg.exe")
| where AccountName !endswith "$"
| extend PraisonAILoaded = iff(InitiatingProcessCommandLine has "praisonai" or InitiatingProcessFolderPath has "praisonai", "yes", "unknown")
| project Timestamp, DeviceName, AccountName, ParentImage=InitiatingProcessFolderPath, ParentCmd=InitiatingProcessCommandLine, ChildImage=FolderPath, ChildCmd=ProcessCommandLine, PraisonAILoaded, SHA256
| order by PraisonAILoaded desc, Timestamp desc
```

### PraisonAI codeMode blocklist trigger — sandbox probing in application logs

`UC_24_4` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*praisonai*" OR Filesystem.file_name="*.log" OR Filesystem.file_name="*stderr*") by Filesystem.dest Filesystem.user Filesystem.process_name | `drop_dm_object_name(Filesystem)` | join type=outer dest [ | tstats `summariesonly` count from datamodel=Endpoint.Processes where Processes.process="*Blocked pattern detected*" OR Processes.process="*Code contains blocked patterns for security*" by Processes.dest | `drop_dm_object_name(Processes)` ] | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let blocklist_strings = dynamic(["Blocked pattern detected:","Code contains blocked patterns for security","require\\s*\\(\\s*['\"]fs['\"]","require\\s*\\(\\s*['\"]child_process['\"]"]);
(union isfuzzy=true
    (DeviceProcessEvents
     | where Timestamp > ago(30d)
     | where ProcessCommandLine has_any (blocklist_strings) or InitiatingProcessCommandLine has_any (blocklist_strings)
     | project Timestamp, DeviceName, AccountName, Source="Process", FileName, ProcessCommandLine, InitiatingProcessFileName),
    (DeviceFileEvents
     | where Timestamp > ago(30d)
     | where InitiatingProcessFileName =~ "node.exe"
     | where FolderPath has_any ("praisonai","\\logs\\","\\log\\","stderr")
     | where FileName endswith ".log" or FileName endswith ".err" or FileName endswith ".txt" or FileName endswith ".json"
     | summarize WriteCount=count(), Files=make_set(FileName, 25) by bin(Timestamp, 1h), DeviceName, InitiatingProcessAccountName, FolderPath
     | where WriteCount >= 3)
)
| order by Timestamp desc
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-vmmj-pfw7-fjwp: npm PraisonAI codeMode sandbox escape via

`UC_24_0` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-vmmj-pfw7-fjwp: npm PraisonAI codeMode sandbox escape via ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js","mode.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("node.js","mode.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-vmmj-pfw7-fjwp: npm PraisonAI codeMode sandbox escape via
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js", "mode.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("node.js", "mode.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **CRIT** based on: 5 use case(s) fired, 10 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

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
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1068** — Exploitation for Privilege Escalation
- **T1611** — Escape to Host
- **T1027** — Obfuscated Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Node.js spawned shell/utility from praisonai codeMode context (sandbox escape post-exploitation)

`UC_50_1` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name="node.exe" OR Processes.parent_process_name="node") AND (Processes.parent_process LIKE "%praisonai%" OR Processes.parent_process LIKE "%code-mode%" OR Processes.parent_process LIKE "%codeMode%") AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","sh","bash","zsh","printf","printf.exe","wscript.exe","cscript.exe","curl.exe","wget.exe") by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node.exe","node")
| where InitiatingProcessCommandLine has_any ("praisonai","code-mode","codeMode")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","sh","bash","zsh","dash","printf","printf.exe","wscript.exe","cscript.exe","curl.exe","wget.exe")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, ParentCmd=InitiatingProcessCommandLine, ParentImage=InitiatingProcessFolderPath, ChildImage=FolderPath, ChildCmd=ProcessCommandLine, SHA256
| order by Timestamp desc
```

### PraisonAI codeMode prototype-chain escape payload (constructor.constructor / mainModule.require strings)

`UC_50_2` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="node.exe" OR Processes.process_name="node") AND (Processes.process LIKE "%constructor.constructor%" OR Processes.process LIKE "%mainModule.require%" OR Processes.process LIKE "%return process%") by Processes.dest Processes.user Processes.process Processes.process_id Processes.parent_process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
union
(DeviceProcessEvents
  | where Timestamp > ago(14d)
  | where FileName in~ ("node.exe","node")
  | where ProcessCommandLine has_any ("constructor.constructor","mainModule.require","return process")
  | project Timestamp, DeviceName, AccountName, EvidenceKind="cmdline", Image=FolderPath, Detail=ProcessCommandLine),
(DeviceFileEvents
  | where Timestamp > ago(14d)
  | where InitiatingProcessFileName in~ ("node.exe","node")
  | where FolderPath has "node_modules\\praisonai" or FolderPath has "node_modules/praisonai" or FileName has "code-mode"
  | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, EvidenceKind="file", Image=InitiatingProcessFolderPath, Detail=FolderPath)
| order by Timestamp desc
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-vmmj-pfw7-fjwp: npm PraisonAI codeMode sandbox escape via

`UC_50_0` · phase: **exploit** · confidence: **High**

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

Severity classified as **CRIT** based on: 3 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

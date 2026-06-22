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
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1190** — Exploit Public-Facing Application
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1211** — Exploitation for Defense Evasion

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### PraisonAI codeMode escape: Node.js process spawning OS shell for recon/secret access

`UC_69_1` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name="node.exe" (Processes.process_name="cmd.exe" OR Processes.process_name="powershell.exe" OR Processes.process_name="pwsh.exe" OR Processes.process_name="sh" OR Processes.process_name="bash" OR Processes.process_name="dash" OR Processes.process_name="zsh") by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| search process="*/etc/passwd*" OR process="*/etc/shadow*" OR process="*.env*" OR process="*printenv*" OR process="*whoami*" OR process="*child_process*" OR process="*base64*" OR process="*cat *" OR process="*curl *" OR process="*wget *"
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node.exe","node")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","sh","bash","dash","zsh","sh.exe")
| where ProcessCommandLine has_any ("/etc/passwd","/etc/shadow",".env","printenv","whoami","cat ","curl ","wget ","base64","child_process","uname","id ","hostname")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### PraisonAI codeMode Function-constructor prototype-chain escape payload signature

`UC_69_2` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process="*constructor.constructor*" by Processes.dest Processes.user Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| search process="*mainModule*" OR process="*return process*" OR process="*return this.process*" OR process="*child_process*"
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine contains "constructor.constructor"
| where ProcessCommandLine has_any ("return process","return this.process","mainModule","process.mainModule","child_process")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
| order by Timestamp desc
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-vmmj-pfw7-fjwp: npm PraisonAI codeMode sandbox escape via

`UC_69_0` · phase: **exploit** · confidence: **High**

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

Severity classified as **CRIT** based on: 3 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

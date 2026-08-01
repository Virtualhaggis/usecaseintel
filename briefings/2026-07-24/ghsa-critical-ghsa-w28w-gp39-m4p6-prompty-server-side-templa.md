# [CRIT] [GHSA / CRITICAL] GHSA-w28w-gp39-m4p6: Prompty: Server-Side Template Injection to Remote Code Execution in the @prompty/core Nunjucks Renderer

**Source:** GitHub Security Advisories
**Published:** 2026-07-24
**Article:** https://github.com/advisories/GHSA-w28w-gp39-m4p6

## Threat Profile

Prompty: Server-Side Template Injection to Remote Code Execution in the @prompty/core Nunjucks Renderer

## Summary
The TypeScript Nunjucks renderer evaluated untrusted `.prompty` template bodies with unrestricted JavaScript member access. An attacker-controlled template could traverse constructor and prototype properties to execute JavaScript in the host Node.js process.

## Affected packages
- npm `@prompty/core` versions `<= 0.1.4`
- npm `@prompty/core` versions `<= 2.0.0-beta.4`

## Impact
A…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File
- **T1190** — Exploit Public-Facing Application
- **T1059.003** — Windows Command Shell
- **T1059.004** — Unix Shell
- **T1195.001** — Compromise Software Dependencies and Development Tools

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Node.js host process spawning OS shell (Nunjucks SSTI child_process.execSync RCE)

`UC_125_1` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t allow_old_summaries=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("node.exe","node") AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","sh","bash","dash","zsh")) AND (Processes.process="*/d /s /c*" OR Processes.process="*/c *" OR Processes.process="* -c *") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.parent_process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("node.exe","node")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","sh","bash","dash","zsh")
| where ProcessCommandLine has_any ("/d /s /c","/c "," -c ")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, InitiatingProcessFolderPath, SHA256
| order by Timestamp desc
```

### Vulnerable @prompty/core package present in node_modules (GHSA-w28w-gp39-m4p6 exposure)

`UC_125_2` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t allow_old_summaries=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*node_modules*@prompty*core*") by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.user | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has "node_modules"
| where FolderPath contains @"\@prompty\core" or FolderPath contains "/@prompty/core"
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Files=make_set(FileName, 25) by DeviceName, FolderPath, InitiatingProcessAccountName, InitiatingProcessFileName
| order by LastSeen desc
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-w28w-gp39-m4p6: Prompty: Server-Side Template Injection t

`UC_125_0` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-w28w-gp39-m4p6: Prompty: Server-Side Template Injection t ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("node.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-w28w-gp39-m4p6: Prompty: Server-Side Template Injection t
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **CRIT** based on: 3 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

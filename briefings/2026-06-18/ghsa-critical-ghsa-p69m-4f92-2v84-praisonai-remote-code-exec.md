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
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1033** — System Owner/User Discovery
- **T1041** — Exfiltration Over C2 Channel
- **T1552.001** — Unsecured Credentials: Credentials In Files

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### PraisonAI codeMode sandbox-escape RCE: node process spawning OS shell / recon binaries

`UC_116_2` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name="node" OR Processes.parent_process_name="node.exe") (Processes.process_name IN ("sh","bash","dash","zsh","cmd.exe","powershell.exe","pwsh","id","whoami","uname","curl","wget","ncat")) by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | search (parent_process="*praisonai*" OR parent_process="*node_modules*praisonai*") AND parent_process!="*npm*" AND parent_process!="*node-gyp*" | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("node","node.exe")
| where InitiatingProcessCommandLine has "praisonai" or InitiatingProcessFolderPath has "praisonai"
| where not(InitiatingProcessCommandLine has_any ("npm","node-gyp","yarn","webpack","install"))
| where FileName in~ ("sh","bash","dash","zsh","cmd.exe","powershell.exe","pwsh","id","whoami","uname","hostname","curl","wget","nc","ncat","python3")
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd = InitiatingProcessCommandLine,
          ChildProcess = FileName, ChildCmd = ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Vulnerable PraisonAI codeMode component present on host (code-mode.ts/js under praisonai)

`UC_116_3` · phase: **recon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_path="*praisonai*" (Filesystem.file_name="code-mode.ts" OR Filesystem.file_name="code-mode.js") by Filesystem.dest Filesystem.file_path Filesystem.file_name | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has "praisonai"
| where FileName in~ ("code-mode.ts","code-mode.js")
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), arg_max(Timestamp, InitiatingProcessFileName, InitiatingProcessAccountName) by DeviceName, FolderPath, FileName
| order by LastSeen desc
```

### PraisonAI node process novel outbound egress (post-escape secret/API-key exfiltration or C2)

`UC_116_4` · phase: **actions** · confidence: **Low** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.process_name="node" OR All_Traffic.process_name="node.exe") All_Traffic.dest_category!="internal" by All_Traffic.src All_Traffic.process_name All_Traffic.dest All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)` | search dest!="*.openai.com" AND dest!="*.anthropic.com" AND dest!="*.googleapis.com" AND dest!="*.npmjs.org" AND dest!="*.huggingface.co" | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("node","node.exe")
| where InitiatingProcessCommandLine has "praisonai" or InitiatingProcessFolderPath has "praisonai"
| where RemoteIPType == "Public"
| where not(RemoteUrl has_any ("api.openai.com","api.anthropic.com","openai.azure.com","googleapis.com","api.cohere.ai","api.mistral.ai","huggingface.co","ollama.com","registry.npmjs.org"))
| summarize FirstSeen=min(Timestamp), ConnCount=count(), Ports=make_set(RemotePort,10) by DeviceName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl
| order by FirstSeen desc
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

`UC_116_1` · phase: **exploit** · confidence: **High**

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

Severity classified as **CRIT** based on: 5 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

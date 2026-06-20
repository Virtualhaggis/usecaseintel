# [CRIT] [GHSA / CRITICAL] GHSA-x227-pf99-vffg: PraisonAI: MCP SSE transport binds 0.0.0.0 with no authentication and no Origin validation; bundled SecurityConfig is never wired in

**Source:** GitHub Security Advisories
**Published:** 2026-06-18
**Article:** https://github.com/advisories/GHSA-x227-pf99-vffg

## Threat Profile

PraisonAI: MCP SSE transport binds 0.0.0.0 with no authentication and no Origin validation; bundled SecurityConfig is never wired in

The MCP SSE server started via ToolsMCPServer.run_sse() / launch_tools_mcp_server(transport="sse")
binds to 0.0.0.0 by default and builds its Starlette application with no authentication middleware
and no Origin-header validation. The module mcp/mcp_security.py provides exactly the needed controls
(origin validation, DNS-rebinding detection, auth-header enforcemen…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File
- **T1190** — Exploit Public-Facing Application
- **T1133** — External Remote Services
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1059** — Command and Scripting Interpreter
- **T1059.001** — PowerShell
- **T1059.003** — Windows Command Shell
- **T1059.004** — Unix Shell
- **T1105** — Ingress Tool Transfer

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### PraisonAI MCP SSE server launched with vulnerable defaults (GHSA-x227-pf99-vffg)

`UC_63_1` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("python.exe","python3.exe","pythonw.exe","python","python3","uvicorn","uvicorn.exe") OR Processes.parent_process_name IN ("python.exe","python3.exe","pythonw.exe","python","python3")) AND (Processes.process="*praisonaiagents.mcp*" OR Processes.process="*launch_tools_mcp_server*" OR Processes.process="*ToolsMCPServer*" OR Processes.parent_process="*praisonaiagents.mcp*") by Processes.dest Processes.user Processes.process Processes.process_name Processes.parent_process Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (FileName in~ ("python.exe","python3.exe","pythonw.exe","python","python3","uvicorn","uvicorn.exe")
      or InitiatingProcessFileName in~ ("python.exe","python3.exe","pythonw.exe","python","python3"))
| where ProcessCommandLine has "praisonaiagents"
    or InitiatingProcessCommandLine has "praisonaiagents"
| where ProcessCommandLine has_any ("praisonaiagents.mcp","mcp_server","launch_tools_mcp_server","ToolsMCPServer","run_sse","transport=\"sse\"","transport='sse'")
    or InitiatingProcessCommandLine has_any ("praisonaiagents.mcp","mcp_server","launch_tools_mcp_server","ToolsMCPServer","run_sse","transport=\"sse\"","transport='sse'")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, SHA256
| order by Timestamp desc
```

### PraisonAI MCP host spawns shell/LOLBin — likely unauthenticated tools/call RCE (GHSA-x227-pf99-vffg)

`UC_63_2` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("python.exe","python3.exe","pythonw.exe","python","python3","uvicorn","uvicorn.exe") AND Processes.parent_process="*praisonaiagents*" AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","bash","sh","zsh","dash","whoami.exe","whoami","hostname.exe","hostname","ipconfig.exe","ifconfig","ip","net.exe","net1.exe","nltest.exe","systeminfo.exe","tasklist.exe","ps","curl.exe","curl","wget.exe","wget","certutil.exe","bitsadmin.exe","nc","ncat","ncat.exe","schtasks.exe","at.exe","reg.exe","rundll32.exe","regsvr32.exe") by Processes.dest Processes.user Processes.parent_process Processes.process Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("python.exe","python3.exe","pythonw.exe","python","python3","uvicorn","uvicorn.exe")
| where InitiatingProcessCommandLine has "praisonaiagents"
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe",
                     "bash","sh","zsh","dash",
                     "whoami.exe","whoami","hostname.exe","hostname",
                     "ipconfig.exe","ifconfig","ip",
                     "net.exe","net1.exe","nltest.exe","systeminfo.exe","tasklist.exe","ps",
                     "curl.exe","curl","wget.exe","wget",
                     "certutil.exe","bitsadmin.exe",
                     "nc","ncat","ncat.exe",
                     "schtasks.exe","at.exe","reg.exe",
                     "rundll32.exe","regsvr32.exe")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, SHA256
| order by Timestamp desc
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-x227-pf99-vffg: PraisonAI: MCP SSE transport binds 0.0.0.

`UC_63_0` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-x227-pf99-vffg: PraisonAI: MCP SSE transport binds 0.0.0. ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("mcp_security.py","mcp_websocket.py"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("mcp_security.py","mcp_websocket.py"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-x227-pf99-vffg: PraisonAI: MCP SSE transport binds 0.0.0.
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("mcp_security.py", "mcp_websocket.py"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("mcp_security.py", "mcp_websocket.py"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **CRIT** based on: 3 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

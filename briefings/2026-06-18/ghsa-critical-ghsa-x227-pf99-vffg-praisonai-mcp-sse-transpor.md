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
- **T1189** — Drive-by Compromise
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1059.001** — Command and Scripting Interpreter: PowerShell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Exposed PraisonAI MCP SSE listener accepting non-loopback connections

`UC_65_1` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count, values(All_Traffic.src) as src, values(All_Traffic.transport) as transport, min(_time) as firstTime, max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.direction="inbound" AND All_Traffic.process="*python*" AND NOT All_Traffic.src IN ("127.0.0.1","::1")) by All_Traffic.dest, All_Traffic.dest_port, All_Traffic.process | `drop_dm_object_name(All_Traffic)` | where dest_port!=0
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "InboundConnectionAccepted"
| where InitiatingProcessFileName has_any ("python","python3","python.exe","uvicorn")
| where InitiatingProcessCommandLine has "praisonai"
| where not(ipv4_is_match(RemoteIP, "127.0.0.0/8")) and RemoteIP != "::1"
| summarize Connections=count(), RemoteIPs=make_set(RemoteIP,20), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, LocalPort
| order by Connections desc
```

### Unauthenticated MCP SSE JSON-RPC tool invocation (/sse + /messages/ no Authorization)

`UC_65_2` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count, values(Web.http_method) as http_method, values(Web.status) as status, values(Web.http_user_agent) as user_agent, min(_time) as firstTime, max(_time) as lastTime from datamodel=Web where (Web.url="*/messages/*session_id=*" OR Web.url="*/sse*") by Web.src, Web.dest, Web.dest_port, Web.url | `drop_dm_object_name(Web)`
```

### PraisonAI MCP Python server spawning a command shell (unauth tools/call RCE)

`UC_65_3` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count, values(Processes.process) as process, min(_time) as firstTime, max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("python.exe","python3","python","uvicorn") AND Processes.parent_process="*praisonai*" AND Processes.process_name IN ("sh","bash","dash","zsh","cmd.exe","powershell.exe","pwsh")) by Processes.dest, Processes.user, Processes.parent_process, Processes.process_name, Processes.process | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName has_any ("python","python3","python.exe","uvicorn")
| where InitiatingProcessCommandLine has "praisonai"
| where FileName in~ ("sh","bash","dash","zsh","cmd.exe","powershell.exe","pwsh")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-x227-pf99-vffg: PraisonAI: MCP SSE transport binds 0.0.0.

`UC_65_0` · phase: **exploit** · confidence: **High**

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

Severity classified as **CRIT** based on: 4 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

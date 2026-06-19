# [CRIT] [GHSA / CRITICAL] GHSA-p75f-6fp4-p57w: PraisonAI: Missing Authentication for Critical Function and Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in praiso

**Source:** GitHub Security Advisories
**Published:** 2026-06-18
**Article:** https://github.com/advisories/GHSA-p75f-6fp4-p57w

## Threat Profile

PraisonAI: Missing Authentication for Critical Function and Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in praisonai

# Unauthenticated PraisonAI UI MCP connect endpoint executes attacker-chosen local commands

## Summary

PraisonAI v4.6.48 exposes the PraisonAIUI MCP client management API through the default UI host apps without authentication. A remote unauthenticated client can send `POST /api/mcp/connect` with a `command` and `args` field. The e…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File
- **T1190** — Exploit Public-Facing Application
- **T1133** — External Remote Services
- **T1059** — Command and Scripting Interpreter
- **T1106** — Native API

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### PraisonAI UI / aiui server listening on 0.0.0.0 (vulnerable exposure)

`UC_33_1` · phase: **weapon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where (Processes.process="*praisonai ui*" OR Processes.process="*praisonai claw*" OR Processes.process="*aiui run*" OR Processes.process="*praisonaiui.server.create_app*" OR Processes.process="*create_host_app*" OR Processes.process="*build_host_app*") by Processes.dest Processes.user Processes.process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents | where Timestamp > ago(7d) | where ProcessCommandLine has_any ("praisonai ui", "praisonai claw", "aiui run", "praisonaiui.server.create_app", "create_host_app", "build_host_app") | where AccountName !endswith "$" | project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine | order by Timestamp desc
```

### Unauthenticated POST /api/mcp/connect — exploit attempt at web tier

`UC_33_2` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as urls values(Web.http_user_agent) as ua values(Web.dest) as dest from datamodel=Web.Web where Web.http_method="POST" Web.url="*/api/mcp/connect*" by Web.src Web.user | `drop_dm_object_name(Web)` | where NOT cidrmatch("127.0.0.0/8",src) AND NOT cidrmatch("::1/128",src) | convert ctime(firstTime) ctime(lastTime)
```

### Child process spawned by PraisonAI UI / aiui (post-exploitation RCE)

`UC_33_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as child_cmd values(Processes.process_name) as child_name from datamodel=Endpoint.Processes where (Processes.parent_process="*praisonai ui*" OR Processes.parent_process="*praisonai claw*" OR Processes.parent_process="*aiui run*" OR Processes.parent_process="*praisonaiui.server*" OR Processes.parent_process="*create_host_app*" OR Processes.parent_process="*build_host_app*") AND NOT (Processes.process_name IN ("python.exe","python3","python3.10","python3.11","python3.12","conhost.exe","uvicorn","uvicorn.exe","node","node.exe")) by Processes.dest Processes.user Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents | where Timestamp > ago(7d) | where InitiatingProcessCommandLine has_any ("praisonai ui", "praisonai claw", "aiui run", "praisonaiui.server", "create_host_app", "build_host_app") | where FileName !in~ ("python.exe","python3","python3.exe","python3.10","python3.11","python3.12","conhost.exe","uvicorn","uvicorn.exe","node.exe") | project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine | order by Timestamp desc
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-p75f-6fp4-p57w: PraisonAI: Missing Authentication for Cri

`UC_33_0` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-p75f-6fp4-p57w: PraisonAI: Missing Authentication for Cri ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("aiui-mcp-connect-rce.py","server.py","mcp.py"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/usr/bin/touch*" OR Filesystem.file_path="*/tmp/praisonai_host_app_mcp_touch_marker.txt*" OR Filesystem.file_path="*/tmp/pwned-by-ui-mcp*" OR Filesystem.file_name IN ("aiui-mcp-connect-rce.py","server.py","mcp.py"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-p75f-6fp4-p57w: PraisonAI: Missing Authentication for Cri
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("aiui-mcp-connect-rce.py", "server.py", "mcp.py"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/usr/bin/touch", "/tmp/praisonai_host_app_mcp_touch_marker.txt", "/tmp/pwned-by-ui-mcp") or FileName in~ ("aiui-mcp-connect-rce.py", "server.py", "mcp.py"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **CRIT** based on: 4 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

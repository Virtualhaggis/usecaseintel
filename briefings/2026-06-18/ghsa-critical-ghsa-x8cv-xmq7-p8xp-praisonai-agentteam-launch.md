# [CRIT] [GHSA / CRITICAL] GHSA-x8cv-xmq7-p8xp: PraisonAI AgentTeam.launch exposes unauthenticated remote agent listing and invocation endpoints

**Source:** GitHub Security Advisories
**Published:** 2026-06-18
**Article:** https://github.com/advisories/GHSA-x8cv-xmq7-p8xp

## Threat Profile

PraisonAI AgentTeam.launch exposes unauthenticated remote agent listing and invocation endpoints

# PraisonAI `AgentTeam.launch()` exposes unauthenticated remote agent invocation endpoints

## Summary

PraisonAI's documented Python `AgentTeam.launch()` / `Agents.launch()` HTTP server starts externally reachable agent invocation endpoints without any authentication enforcement.

The current implementation registers `GET /{path}/list`, `POST /{path}`, and `POST /{path}/{agent_id}` routes. The POST…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File
- **T1190** — Exploit Public-Facing Application
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1133** — External Remote Services

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### PraisonAI AgentTeam.launch / Agents.launch bound to 0.0.0.0 (GHSA-x8cv-xmq7-p8xp)

`UC_56_1` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process_name) as parent_process_name from datamodel=Endpoint.Processes where Processes.process_name IN ("python.exe","python3.exe","pythonw.exe") (Processes.process="*praisonaiagents*" OR Processes.process="*AgentTeam*" OR Processes.process="*Agents.launch*" OR Processes.process="*praisonai*") (Processes.process="*0.0.0.0*" OR Processes.process="*host=0*" OR Processes.process="*--host 0*") by Processes.dest Processes.user Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("python.exe","python3.exe","pythonw.exe","uvicorn.exe")
| where ProcessCommandLine has_any ("praisonaiagents","AgentTeam","Agents.launch","praisonai")
| where ProcessCommandLine has_any ("0.0.0.0","host=0","--host 0")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Unauthenticated GET /{path}/list and POST hits to PraisonAI agent route

`UC_56_2` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.http_method) as method values(Web.src) as src from datamodel=Web.Web where (Web.url="*/list" OR Web.http_method="POST") Web.dest_port IN (8000,8080,5000,3000,7860,8001) by Web.dest Web.url Web.http_method Web.http_user_agent | `drop_dm_object_name(Web)` | where like(url,"%/list") OR method="POST" | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let PraisonHosts = DeviceProcessEvents
  | where Timestamp > ago(14d)
  | where ProcessCommandLine has_any ("praisonaiagents","AgentTeam","Agents.launch","praisonai")
  | distinct DeviceId, DeviceName;
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType in ("InboundConnectionAccepted","ListeningConnectionCreated","ConnectionSuccess")
| where InitiatingProcessFileName in~ ("python.exe","python3.exe","pythonw.exe","uvicorn.exe")
| where InitiatingProcessCommandLine has_any ("praisonaiagents","AgentTeam","Agents.launch","praisonai")
| where LocalPort in (8000,8080,5000,3000,7860,8001) or LocalPort > 1024
| where RemoteIPType in ("Public","Private") and RemoteIP !in ("127.0.0.1","::1")
| join kind=inner PraisonHosts on DeviceId
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, LocalIP, LocalPort, RemoteIP, RemotePort, ActionType
| order by Timestamp desc
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-x8cv-xmq7-p8xp: PraisonAI AgentTeam.launch exposes unauth

`UC_56_0` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-x8cv-xmq7-p8xp: PraisonAI AgentTeam.launch exposes unauth ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("poc_agentteam_launch_unauth.py"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/usr/bin/env*" OR Filesystem.file_name IN ("poc_agentteam_launch_unauth.py"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-x8cv-xmq7-p8xp: PraisonAI AgentTeam.launch exposes unauth
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("poc_agentteam_launch_unauth.py"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/usr/bin/env") or FileName in~ ("poc_agentteam_launch_unauth.py"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **CRIT** based on: 3 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

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
- **T1133** — External Remote Services

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Unauthenticated PraisonAI AgentTeam.launch agent invocation via /agents endpoints

`UC_145_1` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.http_method="GET" AND Web.url="*/agents/list") OR (Web.http_method="POST" AND Web.url="*/agents") OR (Web.http_method="POST" AND Web.url="*/agents/*") by Web.src, Web.dest, Web.http_user_agent, Web.url, Web.http_method, Web.status
| `drop_dm_object_name(Web)`
| where status=200
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| sort - count
```

### Internet-facing Python host running PraisonAI Agents.launch bound to 0.0.0.0

`UC_145_2` · phase: **delivery** · confidence: **Low** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where Network_Traffic.direction="inbound" AND Network_Traffic.app IN ("python*","uvicorn*") by Network_Traffic.dest, Network_Traffic.dest_port, Network_Traffic.src, Network_Traffic.app
| `drop_dm_object_name(Network_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| sort - count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "InboundConnectionAccepted"
| where RemoteIPType == "Public"
| where InitiatingProcessFileName in~ ("python.exe","python3.exe","pythonw.exe","uvicorn.exe")
| where InitiatingProcessCommandLine has_any ("praisonai","AgentTeam",".launch","Agents") or InitiatingProcessFolderPath has "praisonai"
| summarize Connections = count(), DistinctSources = dcount(RemoteIP), Ports = make_set(LocalPort), SampleCmd = any(InitiatingProcessCommandLine), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Connections desc
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-x8cv-xmq7-p8xp: PraisonAI AgentTeam.launch exposes unauth

`UC_145_0` · phase: **exploit** · confidence: **High**

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

Severity classified as **CRIT** based on: 3 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

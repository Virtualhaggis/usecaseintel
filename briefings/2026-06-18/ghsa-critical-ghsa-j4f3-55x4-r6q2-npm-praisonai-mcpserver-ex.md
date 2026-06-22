# [CRIT] [GHSA / CRITICAL] GHSA-j4f3-55x4-r6q2: npm PraisonAI MCPServer exposes unauthenticated HTTP tools/call

**Source:** GitHub Security Advisories
**Published:** 2026-06-18
**Article:** https://github.com/advisories/GHSA-j4f3-55x4-r6q2

## Threat Profile

npm PraisonAI MCPServer exposes unauthenticated HTTP tools/call

## Summary

The published npm package `praisonai` exports a TypeScript `MCPServer` that can expose tools, resources, and prompts over an HTTP JSON-RPC transport with:

```ts
await server.start({ port: 3000 });
```

The HTTP transport has no authentication or authorization path. `MCPServerConfig` does not expose an auth/security setting, `startHttp()` ignores the `Authorization` header, and every POST request is parsed and forwarded…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1204.002** — User Execution: Malicious File
- **T1190** — Exploit Public-Facing Application
- **T1059** — Command and Scripting Interpreter

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Node.js MCP server reachable from public clients (unauthenticated MCPServer exposure)

`UC_58_2` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.direction=inbound All_Traffic.process_name=node* by All_Traffic.src_ip All_Traffic.dest All_Traffic.dest_port All_Traffic.process_name | `drop_dm_object_name(All_Traffic)` | where NOT (cidrmatch("10.0.0.0/8",src_ip) OR cidrmatch("172.16.0.0/12",src_ip) OR cidrmatch("192.168.0.0/16",src_ip) OR cidrmatch("127.0.0.0/8",src_ip)) | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "InboundConnectionAccepted"
| where InitiatingProcessFileName in~ ("node.exe","node")
| where RemoteIPType == "Public"
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), ConnCount=count(), RemoteIPs=make_set(RemoteIP, 50) by DeviceName, LocalPort, InitiatingProcessId, InitiatingProcessCommandLine
| order by FirstSeen desc
```

### PraisonAI MCP server (node) spawns shell/LOLBin child after external connection

`UC_58_3` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name=node.exe (Processes.process_name=cmd.exe OR Processes.process_name=powershell.exe OR Processes.process_name=pwsh.exe OR Processes.process_name=wscript.exe OR Processes.process_name=cscript.exe OR Processes.process_name=mshta.exe OR Processes.process_name=rundll32.exe OR Processes.process_name=certutil.exe OR Processes.process_name=curl.exe OR Processes.process_name=bitsadmin.exe) by Processes.dest Processes.user Processes.parent_process Processes.process Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let Window = 5m;
let InboundReach = DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where ActionType == "InboundConnectionAccepted"
    | where InitiatingProcessFileName in~ ("node.exe","node")
    | where RemoteIPType == "Public"
    | project ConnTime=Timestamp, DeviceId, ServerPid=InitiatingProcessId, RemoteIP, LocalPort;
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node.exe","node")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","certutil.exe","curl.exe","bitsadmin.exe","bash.exe","sh.exe")
| join kind=inner InboundReach on DeviceId
| where InitiatingProcessId == ServerPid
| where Timestamp between (ConnTime .. ConnTime + Window)
| project ConnTime, SpawnTime=Timestamp, DelaySec=datetime_diff('second', Timestamp, ConnTime), DeviceName, AccountName, RemoteIP, LocalPort, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by ConnTime desc
```

### OAuth consent / suspicious app grant

`UC_OAUTH_ABUSE` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Authentication.Authentication
    where Authentication.action="success"
      AND Authentication.signature IN (
        "Consent to application",
        "Add app role assignment grant to user",
        "Add OAuth2PermissionGrant",
        "Add delegated permission grant")
    by Authentication.user, Authentication.app, Authentication.src, Authentication.signature
| `drop_dm_object_name(Authentication)`
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("Consent to application.","Add OAuth2PermissionGrant.","Add delegated permission grant.")
| project Timestamp, AccountObjectId, AccountDisplayName, ActivityType,
          ActivityObjects, IPAddress, UserAgent
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-j4f3-55x4-r6q2: npm PraisonAI MCPServer exposes unauthent

`UC_58_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-j4f3-55x4-r6q2: npm PraisonAI MCPServer exposes unauthent ```
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
// Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-j4f3-55x4-r6q2: npm PraisonAI MCPServer exposes unauthent
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

Severity classified as **CRIT** based on: 4 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

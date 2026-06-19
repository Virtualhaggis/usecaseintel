# [CRIT] [GHSA / CRITICAL] GHSA-9752-mhqh-h34f: npm PraisonAI AgentOS exposes unauthenticated agent listing and invocation

**Source:** GitHub Security Advisories
**Published:** 2026-06-18
**Article:** https://github.com/advisories/GHSA-9752-mhqh-h34f

## Threat Profile

npm PraisonAI AgentOS exposes unauthenticated agent listing and invocation

## Summary

The published npm package `praisonai` ships a TypeScript `AgentOS` HTTP server that defaults to `host: "0.0.0.0"` and registers sensitive agent routes without any authentication or authorization middleware.

When a developer starts `AgentOS`, a network attacker who can reach the service can:

- read configured agent names, roles, and the first 100 characters of each agent's instructions through `GET /api/agen…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1190** — Exploit Public-Facing Application
- **T1133** — External Remote Services
- **T1059** — Command and Scripting Interpreter
- **T1213** — Data from Information Repositories

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Vulnerable PraisonAI npm AgentOS server process running (GHSA-9752-mhqh-h34f, 1.6.0-1.7.1)

`UC_32_1` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="node.exe" OR Processes.process_name="node") AND (Processes.process="*praisonai*" OR Processes.process="*agentos.js*" OR Processes.process="*dist/os/agentos*" OR Processes.process="*dist\\os\\agentos*") by Processes.dest Processes.user Processes.process Processes.parent_process Processes.process_id | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | eval ghsa="GHSA-9752-mhqh-h34f"
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("node.exe", "node")
| where ProcessCommandLine has_any ("praisonai", "agentos.js", "dist/os/agentos", @"dist\os\agentos", "AgentOS")
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            arg_max(Timestamp, ProcessCommandLine, FolderPath, InitiatingProcessFileName, AccountName)
        by DeviceId, DeviceName
| project DeviceName, AccountName, FirstSeen, LastSeen, ProcessCommandLine, FolderPath, InitiatingProcessFileName
| order by LastSeen desc
```

### Unauthenticated request to PraisonAI AgentOS /api/agents or /api/chat from non-loopback source

`UC_32_2` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as urls values(Web.http_method) as methods values(Web.status) as statuses values(Web.http_user_agent) as user_agents from datamodel=Web.Web where (Web.url="*/api/agents*" OR Web.url="*/api/chat*") AND Web.dest_port IN (8000,3000,4000,80,443) AND NOT (Web.src IN ("127.0.0.1","::1")) by Web.src Web.dest Web.dest_port | `drop_dm_object_name(Web)` | search urls="*/api/agents*" OR urls="*/api/chat*" | eval ghsa="GHSA-9752-mhqh-h34f" | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let praisonHosts = DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName in~ ("node.exe", "node")
    | where ProcessCommandLine has_any ("praisonai", "agentos.js", "dist/os/agentos")
    | summarize by DeviceId, DeviceName;
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "InboundConnectionAccepted"
| where InitiatingProcessFileName in~ ("node.exe", "node")
| where InitiatingProcessCommandLine has_any ("praisonai", "agentos.js", "dist/os/agentos")
| where LocalPort in (8000, 3000, 4000)
| where RemoteIPType != "Loopback"
| join kind=inner praisonHosts on DeviceId
| project Timestamp, DeviceName, RemoteIP, RemoteIPType, RemotePort, LocalPort,
          InitiatingProcessId, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
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


## Why this matters

Severity classified as **CRIT** based on: 3 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

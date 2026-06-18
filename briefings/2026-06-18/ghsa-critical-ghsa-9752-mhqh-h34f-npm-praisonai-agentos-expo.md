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
- **T1059** — Command and Scripting Interpreter

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### node.exe spawn loading vulnerable PraisonAI AgentOS package (npm:praisonai 1.6.0-1.7.1)

`UC_22_1` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="node.exe" (Processes.process="*praisonai*" OR Processes.process="*agentos.js*" OR Processes.process="*dist/os/agentos*" OR Processes.process="*AgentOS*") by Processes.dest Processes.user Processes.process Processes.parent_process_name Processes.parent_process Processes.process_path | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "node.exe"
| where ProcessCommandLine has_any ("praisonai", "agentos.js", "AgentOS", "dist/os/agentos")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, SHA256
| order by Timestamp desc
```

### Unauthenticated requests to PraisonAI AgentOS /api/agents or /api/chat endpoints

`UC_22_2` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*/api/agents*" OR Web.url="*/api/chat*") Web.status=200 by Web.src Web.dest Web.url Web.http_method Web.http_user_agent Web.dest_port | `drop_dm_object_name(Web)` | where dest_port=8000 OR dest_port=3000 OR dest_port=8080 | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType in ("InboundConnectionAccepted", "ConnectionAccepted")
| where InitiatingProcessFileName =~ "node.exe"
| where InitiatingProcessCommandLine has_any ("praisonai", "agentos")
| where LocalPort in (8000, 3000, 8080)
| where RemoteIPType !in ("Loopback")
| project Timestamp, DeviceName, LocalIP, LocalPort, RemoteIP, RemotePort, RemoteIPType, InitiatingProcessCommandLine, InitiatingProcessAccountName
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

Severity classified as **CRIT** based on: 3 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

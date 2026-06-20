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
- **T1213** — Data from Information Repositories
- **T1133** — External Remote Services

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Unauthenticated PraisonAI AgentOS API access (GET /api/agents, POST /api/chat)

`UC_54_1` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url IN ("*/api/agents","*/api/agents?*","*/api/chat","*/api/chat?*")) (Web.http_method IN ("GET","POST")) (Web.status=200) by Web.src, Web.dest, Web.dest_port, Web.http_method, Web.url, Web.status, Web.http_user_agent | `drop_dm_object_name(Web)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | sort - lastTime
```

### PraisonAI AgentOS node listener exposed on 0.0.0.0:8000 to non-loopback

`UC_54_2` · phase: **delivery** · confidence: **Low** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_port=8000) (All_Traffic.direction="inbound" OR All_Traffic.transport="tcp") (All_Traffic.action="allowed") by All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port, All_Traffic.app, All_Traffic.action | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType in ("InboundConnectionAccepted", "ListeningConnectionCreated")
| where LocalPort == 8000
| where InitiatingProcessFileName =~ "node.exe"
| where RemoteIPType == "Public" or ActionType == "ListeningConnectionCreated"
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), RemoteIPs=make_set(RemoteIP, 50), ConnCount=count() by DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, LocalIP, LocalPort, ActionType
| order by LastSeen desc
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

Severity classified as **CRIT** based on: 3 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

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

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### PraisonAI AgentOS Node server exposed to non-loopback on default port 8000

`UC_91_1` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true allow_old_summaries=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port=8000 All_Traffic.direction=inbound (All_Traffic.transport=tcp OR All_Traffic.transport="6") by All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port, All_Traffic.app | `drop_dm_object_name(All_Traffic)` | where app="node.exe" OR app="node" OR isnull(app) | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "InboundConnectionAccepted"
| where LocalPort == 8000
| where InitiatingProcessFileName =~ "node.exe"
| where RemoteIPType != "Loopback" and RemoteIP != "127.0.0.1" and RemoteIP != "::1"
| summarize Connections = count(), DistinctSources = dcount(RemoteIP), FirstSeen = min(Timestamp), LastSeen = max(Timestamp), SampleSources = make_set(RemoteIP, 20) by DeviceName, LocalPort, InitiatingProcessFolderPath, InitiatingProcessCommandLine
| order by LastSeen desc
```

### Unauthenticated PraisonAI AgentOS API hits: GET /api/agents enumeration + POST /api/chat invocation

`UC_91_2` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true allow_old_summaries=true count values(Web.http_method) as methods values(Web.url) as urls min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*/api/agents*" OR Web.url="*/api/chat*") Web.status=200 by Web.src, Web.dest, Web.site, Web.http_user_agent | `drop_dm_object_name(Web)` | eval scanner=if(match(http_user_agent,"(?i)CVE-Detector"),"yes","no") | eval hit_both=if(mvcount(mvfilter(match(urls,"/api/agents")))>0 AND mvcount(mvfilter(match(urls,"/api/chat")))>0,"yes","no") | where hit_both="yes" OR scanner="yes" | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

### Vulnerable PraisonAI npm package present (dist/os/agentos.js) on managed hosts

`UC_91_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true allow_old_summaries=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Endpoint.Filesystem.file_name="agentos.js" Endpoint.Filesystem.file_path="*praisonai*os*" by Endpoint.Filesystem.dest, Endpoint.Filesystem.file_path, Endpoint.Filesystem.process_name, Endpoint.Filesystem.user | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName =~ "agentos.js"
| where FolderPath has "praisonai" and FolderPath has @"\dist\os\"
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp), Paths = make_set(FolderPath, 10) by DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
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

Severity classified as **CRIT** based on: 4 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

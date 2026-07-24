# [CRIT] [GHSA / CRITICAL] GHSA-vjc7-jrh9-9j86: 9router has unauthenticated CRUD on /api/providers and Full API Key Leak via /api/usage/stats

**Source:** GitHub Security Advisories
**Published:** 2026-07-06
**Article:** https://github.com/advisories/GHSA-vjc7-jrh9-9j86

## Threat Profile

9router has unauthenticated CRUD on /api/providers and Full API Key Leak via /api/usage/stats

---
title: Unauthenticated CRUD on /api/providers and Full API Key Leak via /api/usage/stats
product: 9Router
version: <= 0.4.41
severity: critical
cve_request: true
---

## Summary

Multiple critical API security vulnerabilities were discovered in 9Router's Next.js dashboard. The `/api/providers` endpoints lack authentication entirely, allowing anyone to create, read, update, and delete provider conne…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1204.002** — User Execution: Malicious File
- **T1595.002** — Active Scanning: Vulnerability Scanning
- **T1046** — Network Service Discovery
- **T1565.001** — Data Manipulation: Stored Data Manipulation
- **T1098.003** — Account Manipulation: Additional Cloud Roles
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1530** — Data from Cloud Storage
- **T1213** — Data from Information Repositories

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Recon scanning of 9router unauthenticated /api/* endpoints from single source

`UC_207_2` · phase: **recon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count as req_count, dc(Web.uri_path) as distinct_paths, values(Web.uri_path) as paths, values(Web.status) as statuses from datamodel=Web where (Web.uri_path IN ("/api/providers","/api/usage/stats","/api/usage/request-logs","/api/models","/api/v1/models","/api/version") OR Web.uri_path="/api/providers/*" OR Web.uri_path="/api/usage/request-details/*") by Web.src, Web.dest, Web.http_user_agent, _time span=5m
| `drop_dm_object_name(Web)`
| where distinct_paths >= 6
| sort - distinct_paths, - req_count
```

### Unauthenticated 9router provider CRUD mutation (rogue-provider / key-swap / DoS)

`UC_207_3` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, values(Web.http_method) as methods, values(Web.status) as statuses, values(Web.http_user_agent) as user_agents from datamodel=Web where (Web.uri_path="/api/providers" OR Web.uri_path="/api/providers/*") AND Web.http_method IN ("POST","PUT","DELETE") by Web.src, Web.dest, Web.uri_path, _time span=1m
| `drop_dm_object_name(Web)`
| sort - _time
```

### 9router API-key leak via unauthenticated GET /api/usage/stats and /api/usage/request-logs

`UC_207_4` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, values(Web.http_user_agent) as user_agents, sum(Web.bytes_out) as bytes_out from datamodel=Web where Web.uri_path IN ("/api/usage/stats","/api/usage/request-logs") AND Web.http_method="GET" AND Web.status=200 by Web.src, Web.dest, Web.uri_path, _time span=1m
| `drop_dm_object_name(Web)`
| sort - _time
```

### Bulk enumeration of 9router /api/usage/request-details (conversation-history exfiltration)

`UC_207_5` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, dc(Web.uri_path) as distinct_details, sum(Web.bytes_out) as bytes_out, values(Web.http_user_agent) as user_agents from datamodel=Web where Web.uri_path="/api/usage/request-details/*" AND Web.http_method="GET" AND Web.status=200 by Web.src, Web.dest, _time span=30m
| `drop_dm_object_name(Web)`
| where distinct_details >= 25   // 25+ distinct conversation UUIDs pulled by one src in 30m = enumeration, not a user reviewing their own history
| sort - distinct_details
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

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-vjc7-jrh9-9j86: 9router has unauthenticated CRUD on /api/

`UC_207_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-vjc7-jrh9-9j86: 9router has unauthenticated CRUD on /api/ ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("next.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("next.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-vjc7-jrh9-9j86: 9router has unauthenticated CRUD on /api/
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("next.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("next.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **CRIT** based on: 6 use case(s) fired, 10 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

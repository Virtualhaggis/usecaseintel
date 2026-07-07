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
- **T1190** — Exploit Public-Facing Application
- **T1552** — Unsecured Credentials
- **T1565.001** — Data Manipulation: Stored Data Manipulation

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Unauthenticated read of 9router credential/usage API endpoints (API-key & conversation leak)

`UC_3_2` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, min(_time) as firstTime, max(_time) as lastTime from datamodel=Web where Web.http_method=GET Web.status=200 (Web.uri_path IN ("/api/usage/stats","/api/providers","/api/usage/request-logs") OR Web.uri_path="/api/usage/request-details/*" OR Web.uri_path="/api/providers/*") by Web.src, Web.dest, Web.uri_path, Web.http_method, Web.status, Web.http_user_agent
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| sort - lastTime
```

### Unauthenticated provider CRUD tampering on 9router /api/providers (rogue provider / key swap / DoS)

`UC_3_3` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, values(Web.http_method) as http_methods, values(Web.status) as statuses, min(_time) as firstTime, max(_time) as lastTime from datamodel=Web where Web.http_method IN ("POST","PUT","DELETE") (Web.uri_path="/api/providers" OR Web.uri_path="/api/providers/*") by Web.src, Web.dest, Web.uri_path, Web.http_user_agent
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| sort - lastTime
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

`UC_3_1` · phase: **exploit** · confidence: **High**

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

Severity classified as **CRIT** based on: 4 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

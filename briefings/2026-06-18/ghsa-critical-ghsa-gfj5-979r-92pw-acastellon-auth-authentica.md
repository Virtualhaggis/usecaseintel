# [CRIT] [GHSA / CRITICAL] GHSA-gfj5-979r-92pw: @acastellon/auth: Authentication bypass via spoofable headers in validateToken()

**Source:** GitHub Security Advisories
**Published:** 2026-06-18
**Article:** https://github.com/advisories/GHSA-gfj5-979r-92pw

## Threat Profile

@acastellon/auth: Authentication bypass via spoofable headers in validateToken()

@acastellon/auth v2.2.0 appears to allow an unauthenticated authentication bypass in validateToken() through spoofable auth-user and Host request headers.

The validateToken middleware contains a service-to-service bypass for auth-user: service-brother when req.get('host').startsWith(getHostName()). Both values involved in the check can be influenced by an unauthenticated HTTP client: auth-user is a request header,…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File
- **T1190** — Exploit Public-Facing Application
- **T1078** — Valid Accounts
- **T1556** — Modify Authentication Process

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### service-brother identity reaching admin/protected or mutating endpoints (post-bypass abuse)

`UC_50_1` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, min(_time) as firstTime, max(_time) as lastTime, values(Web.status) as status, values(Web.http_user_agent) as user_agent from datamodel=Web where Web.http_method IN ("POST","PUT","DELETE","PATCH") (Web.url="*/admin*" OR Web.url="*/protected*" OR Web.url="*/graphql*" OR Web.url="*/internal*") Web.status>=200 Web.status<300 by Web.src, Web.dest, Web.url, Web.http_method
| `drop_dm_object_name(Web)`
| sort - lastTime
```

### Vulnerable @acastellon/auth (<2.3.0) package present on host

`UC_50_2` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, min(_time) as firstTime, max(_time) as lastTime, values(Filesystem.file_name) as file_name from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*node_modules/@acastellon/auth*" OR Filesystem.file_path="*node_modules\\@acastellon\\auth*") (Filesystem.file_name="auth.js" OR Filesystem.file_name="package.json") by Filesystem.dest, Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has @"node_modules\@acastellon\auth" or FolderPath has "node_modules/@acastellon/auth"
| where FileName in~ ("auth.js","package.json")
| project Timestamp, DeviceName, FolderPath, FileName, SHA256, InitiatingProcessFileName, InitiatingProcessAccountName
| sort by Timestamp desc
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-gfj5-979r-92pw: @acastellon/auth: Authentication bypass v

`UC_50_0` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-gfj5-979r-92pw: @acastellon/auth: Authentication bypass v ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("auth.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("auth.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-gfj5-979r-92pw: @acastellon/auth: Authentication bypass v
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("auth.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("auth.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **CRIT** based on: 3 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

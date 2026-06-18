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

### @acastellon/auth validateToken() bypass via spoofable 'auth-user: service-brother' header

`UC_2_1` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.http_method) as http_method values(Web.http_user_agent) as ua values(Web.dest) as dest from datamodel=Web.Web where (Web.http_request_headers="*auth-user: service-brother*" OR Web.http_request_headers="*auth-user:service-brother*" OR Web.http_request_headers="*Auth-User: service-brother*") by Web.src Web.user Web.dest Web.url _time span=1m | `drop_dm_object_name("Web")` | rename src as src_ip | eval is_admin_flag=if(match(http_request_headers,"(?i)is-admin\s*:\s*true"),"yes","no") | where firstTime > relative_time(now(),"-7d")
```

**Defender KQL:**
```kql
// Surfaces auth-user: service-brother header in WAF/proxy events forwarded to Defender via custom connectors
let Lookback = 7d;
DeviceNetworkEvents
| where Timestamp > ago(Lookback)
| where RemotePort in (80, 443, 8080, 8443)
| where InitiatingProcessFileName has_any ("node.exe", "node", "nginx", "haproxy", "envoy")
| join kind=inner (
    AlertEvidence
    | where Timestamp > ago(Lookback)
    | where AdditionalFields has "auth-user" and AdditionalFields has "service-brother"
) on DeviceId
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          AdditionalFields
| order by Timestamp desc
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-gfj5-979r-92pw: @acastellon/auth: Authentication bypass v

`UC_2_0` · phase: **exploit** · confidence: **High**

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

Severity classified as **CRIT** based on: 2 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

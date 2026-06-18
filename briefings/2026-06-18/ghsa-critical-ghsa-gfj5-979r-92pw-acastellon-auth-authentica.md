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
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1078** — Valid Accounts
- **T1068** — Exploitation for Privilege Escalation
- **T1556** — Modify Authentication Process
- **T1071.001** — Application Layer Protocol: Web Protocols

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### @acastellon/auth bypass — spoofed 'auth-user: service-brother' header from untrusted source

`UC_5_1` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where Web.http_user_agent_length>0 (Web.http_request_headers="*auth-user: service-brother*" OR Web.http_request_headers="*auth-user:service-brother*") by Web.src Web.dest Web.url Web.http_method Web.status Web.http_user_agent | `drop_dm_object_name(Web)` | search NOT src IN (10.0.0.0/8,172.16.0.0/12,192.168.0.0/16) | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

### @acastellon/auth bypass — auth-user spoof combined with is-admin / is-* privilege headers

`UC_5_2` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.http_request_headers="*auth-user: service-brother*" OR Web.http_request_headers="*auth-user:service-brother*") (Web.http_request_headers="*is-admin: true*" OR Web.http_request_headers="*is-admin:true*" OR Web.http_request_headers="*is-superuser:*" OR Web.http_request_headers="*is-internal:*") by Web.src Web.dest Web.url Web.http_method Web.status | `drop_dm_object_name(Web)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

### @acastellon/auth bypass — Host header reflection matching getHostName() check

`UC_5_3` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.http_request_headers="*auth-user: service-brother*" OR Web.http_request_headers="*auth-user:service-brother*") by Web.src Web.dest Web.dest_host Web.url Web.http_method Web.status Web.vendor_product | `drop_dm_object_name(Web)` | rex field=http_request_headers "(?i)host\s*:\s*(?<HostHeader>[^\r\n]+)" | eval HostMismatch=if(match(HostHeader,"(?i)".dest_host),"match","mismatch") | where HostMismatch="mismatch" OR isnull(dest_host) | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

### @acastellon/auth bypass — anomalous endpoints accessed under 'service-brother' identity

`UC_5_4` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Web.Web where (Web.http_request_headers="*auth-user: service-brother*" OR Web.http_request_headers="*auth-user:service-brother*") by _time Web.src Web.dest Web.url Web.http_method | `drop_dm_object_name(Web)` | bin _time span=1d | eventstats values(url) as BaselineUrls by dest | eval IsNewUrl=if(mvfind(BaselineUrls,url)>=0,0,1) | where IsNewUrl=1 OR http_method IN ("DELETE","PUT","PATCH") | stats count min(_time) as firstSeen max(_time) as lastSeen values(url) as Urls values(http_method) as Methods by src dest | where count > 0
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-gfj5-979r-92pw: @acastellon/auth: Authentication bypass v

`UC_5_0` · phase: **exploit** · confidence: **High**

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

Severity classified as **CRIT** based on: 5 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

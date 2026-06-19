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
- **T1195.001** — Supply Chain Compromise: Compromise Software Dependencies
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1548** — Abuse Elevation Control Mechanism

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### HTTP request with spoofed 'auth-user: service-brother' header (@acastellon/auth GHSA-gfj5-979r-92pw)

`UC_20_1` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count earliest(_time) as first_seen latest(_time) as last_seen from datamodel=Web where (Web.cookie="*service-brother*" OR Web.url="*service-brother*" OR Web.http_user_agent="*service-brother*" OR Web.body="*auth-user*service-brother*") by Web.src Web.dest Web.url Web.http_method Web.http_user_agent Web.user
| `drop_dm_object_name(Web)`
| eval signature="auth-user: service-brother (GHSA-gfj5-979r-92pw)", external_src=if(cidrmatch("10.0.0.0/8",src) OR cidrmatch("172.16.0.0/12",src) OR cidrmatch("192.168.0.0/16",src),"no","yes")
| where count > 0
| sort 0 - last_seen
```

**Defender KQL:**
```kql
// @acastellon/auth ships as a Node.js dependency — HTTP request headers are NOT in Defender XDR endpoint tables. This query surfaces internet-facing Node.js listeners on hosts likely to be running the vulnerable middleware; the actual header inspection must run on WAF/proxy logs (see sentinel_kql / datadog_query).
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName in~ ("node.exe","nodejs.exe","pm2.exe")
| where LocalPort in (80,443,3000,4000,5000,8080,8443)
| where RemoteIPType == "Public"
| where ActionType == "InboundConnectionAccepted" or ActionType == "ConnectionAccepted"
| summarize InboundConns=count(), DistinctRemoteIPs=dcount(RemoteIP), arg_max(Timestamp, RemoteIP, RemotePort) by DeviceName, InitiatingProcessFileName, LocalPort
| where InboundConns > 0
| extend Advisory="GHSA-gfj5-979r-92pw — verify @acastellon/auth dependency on this host"
| order by InboundConns desc
```

### Vulnerable @acastellon/auth (<2.3.0) package on disk + internet-facing Node.js listener

`UC_20_2` · phase: **weapon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count earliest(_time) as first_seen latest(_time) as last_seen from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*node_modules*acastellon*auth*" AND (Filesystem.file_name="package.json" OR Filesystem.file_name="auth.js")) by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.user
| `drop_dm_object_name(Filesystem)`
| eval advisory="GHSA-gfj5-979r-92pw — verify version < 2.3.0 in package.json"
| stats values(file_path) as paths, values(file_name) as files, min(first_seen) as first_seen, max(last_seen) as last_seen by dest, advisory
| sort 0 - last_seen
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath contains "node_modules" and FolderPath contains "acastellon" and FolderPath contains "auth"
| where FileName in~ ("package.json","auth.js")
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), arg_max(Timestamp, FolderPath, InitiatingProcessFileName) by DeviceName, FileName
| join kind=leftouter (
    DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessFileName in~ ("node.exe","nodejs.exe")
    | where LocalPort in (80,443,3000,4000,5000,8080,8443)
    | where RemoteIPType == "Public"
    | summarize NodeInboundConns=count() by DeviceName
) on DeviceName
| extend InternetFacing = iif(isnotempty(NodeInboundConns) and NodeInboundConns > 0, "yes", "unknown"), Advisory="GHSA-gfj5-979r-92pw — @acastellon/auth < 2.3.0"
| project DeviceName, FileName, FolderPath, FirstSeen, LastSeen, NodeInboundConns, InternetFacing, Advisory
| order by InternetFacing desc, LastSeen desc
```

### Spoofable privilege-claim headers (is-admin / is-*) downstream of @acastellon/auth bypass

`UC_20_3` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count earliest(_time) as first_seen latest(_time) as last_seen from datamodel=Web where (Web.cookie="*is-admin*" OR Web.cookie="*is-superuser*" OR Web.cookie="*is-staff*" OR Web.cookie="*is-root*" OR Web.body="*is-admin*true*" OR Web.body="*is-superuser*true*" OR Web.url="*is-admin*") by Web.src Web.dest Web.url Web.http_method Web.http_user_agent
| `drop_dm_object_name(Web)`
| eval paired_with_bypass=if(match(_raw,"(?i)service-brother"),"yes","no"), external_src=if(cidrmatch("10.0.0.0/8",src) OR cidrmatch("172.16.0.0/12",src) OR cidrmatch("192.168.0.0/16",src),"no","yes"), signature="is-* privilege-claim header (GHSA-gfj5-979r-92pw downstream primitive)"
| where count > 0
| sort 0 - paired_with_bypass - last_seen
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-gfj5-979r-92pw: @acastellon/auth: Authentication bypass v

`UC_20_0` · phase: **exploit** · confidence: **High**

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

Severity classified as **CRIT** based on: 4 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

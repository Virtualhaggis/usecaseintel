# [CRIT] [GHSA / CRITICAL] GHSA-mqhr-6j6h-74p5: Budibase: Unauthenticated REST Datasource Credential Theft via Cross-Origin Auth Leak

**Source:** GitHub Security Advisories
**Published:** 2026-07-24
**Article:** https://github.com/advisories/GHSA-mqhr-6j6h-74p5

## Threat Profile

Budibase: Unauthenticated REST Datasource Credential Theft via Cross-Origin Auth Leak

## Summary
Budibase attaches a REST datasource's stored credentials (Bearer/Basic tokens and static headers) to an outgoing request before it decides which host the request goes to, and never checks that the destination host matches the datasource. A query's request path can be pointed at any host (via an absolute URL or a user-supplied `{{ parameter }}`), so the stored credentials are delivered to an attacker…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File
- **T1190** — Exploit Public-Facing Application
- **T1552** — Unsecured Credentials
- **T1567** — Exfiltration Over Web Service

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Budibase REST query published to PUBLIC role (unauth cred-leak enabler)

`UC_154_1` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.http_user_agent) as user_agent values(Web.status) as status from datamodel=Web where Web.http_method=POST Web.url="*/api/permission/PUBLIC/query_*" (Web.url="*/read" OR Web.url="*/write") by Web.src Web.dest Web.url
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| sort - lastTime
```

### Budibase server leaks datasource auth to first-seen host (undici + Authorization egress)

`UC_154_2` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` earliest(_time) as firstTime latest(_time) as lastTime count from datamodel=Web where Web.http_user_agent="undici" by Web.dest
| `drop_dm_object_name(Web)`
| where firstTime >= relative_time(now(), "-1d@d")
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| sort - firstTime
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-mqhr-6j6h-74p5: Budibase: Unauthenticated REST Datasource

`UC_154_0` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-mqhr-6j6h-74p5: Budibase: Unauthenticated REST Datasource ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/dev/null*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-mqhr-6j6h-74p5: Budibase: Unauthenticated REST Datasource
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/dev/null"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **CRIT** based on: 3 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

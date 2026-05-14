# [CRIT] [GHSA / CRITICAL] GHSA-9pq7-mfwh-xx2j: phpMyFAQ enables unauthenticated 2FA brute-force attack via /admin/check acceptance of arbitrary user-id

**Source:** GitHub Security Advisories
**Published:** 2026-05-06
**Article:** https://github.com/advisories/GHSA-9pq7-mfwh-xx2j

## Threat Profile

phpMyFAQ enables unauthenticated 2FA brute-force attack via /admin/check acceptance of arbitrary user-id

## Summary

The `/admin/check` endpoint in `AuthenticationController` implements `SkipsAuthenticationCheck`, making it reachable without any prior authentication. An anonymous attacker (Bob) can POST arbitrary `user-id` and `token` values to brute-force any user's 6-digit TOTP code. No rate limiting exists. The 10^6 keyspace is exhaustible in minutes. Reachability confirmed against a default…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File
- **T1110.001** — Brute Force: Password Guessing
- **T1556.006** — Modify Authentication Process: Multi-Factor Authentication
- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] phpMyFAQ /admin/check unauthenticated 2FA brute-force burst (GHSA-9pq7-mfwh-xx2j)

`UC_151_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count as Attempts, values(Web.status) as Statuses, values(Web.http_user_agent) as UserAgents, min(_time) as FirstSeen, max(_time) as LastSeen from datamodel=Web where Web.http_method=POST AND Web.url="*/admin/check*" by Web.src, Web.dest, _time span=5m | `drop_dm_object_name("Web")` | where Attempts > 50 | sort - Attempts
```

### [LLM] phpMyFAQ /admin/check accessed by scripted HTTP client (curl / python-requests / Go-http-client)

`UC_151_2` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count as Hits, values(Web.status) as Statuses, values(Web.http_user_agent) as UserAgents, min(_time) as FirstSeen, max(_time) as LastSeen from datamodel=Web where Web.http_method=POST AND Web.url="*/admin/check*" AND (Web.http_user_agent="*python-requests*" OR Web.http_user_agent="*curl/*" OR Web.http_user_agent="*Go-http-client*" OR Web.http_user_agent="*Apache-HttpClient*" OR Web.http_user_agent="*libwww-perl*" OR Web.http_user_agent="*Wget/*" OR Web.http_user_agent="*aiohttp*" OR Web.http_user_agent="*okhttp*") by Web.src, Web.dest, Web.http_user_agent | `drop_dm_object_name("Web")` | sort - Hits
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-9pq7-mfwh-xx2j: phpMyFAQ enables unauthenticated 2FA brut

`UC_151_0` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-9pq7-mfwh-xx2j: phpMyFAQ enables unauthenticated 2FA brut ```
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
// Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-9pq7-mfwh-xx2j: phpMyFAQ enables unauthenticated 2FA brut
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

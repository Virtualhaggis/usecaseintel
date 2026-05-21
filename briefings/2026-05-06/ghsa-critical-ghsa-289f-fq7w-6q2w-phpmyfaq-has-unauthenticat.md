# [CRIT] [GHSA / CRITICAL] GHSA-289f-fq7w-6q2w: phpMyFAQ has unauthenticated SQL injection via User-Agent header in BuiltinCaptcha

**Source:** GitHub Security Advisories
**Published:** 2026-05-06
**Article:** https://github.com/advisories/GHSA-289f-fq7w-6q2w

## Threat Profile

phpMyFAQ has unauthenticated SQL injection via User-Agent header in BuiltinCaptcha

## Summary

`BuiltinCaptcha::garbageCollector()` and `BuiltinCaptcha::saveCaptcha()` at `phpmyfaq/src/phpMyFAQ/Captcha/BuiltinCaptcha.php:298` and `:330` interpolate the `User-Agent` header and client IP address into DELETE and INSERT queries with `sprintf` and no escaping. Both methods run on every hit to the public `GET /api/captcha` endpoint, which requires no authentication. An unauthenticated attacker sets t…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File
- **T1190** — Exploit Public-Facing Application
- **T1059** — Command and Scripting Interpreter

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] phpMyFAQ unauthenticated SQLi via User-Agent on /api/captcha (GHSA-289f-fq7w-6q2w)

`UC_250_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.http_user_agent) as user_agents values(Web.src) as src_ips values(Web.status) as statuses from datamodel=Web where Web.url="*/api/captcha*" Web.http_method=GET (Web.http_user_agent="*SLEEP(*" OR Web.http_user_agent="*BENCHMARK(*" OR Web.http_user_agent="*SUBSTR(*" OR Web.http_user_agent="*SUBSTRING(*" OR Web.http_user_agent="* OR 1=1*" OR Web.http_user_agent="*UNION SELECT*" OR Web.http_user_agent="*UNION/**/SELECT*" OR Web.http_user_agent="*' OR '*" OR Web.http_user_agent="*-- *" OR Web.http_user_agent="*/*!*") by Web.src Web.dest Web.url Web.http_user_agent | `drop_dm_object_name(Web)` | where count >= 1
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-289f-fq7w-6q2w: phpMyFAQ has unauthenticated SQL injectio

`UC_250_0` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-289f-fq7w-6q2w: phpMyFAQ has unauthenticated SQL injectio ```
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
// Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-289f-fq7w-6q2w: phpMyFAQ has unauthenticated SQL injectio
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

Severity classified as **CRIT** based on: 2 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

# [CRIT] [GHSA / CRITICAL] GHSA-289f-fq7w-6q2w: phpMyFAQ has unauthenticated SQL injection via User-Agent header in BuiltinCaptcha

**Source:** GitHub Security Advisories
**Published:** 2026-05-06
**Article:** https://github.com/advisories/GHSA-289f-fq7w-6q2w

## Threat Profile

phpMyFAQ has unauthenticated SQL injection via User-Agent header in BuiltinCaptcha

## Summary

`BuiltinCaptcha::garbageCollector()` and `BuiltinCaptcha::saveCaptcha()` at `phpmyfaq/src/phpMyFAQ/Captcha/BuiltinCaptcha.php:298` and `:330` interpolate the `User-Agent` header and client IP address into DELETE and INSERT queries with `sprintf` and no escaping. Both methods run on every hit to the public `GET /api/captcha` endpoint, which requires no authentication. An unauthenticated attacker sets t…

## Indicators of Compromise (high-fidelity only)

- **SHA1:** `b9f25109fddb38eee19987183798638d07943f92`

## MITRE ATT&CK Techniques

- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1190** — Exploit Public-Facing Application
- **T1059** — Command and Scripting Interpreter
- **T1005** — Data from Local System

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] phpMyFAQ unauthenticated SQLi via User-Agent on /api/captcha (GHSA-289f-fq7w-6q2w)

`UC_174_2` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.http_user_agent) as user_agents values(Web.status) as statuses values(Web.http_method) as methods from datamodel=Web where Web.url="*/api/captcha*" (Web.http_user_agent="*SLEEP(*" OR Web.http_user_agent="*sleep(*" OR Web.http_user_agent="*BENCHMARK(*" OR Web.http_user_agent="*benchmark(*" OR Web.http_user_agent="*UNION SELECT*" OR Web.http_user_agent="*union select*" OR Web.http_user_agent="*' OR *" OR Web.http_user_agent="*\" OR *" OR Web.http_user_agent="*SUBSTR(*" OR Web.http_user_agent="*substr(*" OR Web.http_user_agent="*INFORMATION_SCHEMA*" OR Web.http_user_agent="*information_schema*" OR Web.http_user_agent="*WAITFOR DELAY*" OR Web.http_user_agent="* OR 1=1*" OR Web.http_user_agent="*/*!*" OR Web.http_user_agent="*pg_sleep(*") by Web.src Web.dest Web.url Web.http_user_agent
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| sort - lastTime
```

### [LLM] phpMyFAQ /api/captcha anomalous response time (time-based blind SQLi extraction)

`UC_174_3` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count avg(Web.response_time) as avg_resp_sec max(Web.response_time) as max_resp_sec values(Web.http_user_agent) as user_agents values(Web.status) as statuses from datamodel=Web where Web.url="*/api/captcha*" by Web.src Web.dest Web.url _time span=1m
| `drop_dm_object_name(Web)`
| where max_resp_sec >= 1.5
| eval baseline_ms=147, observed_ms=round(max_resp_sec*1000,0)
| where observed_ms > (baseline_ms * 5)
| sort - observed_ms
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-289f-fq7w-6q2w: phpMyFAQ has unauthenticated SQL injectio

`UC_174_1` · phase: **install** · confidence: **High**

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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `b9f25109fddb38eee19987183798638d07943f92`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 4 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

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

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-289f-fq7w-6q2w: phpMyFAQ has unauthenticated SQL injectio

`UC_206_0` · phase: **install** · confidence: **High**

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

Severity classified as **CRIT** based on: 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

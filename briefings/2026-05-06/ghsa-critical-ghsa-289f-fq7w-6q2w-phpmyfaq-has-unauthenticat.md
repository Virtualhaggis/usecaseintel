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

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-289f-fq7w-6q2w: phpMyFAQ has unauthenticated SQL injectio

`UC_186_1` · phase: **install** · confidence: **High**

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

Severity classified as **CRIT** based on: IOCs present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

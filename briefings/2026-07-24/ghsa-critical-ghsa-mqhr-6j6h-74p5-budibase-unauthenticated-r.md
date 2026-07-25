# [CRIT] [GHSA / CRITICAL] GHSA-mqhr-6j6h-74p5: Budibase: Unauthenticated REST Datasource Credential Theft via Cross-Origin Auth Leak

**Source:** GitHub Security Advisories
**Published:** 2026-07-24
**Article:** https://github.com/advisories/GHSA-mqhr-6j6h-74p5

## Threat Profile

Budibase: Unauthenticated REST Datasource Credential Theft via Cross-Origin Auth Leak

## Summary
Budibase attaches a REST datasource's stored credentials (Bearer/Basic tokens and static headers) to an outgoing request before it decides which host the request goes to, and never checks that the destination host matches the datasource. A query's request path can be pointed at any host (via an absolute URL or a user-supplied `{{ parameter }}`), so the stored credentials are delivered to an attacker…

## Indicators of Compromise (high-fidelity only)

- **MD5:** `6a56b19a000000002a1e99450570f12e`

## MITRE ATT&CK Techniques

- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-mqhr-6j6h-74p5: Budibase: Unauthenticated REST Datasource

`UC_16_1` · phase: **install** · confidence: **High**

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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `6a56b19a000000002a1e99450570f12e`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

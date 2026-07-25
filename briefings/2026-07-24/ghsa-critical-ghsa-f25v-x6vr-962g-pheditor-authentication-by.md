# [CRIT] [GHSA / CRITICAL] GHSA-f25v-x6vr-962g: Pheditor: Authentication Bypass in Forced Password-Change Flow via Unverified Current Password

**Source:** GitHub Security Advisories
**Published:** 2026-07-24
**Article:** https://github.com/advisories/GHSA-f25v-x6vr-962g

## Threat Profile

Pheditor: Authentication Bypass in Forced Password-Change Flow via Unverified Current Password

## Summary

The forced password-change flow, triggered when the stored password is still the default (`admin`), does not verify that the password submitted by the client actually matches the current password. Any non-empty value in `pheditor_password` is enough to reach the password-change form, and submitting `pheditor_new_password` / `pheditor_confirm_password` in the same request is enough to set a…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-f25v-x6vr-962g: Pheditor: Authentication Bypass in Forced

`UC_3_0` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-f25v-x6vr-962g: Pheditor: Authentication Bypass in Forced ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/tmp/j.txt*" OR Filesystem.file_path="*/dev/null*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-f25v-x6vr-962g: Pheditor: Authentication Bypass in Forced
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/tmp/j.txt", "/dev/null"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **CRIT** based on: 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

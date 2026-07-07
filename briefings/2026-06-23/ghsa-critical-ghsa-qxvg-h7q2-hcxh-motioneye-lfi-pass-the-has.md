# [CRIT] [GHSA / CRITICAL] GHSA-qxvg-h7q2-hcxh: motionEye: LFI → pass‑the‑hash admin → unsafe restore → unauth action exec (RCE)

**Source:** GitHub Security Advisories
**Published:** 2026-06-23
**Article:** https://github.com/advisories/GHSA-qxvg-h7q2-hcxh

## Threat Profile

motionEye: LFI → pass‑the‑hash admin → unsafe restore → unauth action exec (RCE)

## Summary
A multi‑stage chain in motionEye leads to remote code execution. The chain combines:

1. **Arbitrary file read (LFI)** via the picture download endpoint for **local motion cameras** using absolute paths.
2. **Pass‑the‑hash admin auth** due to accepting request signatures computed with password hashes.
3. **Unsafe config restore** that extracts attacker‑controlled tarballs into `CONF_PATH`.
4. **Unauthent…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-qxvg-h7q2-hcxh: motionEye: LFI → pass‑the‑hash admin → un

`UC_176_0` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-qxvg-h7q2-hcxh: motionEye: LFI → pass‑the‑hash admin → un ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/etc/hosts*" OR Filesystem.file_path="*/etc/motioneye/motion.conf*" OR Filesystem.file_path="*/tmp/meye_rce_ok*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-qxvg-h7q2-hcxh: motionEye: LFI → pass‑the‑hash admin → un
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/etc/hosts", "/etc/motioneye/motion.conf", "/tmp/meye_rce_ok"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **CRIT** based on: 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

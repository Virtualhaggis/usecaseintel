# [CRIT] [GHSA / CRITICAL] GHSA-phv5-334h-mxcw: motionEye Partial Authentication Bypass: Unauthenticated Admin Credential Theft via Path Traversal

**Source:** GitHub Security Advisories
**Published:** 2026-06-23
**Article:** https://github.com/advisories/GHSA-phv5-334h-mxcw

## Threat Profile

motionEye Partial Authentication Bypass: Unauthenticated Admin Credential Theft via Path Traversal

# Partial Authentication Bypass: Unauthenticated Admin Credential Theft via Path Traversal

### Summary

Myself and others have reported several RCE vulnerabilities to this project. However, due to the nature of the app, these are largely not of all that much value, as there is built-in functionality to run commands upon certain actions — i.e. RCE is by design.

With that in mind, I endeavored to …

## Indicators of Compromise (high-fidelity only)

- **SHA1:** `7b7d55439abccf4ae83047c1af2707e6eb6664db`

## MITRE ATT&CK Techniques

- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-phv5-334h-mxcw: motionEye Partial Authentication Bypass:

`UC_175_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-phv5-334h-mxcw: motionEye Partial Authentication Bypass: ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("config.py","mediafiles.py","movie_playback.py","base.py"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/etc/motioneye/motion.conf*" OR Filesystem.file_path="*/tmp/pwned*" OR Filesystem.file_path="*/etc/passwd*" OR Filesystem.file_path="*/etc/shadow*" OR Filesystem.file_name IN ("config.py","mediafiles.py","movie_playback.py","base.py"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-phv5-334h-mxcw: motionEye Partial Authentication Bypass:
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("config.py", "mediafiles.py", "movie_playback.py", "base.py"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/etc/motioneye/motion.conf", "/tmp/pwned", "/etc/passwd", "/etc/shadow") or FileName in~ ("config.py", "mediafiles.py", "movie_playback.py", "base.py"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `7b7d55439abccf4ae83047c1af2707e6eb6664db`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

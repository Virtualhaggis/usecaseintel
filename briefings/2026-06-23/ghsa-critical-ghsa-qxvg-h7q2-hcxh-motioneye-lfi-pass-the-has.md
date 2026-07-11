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
- **T1190** — Exploit Public-Facing Application
- **T1083** — File and Directory Discovery
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1105** — Ingress Tool Transfer
- **T1059.004** — Command and Scripting Interpreter: Unix Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### motionEye picture-download LFI via absolute path (/picture/<id>/download/<abs>)

`UC_213_1` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*/picture/*/download/*") AND (Web.url="*/download//*" OR Web.url="*/download/%2f*" OR Web.url="*/etc/motioneye*" OR Web.url="*/etc/passwd*" OR Web.url="*/etc/shadow*" OR Web.url="*motion.conf*") by Web.src Web.dest Web.http_user_agent Web.url Web.status | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

### motionEye unsafe restore drops non-config file into CONF_PATH (/etc/motioneye)

`UC_213_2` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="/etc/motioneye/*") AND (Filesystem.action=created OR Filesystem.action=modified) AND (Filesystem.process_name=tar OR Filesystem.process_name=python OR Filesystem.process_name=python3 OR Filesystem.process_name=meyectl) AND NOT (Filesystem.file_name="*.conf" OR Filesystem.file_name="*.json" OR Filesystem.file_name="*.pgm") by Filesystem.dest Filesystem.process_name Filesystem.file_name Filesystem.file_path | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath startswith "/etc/motioneye/"
| where InitiatingProcessFileName in~ ("tar","python","python3","meyectl")
| where FileName !endswith ".conf" and FileName !endswith ".json" and FileName !endswith ".pgm"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, FolderPath, SHA256
| order by Timestamp desc
```

### motionEye RCE: process executed from CONF_PATH (/etc/motioneye) via action handler

`UC_213_3` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_path="/etc/motioneye/*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process_path Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FolderPath startswith "/etc/motioneye/"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, FolderPath, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-qxvg-h7q2-hcxh: motionEye: LFI → pass‑the‑hash admin → un

`UC_213_0` · phase: **install** · confidence: **High**

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

Severity classified as **CRIT** based on: 4 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

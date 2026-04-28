# [HIGH] ESET Research: Sandworm behind cyberattack on Poland’s power grid in late 2025

**Source:** ESET WeLiveSecurity
**Published:** 2026-01-23
**Article:** https://www.welivesecurity.com/en/eset-research/eset-research-sandworm-cyberattack-poland-power-grid-late-2025/

## Threat Profile

ESET Research: Sandworm behind cyberattack on Poland’s power grid in late 2025 
ESET Research
ESET Research: Sandworm behind cyberattack on Poland’s power grid in late 2025 The attack involved data-wiping malware that ESET researchers have now analyzed and named DynoWiper
ESET Research 
23 Jan 2026 
 •  
, 
2 min. read 
UPDATE (January 30 th , 2026): For a technical breakdown of the incident affecting a company in Poland’s energy sector, refer to this blogpost . 
In late 2025, Poland’s energy sy…

## Indicators of Compromise (high-fidelity only)

- **SHA1:** `4EC3C90846AF6B79EE1A5188EEFA3FD21F6D4CF6`

## MITRE ATT&CK Techniques

- **T1027** — Obfuscated Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### File hash IOCs — endpoint file/process match

`UC_HASH_IOC` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where Filesystem.file_hash IN ("4EC3C90846AF6B79EE1A5188EEFA3FD21F6D4CF6")
    by Filesystem.dest, Filesystem.user, Filesystem.file_path, Filesystem.file_name, Filesystem.file_hash
| `drop_dm_object_name(Filesystem)`
| append
    [| tstats `summariesonly` count from datamodel=Endpoint.Processes
        where Processes.process_hash IN ("4EC3C90846AF6B79EE1A5188EEFA3FD21F6D4CF6")
        by Processes.dest, Processes.user, Processes.process_name, Processes.process_hash
     | `drop_dm_object_name(Processes)`]
```

**Defender KQL:**
```kql
union DeviceFileEvents, DeviceProcessEvents
| where Timestamp > ago(7d)
| where SHA256 in~ ("4EC3C90846AF6B79EE1A5188EEFA3FD21F6D4CF6") or SHA1 in~ ("4EC3C90846AF6B79EE1A5188EEFA3FD21F6D4CF6") or MD5 in~ ("4EC3C90846AF6B79EE1A5188EEFA3FD21F6D4CF6")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

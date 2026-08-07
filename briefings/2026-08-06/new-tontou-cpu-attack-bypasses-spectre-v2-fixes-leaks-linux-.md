# [HIGH] New TONTOU CPU attack bypasses Spectre v2 fixes, leaks Linux password hashes

**Source:** BleepingComputer
**Published:** 2026-08-06
**Article:** https://www.bleepingcomputer.com/news/security/new-tontou-cpu-attack-bypasses-spectre-v2-fixes-leaks-linux-password-hashes/

## Threat Profile

New TONTOU CPU attack bypasses Spectre v2 fixes, leaks Linux password hashes 
By Ionut Ilascu 
August 6, 2026
02:03 PM
0 
Researchers found a way to bypass recent mitigations for Spectre v2 speculative execution side-channel attacks and developed an exploit to leak secrets from Linux machines.
​The method works against Spectre v2 defenses on AMD and Intel processors that rely on sanitizing or isolating branch predictors, which researchers generically refer to as neutralization-based mitigations.…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2023-20569`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — New TONTOU CPU attack bypasses Spectre v2 fixes, leaks Linux password hashes

`UC_28_1` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — New TONTOU CPU attack bypasses Spectre v2 fixes, leaks Linux password hashes ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/etc/shadow*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — New TONTOU CPU attack bypasses Spectre v2 fixes, leaks Linux password hashes
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/etc/shadow"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2023-20569`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

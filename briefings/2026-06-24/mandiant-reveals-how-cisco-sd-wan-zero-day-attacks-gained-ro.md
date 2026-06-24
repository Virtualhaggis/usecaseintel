# [HIGH] Mandiant reveals how Cisco SD-WAN zero-day attacks gained root access

**Source:** BleepingComputer
**Published:** 2026-06-24
**Article:** https://www.bleepingcomputer.com/news/security/mandiant-reveals-how-cisco-sd-wan-zero-day-attacks-gained-root-access/

## Threat Profile

Mandiant reveals how Cisco SD-WAN zero-day attacks gained root access 
By Lawrence Abrams 
June 24, 2026
05:29 PM
0 


New details have been revealed on how hackers exploited a Cisco Catalyst SD-WAN vulnerability tracked as CVE-2026-20245 in zero-day attacks to create rogue root accounts on targeted devices.


The CVE-2026-20245 vulnerability is a high-severity command injection flaw in Cisco Catalyst SD-WAN Manager (vManage), Controller (vSmart), and Validator (vBond) that allows authentica…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-20245`
- **CVE:** `CVE-2026-20127`
- **CVE:** `CVE-2026-20182`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — Mandiant reveals how Cisco SD-WAN zero-day attacks gained root access

`UC_0_1` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Mandiant reveals how Cisco SD-WAN zero-day attacks gained root access ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/etc/passwd*" OR Filesystem.file_path="*/etc/shadow*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Mandiant reveals how Cisco SD-WAN zero-day attacks gained root access
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/etc/passwd", "/etc/shadow"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-20245`, `CVE-2026-20127`, `CVE-2026-20182`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

# [CRIT] UAT-4356's Targeting of Cisco Firepower Devices

**Source:** Cisco Talos
**Published:** 2026-04-23
**Article:** https://blog.talosintelligence.com/uat-4356-firestarter/

## Threat Profile

UAT-4356's Targeting of Cisco Firepower Devices 
By 
Cisco Talos 
Thursday, April 23, 2026 11:10
Threat Advisory
Threats
APT
Cisco Talos is aware of UAT-4356 's continued active targeting of Cisco Firepower devices’ Firepower eXtensible Operating System (FXOS). UAT-4356 exploited n-day vulnerabilities ( CVE-2025-20333 and CVE-2025-20362 ) to gain unauthorized access to vulnerable devices, where the threat actor deployed their custom-built backdoor dubbed “FIRESTARTER.” FIRESTARTER considerably o…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-20333`
- **CVE:** `CVE-2025-20362`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — UAT-4356's Targeting of Cisco Firepower Devices

`UC_92_1` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — UAT-4356's Targeting of Cisco Firepower Devices ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/opt/cisco/platform/logs/var/log/svc_samcore.log*" OR Filesystem.file_path="*/usr/bin/lina_cs*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — UAT-4356's Targeting of Cisco Firepower Devices
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/opt/cisco/platform/logs/var/log/svc_samcore.log", "/usr/bin/lina_cs"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2025-20333`, `CVE-2025-20362`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

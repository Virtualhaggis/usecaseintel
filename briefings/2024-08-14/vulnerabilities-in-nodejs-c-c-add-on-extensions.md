# [HIGH] Vulnerabilities in NodeJS C/C++ add-on extensions

**Source:** Snyk
**Published:** 2024-08-14
**Article:** https://snyk.io/blog/nodejs-add-on-extensions/

## Threat Profile

Snyk Blog In this article
Written by Alessio Della Libera 
August 14, 2024
0 mins read One of the main goals of this research was to explore C/C++ vulnerabilities in the context of NodeJS npm packages. The focus will be on exploring and identifying classic vulnerabilities like Buffer Overflow, Denial of Service (process crash, unchecked types), and Memory Leakages in the context of NodeJS C/C++ addons and modeling relevant sources, sinks, and sanitizers using Snyk Code (see Snyk brings developer…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2024-21521`
- **CVE:** `CVE-2024-21522`
- **CVE:** `CVE-2024-21523`
- **CVE:** `CVE-2024-21524`
- **CVE:** `CVE-2024-21525`
- **CVE:** `CVE-2024-21526`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — Vulnerabilities in NodeJS C/C++ add-on extensions

`UC_1140_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Vulnerabilities in NodeJS C/C++ add-on extensions ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("main.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("main.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Vulnerabilities in NodeJS C/C++ add-on extensions
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("main.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("main.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2024-21521`, `CVE-2024-21522`, `CVE-2024-21523`, `CVE-2024-21524`, `CVE-2024-21525`, `CVE-2024-21526`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

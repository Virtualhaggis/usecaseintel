# [HIGH] Best Practices for Creating a Modern npm Package with Security in Mind

**Source:** Snyk
**Published:** 2025-02-04
**Article:** https://snyk.io/blog/best-practices-create-modern-npm-package/

## Threat Profile

Snyk Blog In this article
Written by Brian Clark 
February 4, 2025
0 mins read Technology is always changing and your processes and practices need to keep up with those changes. So while npm is 15 years old (as of 2025), your practices around npm package creation should hopefully be a lot more modern. If you have a feeling they may be a little out of date, though, keep reading. 
In this tutorial, we’re going to walk step by step through creating an npm package using modern best practices (as of …

## Indicators of Compromise (high-fidelity only)

- **SHA1:** `40ede3ed630fa8857c0c9b8d4c81664374aa811c`
- **SHA1:** `6f335d6254ebb77a5a24ee729650052a69994594`

## MITRE ATT&CK Techniques

- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — Best Practices for Creating a Modern npm Package with Security in Mind

`UC_969_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Best Practices for Creating a Modern npm Package with Security in Mind ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js","index.js","bun.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("node.js","index.js","bun.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Best Practices for Creating a Modern npm Package with Security in Mind
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js", "index.js", "bun.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("node.js", "index.js", "bun.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `40ede3ed630fa8857c0c9b8d4c81664374aa811c`, `6f335d6254ebb77a5a24ee729650052a69994594`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

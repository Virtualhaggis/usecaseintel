# [CRIT] Understanding filesystem takeover vulnerabilities in npm JavaScript package manager

**Source:** Snyk
**Published:** 2020-01-07
**Article:** https://snyk.io/blog/understanding-filesystem-takeover-vulnerabilities-in-npm-javascript-package-manager/

## Threat Profile

Snyk Blog In this article
Written by Liran Tal 
January 7, 2020
0 mins read On the 11th of December, 2019 a security vulnerability which extends to all major JavaScript package managers (npm, yarn and pnpm) was publicly disclosed. This vulnerability, discovered by security researcher Daniel Ruf , allows malicious actors to apply varied tactics of arbitrary file overwrites.
In this article:
How do Node.js command line packages work? 
How does this security vulnerability affect the npm package man…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2019-16776`
- **CVE:** `CVE-2019-16777`
- **CVE:** `CVE-2019-10773`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — Understanding filesystem takeover vulnerabilities in npm JavaScript package mana

`UC_3139_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Understanding filesystem takeover vulnerabilities in npm JavaScript package mana ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js","index.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/usr/bin/env*" OR Filesystem.file_path="*/usr/bin/date*" OR Filesystem.file_name IN ("node.js","index.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Understanding filesystem takeover vulnerabilities in npm JavaScript package mana
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js", "index.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/usr/bin/env", "/usr/bin/date") or FileName in~ ("node.js", "index.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2019-16776`, `CVE-2019-16777`, `CVE-2019-10773`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

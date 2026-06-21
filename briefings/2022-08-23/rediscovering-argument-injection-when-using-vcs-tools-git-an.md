# [HIGH] Rediscovering argument injection when using VCS tools — git and mercurial

**Source:** Snyk
**Published:** 2022-08-23
**Article:** https://snyk.io/blog/argument-injection-when-using-git-and-mercurial/

## Threat Profile

Snyk Blog In this article
Written by Alessio Della Libera 
August 23, 2022
0 mins read One of the main goals for this research was to explore how it is possible to execute arbitrary commands even when using a safe API that prevents command injection. The focus will be on Version Control System (VCS) tools like git and hg (mercurial), that, among some of their options, allow the execution of arbitrary commands (under some circumstances).
The targets for this research are web applications and libr…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2022-25766`
- **CVE:** `CVE-2022-29184`
- **CVE:** `CVE-2022-23915`
- **CVE:** `CVE-2022-24433`
- **CVE:** `CVE-2022-25648`
- **CVE:** `CVE-2022-24440`
- **CVE:** `CVE-2022-21223`
- **CVE:** `CVE-2022-21235`
- **CVE:** `CVE-2022-25866`
- **CVE:** `CVE-2022-21187`
- **CVE:** `CVE-2022-25865`
- **CVE:** `CVE-2022-24065`
- **CVE:** `CVE-2022-26945`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — Rediscovering argument injection when using VCS tools — git and mercurial

`UC_1950_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Rediscovering argument injection when using VCS tools — git and mercurial ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("node.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Rediscovering argument injection when using VCS tools — git and mercurial
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2022-25766`, `CVE-2022-29184`, `CVE-2022-23915`, `CVE-2022-24433`, `CVE-2022-25648`, `CVE-2022-24440`, `CVE-2022-21223`, `CVE-2022-21235` _(+5 more)_


## Why this matters

Severity classified as **HIGH** based on: CVE present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

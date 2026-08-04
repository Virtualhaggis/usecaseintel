# [CRIT] URL confusion vulnerabilities in the wild: Exploring parser inconsistencies

**Source:** Snyk
**Published:** 2022-01-10
**Article:** https://snyk.io/blog/url-confusion-vulnerabilities/

## Threat Profile

Snyk Blog In this article
Written by Snyk Security Research Team 
Claroty Team82 
January 10, 2022
0 mins read URLs have forever changed the way we interact with computers. Conceptualized in 1992 and defined in 1994 , the Uniform Resource Locator (URL) continues to be a critical component of the internet, allowing people to navigate the web via descriptive, human-understandable addresses. But with the need for human readability came the need for breaking them into machine-usable components; this…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2021-23385`
- **CVE:** `CVE-2021-32618`
- **CVE:** `CVE-2021-23401`
- **CVE:** `CVE-2021-23393`
- **CVE:** `CVE-2021-33056`
- **CVE:** `CVE-2021-23414`
- **CVE:** `CVE-2021-37352`
- **CVE:** `CVE-2021-23435`
- **CVE:** `CVE-2021-45046`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — URL confusion vulnerabilities in the wild: Exploring parser inconsistencies

`UC_2704_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — URL confusion vulnerabilities in the wild: Exploring parser inconsistencies ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("video.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/etc/passwd*" OR Filesystem.file_name IN ("video.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — URL confusion vulnerabilities in the wild: Exploring parser inconsistencies
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("video.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/etc/passwd") or FileName in~ ("video.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2021-23385`, `CVE-2021-32618`, `CVE-2021-23401`, `CVE-2021-23393`, `CVE-2021-33056`, `CVE-2021-23414`, `CVE-2021-37352`, `CVE-2021-23435` _(+1 more)_


## Why this matters

Severity classified as **CRIT** based on: CVE present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

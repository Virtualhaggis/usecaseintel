# [HIGH] Attacking an FTP Client: MGETting more than you bargained for

**Source:** Snyk
**Published:** 2018-04-04
**Article:** https://snyk.io/blog/attacking-an-ftp-client/

## Threat Profile

Snyk Blog In this article
Written by Danny Grander 
April 4, 2018
0 mins read Introduction We often hear about vulnerabilities in HTTP clients, such as web browsers, that are typically exploited by malicious web content, there’s nothing new here. But did you know that the FTP clients themselves can also have vulnerabilities that can be exploited? FTP clients can be targeted by malicious servers that the clients connect to.
In this blog post, I’ll show an interesting path traversal vulnerability …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2018-1315`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — Attacking an FTP Client: MGETting more than you bargained for

`UC_3317_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Attacking an FTP Client: MGETting more than you bargained for ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("autoexec.bat"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/var/data/sync/*" OR Filesystem.file_path="*/var/data/sync/passwd*" OR Filesystem.file_path="*/etc/passwd*" OR Filesystem.file_path="*/var/data/sync/../../../../etc/passwd*" OR Filesystem.file_path="*/home/root/.ssh/authorized_keys*" OR Filesystem.file_name IN ("autoexec.bat"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Attacking an FTP Client: MGETting more than you bargained for
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("autoexec.bat"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/var/data/sync/", "/var/data/sync/passwd", "/etc/passwd", "/var/data/sync/../../../../etc/passwd", "/home/root/.ssh/authorized_keys") or FileName in~ ("autoexec.bat"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2018-1315`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

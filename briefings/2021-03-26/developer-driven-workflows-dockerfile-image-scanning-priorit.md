# [HIGH] Developer driven workflows: Dockerfile image scanning, prioritization, and remediation

**Source:** Snyk
**Published:** 2021-03-26
**Article:** https://snyk.io/blog/dockerfile-optimization-and-docker-image-security-scanning/

## Threat Profile

Snyk Blog In this article
Written by Eric Smalling 
March 26, 2021
0 mins read When deploying applications in containers, developers are now having to take on responsibilities related to operating system level security concerns. Often, these are unfamiliar topics that, in many cases, had previously been handled by operations and security teams. While this new domain can seem daunting there are various tools and practices that you can incorporate into your workflow to make sure you’re catching an…

## Indicators of Compromise (high-fidelity only)

- **SHA256:** `c365dec0cfdf64d8cfd43ebd8f2bcd534cfe7b71849796dfb3030b4fe5ff7f93`

## MITRE ATT&CK Techniques

- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — Developer driven workflows: Dockerfile image scanning, prioritization, and remed

`UC_3162_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Developer driven workflows: Dockerfile image scanning, prioritization, and remed ```
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
      AND (Filesystem.file_path="*/usr/src/goof*" OR Filesystem.file_path="*/tmp/extracted_files*" OR Filesystem.file_path="*/var/lib/docker*" OR Filesystem.file_path="*/var/lib/containerd*" OR Filesystem.file_path="*/etc/passwd*" OR Filesystem.file_name IN ("node.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Developer driven workflows: Dockerfile image scanning, prioritization, and remed
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
| where (FolderPath has_any ("/usr/src/goof", "/tmp/extracted_files", "/var/lib/docker", "/var/lib/containerd", "/etc/passwd") or FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `c365dec0cfdf64d8cfd43ebd8f2bcd534cfe7b71849796dfb3030b4fe5ff7f93`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

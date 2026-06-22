# [CRIT] Exploring 3 types of directory traversal vulnerabilities in C/C++

**Source:** Snyk
**Published:** 2022-04-04
**Article:** https://snyk.io/blog/exploring-3-types-of-directory-traversal-vulnerabilities-in-c-c/

## Threat Profile

Snyk Blog In this article
Written by Kirill Efimov 
April 4, 2022
0 mins read Directory traversal vulnerabilities (also known as path traversal vulnerabilities) allow bad actors to gain access to folders that they shouldn’t have access to. In this post, we are going to take a look how directory traversal vulnerabilities work on web servers written on C/C++, as well as how to prevent them.
For us on the Security Research team, the C and C++ ecosystems have been out of scope for a long time, but t…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2021-23514`
- **CVE:** `CVE-2022-25299`
- **CVE:** `CVE-2021-23520`
- **CVE:** `CVE-2021-23521`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — Exploring 3 types of directory traversal vulnerabilities in C/C++

`UC_2186_1` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Exploring 3 types of directory traversal vulnerabilities in C/C++ ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/etc/passwd*" OR Filesystem.file_path="*/tmp/test.txt*" OR Filesystem.file_path="*/etc/init.d/*" OR Filesystem.file_path="*/tmp/path_to_the_content_root_directory/*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Exploring 3 types of directory traversal vulnerabilities in C/C++
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/etc/passwd", "/tmp/test.txt", "/etc/init.d/", "/tmp/path_to_the_content_root_directory/"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2021-23514`, `CVE-2022-25299`, `CVE-2021-23520`, `CVE-2021-23521`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

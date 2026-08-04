# [CRIT] Solve Hack the Box and other CTF challenges with Snyk

**Source:** Snyk
**Published:** 2022-09-01
**Article:** https://snyk.io/blog/solve-hack-the-box-and-ctf-challenges-with-snyk/

## Threat Profile

Snyk Blog In this article
Written by Mathias Conradt 
September 1, 2022
0 mins read Hack The Box (HTB) is a platform that gamifies cybersecurity training. It's suitable for aspiring pen testers, as well as developers who want to become security champions — or simply understand the mindset of adversaries a bit better — in order to make their applications more secure.
I believe in the effectiveness of gamification in training and education, because let's be honest — who doesn't know what it’s like…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2021-23639`
- **CVE:** `CVE-2022-21680`
- **CVE:** `CVE-2022-21681`
- **CVE:** `CVE-2021-3807`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — Solve Hack the Box and other CTF challenges with Snyk

`UC_2043_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Solve Hack the Box and other CTF challenges with Snyk ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("index.js","node.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/home/mconradt/Documents/HTB/Challenges/web_blinkerfluids/challenge*" OR Filesystem.file_name IN ("index.js","node.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Solve Hack the Box and other CTF challenges with Snyk
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("index.js", "node.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/home/mconradt/Documents/HTB/Challenges/web_blinkerfluids/challenge") or FileName in~ ("index.js", "node.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2021-23639`, `CVE-2022-21680`, `CVE-2022-21681`, `CVE-2021-3807`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

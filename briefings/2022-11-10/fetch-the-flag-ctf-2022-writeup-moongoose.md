# [HIGH] Fetch the Flag CTF 2022 writeup: Moongoose

**Source:** Snyk
**Published:** 2022-11-10
**Article:** https://snyk.io/blog/fetch-the-flag-ctf-2022-writeup-moongoose/

## Threat Profile

Snyk Blog In this article
Written by Jason Lynch 
November 10, 2022
0 mins read Thanks for playing Fetch with us! Congrats to the thousands of players who joined us for Fetch the Flag CTF . And a huge thanks to the Snykers that built, tested, and wrote up the challenges! 
As a Snyk employee, I had the opportunity to join my teammates in a "beta test" of Snyk’s 2022 Fetch the Flag competition. We had a lot of fun solving these challenges together and I, personally, learned a lot from the experien…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `moongoose.c.ctf-snyk.io`

## MITRE ATT&CK Techniques

- **T1071** — Application Layer Protocol
- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — Fetch the Flag CTF 2022 writeup: Moongoose

`UC_1930_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Fetch the Flag CTF 2022 writeup: Moongoose ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js","server.js","init.js","2fserver.js","model.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("node.js","server.js","init.js","2fserver.js","model.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Fetch the Flag CTF 2022 writeup: Moongoose
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js", "server.js", "init.js", "2fserver.js", "model.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("node.js", "server.js", "init.js", "2fserver.js", "model.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `moongoose.c.ctf-snyk.io`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

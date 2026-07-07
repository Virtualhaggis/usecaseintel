# [CRIT] [GHSA / CRITICAL] GHSA-g6g7-pvmx-m74p: 9router: Missing Authorization and OS Command Injection

**Source:** GitHub Security Advisories
**Published:** 2026-07-02
**Article:** https://github.com/advisories/GHSA-g6g7-pvmx-m74p

## Threat Profile

9router: Missing Authorization and OS Command Injection

# Unauthenticated RCE via `/api/tunnel/tailscale-install`

**Affected:** `9router` (npm package) — current master (`v0.4.39`).

### Summary

`POST /api/tunnel/tailscale-install` accepts a JSON body with a `sudoPassword` field and pipes it, followed by the body of `https://tailscale.com/install.sh`, into a child process spawned as `sudo -S sh`. The route is not present in the dashboard middleware matcher in `src/proxy.js`, so the request re…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-g6g7-pvmx-m74p: 9router: Missing Authorization and OS Com

`UC_51_0` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-g6g7-pvmx-m74p: 9router: Missing Authorization and OS Com ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("next.js","install.sh"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/var/lib/apt/lists/*" OR Filesystem.file_path="*/dev/null*" OR Filesystem.file_path="*/tmp/pwned.txt*" OR Filesystem.file_name IN ("next.js","install.sh"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-g6g7-pvmx-m74p: 9router: Missing Authorization and OS Com
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("next.js", "install.sh"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/var/lib/apt/lists/", "/dev/null", "/tmp/pwned.txt") or FileName in~ ("next.js", "install.sh"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **CRIT** based on: 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

# [CRIT] [GHSA / CRITICAL] GHSA-2jq4-q6vv-4cp3: Crawl4AI: Arbitrary file write (path traversal) in crawler downloads can lead to RCE

**Source:** GitHub Security Advisories
**Published:** 2026-06-18
**Article:** https://github.com/advisories/GHSA-2jq4-q6vv-4cp3

## Threat Profile

Crawl4AI: Arbitrary file write (path traversal) in crawler downloads can lead to RCE

### Summary

When the crawler saves a downloaded file, the destination filename was taken from attacker-influenced input and joined to the downloads directory with no confinement. A filename containing an absolute path (e.g. `/etc/cron.d/evil`) or `../` traversal escaped the downloads directory, giving an arbitrary file write with attacker-controlled contents. Because the written bytes are attacker-controlled, …

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File
- **T1190** — Exploit Public-Facing Application
- **T1053.003** — Scheduled Task/Job: Cron
- **T1098.004** — Account Manipulation: SSH Authorized Keys
- **T1546.004** — Event Triggered Execution: Unix Shell Configuration Modification

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Crawl4AI path-traversal: crawler Python process writes to RCE-enabling paths (cron.d, authorized_keys, shell rc, site-packages)

`UC_67_1` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path IN ("/etc/cron.d/*","/etc/cron.daily/*","/etc/cron.hourly/*","/var/spool/cron/*","*/.ssh/authorized_keys","*/site-packages/*","*/dist-packages/*") OR Filesystem.file_name IN ("authorized_keys",".bashrc",".bash_profile",".profile",".zshrc",".bash_login")) by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_id Filesystem.action | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified")
| where InitiatingProcessFileName has "python" or InitiatingProcessCommandLine has "crawl4ai"
| where (FolderPath has_any ("/etc/cron.d","/etc/cron.daily","/etc/cron.hourly","/var/spool/cron","/site-packages/","/dist-packages/"))
    or FileName =~ "authorized_keys"
    or FileName in~ (".bashrc",".bash_profile",".profile",".zshrc",".bash_login")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName, SHA256
| order by Timestamp desc
```

### Crawl4AI RCE confirmation: cron/sshd/shell executes payload dropped by crawler within correlation window

`UC_67_2` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Endpoint.Filesystem where (Filesystem.file_path IN ("/etc/cron.d/*","/var/spool/cron/*") OR Filesystem.file_name="authorized_keys") by Filesystem.dest Filesystem.file_path _time span=1s | `drop_dm_object_name(Filesystem)` | eval marker="drop", detail=file_path | fields dest _time marker detail | append [ | tstats `summariesonly` count from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("cron","crond","sshd") by Processes.dest Processes.process Processes.parent_process_name _time span=1s | `drop_dm_object_name(Processes)` | eval marker="exec", detail=process | fields dest _time marker detail ] | sort 0 dest _time | transaction dest maxspan=24h | where eventcount>1 AND searchmatch("marker=drop") AND searchmatch("marker=exec")
```

**Defender KQL:**
```kql
let Window = 24h;
let Drops = DeviceFileEvents
    | where Timestamp > ago(7d)
    | where ActionType in ("FileCreated","FileModified")
    | where InitiatingProcessFileName has "python"
    | where FolderPath has_any ("/etc/cron.d","/var/spool/cron") or FileName =~ "authorized_keys"
    | project DropTime = Timestamp, DeviceId, DeviceName, DropPath = FolderPath, DropFile = FileName;
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("cron","crond","sshd")
| join kind=inner Drops on DeviceId
| where Timestamp between (DropTime .. DropTime + Window)
| project DropTime, ExecTime = Timestamp, DeviceName, DropPath, DropFile, SpawnedBy = InitiatingProcessFileName, ExecFile = FileName, ProcessCommandLine, AccountName
| order by ExecTime desc
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-2jq4-q6vv-4cp3: Crawl4AI: Arbitrary file write (path trav

`UC_67_0` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-2jq4-q6vv-4cp3: Crawl4AI: Arbitrary file write (path trav ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/etc/cron.d/evil*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-2jq4-q6vv-4cp3: Crawl4AI: Arbitrary file write (path trav
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/etc/cron.d/evil"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **CRIT** based on: 3 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

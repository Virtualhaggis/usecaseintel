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
- **T1505** — Server Software Component
- **T1098.004** — SSH Authorized Keys
- **T1053.003** — Scheduled Task/Job: Cron
- **T1546.004** — Unix Shell Configuration Modification
- **T1190** — Exploit Public-Facing Application
- **T1059.004** — Command and Scripting Interpreter: Unix Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Crawl4AI Python process writes to Linux persistence path (GHSA-2jq4-q6vv-4cp3 exploitation)

`UC_19_1` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_paths values(Filesystem.file_name) as file_names from datamodel=Endpoint.Filesystem where Filesystem.action=created AND Filesystem.process_name IN ("python","python3","python3.10","python3.11","python3.12","uvicorn","gunicorn") AND (Filesystem.file_path="/etc/cron.d/*" OR Filesystem.file_path="/etc/cron.daily/*" OR Filesystem.file_path="/etc/cron.hourly/*" OR Filesystem.file_path="/etc/cron.weekly/*" OR Filesystem.file_path="/etc/cron.monthly/*" OR Filesystem.file_path="/etc/profile.d/*" OR Filesystem.file_path="*/.ssh/authorized_keys" OR Filesystem.file_name IN (".bashrc",".bash_profile",".profile",".zshrc",".bash_login","authorized_keys")) by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.process_path Filesystem.file_path | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified")
| where InitiatingProcessFileName startswith "python" or InitiatingProcessFileName in~ ("uvicorn","gunicorn")
| where (FolderPath has_any ("/etc/cron.d/","/etc/cron.daily/","/etc/cron.hourly/","/etc/cron.weekly/","/etc/cron.monthly/","/etc/profile.d/"))
    or (FolderPath has "/.ssh/" and FileName =~ "authorized_keys")
    or (FileName in~ (".bashrc",".bash_profile",".profile",".zshrc",".bash_login") and FolderPath !startswith "/etc/skel")
| extend Crawl4AIContext = iff(InitiatingProcessCommandLine has_any ("crawl4ai","async_crawler_strategy","docker_server:app"), "crawl4ai", "other-python")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, ActionType, FolderPath, FileName, SHA256, Crawl4AIContext
| order by Timestamp desc
```

### Vulnerable Crawl4AI package inventory (<= 0.8.9, pre-patch for GHSA-2jq4-q6vv-4cp3)

`UC_19_2` · phase: **recon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| inputlookup software_inventory.csv where package_manager="pip" AND package_name="crawl4ai" | rex field=package_version "^(?<major>\d+)\.(?<minor>\d+)\.(?<patch>\d+)" | where major=0 AND (minor<8 OR (minor=8 AND patch<=9)) | table host package_name package_version last_seen | sort - last_seen
```

**Defender KQL:**
```kql
DeviceTvmSoftwareInventory
| where SoftwareName =~ "crawl4ai"
| extend MajorVer = toint(extract(@"^(\d+)", 1, SoftwareVersion))
| extend MinorVer = toint(extract(@"^\d+\.(\d+)", 1, SoftwareVersion))
| extend PatchVer = toint(extract(@"^\d+\.\d+\.(\d+)", 1, SoftwareVersion))
| where MajorVer == 0 and (MinorVer < 8 or (MinorVer == 8 and PatchVer <= 9))
| join kind=leftouter (DeviceInfo | summarize arg_max(Timestamp, OSPlatform, PublicIP, IsInternetFacing) by DeviceId) on DeviceId
| project DeviceName, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion, IsInternetFacing, PublicIP
| order by IsInternetFacing desc, DeviceName asc
```

### Python crawl4ai process spawns shell or persistence helper (post-exploitation child)

`UC_19_3` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("python","python3","python3.10","python3.11","python3.12","uvicorn","gunicorn")) AND (Processes.parent_process LIKE "%crawl4ai%" OR Processes.parent_process LIKE "%async_crawler_strategy%" OR Processes.parent_process LIKE "%docker_server:app%") AND Processes.process_name IN ("bash","sh","dash","zsh","ksh","crontab","ssh-keygen","curl","wget","nc","ncat","socat","chmod") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName startswith "python" or InitiatingProcessFileName in~ ("uvicorn","gunicorn")
| where InitiatingProcessCommandLine has_any ("crawl4ai","async_crawler_strategy","docker_server:app")
| where FileName in~ ("bash","sh","dash","zsh","ksh","crontab","ssh-keygen","curl","wget","nc","ncat","socat","chmod")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessId, FileName, ProcessCommandLine, FolderPath
| order by Timestamp desc
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-2jq4-q6vv-4cp3: Crawl4AI: Arbitrary file write (path trav

`UC_19_0` · phase: **install** · confidence: **High**

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

Severity classified as **CRIT** based on: 4 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

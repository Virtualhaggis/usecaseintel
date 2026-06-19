# [CRIT] [GHSA / CRITICAL] GHSA-29w3-p9w9-wc47: PraisonAI: Arbitrary File Read/Write via `multiedit` Tool Without Path Validation

**Source:** GitHub Security Advisories
**Published:** 2026-06-18
**Article:** https://github.com/advisories/GHSA-29w3-p9w9-wc47

## Threat Profile

PraisonAI: Arbitrary File Read/Write via `multiedit` Tool Without Path Validation

## Summary

The `multiedit` tool in `src/praisonai/praisonai/tools/multiedit.py` allows LLM-controlled arbitrary file read and write without any path validation, workspace boundary check, or protected path guard. This enables an attacker who can influence agent tool arguments (via crafted prompts, user input in chat bots, or malicious YAML workflow configs) to read sensitive files (e.g., `/etc/shadow`, `~/.ssh/id_…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1552.004** — Unsecured Credentials: Private Keys
- **T1083** — File and Directory Discovery
- **T1098.004** — Account Manipulation: SSH Authorized Keys
- **T1546.004** — Event Triggered Execution: Unix Shell Configuration Modification
- **T1053.003** — Scheduled Task/Job: Cron
- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### PraisonAI multiedit tool reading sensitive credentials (GHSA-29w3-p9w9-wc47)

`UC_27_1` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_paths from datamodel=Endpoint.Filesystem where (Filesystem.process_name="python*" OR Filesystem.process_name="python3*" OR Filesystem.process_name="pythonw.exe") AND (Filesystem.file_path="*/.ssh/id_rsa*" OR Filesystem.file_path="*/.ssh/id_ed25519*" OR Filesystem.file_path="*/.aws/credentials*" OR Filesystem.file_path="*/.aws/config*" OR Filesystem.file_path="*/etc/shadow" OR Filesystem.file_path="*/etc/passwd" OR Filesystem.file_path="*/.netrc" OR Filesystem.file_path="*/.env" OR Filesystem.file_path="*\\.ssh\\*" OR Filesystem.file_path="*\\.aws\\credentials*") by host Filesystem.process_name Filesystem.process_id Filesystem.action Filesystem.file_path Filesystem.user | `drop_dm_object_name(Filesystem)` | join type=inner host process_id [| tstats summariesonly=true count from datamodel=Endpoint.Processes where (Processes.process="*praisonai*" OR Processes.process="*multiedit*") by host Processes.process_id Processes.process Processes.parent_process | `drop_dm_object_name(Processes)`] | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
   or ActionType startswith "File"
| where InitiatingProcessFileName in~ ("python.exe", "python3", "python", "python3.exe", "pythonw.exe", "python3.10", "python3.11", "python3.12")
| where InitiatingProcessCommandLine has_any ("praisonai", "multiedit")
| where FolderPath has_any (@"\.ssh\", @"\.aws\", @"\.env", @"\.netrc", "/etc/shadow", "/etc/passwd", "/.ssh/", "/.aws/", "/root/", "id_rsa", "id_ed25519", "credentials")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, InitiatingProcessAccountName,
          InitiatingProcessParentFileName
| order by Timestamp desc
```

### PraisonAI multiedit writing to persistence locations (authorized_keys / shell rc / cron)

`UC_27_2` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.action) as actions from datamodel=Endpoint.Filesystem where (Filesystem.process_name="python*" OR Filesystem.process_name="python3*" OR Filesystem.process_name="pythonw.exe") AND Filesystem.action IN ("created","modified","written","renamed") AND (Filesystem.file_path="*/.ssh/authorized_keys*" OR Filesystem.file_path="*/.bashrc" OR Filesystem.file_path="*/.bash_profile" OR Filesystem.file_path="*/.profile" OR Filesystem.file_path="*/.zshrc" OR Filesystem.file_path="*/etc/cron.d/*" OR Filesystem.file_path="*/etc/crontab" OR Filesystem.file_path="*/var/spool/cron/*" OR Filesystem.file_path="*/etc/sudoers*" OR Filesystem.file_path="*\\Start Menu\\Programs\\Startup\\*") by host Filesystem.process_name Filesystem.process_id Filesystem.file_path Filesystem.user | `drop_dm_object_name(Filesystem)` | join type=inner host process_id [| tstats summariesonly=true count from datamodel=Endpoint.Processes where (Processes.process="*praisonai*" OR Processes.process="*multiedit*") by host Processes.process_id Processes.process Processes.parent_process | `drop_dm_object_name(Processes)`] | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where InitiatingProcessFileName in~ ("python.exe", "python3", "python", "python3.exe", "pythonw.exe", "python3.10", "python3.11", "python3.12")
| where InitiatingProcessCommandLine has_any ("praisonai", "multiedit")
| where FolderPath has_any ("/.ssh/authorized_keys", "/.bashrc", "/.bash_profile", "/.profile", "/.zshrc", "/etc/cron.d", "/etc/crontab", "/var/spool/cron", "/etc/sudoers", @"\Start Menu\Programs\Startup\")
   or FileName in~ ("authorized_keys", ".bashrc", ".bash_profile", ".profile", ".zshrc", "crontab", "sudoers")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessParentFileName,
          PreviousFileName, PreviousFolderPath
| order by Timestamp desc
```

### Vulnerable PraisonAI package exposure (< 4.6.61, GHSA-29w3-p9w9-wc47)

`UC_27_3` · phase: **recon** · confidence: **High** · AI-generated for this article

**Defender KQL:**
```kql
DeviceTvmSoftwareInventory
| where SoftwareName has "praisonai" or SoftwareName == "praisonai"
| extend VersionParts = split(SoftwareVersion, ".")
| extend Major = toint(VersionParts[0]), Minor = toint(VersionParts[1]), Patch = toint(VersionParts[2])
| where Major < 4
   or (Major == 4 and Minor < 6)
   or (Major == 4 and Minor == 6 and Patch < 61)
| join kind=leftouter (
    DeviceInfo
    | summarize arg_max(Timestamp, *) by DeviceId
    | project DeviceId, IsInternetFacing, MachineGroup, LoggedOnUsers
  ) on DeviceId
| project DeviceName, DeviceId, SoftwareVendor, SoftwareName, SoftwareVersion,
          OSPlatform, IsInternetFacing, MachineGroup, LoggedOnUsers
| order by tostring(IsInternetFacing) desc, DeviceName asc
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-29w3-p9w9-wc47: PraisonAI: Arbitrary File Read/Write via

`UC_27_0` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-29w3-p9w9-wc47: PraisonAI: Arbitrary File Read/Write via ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("file_tools.py","edit_tools.py","skill_tools.py","write_file.py","read_file.py","apply_diff.py","search_replace.py"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/etc/shadow*" OR Filesystem.file_path="*/etc/hostname*" OR Filesystem.file_path="*/tmp/victim_file.txt*" OR Filesystem.file_name IN ("file_tools.py","edit_tools.py","skill_tools.py","write_file.py","read_file.py","apply_diff.py","search_replace.py"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-29w3-p9w9-wc47: PraisonAI: Arbitrary File Read/Write via
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("file_tools.py", "edit_tools.py", "skill_tools.py", "write_file.py", "read_file.py", "apply_diff.py", "search_replace.py"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/etc/shadow", "/etc/hostname", "/tmp/victim_file.txt") or FileName in~ ("file_tools.py", "edit_tools.py", "skill_tools.py", "write_file.py", "read_file.py", "apply_diff.py", "search_replace.py"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **CRIT** based on: 4 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

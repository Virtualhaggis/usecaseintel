# [CRIT] Cursor Flaw Lets Malicious Cloned Repositories Trigger Windows Code Execution

**Source:** The Hacker News
**Published:** 2026-07-15
**Article:** https://thehackernews.com/2026/07/cursor-flaw-lets-malicious-cloned.html

## Threat Profile

Cursor Flaw Lets Malicious Cloned Repositories Trigger Windows Code Execution 
 Swati Khandelwal  Jul 15, 2026 Endpoint Security / Vulnerability 
Open a repository in Cursor on Windows and, if a file named git.exe is sitting in the project root, Cursor runs it. No click, no approval dialog, no warning that anything in the folder is about to execute.
Whatever that binary does, it does as you, with your source, your SSH keys and your cloud tokens. Cursor keeps re-running it for as long as the pr…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-26268`
- **CVE:** `CVE-2026-10591`
- **CVE:** `CVE-2020-26233`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1574.008** — Hijack Execution Flow: Path Interception by Search Order Hijacking
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1204.003** — User Execution: Malicious Image
- **T1195.001** — Supply Chain Compromise: Compromise Software Dependencies and Development Tools
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1105** — Ingress Tool Transfer
- **T1546** — Event Triggered Execution

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Cursor IDE spawning workspace git.exe via 'rev-parse --show-toplevel' search-order hijack

`UC_7_3` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name="Cursor.exe" Processes.process_name="git.exe" Processes.process="*rev-parse*--show-toplevel*" by Processes.dest Processes.user Processes.parent_process Processes.process Processes.process_path Processes.process_id | `drop_dm_object_name(Processes)` | where NOT match(process_path, "(?i)\\\\Program Files") | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName =~ "Cursor.exe"
| where FileName =~ "git.exe"
| where ProcessCommandLine has "rev-parse" and ProcessCommandLine has "--show-toplevel"
| where FolderPath !contains "\\Program Files"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine, SHA256, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Search-order helper binary (git/node/npx/where.exe) executing from a repo/workspace path

`UC_7_4` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="git.exe" OR Processes.process_name="node.exe" OR Processes.process_name="npx.exe" OR Processes.process_name="where.exe") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process_path Processes.process | `drop_dm_object_name(Processes)` | where match(process_path, "(?i)\\\\Users\\\\[^\\\\]+\\\\(source\\\\repos|Downloads|Desktop|Documents|Projects|repos)\\\\") AND NOT match(process_path, "(?i)\\\\Program Files") | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("git.exe","node.exe","npx.exe","where.exe")
| where FolderPath matches regex @"(?i)\\Users\\[^\\]+\\(source\\repos|Downloads|Desktop|Documents|Projects|repos)\\"
| where FolderPath !contains "\\Program Files"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, SHA256
| order by Timestamp desc
```

### Masqueraded git/node/npx binary — image name mismatches embedded original filename (calc-as-git PoC)

`UC_7_5` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="git.exe" OR Processes.process_name="node.exe" OR Processes.process_name="npx.exe" OR Processes.process_name="where.exe") by Processes.dest Processes.user Processes.process_name Processes.process_path Processes.original_file_name Processes.vendor_product | `drop_dm_object_name(Processes)` | where isnotnull(original_file_name) AND NOT match(lower(original_file_name), "(git|node|npx|where)\.exe") | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("git.exe","node.exe","npx.exe","where.exe")
| where isnotempty(ProcessVersionInfoOriginalFileName)
| where not(ProcessVersionInfoOriginalFileName has_any ("git.exe","node.exe","npx.exe","where.exe"))
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessVersionInfoOriginalFileName, ProcessVersionInfoCompanyName, ProcessVersionInfoProductName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Planting of git/node/npx/where.exe into a cloned repo or extracted archive

`UC_7_6` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name="git.exe" OR Filesystem.file_name="node.exe" OR Filesystem.file_name="npx.exe" OR Filesystem.file_name="where.exe") Filesystem.action=created by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)` | where match(file_path, "(?i)\\\\Users\\\\[^\\\\]+\\\\(source\\\\repos|Downloads|Desktop|Documents|Projects|repos)\\\\") AND NOT match(file_path, "(?i)\\\\Program Files") | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| where FileName in~ ("git.exe","node.exe","npx.exe","where.exe")
| where FolderPath matches regex @"(?i)\\Users\\[^\\]+\\(source\\repos|Downloads|Desktop|Documents|Projects|repos)\\"
| where FolderPath !contains "\\Program Files"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256, FileOriginUrl
| order by Timestamp desc
```

### Git hook script execution inside a cloned repo (.git\hooks) — CVE-2026-26268 class

`UC_7_7` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name="git.exe" OR Processes.parent_process_name="Cursor.exe" OR Processes.parent_process_name="bash.exe" OR Processes.parent_process_name="sh.exe") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_path | `drop_dm_object_name(Processes)` | where match(process_path, "(?i)\\.git\\\\hooks\\\\") OR match(process, "(?i)\\.git[\\\\/]hooks[\\\\/]") | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FolderPath has "\\.git\\hooks\\" or ProcessCommandLine has ".git/hooks/" or ProcessCommandLine has "\\.git\\hooks\\"
| where InitiatingProcessFileName in~ ("git.exe","Cursor.exe","bash.exe","sh.exe")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### Trusted vendor binary / installer launching unusual children

`UC_SUPPLY_CHAIN` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("setup.exe","installer.exe","update.exe")
      AND Processes.process_name IN ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
    by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("setup.exe","installer.exe","update.exe")
| where FileName in~ ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### Article-specific behavioural hunt — Cursor Flaw Lets Malicious Cloned Repositories Trigger Windows Code Execution

`UC_7_2` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Cursor Flaw Lets Malicious Cloned Repositories Trigger Windows Code Execution ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("filename.exe","npx.exe") OR Processes.process_path="*%USERPROFILE%\source\repos\*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*%USERPROFILE%\source\repos\*" OR Filesystem.file_name IN ("filename.exe","npx.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Cursor Flaw Lets Malicious Cloned Repositories Trigger Windows Code Execution
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("filename.exe", "npx.exe") or FolderPath has_any ("%USERPROFILE%\source\repos\"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("%USERPROFILE%\source\repos\") or FileName in~ ("filename.exe", "npx.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-26268`, `CVE-2026-10591`, `CVE-2020-26233`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 8 use case(s) fired, 10 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

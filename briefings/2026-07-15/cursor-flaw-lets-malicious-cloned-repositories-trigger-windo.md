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
- **T1203** — Exploitation for Client Execution
- **T1574.007** — Path Interception by PATH Environment Variable
- **T1195.001** — Compromise Software Dependencies and Development Tools
- **T1059.004** — Unix Shell
- **T1059.003** — Windows Command Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### AI IDE runs workspace-root git.exe via 'rev-parse --show-toplevel' probe (Cursor search-order RCE)

`UC_47_3` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=git.exe Processes.process="*rev-parse*" Processes.process="*--show-toplevel*" (Processes.parent_process_name=Cursor.exe OR Processes.parent_process_name=Code.exe OR Processes.parent_process_name=codex.exe OR Processes.parent_process_name=gemini.exe OR Processes.parent_process_name=kiro.exe) by Processes.dest Processes.user Processes.process_path Processes.process Processes.parent_process_name Processes.process_name
| `drop_dm_object_name(Processes)`
| search NOT (process_path="*\\Program Files\\Git\\*" OR process_path="*\\Program Files (x86)\\Git\\*" OR process_path="*\\scoop\\apps\\git\\*")
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "git.exe"
| where ProcessCommandLine has "rev-parse" and ProcessCommandLine has "--show-toplevel"
| where InitiatingProcessFileName has_any ("Cursor.exe","Code.exe","codex.exe","gemini.exe","kiro.exe")
| where not(FolderPath has @"\Program Files\Git\" or FolderPath has @"\Program Files (x86)\Git\" or FolderPath has @"\scoop\apps\git\")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine, SHA256, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```

### AI IDE spawns helper binary (git/node/npx/where.exe) from cloned-repo root

`UC_47_4` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name=git.exe OR Processes.process_name=node.exe OR Processes.process_name=npx.exe OR Processes.process_name=where.exe) (Processes.parent_process_name=Cursor.exe OR Processes.parent_process_name=Code.exe OR Processes.parent_process_name=codex.exe OR Processes.parent_process_name=gemini.exe OR Processes.parent_process_name=kiro.exe) by Processes.dest Processes.user Processes.process_path Processes.process Processes.parent_process_name Processes.process_name
| `drop_dm_object_name(Processes)`
| search (process_path="*\\Downloads\\*" OR process_path="*\\source\\repos\\*" OR process_path="*\\Desktop\\*" OR process_path="*\\OneDrive\\*" OR process_path="*\\Documents\\*" OR process_path="*\\repos\\*" OR process_path="*\\Projects\\*")
| search NOT (process_path="*\\Program Files\\*" OR process_path="*\\Program Files (x86)\\*" OR process_path="*\\System32\\*" OR process_path="*\\nvm\\*" OR process_path="*\\scoop\\apps\\*")
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("git.exe","node.exe","npx.exe","where.exe")
| where InitiatingProcessFileName has_any ("Cursor.exe","Code.exe","codex.exe","gemini.exe","kiro.exe")
| where FolderPath has_any (@"\Downloads\", @"\source\repos\", @"\Desktop\", @"\OneDrive\", @"\Documents\", @"\repos\", @"\Projects\")
| where not(FolderPath has @"\Program Files\" or FolderPath has @"\Program Files (x86)\" or FolderPath has @"\System32\" or FolderPath has @"\nvm\" or FolderPath has @"\scoop\apps\")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, SHA256, InitiatingProcessFileName
| order by Timestamp desc
```

### Cloned-repo Git hook executes shell via IDE/git subprocess (Cursor CVE-2026-26268 class)

`UC_47_5` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*\\.git\\hooks\\*" OR Processes.parent_process="*\\.git\\hooks\\*" OR Processes.process_path="*\\.git\\hooks\\*") by Processes.dest Processes.user Processes.process_path Processes.process Processes.parent_process_name Processes.process_name
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FolderPath has @"\.git\hooks\" or ProcessCommandLine has @"\.git\hooks\" or InitiatingProcessCommandLine has @"\.git\hooks\"
| where InitiatingProcessFileName has_any ("git.exe","Cursor.exe","Code.exe","codex.exe","gemini.exe","kiro.exe","bash.exe","sh.exe")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Poisoned .vscode/tasks.json lands in cloned repo via git/archive (AWS Kiro CVE-2026-10591)

`UC_47_6` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name=tasks.json Filesystem.file_path="*\\.vscode\\*" (Filesystem.process_name=git.exe OR Filesystem.process_name=curl.exe OR Filesystem.process_name=tar.exe OR Filesystem.process_name=node.exe) by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName =~ "tasks.json"
| where FolderPath has @"\.vscode\"
| where InitiatingProcessFileName in~ ("git.exe","curl.exe","tar.exe","node.exe","7z.exe")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine
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

`UC_47_2` · phase: **exploit** · confidence: **High**

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

Severity classified as **CRIT** based on: CVE present, 7 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

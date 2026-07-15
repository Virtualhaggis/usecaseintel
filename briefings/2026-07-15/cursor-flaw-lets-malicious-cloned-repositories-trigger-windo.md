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
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1195.001** — Supply Chain Compromise: Compromise Software Dependencies and Development Tools
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1041** — Exfiltration Over C2 Channel

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Cursor IDE spawns masqueraded git.exe/node.exe from repo workspace root

`UC_2_3` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name="Cursor.exe" (Processes.process_name="git.exe" OR Processes.process_name="node.exe" OR Processes.process_name="npx.exe" OR Processes.process_name="where.exe") NOT (Processes.process_path="C:\\Program Files*" OR Processes.process_path="C:\\Program Files (x86)*" OR Processes.process_path="C:\\Windows*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process_path Processes.process | `drop_dm_object_name(Processes)` | search (process_name="git.exe" AND process="*rev-parse*--show-toplevel*") OR process_name IN ("node.exe","npx.exe","where.exe") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "Cursor.exe"
| where FileName in~ ("git.exe","node.exe","npx.exe","where.exe")
| where not(FolderPath startswith @"C:\Program Files" or FolderPath startswith @"C:\Windows")
| where FolderPath !has @"\nodejs\"
| where (FileName =~ "git.exe" and ProcessCommandLine has "rev-parse" and ProcessCommandLine has "--show-toplevel") or FileName in~ ("node.exe","npx.exe","where.exe")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, FileName, FolderPath, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Helper executable (git.exe/node.exe/where.exe) written to a cloned repo root

`UC_2_4` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name="git.exe" OR Filesystem.file_name="node.exe" OR Filesystem.file_name="npx.exe" OR Filesystem.file_name="where.exe") (Filesystem.file_path="*\\source\\repos\\*" OR Filesystem.file_path="*\\Users\\*\\repos\\*" OR Filesystem.file_path="*\\Users\\*\\projects\\*" OR Filesystem.file_path="*\\Users\\*\\dev\\*" OR Filesystem.file_path="*\\Users\\*\\git\\*") by Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.file_create_time | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| where FileName in~ ("git.exe","node.exe","npx.exe","where.exe")
| where FolderPath matches regex @"(?i)\\Users\\[^\\]+\\(source\\repos|repos|projects|dev|git|workspace|code)\\"
| where InitiatingProcessFileName in~ ("git.exe","tar.exe","7z.exe","7zg.exe","WinRAR.exe","Cursor.exe","Code.exe","explorer.exe","powershell.exe","pwsh.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### Workspace-rooted git.exe/where.exe making outbound public connections (payload exfil)

`UC_2_5` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.process_name="git.exe" OR All_Traffic.process_name="where.exe") NOT (All_Traffic.process_path="C:\\Program Files*" OR All_Traffic.process_path="C:\\Windows*") All_Traffic.dest_category="external" by All_Traffic.src All_Traffic.user All_Traffic.process_name All_Traffic.process_path All_Traffic.dest All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("git.exe","where.exe")
| where not(InitiatingProcessFolderPath startswith @"C:\Program Files" or InitiatingProcessFolderPath startswith @"C:\Windows")
| where InitiatingProcessFolderPath matches regex @"(?i)\\Users\\[^\\]+\\"
| where RemoteIPType == "Public"
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessCommandLine
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

`UC_2_2` · phase: **exploit** · confidence: **High**

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

Severity classified as **CRIT** based on: CVE present, 6 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

# [HIGH] Miasma and Hades Are Spreading Now: Detect Them on Developer Machines with Suspicious Files

**Source:** StepSecurity
**Published:** 2026-06-11
**Article:** https://www.stepsecurity.io/blog/miasma-and-hades-are-spreading-now-detect-them-on-developer-machines-with-suspicious-files

## Threat Profile

Back to Blog Product Miasma and Hades Are Spreading Now: Detect Them on Developer Machines with Suspicious Files Miasma and Hades worms are spreading across npm and PyPI, running on import and project open. See how Dev Machine Guard's Suspicious Files detects them. Ashish Kurmi View LinkedIn June 11, 2026
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS feed 
Table of Contents Loading nav... 
The Miasma worm and its PyPI branch, Hades, are spreading across the npm and PyP…

## Indicators of Compromise (high-fidelity only)

- **SHA256:** `dc48b09b2a5954f7ff79ab8a2fd80202bd3b59c08c7cdbc6025aa923cb4c0efe`
- **SHA256:** `e1342a80d4b5e83d2c7c22e1e0aaa95f2d88e3dbf0d853a4994b180c93a4b17d`
- **SHA256:** `c539766062555d47716f8432e73adbe3a0c0c954a0b6c4005017a668975e275c`
- **SHA256:** `7069e28a5806db4ab0273639667d203f5e31b401d403af7e36d9f360c1f6d655`
- **SHA256:** `b86c5ae9e95bd841a595440faa3eb6317441e746f241ae8fd641ab59ed1d1966`

## MITRE ATT&CK Techniques

- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1546** — Event Triggered Execution
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1105** — Ingress Tool Transfer
- **T1027.013** — Encrypted/Encoded File
- **T1552.001** — Credentials In Files
- **T1567** — Exfiltration Over Web Service

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Miasma/Hades: AI-agent or editor config file written outside the IDE (auto-exec on project open)

`UC_28_4` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as process_name values(Filesystem.file_path) as file_path values(Filesystem.file_hash) as file_hash from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\.vscode\\tasks.json" OR Filesystem.file_path="*\\.vscode\\setup.mjs" OR Filesystem.file_path="*\\.claude\\setup.mjs" OR Filesystem.file_path="*\\.claude\\settings.json" OR Filesystem.file_path="*\\.cursor\\rules\\setup.mdc" OR Filesystem.file_path="*\\.gemini\\settings.json" OR Filesystem.file_path="*\\.github\\setup.js") (Filesystem.action=created OR Filesystem.action=modified) NOT (Filesystem.process_name IN ("Code.exe","Code - Insiders.exe","cursor.exe","claude.exe","gemini.exe","windsurf.exe","devenv.exe")) by Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.user | `drop_dm_object_name(Filesystem)` | rename firstTime as first_time lastTime as last_time | convert ctime(first_time) ctime(last_time) | sort - last_time
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where (FolderPath has @"\.vscode" and FileName in~ ("tasks.json","setup.mjs"))
   or (FolderPath has @"\.claude" and FileName in~ ("setup.mjs","settings.json"))
   or (FolderPath has @"\.cursor\rules" and FileName =~ "setup.mdc")
   or (FolderPath has @"\.gemini" and FileName =~ "settings.json")
   or (FolderPath has @"\.github" and FileName =~ "setup.js")
| where InitiatingProcessFileName !in~ ("Code.exe","Code - Insiders.exe","cursor.exe","claude.exe","gemini.exe","windsurf.exe","devenv.exe")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, FolderPath, FileName, FileSize, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### Hades PyPI worm: Python interpreter spawns Bun runtime or downloads it from bun.sh/oven-sh

`UC_28_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process) as parent_cmd values(Processes.process_hash) as hash from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("python.exe","pythonw.exe","python3.exe","python3.11.exe","python3.12.exe","python3.13.exe") AND (Processes.process_name="bun.exe" OR Processes.process IN ("*bun.sh*","*bun.com/install*","*oven-sh/bun*","*bun-windows-*","*bun-linux-*","*bun-darwin-*")) by Processes.dest Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | rename firstTime as first_time lastTime as last_time | convert ctime(first_time) ctime(last_time) | sort - last_time
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("python.exe","pythonw.exe","python3.exe","python3.11.exe","python3.12.exe","python3.13.exe")
| where FileName =~ "bun.exe"
   or (FileName in~ ("curl.exe","wget.exe","powershell.exe","pwsh.exe","bitsadmin.exe") and ProcessCommandLine has_any ("bun.sh","bun.com/install","oven-sh/bun","bun-windows-","bun-linux-","bun-darwin-"))
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, ParentImage=InitiatingProcessFolderPath, ParentCmd=InitiatingProcessCommandLine, ChildImage=FolderPath, ChildCmd=ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Miasma Phantom Gyp: ~157-byte binding.gyp file dropped in package root (npm install code-exec primitive)

`UC_28_6` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.file_size) as file_size values(Filesystem.process_name) as process_name values(Filesystem.file_hash) as file_hash from datamodel=Endpoint.Filesystem where Filesystem.file_name="binding.gyp" Filesystem.file_size<400 (Filesystem.action=created OR Filesystem.action=modified) NOT Filesystem.file_path="*\\node_modules\\node-gyp\\*" by Filesystem.dest Filesystem.user Filesystem.file_path | `drop_dm_object_name(Filesystem)` | rename firstTime as first_time lastTime as last_time | convert ctime(first_time) ctime(last_time) | sort - last_time
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType in ("FileCreated","FileModified")
| where FileName =~ "binding.gyp"
| where FileSize < 400
| where FolderPath !has @"\node_modules\node-gyp\"
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, FolderPath, FileName, FileSize, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### Known Miasma/Hades payload SHA256 observed in file write or process execution

`UC_28_7` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.process_name) as process_name from datamodel=Endpoint.Processes where Processes.process_hash IN ("dc48b09b2a5954f7ff79ab8a2fd80202bd3b59c08c7cdbc6025aa923cb4c0efe","e1342a80d4b5e83d2c7c22e1e0aaa95f2d88e3dbf0d853a4994b180c93a4b17d","c539766062555d47716f8432e73adbe3a0c0c954a0b6c4005017a668975e275c","7069e28a5806db4ab0273639667d203f5e31b401d403af7e36d9f360c1f6d655","b86c5ae9e95bd841a595440faa3eb6317441e746f241ae8fd641ab59ed1d1966") by Processes.dest Processes.user Processes.process_hash Processes.parent_process_name | `drop_dm_object_name(Processes)` | append [| tstats summariesonly=t count from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("dc48b09b2a5954f7ff79ab8a2fd80202bd3b59c08c7cdbc6025aa923cb4c0efe","e1342a80d4b5e83d2c7c22e1e0aaa95f2d88e3dbf0d853a4994b180c93a4b17d","c539766062555d47716f8432e73adbe3a0c0c954a0b6c4005017a668975e275c","7069e28a5806db4ab0273639667d203f5e31b401d403af7e36d9f360c1f6d655","b86c5ae9e95bd841a595440faa3eb6317441e746f241ae8fd641ab59ed1d1966") by Filesystem.dest Filesystem.user Filesystem.file_hash Filesystem.file_path | `drop_dm_object_name(Filesystem)`] | rename firstTime as first_time lastTime as last_time | convert ctime(first_time) ctime(last_time) | sort - last_time
```

**Defender KQL:**
```kql
let MiasmaHashes = dynamic([
    "dc48b09b2a5954f7ff79ab8a2fd80202bd3b59c08c7cdbc6025aa923cb4c0efe",
    "e1342a80d4b5e83d2c7c22e1e0aaa95f2d88e3dbf0d853a4994b180c93a4b17d",
    "c539766062555d47716f8432e73adbe3a0c0c954a0b6c4005017a668975e275c",
    "7069e28a5806db4ab0273639667d203f5e31b401d403af7e36d9f360c1f6d655",
    "b86c5ae9e95bd841a595440faa3eb6317441e746f241ae8fd641ab59ed1d1966"
]);
union
  (DeviceFileEvents
   | where Timestamp > ago(30d)
   | where SHA256 in (MiasmaHashes)
   | project Timestamp, Source="FileEvent", DeviceName, AccountName=InitiatingProcessAccountName, Path=FolderPath, FileName, SHA256, ParentImage=InitiatingProcessFileName, Cmd=InitiatingProcessCommandLine),
  (DeviceProcessEvents
   | where Timestamp > ago(30d)
   | where SHA256 in (MiasmaHashes) or InitiatingProcessSHA256 in (MiasmaHashes)
   | project Timestamp, Source="ProcessEvent", DeviceName, AccountName, Path=FolderPath, FileName, SHA256, ParentImage=InitiatingProcessFileName, Cmd=ProcessCommandLine)
| order by Timestamp desc
```

### Worm propagation signal: rapid serial npm publish or twine upload from a single developer host

`UC_28_8` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count values(Processes.process) as cmdlines values(Processes.parent_process_name) as parents from datamodel=Endpoint.Processes where ((Processes.process_name="npm.exe" AND Processes.process="*publish*") OR (Processes.process_name="twine.exe" AND Processes.process="*upload*") OR (Processes.process_name="python.exe" AND Processes.process="*twine*upload*") OR (Processes.process_name="node.exe" AND Processes.process="*npm-cli*publish*")) by Processes.dest Processes.user _time span=30m | `drop_dm_object_name(Processes)` | where count >= 3 | sort - count
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where (FileName =~ "npm.exe" and ProcessCommandLine has " publish")
     or (FileName in~ ("twine.exe","twine") and ProcessCommandLine has "upload")
     or (FileName in~ ("python.exe","pythonw.exe") and ProcessCommandLine matches regex @"(?i)twine\s+upload")
     or (FileName =~ "node.exe" and ProcessCommandLine has_any ("npm-cli.js publish","npm publish"))
| where InitiatingProcessAccountName !endswith "$"
| summarize PublishCount = count(),
            DistinctCmds = dcount(ProcessCommandLine),
            SampleCmds = make_set(ProcessCommandLine, 10),
            Parents = make_set(InitiatingProcessFileName, 5),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp)
            by DeviceName, AccountName, bin(Timestamp, 30m)
| where PublishCount >= 3 and DistinctCmds >= 3
| order by LastSeen desc
```

### PowerShell encoded / obfuscated command

`UC_PS_OBFUSCATED` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("powershell.exe","pwsh.exe")
      AND (Processes.process="*-enc *" OR Processes.process="*EncodedCommand*"
        OR Processes.process="*FromBase64String*" OR Processes.process="*-nop*"
        OR Processes.process="*-w hidden*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*IEX(*" OR Processes.process="*DownloadString*"
        OR Processes.process="*Net.WebClient*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)(-enc|encodedcommand|frombase64string|-nop|-w\s+hidden|invoke-expression|iex\s*\(|downloadstring|net\.webclient)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
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

### Article-specific behavioural hunt — Miasma and Hades Are Spreading Now: Detect Them on Developer Machines with Suspi

`UC_28_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Miasma and Hades Are Spreading Now: Detect Them on Developer Machines with Suspi ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("__init__.py"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("__init__.py"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Miasma and Hades Are Spreading Now: Detect Them on Developer Machines with Suspi
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("__init__.py"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("__init__.py"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `dc48b09b2a5954f7ff79ab8a2fd80202bd3b59c08c7cdbc6025aa923cb4c0efe`, `e1342a80d4b5e83d2c7c22e1e0aaa95f2d88e3dbf0d853a4994b180c93a4b17d`, `c539766062555d47716f8432e73adbe3a0c0c954a0b6c4005017a668975e275c`, `7069e28a5806db4ab0273639667d203f5e31b401d403af7e36d9f360c1f6d655`, `b86c5ae9e95bd841a595440faa3eb6317441e746f241ae8fd641ab59ed1d1966`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 9 use case(s) fired, 10 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

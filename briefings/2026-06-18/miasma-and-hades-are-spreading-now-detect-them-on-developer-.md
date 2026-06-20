# [HIGH] Miasma and Hades Are Spreading Now: Detect Them on Developer Machines with Suspicious Files

**Source:** StepSecurity
**Published:** 2026-06-18
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
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1546** — Event Triggered Execution
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1105** — Ingress Tool Transfer
- **T1218** — System Binary Proxy Execution
- **T1059** — Command and Scripting Interpreter

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Phantom Gyp: tiny binding.gyp written into installed npm package

`UC_69_4` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.file_size) as file_size values(Filesystem.process_name) as process_name from datamodel=Endpoint.Filesystem where Filesystem.file_name="binding.gyp" Filesystem.file_path="*\\node_modules\\*" Filesystem.file_size<500 Filesystem.action IN ("created","modified") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_size | `drop_dm_object_name(Filesystem)` | where file_size>20 | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where FileName =~ "binding.gyp"
| where FolderPath has "\\node_modules\\"
| where ActionType in ("FileCreated","FileModified")
| where FileSize between (20 .. 500)   // Miasma Phantom Gyp payload is ~157 bytes
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, FolderPath, FileName, FileSize, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### VS Code .vscode/tasks.json folderOpen auto-execute task dropped into project tree

`UC_69_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.process_name) as parent_process from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\.vscode\\tasks.json" OR Filesystem.file_path="*\\.vscode\\setup.mjs") Filesystem.action IN ("created","modified") by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path | `drop_dm_object_name(Filesystem)` | where parent_process!="Code.exe" AND parent_process!="code.exe" | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath endswith "\\.vscode" and FileName in~ ("tasks.json","setup.mjs"))
     or (FolderPath has "\\.vscode\\" and FileName in~ ("tasks.json","setup.mjs"))
| where InitiatingProcessFileName !in~ ("code.exe","Code.exe","explorer.exe","git.exe")
| where InitiatingProcessFileName has_any ("npm","node.exe","yarn","pnpm","python","pip","tar.exe","7z.exe","powershell.exe","pwsh.exe")
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, SHA256
| order by Timestamp desc
```

### AI coding assistant config file dropped in project (.claude/setup.mjs, .cursor/rules/setup.mdc, .gemini/settings.json)

`UC_69_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.process_name) as parent_process values(Filesystem.process_path) as parent_path from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\.claude\\setup.mjs" OR Filesystem.file_path="*\\.claude\\settings.json" OR Filesystem.file_path="*\\.cursor\\rules\\setup.mdc" OR Filesystem.file_path="*\\.gemini\\settings.json" OR Filesystem.file_path="*\\.github\\setup.js") Filesystem.action IN ("created","modified") by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path | `drop_dm_object_name(Filesystem)` | sort - lastTime
```

**Defender KQL:**
```kql
let WatchedFiles = dynamic(["setup.mjs","settings.json","setup.mdc","setup.js"]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified")
| where FileName in~ (WatchedFiles)
| where FolderPath has_any ("\\.claude","\\.cursor\\rules","\\.gemini","\\.github")
| extend ConfigType = case(
    FolderPath has "\\.claude" and FileName =~ "setup.mjs", "ClaudeCode_SessionStart_Hook",
    FolderPath has "\\.claude" and FileName =~ "settings.json", "ClaudeCode_SettingsInjection",
    FolderPath has "\\.cursor\\rules" and FileName =~ "setup.mdc", "Cursor_RulesAutoLoad",
    FolderPath has "\\.gemini" and FileName =~ "settings.json", "Gemini_SettingsInjection",
    FolderPath has "\\.github" and FileName =~ "setup.js", "GitHubActions_WorkflowInjection",
    "unknown")
| where ConfigType != "unknown"
| where InitiatingProcessFileName !in~ ("claude.exe","cursor.exe","code.exe","Code.exe","explorer.exe","notepad.exe")
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, ConfigType, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### Hades on-import: Bun runtime download/execution chained from Python interpreter

`UC_69_7` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent values(Processes.parent_process) as parent_cmd from datamodel=Endpoint.Processes where (Processes.process_name="bun.exe" OR Processes.process_name="bun") (Processes.parent_process_name="python.exe" OR Processes.parent_process_name="python3.exe" OR Processes.parent_process_name="pythonw.exe" OR Processes.parent_process_name="py.exe" OR Processes.process_path="*\\AppData\\*" OR Processes.process_path="*\\Temp\\*") by Processes.dest Processes.user Processes.process_name Processes.process_path Processes.parent_process_name | `drop_dm_object_name(Processes)` | sort - lastTime
```

**Defender KQL:**
```kql
let BunExec = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName =~ "bun.exe" or FileName =~ "bun"
    | where InitiatingProcessFileName in~ ("python.exe","python3.exe","pythonw.exe","py.exe")
         or FolderPath has_any ("\\AppData\\Local\\Temp\\","\\AppData\\Roaming\\","\\AppData\\Local\\Programs\\")
    | project Timestamp, DeviceName, AccountName, BunPath=FolderPath, BunCmd=ProcessCommandLine, BunSHA256=SHA256,
              InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath;
let BunDrop = DeviceFileEvents
    | where Timestamp > ago(7d)
    | where FileName =~ "bun.exe" or FileName =~ "bun"
    | where ActionType in ("FileCreated","FileRenamed")
    | where InitiatingProcessFileName in~ ("python.exe","python3.exe","pythonw.exe","py.exe","curl.exe","powershell.exe","pwsh.exe")
    | project DropTime=Timestamp, DeviceName, DroppedPath=FolderPath, DropperImage=InitiatingProcessFileName, DropperCmd=InitiatingProcessCommandLine;
BunExec
| join kind=leftouter BunDrop on DeviceName
| where isnull(DropTime) or (Timestamp between (DropTime .. DropTime + 10m))
| project Timestamp, DropTime, DeviceName, AccountName, BunPath, BunCmd, BunSHA256, DropperImage, DropperCmd, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### PyPI package __init__.py modified with one-line obfuscated import-time hook (Hades pattern)

`UC_69_8` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.file_size) as file_size values(Filesystem.process_name) as parent_process from datamodel=Endpoint.Filesystem where Filesystem.file_name="__init__.py" Filesystem.file_path="*\\site-packages\\*" Filesystem.action IN ("created","modified") Filesystem.process_name IN ("pip.exe","pip3.exe","python.exe","python3.exe","uv.exe","poetry.exe") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_size | `drop_dm_object_name(Filesystem)` | where file_size>200 AND file_size<8000 | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where FileName =~ "__init__.py"
| where FolderPath has "\\site-packages\\"
| where ActionType in ("FileCreated","FileModified")
| where InitiatingProcessFileName in~ ("pip.exe","pip3.exe","python.exe","python3.exe","pythonw.exe","py.exe","uv.exe","poetry.exe","conda.exe")
// Hades's one-line obfuscated hook tends to land in a file that's notable for being short but not minimal
| where FileSize between (200 .. 8000)
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, FolderPath, FileSize, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
// Correlate with python.exe network egress within 60s (the on-import download)
| join kind=inner (
    DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessFileName in~ ("python.exe","python3.exe","pythonw.exe")
    | where RemoteIPType == "Public"
    | project NetTime=Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort, NetProc=InitiatingProcessFileName, NetCmd=InitiatingProcessCommandLine
) on DeviceName
| where NetTime between (Timestamp .. Timestamp + 5m)
| project Timestamp, NetTime, DeviceName, AccountName, FolderPath, FileSize, InitiatingProcessCommandLine, NetProc, NetCmd, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### node-gyp spawning a shell, interpreter, or LOLBin during npm install

`UC_69_9` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process) as parent_cmd from datamodel=Endpoint.Processes where (Processes.parent_process_name="node.exe" OR Processes.parent_process_name="node-gyp.exe" OR Processes.parent_process="*node-gyp*") (Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","curl.exe","wget.exe","bitsadmin.exe","certutil.exe","bash.exe","sh.exe","mshta.exe")) by Processes.dest Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "node.exe"
  and (InitiatingProcessCommandLine has "node-gyp" or InitiatingProcessCommandLine has "\\binding.gyp")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","curl.exe","wget.exe","bitsadmin.exe","certutil.exe","bash.exe","sh.exe","mshta.exe","rundll32.exe","regsvr32.exe")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          ParentCmd=InitiatingProcessCommandLine,
          ChildImage=FolderPath,
          ChildCmd=ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### File on disk matches known Miasma/Hades campaign SHA256 IOC

`UC_69_10` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.file_name) as file_name from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("dc48b09b2a5954f7ff79ab8a2fd80202bd3b59c08c7cdbc6025aa923cb4c0efe","e1342a80d4b5e83d2c7c22e1e0aaa95f2d88e3dbf0d853a4994b180c93a4b17d","c539766062555d47716f8432e73adbe3a0c0c954a0b6c4005017a668975e275c","7069e28a5806db4ab0273639667d203f5e31b401d403af7e36d9f360c1f6d655","b86c5ae9e95bd841a595440faa3eb6317441e746f241ae8fd641ab59ed1d1966") by Filesystem.dest Filesystem.user Filesystem.file_hash Filesystem.file_path | `drop_dm_object_name(Filesystem)` | sort - lastTime
```

**Defender KQL:**
```kql
let MiasmaHadesIOCs = dynamic([
    "dc48b09b2a5954f7ff79ab8a2fd80202bd3b59c08c7cdbc6025aa923cb4c0efe",
    "e1342a80d4b5e83d2c7c22e1e0aaa95f2d88e3dbf0d853a4994b180c93a4b17d",
    "c539766062555d47716f8432e73adbe3a0c0c954a0b6c4005017a668975e275c",
    "7069e28a5806db4ab0273639667d203f5e31b401d403af7e36d9f360c1f6d655",
    "b86c5ae9e95bd841a595440faa3eb6317441e746f241ae8fd641ab59ed1d1966"
]);
union isfuzzy=true
    (DeviceFileEvents
     | where Timestamp > ago(30d)
     | where SHA256 in (MiasmaHadesIOCs)
     | project Timestamp, Source="DeviceFileEvents", DeviceName, AccountName=InitiatingProcessAccountName, FilePath=FolderPath, FileName, SHA256, ActorImage=InitiatingProcessFileName, ActorCmd=InitiatingProcessCommandLine),
    (DeviceProcessEvents
     | where Timestamp > ago(30d)
     | where SHA256 in (MiasmaHadesIOCs)
     | project Timestamp, Source="DeviceProcessEvents", DeviceName, AccountName, FilePath=FolderPath, FileName, SHA256, ActorImage=InitiatingProcessFileName, ActorCmd=ProcessCommandLine),
    (DeviceImageLoadEvents
     | where Timestamp > ago(30d)
     | where SHA256 in (MiasmaHadesIOCs)
     | project Timestamp, Source="DeviceImageLoadEvents", DeviceName, AccountName=InitiatingProcessAccountName, FilePath=FolderPath, FileName, SHA256, ActorImage=InitiatingProcessFileName, ActorCmd=InitiatingProcessCommandLine)
| order by Timestamp desc
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

`UC_69_3` · phase: **exploit** · confidence: **High**

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

Severity classified as **HIGH** based on: IOCs present, 11 use case(s) fired, 10 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

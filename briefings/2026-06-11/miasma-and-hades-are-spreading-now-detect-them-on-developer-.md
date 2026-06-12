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
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1547.013** — Boot or Logon Autostart Execution: XDG Autostart Entries
- **T1546** — Event Triggered Execution
- **T1059.007** — JavaScript
- **T1059.006** — Python
- **T1105** — Ingress Tool Transfer
- **T1552.001** — Credentials In Files
- **T1528** — Steal Application Access Token

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Miasma 'Phantom Gyp' — 157-byte binding.gyp drop in node_modules

`UC_16_4` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name="binding.gyp" AND Filesystem.file_path="*\\node_modules\\*" AND Filesystem.file_size<220 by host, Filesystem.user, Filesystem.file_path, Filesystem.file_size, Filesystem.process_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where FileName =~ "binding.gyp"
| where FolderPath has "node_modules"
| where FileSize between (50 .. 220)
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          FileName, FolderPath, FileSize, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName
| order by Timestamp desc
```

### Auto-execute editor/AI-tool config file dropped in repository

`UC_16_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\.vscode\\*" OR Filesystem.file_path="*\\.claude\\*" OR Filesystem.file_path="*\\.cursor\\*" OR Filesystem.file_path="*\\.gemini\\*" OR Filesystem.file_path="*\\.github\\*") AND Filesystem.file_name IN ("tasks.json","setup.mjs","setup.mdc","setup.js","settings.json") AND Filesystem.process_name IN ("node.exe","npm.exe","yarn.exe","pnpm.exe","python.exe","python3.exe","pip.exe","pip3.exe") by host, Filesystem.user, Filesystem.file_path, Filesystem.file_name, Filesystem.process_name | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where (FolderPath contains ".vscode" and FileName in~ ("tasks.json", "setup.mjs"))
     or (FolderPath contains ".claude" and FileName in~ ("setup.mjs", "settings.json"))
     or (FolderPath contains ".cursor" and FileName =~ "setup.mdc")
     or (FolderPath contains ".gemini" and FileName =~ "settings.json")
     or (FolderPath contains ".github" and FileName =~ "setup.js")
| where InitiatingProcessFileName in~ ("node.exe", "npm.exe", "yarn.exe", "pnpm.exe", "python.exe", "python3.exe", "pip.exe", "pip3.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          FileName, FolderPath, FileSize, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName
| order by Timestamp desc
```

### VS Code / Cursor / Claude Code spawning script interpreter on project open

`UC_16_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("code.exe","cursor.exe","claude.exe","gemini.exe","windsurf.exe") AND Processes.process_name IN ("node.exe","python.exe","python3.exe","pwsh.exe","powershell.exe","cmd.exe","bun.exe","wsl.exe","bash.exe") by host, Processes.user, Processes.parent_process, Processes.parent_process_name, Processes.process_name, Processes.process | `drop_dm_object_name(Processes)` | search process="*setup.mjs*" OR process="*setup.js*" OR process="*setup.mdc*" OR process="*tasks.json*" OR process="*.claude\\*" OR process="*.cursor\\*" OR process="*.vscode\\*" OR process="*bun.sh*" OR process="*oven-sh/bun*"
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("code.exe", "cursor.exe", "claude.exe", "gemini.exe", "windsurf.exe")
| where FileName in~ ("node.exe", "python.exe", "python3.exe", "pwsh.exe", "powershell.exe", "cmd.exe", "bun.exe", "wsl.exe", "bash.exe")
| where ProcessCommandLine has_any ("setup.mjs", "setup.js", "setup.mdc", "tasks.json", ".claude", ".cursor", ".vscode", ".gemini", "bun.sh", "oven-sh/bun", "DownloadString", "child_process")
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd = InitiatingProcessCommandLine,
          ChildImage = FolderPath,
          ChildCmd = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### Hades — python.exe child process downloads standalone Bun runtime on import

`UC_16_7` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("python.exe","python3.exe","pythonw.exe") AND (Processes.process_name IN ("curl.exe","powershell.exe","pwsh.exe","cmd.exe","bun.exe") OR Processes.process_name="bun.exe") by host, Processes.user, Processes.parent_process, Processes.process_name, Processes.process | `drop_dm_object_name(Processes)` | search (process="*bun.sh*" OR process="*oven-sh/bun*" OR process="*bun-windows*" OR process="*bun-linux*" OR process_name="bun.exe")
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("python.exe", "python3.exe", "pythonw.exe")
| where (FileName in~ ("curl.exe", "powershell.exe", "pwsh.exe", "cmd.exe", "wget.exe")
         and ProcessCommandLine has_any ("bun.sh", "oven-sh/bun", "bun-windows", "bun-linux", "bun-darwin"))
   or FileName =~ "bun.exe"
| project Timestamp, DeviceName, AccountName,
          ParentCmd = InitiatingProcessCommandLine,
          ParentImage = InitiatingProcessFolderPath,
          ChildImage = FolderPath,
          ChildCmd = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### Miasma/Hades worm credential theft — npm/PyPI publishing token access

`UC_16_8` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count from datamodel=Endpoint.Processes where Processes.process IN ("*.npmrc*","*.pypirc*","*_authToken*","*NPM_TOKEN*","*PYPI_TOKEN*","*NPM_AUTH_TOKEN*","*twine upload*","*npm publish*","*__token__*","*registry.npmjs.org/-/npm/v1/tokens*") AND Processes.parent_process_name IN ("code.exe","cursor.exe","claude.exe","gemini.exe","python.exe","python3.exe","node.exe","bun.exe","npm.exe") by host, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any (".npmrc", ".pypirc", "_authToken", "NPM_TOKEN", "PYPI_TOKEN", "NPM_AUTH_TOKEN", "registry.npmjs.org/-/npm/v1/tokens", "username = __token__", "twine upload", "npm publish", "__token__")
| where InitiatingProcessFileName in~ ("node.exe", "bun.exe", "python.exe", "python3.exe", "pwsh.exe", "powershell.exe", "cmd.exe", "npm.exe")
| where InitiatingProcessParentFileName in~ ("code.exe", "cursor.exe", "claude.exe", "gemini.exe", "python.exe", "node.exe", "npm.exe", "bun.exe")
| project Timestamp, DeviceName, AccountName,
          GrandparentImage = InitiatingProcessParentFileName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd = InitiatingProcessCommandLine,
          ChildImage = FolderPath,
          ChildCmd = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### Known Miasma/Hades payload SHA256 hash observed on developer machine

`UC_16_9` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count from datamodel=Endpoint.Processes where Processes.process_hash IN ("dc48b09b2a5954f7ff79ab8a2fd80202bd3b59c08c7cdbc6025aa923cb4c0efe","e1342a80d4b5e83d2c7c22e1e0aaa95f2d88e3dbf0d853a4994b180c93a4b17d","c539766062555d47716f8432e73adbe3a0c0c954a0b6c4005017a668975e275c","7069e28a5806db4ab0273639667d203f5e31b401d403af7e36d9f360c1f6d655","b86c5ae9e95bd841a595440faa3eb6317441e746f241ae8fd641ab59ed1d1966") by host, Processes.user, Processes.process_name, Processes.process, Processes.process_hash | `drop_dm_object_name(Processes)` | append [| tstats summariesonly=t count from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("dc48b09b2a5954f7ff79ab8a2fd80202bd3b59c08c7cdbc6025aa923cb4c0efe","e1342a80d4b5e83d2c7c22e1e0aaa95f2d88e3dbf0d853a4994b180c93a4b17d","c539766062555d47716f8432e73adbe3a0c0c954a0b6c4005017a668975e275c","7069e28a5806db4ab0273639667d203f5e31b401d403af7e36d9f360c1f6d655","b86c5ae9e95bd841a595440faa3eb6317441e746f241ae8fd641ab59ed1d1966") by host, Filesystem.user, Filesystem.file_name, Filesystem.file_path, Filesystem.file_hash | `drop_dm_object_name(Filesystem)`]
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
  (DeviceProcessEvents
   | where Timestamp > ago(30d)
   | where SHA256 in (MiasmaHashes)
   | project Timestamp, DeviceName, EventType="ProcessExec", FileName, FolderPath, SHA256,
             InitiatingProcessFileName, CmdLine=ProcessCommandLine, AccountName),
  (DeviceFileEvents
   | where Timestamp > ago(30d)
   | where SHA256 in (MiasmaHashes)
   | project Timestamp, DeviceName, EventType="FileWrite", FileName, FolderPath, SHA256,
             InitiatingProcessFileName, CmdLine=InitiatingProcessCommandLine, AccountName=InitiatingProcessAccountName),
  (DeviceImageLoadEvents
   | where Timestamp > ago(30d)
   | where SHA256 in (MiasmaHashes)
   | project Timestamp, DeviceName, EventType="ImageLoad", FileName, FolderPath, SHA256,
             InitiatingProcessFileName, CmdLine=InitiatingProcessCommandLine, AccountName=InitiatingProcessAccountName)
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

`UC_16_3` · phase: **exploit** · confidence: **High**

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

Severity classified as **HIGH** based on: IOCs present, 10 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

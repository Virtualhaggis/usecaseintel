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
- **T1195.001** — Supply Chain Compromise: Compromise Software Dependencies and Development Tools
- **T1554** — Compromise Host Software Binary
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1105** — Ingress Tool Transfer
- **T1218** — System Binary Proxy Execution
- **T1059.001** — Command and Scripting Interpreter: PowerShell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Editor and AI-tool auto-execute config files dropped in repos (Miasma/Hades delivery)

`UC_54_4` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.user) as user values(Filesystem.process_name) as process_name from datamodel=Endpoint.Filesystem where Filesystem.action=created (Filesystem.file_path="*\\.vscode\\tasks.json" OR Filesystem.file_path="*\\.vscode\\setup.mjs" OR Filesystem.file_path="*\\.claude\\setup.mjs" OR Filesystem.file_path="*\\.claude\\settings.json" OR Filesystem.file_path="*\\.cursor\\rules\\setup.mdc" OR Filesystem.file_path="*\\.gemini\\settings.json" OR Filesystem.file_path="*\\.github\\setup.js") by Filesystem.dest Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileRenamed")
| where FolderPath has_any (@"\.vscode\tasks.json", @"\.vscode\setup.mjs", @"\.claude\setup.mjs", @"\.claude\settings.json", @"\.cursor\rules\setup.mdc", @"\.gemini\settings.json", @"\.github\setup.js")
| where InitiatingProcessAccountName !endswith "$"
| extend RiskyFile = case(
    FolderPath endswith @"\.vscode\tasks.json", "vscode-runOnFolderOpen",
    FolderPath endswith @"\.vscode\setup.mjs", "vscode-setup-mjs",
    FolderPath endswith @"\.claude\setup.mjs", "claude-sessionstart-hook",
    FolderPath endswith @"\.claude\settings.json", "claude-settings-injection",
    FolderPath endswith @"\.cursor\rules\setup.mdc", "cursor-rules-on-open",
    FolderPath endswith @"\.gemini\settings.json", "gemini-settings-injection",
    FolderPath endswith @"\.github\setup.js", "github-actions-injection", "unknown")
| project Timestamp, DeviceName, InitiatingProcessAccountName, RiskyFile, FolderPath, FileName, FileSize, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### Suspicious small binding.gyp dropped in repo (Phantom Gyp / Miasma)

`UC_54_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as process_name from datamodel=Endpoint.Filesystem where Filesystem.action=created Filesystem.file_name="binding.gyp" Filesystem.file_size<512 by Filesystem.dest Filesystem.user Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType in ("FileCreated","FileRenamed")
| where FileName =~ "binding.gyp"
| where FileSize < 512  // article: 157-byte Phantom Gyp; legitimate binding.gyp is typically >1KB
| where InitiatingProcessAccountName !endswith "$"
| where InitiatingProcessFileName !in~ ("node-gyp.exe","node.exe")  // exclude in-place regeneration by node-gyp
| project Timestamp, DeviceName, InitiatingProcessAccountName, FolderPath, FileName, FileSize, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### Standalone Bun runtime downloaded or spawned on developer machine (Hades signature)

`UC_54_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process from datamodel=Endpoint.Processes where Processes.process_name="bun.exe" (Processes.parent_process_name="python.exe" OR Processes.parent_process_name="pythonw.exe" OR Processes.parent_process_name="py.exe" OR Processes.parent_process_name="code.exe" OR Processes.parent_process_name="cursor.exe" OR Processes.parent_process_name="claude.exe" OR Processes.parent_process_name="node.exe") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// Hades signature: standalone Bun runtime spawned by Python / IDE, or downloaded fresh
let BunSpawn = DeviceProcessEvents
    | where Timestamp > ago(14d)
    | where FileName =~ "bun.exe" or FileName =~ "bun"
    | where InitiatingProcessFileName in~ ("python.exe","pythonw.exe","py.exe","code.exe","cursor.exe","claude.exe","node.exe","powershell.exe","pwsh.exe")
    | project Timestamp, DeviceName, AccountName, Vector="BunSpawn", FileName, FolderPath, SHA256, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine;
let BunDownload = DeviceNetworkEvents
    | where Timestamp > ago(14d)
    | where RemoteUrl has_any ("bun.sh","github.com/oven-sh/bun","oven-sh.github.io")
    | where InitiatingProcessFileName in~ ("python.exe","pythonw.exe","py.exe","node.exe","powershell.exe","pwsh.exe","curl.exe","wget.exe")
    | project Timestamp, DeviceName, Vector="BunDownload", FileName="", FolderPath="", SHA256="", ProcessCommandLine="", InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName=InitiatingProcessAccountName;
union BunSpawn, BunDownload
| order by Timestamp desc
```

### IDE auto-execute spawning downloader or interpreter (Miasma/Hades folderOpen trigger)

`UC_54_7` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process from datamodel=Endpoint.Processes where (Processes.parent_process_name="code.exe" OR Processes.parent_process_name="cursor.exe" OR Processes.parent_process_name="claude.exe" OR Processes.parent_process_name="code-insiders.exe") (Processes.process_name="powershell.exe" OR Processes.process_name="pwsh.exe" OR Processes.process_name="cmd.exe" OR Processes.process_name="curl.exe" OR Processes.process_name="certutil.exe" OR Processes.process_name="bitsadmin.exe" OR Processes.process_name="mshta.exe" OR Processes.process_name="wscript.exe" OR Processes.process_name="cscript.exe" OR Processes.process_name="bun.exe") (Processes.process="*Invoke-WebRequest*" OR Processes.process="*DownloadString*" OR Processes.process="*-EncodedCommand*" OR Processes.process="*IEX*" OR Processes.process="*Invoke-Expression*" OR Processes.process="*FromBase64*" OR Processes.process="*bun.sh*" OR Processes.process="*oven-sh/bun*" OR Processes.process="*http://*" OR Processes.process="*https://*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("code.exe","cursor.exe","claude.exe","code-insiders.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","curl.exe","certutil.exe","bitsadmin.exe","mshta.exe","wscript.exe","cscript.exe","bun.exe","node.exe")
| where ProcessCommandLine has_any ("Invoke-WebRequest","DownloadString","-EncodedCommand"," -enc "," IEX ","Invoke-Expression","FromBase64String","bun.sh","oven-sh/bun","-Command","curl -","wget ","http://","https://")
| where InitiatingProcessParentFileName !in~ ("explorer.exe")  // keep noisy terminal-spawned removed — this is process-tree from IDE
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### Known Miasma/Hades payload hash on disk or in process

`UC_54_8` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where (Filesystem.file_hash="dc48b09b2a5954f7ff79ab8a2fd80202bd3b59c08c7cdbc6025aa923cb4c0efe" OR Filesystem.file_hash="e1342a80d4b5e83d2c7c22e1e0aaa95f2d88e3dbf0d853a4994b180c93a4b17d" OR Filesystem.file_hash="c539766062555d47716f8432e73adbe3a0c0c954a0b6c4005017a668975e275c" OR Filesystem.file_hash="7069e28a5806db4ab0273639667d203f5e31b401d403af7e36d9f360c1f6d655" OR Filesystem.file_hash="b86c5ae9e95bd841a595440faa3eb6317441e746f241ae8fd641ab59ed1d1966") by Filesystem.dest Filesystem.file_name Filesystem.file_hash
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
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
    | project Timestamp, DeviceName, Source="FileEvent", FileName, FolderPath, SHA256, Account=InitiatingProcessAccountName, ProcessName=InitiatingProcessFileName, ProcessCmd=InitiatingProcessCommandLine),
  (DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where SHA256 in (MiasmaHashes)
    | project Timestamp, DeviceName, Source="ProcessEvent", FileName, FolderPath, SHA256, Account=AccountName, ProcessName=FileName, ProcessCmd=ProcessCommandLine),
  (DeviceImageLoadEvents
    | where Timestamp > ago(30d)
    | where SHA256 in (MiasmaHashes)
    | project Timestamp, DeviceName, Source="ImageLoad", FileName, FolderPath, SHA256, Account=InitiatingProcessAccountName, ProcessName=InitiatingProcessFileName, ProcessCmd=InitiatingProcessCommandLine)
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

`UC_54_3` · phase: **exploit** · confidence: **High**

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

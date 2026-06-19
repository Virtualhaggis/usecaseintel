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
- **T1547** — Boot or Logon Autostart Execution
- **T1105** — Ingress Tool Transfer
- **T1218** — System Binary Proxy Execution
- **T1078** — Valid Accounts
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1059** — Command and Scripting Interpreter

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Miasma Phantom Gyp - tiny binding.gyp dropped inside node_modules

`UC_53_4` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.file_size) as file_size values(Filesystem.process_name) as process_name from datamodel=Endpoint.Filesystem where Filesystem.file_name="binding.gyp" Filesystem.file_path="*\\node_modules\\*" Filesystem.action=created by Filesystem.dest Filesystem.user | `drop_dm_object_name(Filesystem)` | where file_size < 512 | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FileName =~ "binding.gyp"
| where FolderPath has @"\node_modules\"
| where FileSize < 512
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName,
          FolderPath, FileSize, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName
| order by Timestamp desc
```

### Miasma IDE/AI auto-execute config drop (setup.mjs / setup.mdc / setup.js)

`UC_53_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.process_name) as process_name from datamodel=Endpoint.Filesystem where Filesystem.action=created (Filesystem.file_path="*\\.vscode\\setup.mjs" OR Filesystem.file_path="*\\.claude\\setup.mjs" OR Filesystem.file_path="*\\.cursor\\rules\\setup.mdc" OR Filesystem.file_path="*\\.github\\setup.js") by Filesystem.dest Filesystem.user Filesystem.file_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where (FolderPath endswith @"\.vscode" and FileName =~ "setup.mjs")
     or (FolderPath endswith @"\.claude" and FileName =~ "setup.mjs")
     or (FolderPath endswith @"\.cursor\rules" and FileName =~ "setup.mdc")
     or (FolderPath endswith @"\.github" and FileName =~ "setup.js")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName,
          FolderPath, FileName, FileSize, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName
| order by Timestamp desc
```

### Hades - Bun runtime spawned by Python interpreter (post-import payload)

`UC_53_6` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.process_path) as image values(Processes.parent_process) as parent_cmd from datamodel=Endpoint.Processes where (Processes.process_name="bun.exe" OR Processes.process_name="bun") (Processes.parent_process_name="python.exe" OR Processes.parent_process_name="python3.exe" OR Processes.parent_process_name="pythonw.exe" OR Processes.parent_process_name="py.exe") by Processes.dest Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("bun.exe","bun")
| where InitiatingProcessFileName in~ ("python.exe","python3.exe","pythonw.exe","py.exe")
     or InitiatingProcessParentFileName in~ ("python.exe","python3.exe","pythonw.exe","py.exe")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          GrandparentImage=InitiatingProcessParentFileName,
          ParentImage=InitiatingProcessFileName,
          ParentCmd=InitiatingProcessCommandLine,
          ChildImage=FolderPath,
          ChildCmd=ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### Miasma worm propagation - mass npm publish / twine upload burst from one host

`UC_53_7` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdlines dc(Processes.process) as distinct_cmdlines from datamodel=Endpoint.Processes where (Processes.process="*npm*publish*" OR Processes.process="*npm-cli.js*publish*" OR Processes.process="*twine*upload*" OR Processes.process="*python*-m*twine*upload*") by Processes.dest Processes.user span=10m | `drop_dm_object_name(Processes)` | where count >= 5 OR distinct_cmdlines >= 3 | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where (ProcessCommandLine has "npm" and ProcessCommandLine has "publish")
     or (ProcessCommandLine has_any ("npm-cli.js publish","twine upload"))
     or (ProcessCommandLine has "twine" and ProcessCommandLine has "upload")
| where AccountName !endswith "$"
| summarize PublishCount = count(),
            DistinctPackages = dcount(ProcessCommandLine),
            SampleCmds = make_set(ProcessCommandLine, 10),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp)
          by DeviceName, AccountName, bin(Timestamp, 10m)
| where PublishCount >= 5 or DistinctPackages >= 3   // P99 of normal dev publish bursts is ~2/10min
| order by FirstSeen desc
```

### VS Code / Cursor / Claude Code spawning runtime from .vscode/.claude/.cursor on folder open

`UC_53_8` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as child_cmd values(Processes.parent_process) as parent_cmd from datamodel=Endpoint.Processes where (Processes.parent_process_name="Code.exe" OR Processes.parent_process_name="code.exe" OR Processes.parent_process_name="Cursor.exe" OR Processes.parent_process_name="cursor.exe" OR Processes.parent_process_name="claude.exe" OR Processes.parent_process_name="code-insiders.exe") (Processes.process_name="node.exe" OR Processes.process_name="bun.exe" OR Processes.process_name="python.exe" OR Processes.process_name="cmd.exe" OR Processes.process_name="powershell.exe" OR Processes.process_name="pwsh.exe" OR Processes.process_name="wscript.exe" OR Processes.process_name="cscript.exe") (Processes.process="*\\.vscode\\*" OR Processes.process="*\\.claude\\*" OR Processes.process="*\\.cursor\\*" OR Processes.process="*\\.gemini\\*" OR Processes.process="*setup.mjs*" OR Processes.process="*setup.mdc*") by Processes.dest Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("Code.exe","code.exe","Cursor.exe","cursor.exe","claude.exe","code-insiders.exe")
| where FileName in~ ("node.exe","bun.exe","python.exe","python3.exe","cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","sh.exe","bash.exe")
| where ProcessCommandLine has_any (".vscode\\",".claude\\",".cursor\\",".gemini\\",".github\\setup",
                                    "setup.mjs","setup.mdc","setup.js","tasks.json")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd   = InitiatingProcessCommandLine,
          ChildImage  = FolderPath,
          ChildCmd    = ProcessCommandLine,
          SHA256
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

`UC_53_3` · phase: **exploit** · confidence: **High**

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

Severity classified as **HIGH** based on: IOCs present, 9 use case(s) fired, 11 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

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
- **T1547.001** — Registry Run Keys / Startup Folder
- **T1554** — Compromise Host Software Binary
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1204.003** — Malicious Image
- **T1105** — Ingress Tool Transfer
- **T1027.009** — Embedded Payloads
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1555** — Credentials from Password Stores
- **T1005** — Data from Local System
- **T1567** — Exfiltration Over Web Service
- **T1496** — Resource Hijacking

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Editor/AI-tool auto-execute config dropped in developer project (Miasma/Hades)

`UC_14_4` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\.vscode\\tasks.json" OR Filesystem.file_path="*\\.vscode\\setup.mjs" OR Filesystem.file_path="*\\.claude\\setup.mjs" OR Filesystem.file_path="*\\.claude\\settings.json" OR Filesystem.file_path="*\\.cursor\\rules\\setup.mdc" OR Filesystem.file_path="*\\.gemini\\settings.json" OR Filesystem.file_path="*\\.github\\setup.js") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path Filesystem.file_name | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where (FolderPath has @"\.vscode\" and FileName in~ ("tasks.json","setup.mjs"))
    or (FolderPath has @"\.claude\" and FileName in~ ("setup.mjs","settings.json"))
    or (FolderPath has @"\.cursor\rules\" and FileName =~ "setup.mdc")
    or (FolderPath has @"\.gemini\" and FileName =~ "settings.json")
    or (FolderPath has @"\.github\" and FileName =~ "setup.js")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName, SHA256
| order by Timestamp desc
```

### Miasma Phantom Gyp: tiny binding.gyp triggers native build code execution

`UC_14_5` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name="node.exe" OR Processes.parent_process_name="npm.exe" OR Processes.parent_process_name="node-gyp.exe" OR Processes.parent_process_name="npm.cmd") (Processes.process_name="cl.exe" OR Processes.process_name="clang.exe" OR Processes.process_name="clang++.exe" OR Processes.process_name="gcc.exe" OR Processes.process_name="link.exe" OR Processes.process_name="python.exe") (Processes.process="*binding.gyp*" OR Processes.process="*node-gyp*") by Processes.dest Processes.user Processes.parent_process Processes.process | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
let SmallBindingGyp = DeviceFileEvents
| where Timestamp > ago(7d)
| where FileName =~ "binding.gyp"
| where ActionType in ("FileCreated","FileModified")
| where FileSize between (50 .. 400)
| project FileTime=Timestamp, DeviceId, DeviceName, BindingGypPath=FolderPath, BindingGypSize=FileSize, InitiatingProcessFileName, InitiatingProcessCommandLine;
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node.exe","npm.exe","node-gyp.exe","npm.cmd","pnpm.exe","yarn.exe")
| where FileName in~ ("cl.exe","clang.exe","clang++.exe","gcc.exe","link.exe","python.exe","node-gyp.exe")
   or ProcessCommandLine has_any ("binding.gyp","node-gyp rebuild","node-gyp configure")
| join kind=inner SmallBindingGyp on DeviceId
| where Timestamp between (FileTime .. FileTime + 5m)
| project Timestamp, DeviceName, AccountName, BindingGypPath, BindingGypSize, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Hades on-import: Bun runtime downloaded by Python or Node

`UC_14_6` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.app="python.exe" OR All_Traffic.app="python3.exe" OR All_Traffic.app="node.exe" OR All_Traffic.app="py.exe" OR All_Traffic.app="pythonw.exe") (All_Traffic.dest_host="*bun.sh" OR All_Traffic.dest_host="github.com" OR All_Traffic.dest_host="objects.githubusercontent.com") by All_Traffic.src All_Traffic.user All_Traffic.app All_Traffic.dest_host All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("python.exe","python3.exe","py.exe","pythonw.exe","node.exe")
| where (FileName in~ ("curl.exe","wget.exe","powershell.exe","pwsh.exe","bitsadmin.exe")
         and ProcessCommandLine has_any ("bun.sh","oven-sh/bun","bun-windows-x64","bun-linux-x64","bun-darwin"))
    or (FileName =~ "bun.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
| union (
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("python.exe","python3.exe","py.exe","pythonw.exe","node.exe")
| where RemoteUrl has_any ("bun.sh","oven-sh/bun","bun-windows","bun-linux","bun-darwin")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
)
```

### Obfuscated one-line hook injected into __init__.py (Hades persistence)

`UC_14_7` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name="__init__.py" (Filesystem.file_path="*site-packages*" OR Filesystem.file_path="*dist-packages*" OR Filesystem.file_path="*\\venv\\*" OR Filesystem.file_path="*\\.venv\\*") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path Filesystem.file_hash | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where FileName =~ "__init__.py"
| where ActionType in ("FileCreated","FileModified")
| where FolderPath has_any ("site-packages","dist-packages",@"\venv\",@"\.venv\",@"\Lib\")
| where InitiatingProcessFileName !in~ ("pip.exe","pip3.exe","poetry.exe","twine.exe","setup.py","python.exe","py.exe","conda.exe","uv.exe")
   or InitiatingProcessCommandLine has_any ("-c ","exec(","eval(","__import__","base64","compile(")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName, FileSize, SHA256
| order by Timestamp desc
```

### npm/PyPI publishing credentials read by package-manager or shell process

`UC_14_8` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name=".npmrc" OR Filesystem.file_name=".pypirc" OR Filesystem.file_name="npm-token" OR Filesystem.file_path="*\\npm\\_authToken*") (Filesystem.process_name="powershell.exe" OR Filesystem.process_name="pwsh.exe" OR Filesystem.process_name="cmd.exe" OR Filesystem.process_name="node.exe" OR Filesystem.process_name="python.exe" OR Filesystem.process_name="bun.exe" OR Filesystem.process_name="wscript.exe" OR Filesystem.process_name="cscript.exe") NOT (Filesystem.process_name="npm.exe" OR Filesystem.process_name="pip.exe" OR Filesystem.process_name="yarn.exe" OR Filesystem.process_name="pnpm.exe" OR Filesystem.process_name="twine.exe" OR Filesystem.process_name="poetry.exe") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where FileName in~ (".npmrc",".pypirc","npm-token") or FolderPath has @"\npm\_authToken"
| where ActionType in ("FileAccessed","FileOpened","FileModified","FileCreated")
| where InitiatingProcessFileName has_any ("powershell.exe","pwsh.exe","cmd.exe","node.exe","python.exe","bun.exe","wscript.exe","cscript.exe","py.exe")
| where InitiatingProcessFileName !in~ ("npm.exe","pip.exe","yarn.exe","pnpm.exe","twine.exe","poetry.exe","uv.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName
| order by Timestamp desc
```

### Worm propagation: npm publish or twine upload from non-interactive parent

`UC_14_9` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="npm.exe" OR Processes.process_name="npm.cmd" OR Processes.process_name="yarn.exe" OR Processes.process_name="pnpm.exe" OR Processes.process_name="twine.exe") (Processes.process="*publish*" OR Processes.process="*upload*") (Processes.parent_process_name="node.exe" OR Processes.parent_process_name="python.exe" OR Processes.parent_process_name="bun.exe" OR Processes.parent_process_name="py.exe" OR Processes.parent_process_name="wscript.exe" OR Processes.parent_process_name="cscript.exe" OR Processes.parent_process_name="powershell.exe") by Processes.dest Processes.user Processes.parent_process Processes.process | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (FileName in~ ("npm.exe","npm.cmd","yarn.exe","pnpm.exe") and ProcessCommandLine has "publish")
    or (FileName =~ "twine.exe" and ProcessCommandLine has "upload")
    or (FileName in~ ("python.exe","py.exe") and ProcessCommandLine has_all ("twine","upload"))
| where InitiatingProcessFileName in~ ("node.exe","python.exe","bun.exe","py.exe","wscript.exe","cscript.exe","powershell.exe","pwsh.exe")
| where InitiatingProcessParentFileName !in~ ("explorer.exe","code.exe","code-insiders.exe","cursor.exe","WindowsTerminal.exe","conhost.exe","cmd.exe")
   or InitiatingProcessCommandLine has_any ("-c ","exec(","eval(","base64","-EncodedCommand")
| project Timestamp, DeviceName, AccountName, InitiatingProcessParentFileName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath
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

`UC_14_3` · phase: **exploit** · confidence: **High**

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

Severity classified as **HIGH** based on: IOCs present, 10 use case(s) fired, 16 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

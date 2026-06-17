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
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1105** — Ingress Tool Transfer
- **T1027.002** — Obfuscated Files or Information: Software Packing
- **T1546** — Event Triggered Execution
- **T1567** — Exfiltration Over Web Service
- **T1552.001** — Unsecured Credentials: Credentials In Files

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Miasma/Hades known-bad SHA256 execution on developer endpoint

`UC_87_4` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_hash IN ("dc48b09b2a5954f7ff79ab8a2fd80202bd3b59c08c7cdbc6025aa923cb4c0efe","e1342a80d4b5e83d2c7c22e1e0aaa95f2d88e3dbf0d853a4994b180c93a4b17d","c539766062555d47716f8432e73adbe3a0c0c954a0b6c4005017a668975e275c","7069e28a5806db4ab0273639667d203f5e31b401d403af7e36d9f360c1f6d655","b86c5ae9e95bd841a595440faa3eb6317441e746f241ae8fd641ab59ed1d1966") OR Processes.parent_process_hash IN ("dc48b09b2a5954f7ff79ab8a2fd80202bd3b59c08c7cdbc6025aa923cb4c0efe","e1342a80d4b5e83d2c7c22e1e0aaa95f2d88e3dbf0d853a4994b180c93a4b17d","c539766062555d47716f8432e73adbe3a0c0c954a0b6c4005017a668975e275c","7069e28a5806db4ab0273639667d203f5e31b401d403af7e36d9f360c1f6d655","b86c5ae9e95bd841a595440faa3eb6317441e746f241ae8fd641ab59ed1d1966") by Processes.dest Processes.user Processes.process_name Processes.process Processes.process_path Processes.process_hash Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
let MiasmaHashes = dynamic(["dc48b09b2a5954f7ff79ab8a2fd80202bd3b59c08c7cdbc6025aa923cb4c0efe","e1342a80d4b5e83d2c7c22e1e0aaa95f2d88e3dbf0d853a4994b180c93a4b17d","c539766062555d47716f8432e73adbe3a0c0c954a0b6c4005017a668975e275c","7069e28a5806db4ab0273639667d203f5e31b401d403af7e36d9f360c1f6d655","b86c5ae9e95bd841a595440faa3eb6317441e746f241ae8fd641ab59ed1d1966"]);
union
(DeviceProcessEvents
  | where Timestamp > ago(30d)
  | where SHA256 in (MiasmaHashes) or InitiatingProcessSHA256 in (MiasmaHashes)
  | extend Source = "DeviceProcessEvents"
  | project Timestamp, Source, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine),
(DeviceFileEvents
  | where Timestamp > ago(30d)
  | where SHA256 in (MiasmaHashes)
  | extend Source = "DeviceFileEvents"
  | project Timestamp, Source, DeviceName, AccountName=InitiatingProcessAccountName, FileName, FolderPath, SHA256, ProcessCommandLine=InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine)
| order by Timestamp desc
```

### Phantom Gyp: small binding.gyp written into node_modules during npm install

`UC_87_5` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name="binding.gyp" Filesystem.file_path="*\\node_modules\\*" Filesystem.file_size<500 by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_size Filesystem.process_name Filesystem.process_path Filesystem.action | `drop_dm_object_name(Filesystem)` | where match(process_name, "(?i)^(npm|node|yarn|pnpm|tar|7z|git)\.exe$") | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType in ("FileCreated", "FileRenamed", "FileModified")
| where FileName =~ "binding.gyp"
| where FolderPath has @"\node_modules\"
| where FileSize between (50 .. 500)   // article: 157-byte Phantom Gyp; allow small obfuscation variance
| where InitiatingProcessFileName in~ ("npm.exe","node.exe","yarn.exe","pnpm.exe","tar.exe","7z.exe","git.exe")
   or InitiatingProcessCommandLine has_any ("npm install","npm i ","npm ci","yarn add","yarn install","pnpm install","pnpm add")
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, FolderPath, FileName, FileSize, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### Hades on-import payload: python interpreter spawns Bun runtime download

`UC_87_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("python.exe","python3.exe","pythonw.exe","py.exe")) AND (Processes.process_name IN ("bun.exe","curl.exe","wget.exe","powershell.exe","node.exe") AND (Processes.process="*bun.sh*" OR Processes.process="*oven-sh/bun*" OR Processes.process="*bun-windows-x64*" OR Processes.process="*bun-darwin*" OR Processes.process="*bun-linux*" OR Processes.process="*_index.js*" OR Processes.process_name="bun.exe")) by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
let HadesPkgs = dynamic(["ensmallen","mflux-streamlit","nhmpy","ppkt2synergy","embiggen","gpsea","pyphetools"]);
// Stage A: python parent spawns bun / fetcher referencing Bun distribution
let StageA = DeviceProcessEvents
  | where Timestamp > ago(14d)
  | where InitiatingProcessFileName in~ ("python.exe","python3.exe","pythonw.exe","py.exe")
  | where FileName in~ ("bun.exe","curl.exe","wget.exe","powershell.exe","pwsh.exe","node.exe")
  | where FileName =~ "bun.exe"
      or ProcessCommandLine has_any ("bun.sh/install","github.com/oven-sh/bun","bun-windows-x64","bun-darwin","bun-linux","bun-v1.3.13","bun-v1.3.14","_index.js");
// Stage B: python directly egressing to Bun distribution endpoints
let StageB = DeviceNetworkEvents
  | where Timestamp > ago(14d)
  | where InitiatingProcessFileName in~ ("python.exe","python3.exe","pythonw.exe","py.exe")
  | where RemoteUrl has_any ("bun.sh","oven-sh/bun","bun-windows-x64","bun-darwin","bun-linux")
  | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, FileName="(network)", ProcessCommandLine="";
StageA
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, RemoteUrl="", RemoteIP=""
| union StageB
| order by Timestamp desc
```

### Editor/AI tool auto-execute config file dropped into project tree by package manager or git

`UC_87_7` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\.vscode\\tasks.json" OR Filesystem.file_path="*\\.vscode\\setup.mjs" OR Filesystem.file_path="*\\.claude\\setup.mjs" OR Filesystem.file_path="*\\.claude\\settings.json" OR Filesystem.file_path="*\\.cursor\\rules\\setup.mdc" OR Filesystem.file_path="*\\.gemini\\settings.json" OR Filesystem.file_path="*\\.github\\setup.js") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.process_name Filesystem.action | `drop_dm_object_name(Filesystem)` | where match(process_name, "(?i)^(git|npm|node|pip|python|yarn|pnpm|tar|7z|curl|wget)\.exe$") | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| extend FullPath = strcat(FolderPath, @"\", FileName)
| where FullPath has_any (@"\.vscode\tasks.json", @"\.vscode\setup.mjs", @"\.claude\setup.mjs", @"\.claude\settings.json", @"\.cursor\rules\setup.mdc", @"\.gemini\settings.json", @"\.github\setup.js")
// Drop writes by the legitimate IDE — those are user authoring; keep writes by package managers / git / extractors
| where InitiatingProcessFileName in~ ("git.exe","npm.exe","node.exe","pip.exe","python.exe","python3.exe","yarn.exe","pnpm.exe","tar.exe","7z.exe","curl.exe","wget.exe","bun.exe")
   or InitiatingProcessCommandLine has_any ("git clone","git pull","git checkout","npm install","npm i ","pip install","yarn add","pnpm install")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, FullPath, FileSize, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### VS Code/Cursor/Claude/Gemini spawns interpreter referencing folderOpen or SessionStart hook script

`UC_87_8` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("Code.exe","code.exe","Cursor.exe","cursor.exe","Claude.exe","claude.exe","Gemini.exe","gemini.exe","devenv.exe")) AND (Processes.process_name IN ("node.exe","bun.exe","python.exe","python3.exe","pythonw.exe","powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","curl.exe","wget.exe")) AND (Processes.process="*setup.mjs*" OR Processes.process="*setup.mdc*" OR Processes.process="*setup.js*" OR Processes.process="*.vscode\\tasks.json*" OR Processes.process="*.claude\\settings.json*" OR Processes.process="*.gemini\\settings.json*" OR Processes.process="*folderOpen*" OR Processes.process="*SessionStart*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("code.exe","cursor.exe","claude.exe","gemini.exe","devenv.exe")
    or InitiatingProcessParentFileName in~ ("code.exe","cursor.exe","claude.exe","gemini.exe","devenv.exe")
| where FileName in~ ("node.exe","bun.exe","python.exe","python3.exe","pythonw.exe","powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","curl.exe","wget.exe")
| where ProcessCommandLine has_any ("setup.mjs","setup.mdc",".github\\setup.js",@"\.vscode\tasks.json",@"\.claude\settings.json",@"\.gemini\settings.json","folderOpen","SessionStart")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, FileName, FolderPath, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Bun runtime egress to npm/PyPI publish endpoints or attacker-controlled GitHub repos

`UC_87_9` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count values(All_Traffic.url) as urls min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.process_name="bun.exe" AND (All_Traffic.url="*registry.npmjs.org/-/v1/publish*" OR All_Traffic.url="*registry.npmjs.org/-/user*" OR All_Traffic.url="*upload.pypi.org/legacy/*" OR All_Traffic.url="*api.github.com/user/repos*" OR All_Traffic.url="*api.github.com/repos/*/contents/*" OR All_Traffic.url="*api.github.com/repos/*/git/refs*") by All_Traffic.dest All_Traffic.src All_Traffic.user All_Traffic.process_name All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("bun.exe","node.exe")
| where RemoteUrl has_any ("registry.npmjs.org/-/v1/publish","registry.npmjs.org/-/user","upload.pypi.org/legacy","api.github.com/user/repos","api.github.com/repos","api.github.com/gists")
   or (RemoteUrl has "api.github.com" and InitiatingProcessCommandLine has_any ("_index.js","bun-","setup.mjs"))
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, RemoteUrl, RemoteIP, RemotePort
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

`UC_87_3` · phase: **exploit** · confidence: **High**

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

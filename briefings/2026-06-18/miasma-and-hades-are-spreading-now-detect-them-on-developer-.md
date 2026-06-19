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
- **T1546** — Event Triggered Execution
- **T1059.007** — JavaScript
- **T1567** — Exfiltration Over Web Service
- **T1105** — Ingress Tool Transfer
- **T1218** — System Binary Proxy Execution

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Miasma/Hades 'Suspicious Files' — IDE & AI-assistant auto-execute hooks dropped

`UC_54_4` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action="created" AND ( (Filesystem.file_path="*\\.vscode\\*" AND Filesystem.file_name IN ("tasks.json","setup.mjs")) OR (Filesystem.file_path="*\\.claude\\*" AND Filesystem.file_name IN ("setup.mjs","settings.json")) OR (Filesystem.file_path="*\\.cursor\\rules\\*" AND Filesystem.file_name="setup.mdc") OR (Filesystem.file_path="*\\.gemini\\*" AND Filesystem.file_name="settings.json") OR (Filesystem.file_path="*\\.github\\*" AND Filesystem.file_name="setup.js") OR (Filesystem.file_name="binding.gyp" AND Filesystem.file_size<512) ) by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.file_size Filesystem.process_name | `drop_dm_object_name(Filesystem)` | where NOT match(process_name, "(?i)(code|cursor|devenv|claude|msiexec)\\.exe$") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where (FolderPath has @"\.vscode\" and FileName in~ ("tasks.json","setup.mjs"))
   or (FolderPath has @"\.claude\" and FileName in~ ("setup.mjs","settings.json"))
   or (FolderPath has @"\.cursor\rules\" and FileName =~ "setup.mdc")
   or (FolderPath has @"\.gemini\" and FileName =~ "settings.json")
   or (FolderPath has @"\.github\" and FileName =~ "setup.js")
   or (FileName =~ "binding.gyp" and FileSize < 512)
| where not(InitiatingProcessFileName in~ ("code.exe","cursor.exe","claude.exe","devenv.exe","msiexec.exe","git.exe"))
| project Timestamp, DeviceName, InitiatingProcessAccountName, FolderPath, FileName, FileSize, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### IDE / AI assistant auto-execute — Code/Cursor/Claude/Gemini spawning shell or runtime via project-open hook

`UC_54_5` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("Code.exe","code.exe","cursor.exe","Cursor.exe","devenv.exe","claude.exe")) AND (Processes.process_name IN ("powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","bun.exe","node.exe","python.exe","sh.exe","bash.exe")) AND (Processes.process="*setup.mjs*" OR Processes.process="*setup.mdc*" OR Processes.process="*tasks.json*" OR Processes.process="*binding.gyp*" OR Processes.process="*\\.claude\\*" OR Processes.process="*\\.cursor\\*" OR Processes.process="*\\.gemini\\*" OR Processes.process="*\\.vscode\\*" OR Processes.parent_process="*setup.mjs*" OR Processes.parent_process="*tasks.json*") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process Processes.process_hash | `drop_dm_object_name(Processes)` | convert ctime(firstTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("code.exe","cursor.exe","devenv.exe","claude.exe","gemini.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","bun.exe","node.exe","python.exe","sh.exe","bash.exe")
| where ProcessCommandLine has_any ("setup.mjs","setup.mdc","tasks.json","binding.gyp",".claude\\",".cursor\\",".gemini\\",".vscode\\")
   or InitiatingProcessCommandLine has_any ("setup.mjs","setup.mdc","tasks.json","binding.gyp")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Worm propagation — `npm publish` or `twine upload` from interactive developer endpoint

`UC_54_6` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count values(Processes.process) as cmdlines values(Processes.dest) as dest from datamodel=Endpoint.Processes where (Processes.process="*npm* publish*" OR Processes.process="*twine* upload*" OR Processes.process="*pnpm* publish*" OR Processes.process="*yarn* publish*") by Processes.dest Processes.user _time span=10m | `drop_dm_object_name(Processes)` | rex field=cmdlines max_match=0 "publish\s+(?<pkg>[A-Za-z0-9@/_.\\-]+)" | eval pkg_count=mvcount(mvdedup(pkg)) | where pkg_count>=3 OR (count>=5)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (FileName in~ ("npm.cmd","npm.exe","npm","pnpm.cmd","pnpm.exe","yarn.cmd","yarn.exe") and ProcessCommandLine has "publish")
   or (FileName in~ ("twine.exe","twine") and ProcessCommandLine has "upload")
   or ProcessCommandLine matches regex @"(?i)\b(npm|pnpm|yarn)\s+publish\b"
   or ProcessCommandLine matches regex @"(?i)\btwine\s+upload\b"
| where not(InitiatingProcessFileName in~ ("runner.exe","github.runner.worker.exe","gitlab-runner.exe","jenkins.exe","agent.listener.exe","buildkite-agent.exe"))
| where not(InitiatingProcessParentFileName in~ ("runner.exe","github.runner.worker.exe","gitlab-runner.exe","jenkins.exe","agent.listener.exe"))
| summarize PublishCount=count(), Cmds=make_set(ProcessCommandLine, 25), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by DeviceName, AccountName, bin(Timestamp, 10m)
| where PublishCount >= 3
| order by LastSeen desc
```

### Hades on-import payload — Bun runtime fetched and executed by Python interpreter

`UC_54_7` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("python.exe","python3.exe","pythonw.exe","python3","python")) AND (Processes.process_name IN ("bun.exe","bun","curl.exe","wget.exe","powershell.exe","pwsh.exe") OR Processes.process="*bun.sh*" OR Processes.process="*oven-sh/bun*" OR Processes.process="*bun-v*") by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_hash | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
let BunFetch = DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where RemoteUrl has_any ("bun.sh","oven-sh/bun","bun-v")
    | where InitiatingProcessFileName in~ ("python.exe","python3.exe","pythonw.exe","node.exe","powershell.exe","pwsh.exe","curl.exe","wget.exe")
    | project DownloadTime=Timestamp, DeviceId, DeviceName, RemoteUrl, RemoteIP, InitiatingProcessFileName, InitiatingProcessCommandLine;
let BunSpawn = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName =~ "bun.exe" or FileName =~ "bun"
    | where InitiatingProcessFileName in~ ("python.exe","python3.exe","pythonw.exe","node.exe")
       or InitiatingProcessCommandLine has_any ("__init__.py","setup.mjs")
    | project SpawnTime=Timestamp, DeviceId, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256;
union BunFetch, BunSpawn
| order by DeviceName asc, coalesce(DownloadTime, SpawnTime) desc
```

### Miasma Phantom Gyp — 100-300 byte binding.gyp written outside a normal native-addon build

`UC_54_8` · phase: **weapon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count from datamodel=Endpoint.Filesystem where Filesystem.file_name="binding.gyp" Filesystem.file_size<300 Filesystem.file_size>=80 by Filesystem.dest Filesystem.file_path Filesystem.file_size Filesystem.process_name Filesystem.user _time | `drop_dm_object_name(Filesystem)` | where NOT match(process_name, "(?i)(tar|git|msiexec|7z|7zip|winrar)\\.exe$")
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified")
| where FileName =~ "binding.gyp"
| where FileSize between (80 .. 300)
| where not(InitiatingProcessFileName in~ ("tar.exe","git.exe","7z.exe","7zg.exe","winrar.exe","msiexec.exe","code.exe","devenv.exe"))
| project Timestamp, DeviceName, InitiatingProcessAccountName, FolderPath, FileName, FileSize, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
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

Severity classified as **HIGH** based on: IOCs present, 9 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

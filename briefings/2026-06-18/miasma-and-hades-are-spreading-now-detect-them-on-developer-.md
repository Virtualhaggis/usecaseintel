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
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1105** — Ingress Tool Transfer
- **T1059** — Command and Scripting Interpreter
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1555** — Credentials from Password Stores

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Suspicious AI/IDE auto-execute config file dropped in project tree (Miasma/Hades editor-trigger artifacts)

`UC_50_4` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action in ("created","modified") AND (Filesystem.file_path="*\\.claude\\setup.mjs" OR Filesystem.file_path="*\\.claude\\settings.json" OR Filesystem.file_path="*\\.cursor\\rules\\setup.mdc" OR Filesystem.file_path="*\\.gemini\\settings.json" OR Filesystem.file_path="*\\.vscode\\tasks.json" OR Filesystem.file_path="*\\.vscode\\setup.mjs" OR Filesystem.file_path="*\\.github\\setup.js") AND NOT (Filesystem.process_name IN ("code.exe","cursor.exe","claude.exe","explorer.exe","msiexec.exe")) by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.process_name Filesystem.process_path | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where (FolderPath endswith @"\.claude" and FileName in~ ("setup.mjs","settings.json"))
    or (FolderPath endswith @"\.cursor\rules" and FileName =~ "setup.mdc")
    or (FolderPath endswith @"\.gemini" and FileName =~ "settings.json")
    or (FolderPath endswith @"\.vscode" and FileName in~ ("tasks.json","setup.mjs"))
    or (FolderPath endswith @"\.github" and FileName =~ "setup.js")
| where not(InitiatingProcessFileName in~ ("code.exe","cursor.exe","claude.exe","explorer.exe","msiexec.exe","setup.exe"))
| where not(InitiatingProcessAccountName endswith "$")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FolderPath, FileName, FileSize, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, SHA256
| order by Timestamp desc
```

### Phantom Gyp: 157-byte binding.gyp dropped to npm package root (Miasma native-build hijack)

`UC_50_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name="binding.gyp" AND Filesystem.action="created" AND Filesystem.file_size<1024 by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.process_name Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | join type=inner dest [| tstats `summariesonly` count from datamodel=Endpoint.Processes where Processes.process_name="node-gyp.exe" OR (Processes.process_name="node.exe" AND Processes.process="*node-gyp*") by Processes.dest Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let bindingDrops = DeviceFileEvents
    | where Timestamp > ago(7d)
    | where FileName =~ "binding.gyp"
    | where ActionType in ("FileCreated","FileModified")
    | where FileSize < 1024
    | where not(InitiatingProcessFileName in~ ("git.exe","code.exe","explorer.exe","7z.exe","winrar.exe","tar.exe"))
    | project DropTime=Timestamp, DeviceId, DeviceName, InitiatingProcessAccountName, FolderPath, FileSize, DropProcess=InitiatingProcessFileName, DropCmd=InitiatingProcessCommandLine, SHA256;
bindingDrops
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where ProcessCommandLine has "node-gyp" or InitiatingProcessCommandLine has "node-gyp" or FileName =~ "node-gyp.exe"
    | project BuildTime=Timestamp, DeviceId, BuildCmd=ProcessCommandLine, BuildParent=InitiatingProcessFileName
) on DeviceId
| where BuildTime between (DropTime .. DropTime + 5m)
| project DropTime, BuildTime, DeviceName, InitiatingProcessAccountName, FolderPath, FileSize, DropProcess, DropCmd, BuildCmd, BuildParent, SHA256
```

### Hades PyPI import-time Bun runtime download by python.exe

`UC_50_6` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.app="python.exe" OR All_Traffic.app="python3.exe" OR All_Traffic.app="pythonw.exe") AND (All_Traffic.dest_host="bun.sh" OR All_Traffic.dest_host="*.bun.sh" OR All_Traffic.url="*oven-sh/bun*" OR All_Traffic.url="*bun-v*" OR All_Traffic.url="*bun.linux*" OR All_Traffic.url="*bun.windows*") by All_Traffic.src All_Traffic.user All_Traffic.app All_Traffic.dest_host All_Traffic.url | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("python.exe","python3.exe","pythonw.exe","py.exe")
   or InitiatingProcessParentFileName in~ ("python.exe","python3.exe","pythonw.exe","py.exe")
| where RemoteUrl has_any ("bun.sh","oven-sh/bun","bun-v","bun.linux","bun.windows","bun.darwin")
   or RemoteUrl matches regex @"(?i)github.*releases.*download.*bun-"
| where not(InitiatingProcessCommandLine has_any ("pip install bun","bun-py","unittest"))
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFolderPath
| order by Timestamp desc
```

### VS Code tasks.json folderOpen auto-execute spawning interpreter or downloader

`UC_50_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name="Code.exe" OR Processes.parent_process_name="code.exe" OR Processes.parent_process_name="Code - Insiders.exe") AND (Processes.process_name="powershell.exe" OR Processes.process_name="pwsh.exe" OR Processes.process_name="cmd.exe" OR Processes.process_name="node.exe" OR Processes.process_name="bun.exe" OR Processes.process_name="python.exe" OR Processes.process_name="curl.exe" OR Processes.process_name="wget.exe" OR Processes.process_name="bitsadmin.exe") AND (Processes.parent_process="*tasks.json*" OR Processes.parent_process="*folderOpen*" OR Processes.process="*setup.mjs*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_path | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("code.exe","Code.exe","Code - Insiders.exe")
   or InitiatingProcessParentFileName in~ ("code.exe","Code.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","node.exe","bun.exe","python.exe","python3.exe","curl.exe","wget.exe","bitsadmin.exe","mshta.exe","wscript.exe","cscript.exe")
| where InitiatingProcessCommandLine has_any ("tasks.json","folderOpen","runOn","setup.mjs")
   or ProcessCommandLine has_any ("\\.vscode\\setup.mjs","folderOpen")
| where not(AccountName endswith "$")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath, SHA256, InitiatingProcessFolderPath
| order by Timestamp desc
```

### Developer publish-token file accessed by non-package-manager process (worm token theft)

`UC_50_8` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name=".npmrc" OR Filesystem.file_name=".pypirc" OR Filesystem.file_name=".git-credentials" OR Filesystem.file_path="*\\.aws\\credentials" OR Filesystem.file_path="*\\.ssh\\id_rsa" OR Filesystem.file_path="*\\.ssh\\id_ed25519" OR Filesystem.file_path="*\\.config\\pip\\pip.conf") AND NOT (Filesystem.process_name IN ("npm.exe","node.exe","yarn.exe","pnpm.exe","pip.exe","pip3.exe","python.exe","python3.exe","pythonw.exe","pipx.exe","uv.exe","poetry.exe","ssh.exe","ssh-add.exe","git.exe","git-credential-manager.exe","aws.exe","az.exe","kubectl.exe","explorer.exe","code.exe","notepad.exe")) by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.process_name Filesystem.process_path Filesystem.process | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FileName in~ (".npmrc",".pypirc",".git-credentials","credentials","id_rsa","id_ed25519","pip.conf")
   or FolderPath has_any (@"\.npm\", @"\.aws\", @"\.azure\", @"\.kube\", @"\.ssh\", @"\.config\pip\", @"\.docker\")
| where not(InitiatingProcessFileName in~ ("npm.exe","node.exe","yarn.exe","pnpm.exe","pip.exe","pip3.exe","python.exe","python3.exe","pythonw.exe","pipx.exe","uv.exe","poetry.exe","ssh.exe","ssh-add.exe","git.exe","git-credential-manager.exe","aws.exe","az.exe","kubectl.exe","docker.exe","explorer.exe","code.exe","notepad.exe","setup.exe","msiexec.exe"))
| where not(InitiatingProcessAccountName endswith "$")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, ActionType
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

`UC_50_3` · phase: **exploit** · confidence: **High**

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

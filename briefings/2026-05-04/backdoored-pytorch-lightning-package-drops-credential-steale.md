# [HIGH] Backdoored PyTorch Lightning package drops credential stealer

**Source:** BleepingComputer
**Published:** 2026-05-04
**Article:** https://www.bleepingcomputer.com/news/security/backdoored-pytorch-lightning-package-drops-credential-stealer/

## Threat Profile

Backdoored PyTorch Lightning package drops credential stealer 
By Bill Toulas 
May 4, 2026
01:15 PM
0 
A malicious version of the PyTorch Lightning package published on the Python Package Index (PyPI) delivers a credential-stealing payload targeting browsers, environment files, and cloud services.
The developer disclosed the supply-chain attack on April 30, saying that version 2.6.3 of the package included a hidden execution chain that downloads and executes a JavaScript payload.
PyTorch Lightni…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1105** — Ingress Tool Transfer
- **T1588.001** — Obtain Capabilities: Tool

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] ShaiWorm: Bun runtime spawned by Python interpreter executing router_runtime.js

`UC_44_3` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.process_path) as process_path values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("python.exe","python3.exe","python3","pythonw.exe","pip.exe") AND (Processes.process_name="bun.exe" OR Processes.process_name="bun" OR Processes.process LIKE "%router_runtime.js%")) OR (Processes.process LIKE "%router_runtime.js%") by host Processes.parent_process_name Processes.process_name Processes.process Processes.user | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (InitiatingProcessFileName has_any ("python.exe","python3.exe","pythonw.exe","pip.exe","pip3.exe") and (FileName =~ "bun.exe" or FileName =~ "bun" or ProcessCommandLine has "router_runtime.js"))
     or ProcessCommandLine has "router_runtime.js"
     or (FileName in~ ("bun.exe","bun") and InitiatingProcessCommandLine has "lightning")
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd = InitiatingProcessCommandLine,
          ChildImage = FolderPath,
          ChildCmd = ProcessCommandLine,
          ChildSHA256 = SHA256
| order by Timestamp desc
```

### [LLM] Install / import of quarantined PyTorch Lightning 2.6.2 or 2.6.3 wheel

`UC_44_4` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.process_name IN ("pip.exe","pip3.exe","python.exe","python3.exe","poetry.exe","uv.exe") AND (Processes.process LIKE "%lightning==2.6.2%" OR Processes.process LIKE "%lightning==2.6.3%" OR Processes.process LIKE "%pytorch-lightning==2.6.2%" OR Processes.process LIKE "%pytorch-lightning==2.6.3%" OR Processes.process LIKE "%lightning-2.6.2-py3-none-any.whl%" OR Processes.process LIKE "%lightning-2.6.3-py3-none-any.whl%") by host Processes.process_name Processes.process Processes.user | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let bad_specs = dynamic(["lightning==2.6.2","lightning==2.6.3","pytorch-lightning==2.6.2","pytorch-lightning==2.6.3"]);
let bad_wheels = dynamic(["lightning-2.6.2-py3-none-any.whl","lightning-2.6.3-py3-none-any.whl"]);
union
  ( DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where InitiatingProcessFileName has_any ("pip.exe","pip3.exe","python.exe","python3.exe","poetry.exe","uv.exe")
         or FileName has_any ("pip.exe","pip3.exe","poetry.exe","uv.exe")
    | where ProcessCommandLine has_any (bad_specs) or ProcessCommandLine has_any (bad_wheels)
    | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
              Parent = InitiatingProcessFileName, ParentCmd = InitiatingProcessCommandLine ),
  ( DeviceFileEvents
    | where Timestamp > ago(30d)
    | where FileName in~ (bad_wheels)
         or (FolderPath has @"\site-packages\lightning\" and FolderPath has_any ("2.6.2","2.6.3"))
    | project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName, FileName,
              ProcessCommandLine = InitiatingProcessCommandLine, FolderPath,
              Parent = InitiatingProcessFileName, ParentCmd = InitiatingProcessCommandLine )
| order by Timestamp desc
```

### [LLM] Python interpreter pulling Bun runtime from GitHub releases (oven-sh/bun)

`UC_44_5` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dest values(All_Traffic.dest_url) as url values(All_Traffic.user) as user from datamodel=Network_Traffic.All_Traffic where All_Traffic.process_name IN ("python.exe","python3.exe","pythonw.exe","pip.exe") AND (All_Traffic.dest_url LIKE "%github.com/oven-sh/bun/releases%" OR All_Traffic.dest_url LIKE "%objects.githubusercontent.com%bun-windows%" OR All_Traffic.dest_url LIKE "%bun-v1.3.13%") by host All_Traffic.process_name All_Traffic.dest All_Traffic.dest_url | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let bun_url_markers = dynamic(["oven-sh/bun/releases","bun-v1.3.13","bun-windows-x64","bun-linux-x64","bun-darwin"]);
union
  ( DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where InitiatingProcessFileName has_any ("python.exe","python3.exe","pythonw.exe","pip.exe","pip3.exe")
    | where RemoteUrl has_any (bun_url_markers)
          or (RemoteUrl has "github.com" and RemoteUrl has "oven-sh")
    | project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              RemoteUrl, RemoteIP, RemotePort ),
  ( DeviceFileEvents
    | where Timestamp > ago(30d)
    | where InitiatingProcessFileName has_any ("python.exe","python3.exe","pythonw.exe","pip.exe")
    | where (FileName =~ "bun.exe" or FileName =~ "bun")
         or FileOriginUrl has_any (bun_url_markers)
    | project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              FileName, FolderPath, FileOriginUrl, SHA256 )
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

### Article-specific behavioural hunt — Backdoored PyTorch Lightning package drops credential stealer

`UC_44_2` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Backdoored PyTorch Lightning package drops credential stealer ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("router_runtime.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("router_runtime.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Backdoored PyTorch Lightning package drops credential stealer
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("router_runtime.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("router_runtime.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 6 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

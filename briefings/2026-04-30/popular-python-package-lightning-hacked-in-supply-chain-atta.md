# [CRIT] Popular Python Package lightning Hacked in Supply Chain Attack

**Source:** Cyber Security News
**Published:** 2026-04-30
**Article:** https://cybersecuritynews.com/python-package-lightning-hacked/

## Threat Profile

Home Cyber Attack News 
Popular Python Package lightning Hacked in Supply Chain Attack 
By Guru Baran 
April 30, 2026 
The widely used PyTorch Lightning framework, which automatically executes credential-stealing malware on import, has also compromised GitHub maintainer accounts.
The popular PyPI package lightning — the deep learning framework used to train, deploy, and ship AI products has been compromised in an active supply chain attack .
Socket’s Research Team flagged versions 2.6.2 and 2.6.…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1105** — Ingress Tool Transfer
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1027.013** — Obfuscated Files or Information: Encrypted/Encoded File
- **T1567** — Exfiltration Over Web Service
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1552.005** — Unsecured Credentials: Cloud Instance Metadata API
- **T1078.004** — Valid Accounts: Cloud Accounts

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Installation of compromised PyTorch Lightning PyPI versions 2.6.2 / 2.6.3

`UC_15_4` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process_name) as parent values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.process_name IN ("pip.exe","pip3.exe","pip","pip3","poetry","poetry.exe","uv","uv.exe","python.exe","python","python3")) AND (Processes.process="*lightning==2.6.2*" OR Processes.process="*lightning==2.6.3*" OR Processes.process="*lightning-2.6.2*" OR Processes.process="*lightning-2.6.3*" OR Processes.process="*pytorch-lightning==2.6.2*" OR Processes.process="*pytorch-lightning==2.6.3*") by Processes.dest Processes.process Processes.parent_process_name Processes.user | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("pip.exe","pip3.exe","pip","pip3","poetry.exe","poetry","uv.exe","uv","python.exe","python","python3")
| where ProcessCommandLine has_any ("lightning==2.6.2","lightning==2.6.3","lightning-2.6.2","lightning-2.6.3","pytorch-lightning==2.6.2","pytorch-lightning==2.6.3")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine, FolderPath
| order by Timestamp desc
```

### [LLM] Python-spawned download of Bun runtime from GitHub releases (lightning _runtime stage-1)

`UC_15_5` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.process_name) as process_name from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("python.exe","python","python3","python3.exe","pythonw.exe")) AND ((Processes.process="*github.com/oven-sh/bun*" OR Processes.process="*bun-windows-x64*" OR Processes.process="*bun-linux-x64*" OR Processes.process="*bun-darwin*") OR (Processes.process_name IN ("bun.exe","bun") AND Processes.process="*router_runtime.js*") OR Processes.process="*_runtime*start.py*" OR Processes.process="*lightning*_runtime*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let suspProc = DeviceProcessEvents
| where Timestamp > ago(14d)
| where (InitiatingProcessFileName in~ ("python.exe","python","python3","python3.exe","pythonw.exe")
         and (ProcessCommandLine has_any ("github.com/oven-sh/bun","bun-windows-x64","bun-linux-x64","bun-darwin")
              or ProcessCommandLine has_all ("_runtime","start.py")))
     or (FileName in~ ("bun.exe","bun") and ProcessCommandLine has "router_runtime.js")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath;
let suspFile = DeviceFileEvents
| where Timestamp > ago(14d)
| where FolderPath has "lightning" and FolderPath has "_runtime"
| where FileName in~ ("start.py","router_runtime.js")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine;
union suspProc, suspFile
| order by Timestamp desc
```

### [LLM] Outbound GitHub API exfil from dev/CI hosts shortly after lightning import (Shai-Hulud / Team PCP)

`UC_15_6` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count values(All_Traffic.dest) as dest values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as app values(All_Traffic.bytes_out) as bytes_out from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest IN ("api.github.com","uploads.github.com","raw.githubusercontent.com") AND All_Traffic.app IN ("python.exe","python","python3","python3.exe","bun.exe","bun","node.exe","node") by All_Traffic.src All_Traffic.user _time span=1h | where bytes_out > 50000 | join type=inner All_Traffic.src [| tstats summariesonly=true count from datamodel=Endpoint.Processes where (Processes.process="*lightning*" OR Processes.process="*router_runtime.js*" OR Processes.process="*_runtime*start.py*") by Processes.dest | rename Processes.dest as src | fields src] | `drop_dm_object_name(All_Traffic)`
```

**Defender KQL:**
```kql
let lightningHosts = DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any ("lightning","router_runtime.js","_runtime\\start.py","_runtime/start.py")
| where InitiatingProcessFileName in~ ("python.exe","python","python3","python3.exe","bun.exe","bun")
| distinct DeviceId, DeviceName;
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where DeviceId in (lightningHosts | project DeviceId)
| where RemoteUrl has_any ("api.github.com","uploads.github.com","raw.githubusercontent.com")
| where InitiatingProcessFileName in~ ("python.exe","python","python3","python3.exe","bun.exe","bun","node.exe","node")
| summarize bytes=sum(toint(coalesce(tostring(todynamic(AdditionalFields).bytes_sent),"0"))), connections=count(), urls=make_set(RemoteUrl,20) by DeviceName, InitiatingProcessFileName, AccountName, bin(Timestamp,1h)
| where connections > 5
| order by Timestamp desc
```

### OAuth consent / suspicious app grant

`UC_OAUTH_ABUSE` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Authentication.Authentication
    where Authentication.action="success"
      AND Authentication.signature IN (
        "Consent to application",
        "Add app role assignment grant to user",
        "Add OAuth2PermissionGrant",
        "Add delegated permission grant")
    by Authentication.user, Authentication.app, Authentication.src, Authentication.signature
| `drop_dm_object_name(Authentication)`
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("Consent to application.","Add OAuth2PermissionGrant.","Add delegated permission grant.")
| project Timestamp, AccountObjectId, AccountDisplayName, ActivityType,
          ActivityObjects, IPAddress, UserAgent
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
| where InitiatingProcessFileName in~ ("setup.exe","installer.exe","update.exe")
| where FileName in~ ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### Article-specific behavioural hunt — Popular Python Package lightning Hacked in Supply Chain Attack

`UC_15_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Popular Python Package lightning Hacked in Supply Chain Attack ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("start.py","router_runtime.js","node.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("start.py","router_runtime.js","node.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Popular Python Package lightning Hacked in Supply Chain Attack
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("start.py", "router_runtime.js", "node.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("start.py", "router_runtime.js", "node.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **CRIT** based on: 7 use case(s) fired, 14 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

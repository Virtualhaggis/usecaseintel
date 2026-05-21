# [CRIT] Void Botnet Uses Ethereum Smart Contracts for Seizure-Resistant C2 Infrastructure

**Source:** Cyber Security News
**Published:** 2026-05-20
**Article:** https://cybersecuritynews.com/void-botnet-uses-ethereum-smart-contracts/

## Threat Profile

Home Cyber Security News 
Void Botnet Uses Ethereum Smart Contracts for Seizure-Resistant C2 Infrastructure 
By Tushar Subhra Dutta 
May 20, 2026 
A new botnet called Void has emerged on the cybercrime underground, bringing a troubling twist to how attackers manage their operations remotely.
Instead of relying on traditional servers that authorities can seize or shut down, Void Botnet routes its commands through Ethereum smart contracts, placing its infrastructure entirely beyond the reach of co…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1053.005** — Scheduled Task
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1195.002** — Compromise Software Supply Chain
- **T1102.002** — Web Service: Bidirectional Communication
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1568** — Dynamic Resolution
- **T1053.005** — Scheduled Task/Job: Scheduled Task
- **T1547** — Boot or Logon Autostart Execution
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1218.007** — System Binary Proxy Execution: Msiexec
- **T1620** — Reflective Code Loading

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Non-browser process polling public Ethereum/Polygon JSON-RPC endpoints at 3-5 min cadence (Void/Aeternum C2)

`UC_9_7` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count as ConnectCount min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dest from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest IN ("*.infura.io","*.alchemyapi.io","*.alchemy.com","*.cloudflare-eth.com","*.ankr.com","*.quicknode.pro","*.publicnode.com","*.llamarpc.com","*.blockpi.network","*.nodereal.io","*.blastapi.io","*.polygon-rpc.com","*.maticvigil.com")) AND NOT (All_Traffic.app IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","node.exe","Code.exe","devenv.exe","geth.exe","besu.exe","python.exe","go.exe","hardhat.exe","truffle.exe")) by host All_Traffic.src All_Traffic.app All_Traffic.process_id | `drop_dm_object_name(All_Traffic)` | eval WindowMin = (lastTime - firstTime)/60 | where ConnectCount >= 4 AND WindowMin >= 10 AND WindowMin <= 240 | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let RpcProviders = dynamic(["infura.io","alchemyapi.io","alchemy.com","cloudflare-eth.com","ankr.com","quicknode.pro","publicnode.com","llamarpc.com","blockpi.network","nodereal.io","blastapi.io","polygon-rpc.com","maticvigil.com"]);
let BrowserAndDev = dynamic(["chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","node.exe","code.exe","devenv.exe","geth.exe","besu.exe","python.exe","go.exe","hardhat.exe","truffle.exe","slack.exe","discord.exe","electron.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteUrl has_any (RpcProviders)
| where InitiatingProcessFileName !in~ (BrowserAndDev)
| where InitiatingProcessAccountName !endswith "$"
| where isnotempty(InitiatingProcessFileName)
| summarize ConnectCount = count(),
            FirstSeen   = min(Timestamp),
            LastSeen    = max(Timestamp),
            DistinctRpcs = dcount(RemoteUrl),
            SampleRpcs  = make_set(RemoteUrl, 10),
            SampleCmd   = any(InitiatingProcessCommandLine),
            BinSize     = any(InitiatingProcessFileSize)
            by DeviceName, InitiatingProcessFileName, InitiatingProcessSHA256, InitiatingProcessFolderPath
| extend WindowMin = datetime_diff('minute', LastSeen, FirstSeen)
| where ConnectCount >= 4 and WindowMin between (10 .. 240)   // 3-5 min Void poll cadence sustained ≥10 min
| order by ConnectCount desc
```

### [LLM] Scheduled task created by ~1.5MB unsigned binary that subsequently polls Ethereum RPC (Void Botnet v1.1 persistence)

`UC_9_8` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as SchedTime values(Processes.process) as SchedCmd values(Processes.parent_process_name) as SchedParent from datamodel=Endpoint.Processes where Processes.process_name="schtasks.exe" Processes.process="*/create*" Processes.process="*.exe*" by host Processes.dest Processes.user Processes.parent_process_name | `drop_dm_object_name(Processes)` | rex field=SchedCmd "(?i)(?<TaskBinary>[A-Za-z0-9_\-\.]+\.exe)" | join type=inner host TaskBinary [| tstats summariesonly=true count as RpcConnects values(All_Traffic.dest) as RpcDests min(All_Traffic.bytes) as MinBin from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest IN ("*.infura.io","*.alchemyapi.io","*.alchemy.com","*.cloudflare-eth.com","*.ankr.com","*.quicknode.pro","*.publicnode.com","*.llamarpc.com","*.blockpi.network","*.polygon-rpc.com") by host All_Traffic.app | `drop_dm_object_name(All_Traffic)` | rename app as TaskBinary | where RpcConnects >= 3] | table SchedTime host SchedParent SchedCmd TaskBinary RpcConnects RpcDests
```

**Defender KQL:**
```kql
let RpcProviders = dynamic(["infura.io","alchemyapi.io","alchemy.com","cloudflare-eth.com","ankr.com","quicknode.pro","publicnode.com","llamarpc.com","blockpi.network","nodereal.io","blastapi.io","polygon-rpc.com","maticvigil.com"]);
let SchedCreate = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName =~ "schtasks.exe"
    | where ProcessCommandLine has "/create" and ProcessCommandLine has ".exe"
    | extend TaskBinary = tolower(tostring(extract(@'(?i)/tr\s+"?[^"]*?([A-Za-z0-9_\-\.\(\)\s]+\.exe)', 1, ProcessCommandLine)))
    | where isnotempty(TaskBinary)
    | project SchedTime = Timestamp, DeviceId, DeviceName, AccountName,
              SchedCmd  = ProcessCommandLine,
              SchedParent = InitiatingProcessFileName,
              SchedParentPath = InitiatingProcessFolderPath,
              SchedParentSHA = InitiatingProcessSHA256,
              SchedParentSize = InitiatingProcessFileSize,
              TaskBinary;
let RpcCallers = DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where RemoteUrl has_any (RpcProviders)
    | where InitiatingProcessFileSize between (900000 .. 2500000)   // Void Rust loader ≈1.5 MB
    | summarize RpcConnects = count(),
                FirstRpc   = min(Timestamp),
                RpcSample  = make_set(RemoteUrl, 5)
        by DeviceId, LoaderFile = tolower(InitiatingProcessFileName),
           LoaderPath = InitiatingProcessFolderPath,
           LoaderSHA  = InitiatingProcessSHA256,
           LoaderSize = InitiatingProcessFileSize
    | where RpcConnects >= 3;
SchedCreate
| join kind=inner RpcCallers on $left.DeviceId == $right.DeviceId, $left.TaskBinary == $right.LoaderFile
| where FirstRpc between (SchedTime - 1h .. SchedTime + 24h)
| where LoaderPath !startswith "C:\\Program Files" and LoaderPath !startswith "C:\\Windows\\System32"
| project SchedTime, DeviceName, AccountName, SchedParent, SchedCmd,
          LoaderFile, LoaderPath, LoaderSize, LoaderSHA,
          RpcConnects, FirstRpc, RpcSample
| order by SchedTime desc
```

### [LLM] Loader process polling Ethereum RPC also spawning PowerShell/MSI/cmd children (Void task-execution)

`UC_9_9` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count as RpcConnects values(All_Traffic.dest) as RpcDests from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest IN ("*.infura.io","*.alchemyapi.io","*.alchemy.com","*.cloudflare-eth.com","*.ankr.com","*.quicknode.pro","*.publicnode.com","*.llamarpc.com","*.blockpi.network","*.polygon-rpc.com") by host All_Traffic.app All_Traffic.process_id | `drop_dm_object_name(All_Traffic)` | rename app as LoaderFile process_id as LoaderPid | where RpcConnects >= 3 AND LoaderFile!="chrome.exe" AND LoaderFile!="msedge.exe" AND LoaderFile!="firefox.exe" AND LoaderFile!="node.exe" AND LoaderFile!="Code.exe" | join type=inner host LoaderPid [| tstats summariesonly=true count as ChildCount values(Processes.process_name) as ChildBinary values(Processes.process) as ChildCmd from datamodel=Endpoint.Processes where Processes.process_name IN ("powershell.exe","pwsh.exe","cmd.exe","msiexec.exe","rundll32.exe","regsvr32.exe") by host Processes.parent_process_id Processes.parent_process_name | `drop_dm_object_name(Processes)` | rename parent_process_id as LoaderPid parent_process_name as LoaderFile] | table host LoaderFile LoaderPid RpcConnects RpcDests ChildCount ChildBinary ChildCmd
```

**Defender KQL:**
```kql
let RpcProviders = dynamic(["infura.io","alchemyapi.io","alchemy.com","cloudflare-eth.com","ankr.com","quicknode.pro","publicnode.com","llamarpc.com","blockpi.network","nodereal.io","blastapi.io","polygon-rpc.com","maticvigil.com"]);
let Browsers = dynamic(["chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","node.exe","code.exe","devenv.exe","geth.exe","besu.exe","python.exe","slack.exe","discord.exe"]);
let RpcLoaders = DeviceNetworkEvents
    | where Timestamp > ago(1d)
    | where RemoteUrl has_any (RpcProviders)
    | where InitiatingProcessFileName !in~ (Browsers)
    | summarize RpcConnects = count(),
                RpcDests   = make_set(RemoteUrl, 5),
                LoaderSize = any(InitiatingProcessFileSize)
        by DeviceId, DeviceName,
           LoaderPid  = InitiatingProcessId,
           LoaderName = InitiatingProcessFileName,
           LoaderSHA  = InitiatingProcessSHA256,
           LoaderPath = InitiatingProcessFolderPath
    | where RpcConnects >= 3;
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","msiexec.exe","rundll32.exe","regsvr32.exe")
| join kind=inner RpcLoaders on $left.DeviceId == $right.DeviceId, $left.InitiatingProcessId == $right.LoaderPid
| project Timestamp, DeviceName, AccountName,
          ChildBinary = FileName,
          ChildCmd    = ProcessCommandLine,
          LoaderName, LoaderPath, LoaderSize, LoaderSHA,
          RpcConnects, RpcDests
| order by Timestamp desc
```

### Beaconing — periodic outbound to small set of destinations

`UC_BEACONING` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, values(All_Traffic.dest_port) AS ports
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.action="allowed" AND All_Traffic.dest_category!="internal"
    by _time span=10s, All_Traffic.src, All_Traffic.dest
| `drop_dm_object_name(All_Traffic)`
| streamstats current=f last(_time) AS prev_time by src, dest
| eval delta = _time - prev_time
| stats avg(delta) AS avg_delta stdev(delta) AS sd_delta count by src, dest
| where count > 30 AND sd_delta < 5 AND avg_delta>=30 AND avg_delta<=600
| sort - count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteIPType == "Public" and ActionType == "ConnectionSuccess"
| project DeviceName, RemoteIP, RemotePort, Timestamp
| sort by DeviceName asc, RemoteIP asc, RemotePort asc, Timestamp asc
| extend prev_dev = prev(DeviceName, 1), prev_ip = prev(RemoteIP, 1),
         prev_port = prev(RemotePort, 1), prev_ts = prev(Timestamp, 1)
| where DeviceName == prev_dev and RemoteIP == prev_ip and RemotePort == prev_port
| extend delta_sec = datetime_diff('second', Timestamp, prev_ts)
| summarize conn_count = count(), avg_delta = avg(delta_sec), stdev_delta = stdev(delta_sec)
    by DeviceName, RemoteIP, RemotePort
| where conn_count > 30 and avg_delta between (30.0 .. 600.0) and stdev_delta < 5.0
| order by conn_count desc
```

### Scheduled task created with suspicious image / encoded args

`UC_SCHEDULED_TASK` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name="schtasks.exe" AND Processes.process="*/create*"
      AND (Processes.process="*powershell*" OR Processes.process="*cmd.exe*"
        OR Processes.process="*rundll32*" OR Processes.process="*-enc*"
        OR Processes.process="*FromBase64*" OR Processes.process="*\Users\Public*"
        OR Processes.process="*\AppData\*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has_any ("powershell","cmd.exe","rundll32","-enc","FromBase64","\Users\Public","\AppData\")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
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

### Ransomware-style mass file rename / extension change

`UC_RANSOM_ENCRYPT` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, dc(Filesystem.file_name) AS files
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("modified","renamed")
    by Filesystem.dest, Filesystem.user, _time span=1m
| `drop_dm_object_name(Filesystem)`
| where files > 200
| sort - files
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where InitiatingProcessAccountName !endswith "$"
| where ActionType in ("FileRenamed","FileModified")
| summarize files = dcount(FileName) by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 1m)
| where files > 200    // empirical: > 200 unique-file renames in 1m by one account on one host
                       //            is well above the P99 of legitimate bulk-tooling
| order by files desc
```

### LSASS process access / dump (credential theft)

`UC_LSASS` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process="*lsass*" OR Processes.process="*sekurlsa*"
        OR Processes.process="*MiniDump*" OR Processes.process="*comsvcs.dll*MiniDump*"
        OR Processes.process="*procdump*lsass*")
       OR (Processes.process_name="rundll32.exe" AND Processes.process="*comsvcs*MiniDump*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsSense.exe","MsMpEng.exe","csrss.exe",
                                          "svchost.exe","wininit.exe","services.exe",
                                          "lsm.exe","SearchProtocolHost.exe")
| project Timestamp, DeviceName, ActionType, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, AccountName
| order by Timestamp desc
```

### Remote service execution — PsExec / SMB lateral movement

`UC_LATERAL_PSEXEC` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
       OR (Processes.process_name="wmic.exe" AND Processes.process="*/node:*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
   or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
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


## Why this matters

Severity classified as **CRIT** based on: 10 use case(s) fired, 20 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

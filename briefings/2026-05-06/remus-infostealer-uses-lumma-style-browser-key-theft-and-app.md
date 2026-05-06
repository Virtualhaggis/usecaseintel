# [HIGH] Remus Infostealer Uses Lumma-Style Browser Key Theft and Application-Bound Encryption Bypass

**Source:** Cyber Security News
**Published:** 2026-05-06
**Article:** https://cybersecuritynews.com/remus-infostealer-uses-lumma-style-browser-key-theft/

## Threat Profile

Home Cyber Security News 
Remus Infostealer Uses Lumma-Style Browser Key Theft and Application-Bound Encryption Bypass 
By Tushar Subhra Dutta 
May 6, 2026 
A dangerous new piece of malware called Remus has surfaced, quietly picking up where one of the most feared information stealers left off. 
Designed to steal browser passwords, cookies, and cryptocurrency wallets, Remus carries the DNA of Lumma Stealer, one of the most technically advanced stealers-as-a-service seen in recent history. 
Remus…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1219** — Remote Access Software
- **T1195.002** — Compromise Software Supply Chain
- **T1102.001** — Web Service: Dead Drop Resolver
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1055.002** — Process Injection: Portable Executable Injection
- **T1055** — Process Injection
- **T1564.003** — Hide Artifacts: Hidden Window
- **T1106** — Native API

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Remus EtherHiding C2 resolution — outbound to Ethereum public RPC from user-AppData binary

`UC_9_7` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dest values(All_Traffic.dest_port) as dest_port values(Processes.process) as process values(Processes.process_path) as process_path from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest IN ("*.cloudflare-eth.com","cloudflare-eth.com","eth.llamarpc.com","*.llamarpc.com","rpc.ankr.com","*.ankr.com","ethereum.publicnode.com","*.publicnode.com","eth-mainnet.public.blastapi.io","*.blastapi.io","mainnet.infura.io","*.infura.io","*.g.alchemy.com","*.alchemyapi.io")) by All_Traffic.src All_Traffic.dest All_Traffic.app All_Traffic.user host | `drop_dm_object_name(All_Traffic)` | join type=inner host [| tstats summariesonly=t count from datamodel=Endpoint.Processes where (Processes.process_path IN ("*\\AppData\\Local\\Temp\\*","*\\AppData\\Roaming\\*","*\\Users\\Public\\*","*\\ProgramData\\*") AND Processes.process_name!="chrome.exe" AND Processes.process_name!="msedge.exe" AND Processes.process_name!="firefox.exe" AND Processes.process_name!="brave.exe") by Processes.process_name Processes.process Processes.process_path host | `drop_dm_object_name(Processes)`] | where firstTime>=relative_time(now(),"-7d@d") | table firstTime lastTime host src user process_name process_path dest dest_port count
```

**Defender KQL:**
```kql
// Remus EtherHiding C2 resolution — non-browser user-mode process connecting to Ethereum public RPC endpoints
let RpcDomains = dynamic([
    "cloudflare-eth.com","eth.llamarpc.com","rpc.ankr.com",
    "ethereum.publicnode.com","eth-mainnet.public.blastapi.io",
    "mainnet.infura.io","infura.io","g.alchemy.com","alchemyapi.io"]);
let KnownWalletBins = dynamic([
    "metamask.exe","exodus.exe","electrum.exe","ledger live.exe",
    "trezor suite.exe","atomic wallet.exe","frame.exe","rabby wallet.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIPType == "Public"
| where isnotempty(RemoteUrl)
| where RemoteUrl has_any (RpcDomains)
// Exclude legitimate browsers and known wallet apps — Remus runs from temp/appdata
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","iexplore.exe")
| where InitiatingProcessFileName !in~ (KnownWalletBins)
| where InitiatingProcessAccountName !endswith "$"
| where InitiatingProcessFolderPath has_any (@"\AppData\Local\Temp\", @"\AppData\Roaming\", @"\Users\Public\", @"\ProgramData\", @"\Downloads\")
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessSHA256, InitiatingProcessCommandLine,
          RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### [LLM] Remus ABE bypass — cross-process injection into Chromium browser by non-browser binary

`UC_9_8` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`sysmon` EventCode=8 TargetImage IN ("*\\chrome.exe","*\\msedge.exe","*\\brave.exe","*\\opera.exe") SourceImage!="*\\chrome.exe" SourceImage!="*\\msedge.exe" SourceImage!="*\\brave.exe" SourceImage!="*\\opera.exe" SourceImage!="*\\Program Files*" SourceImage!="*\\Windows\\System32*" SourceImage!="*\\Windows\\SysWOW64*" (SourceImage="*\\AppData\\Local\\Temp\\*" OR SourceImage="*\\AppData\\Roaming\\*" OR SourceImage="*\\ProgramData\\*" OR SourceImage="*\\Users\\Public\\*" OR SourceImage="*\\Downloads\\*") | stats min(_time) as firstTime max(_time) as lastTime values(SourceImage) as injector values(StartFunction) as start_func count by host User TargetImage SourceProcessGUID
```

**Defender KQL:**
```kql
// Remus / Lumma ABE bypass — cross-process injection into Chromium browser
let BrowserBins = dynamic(["chrome.exe","msedge.exe","brave.exe","opera.exe","vivaldi.exe"]);
let StagingPaths = dynamic([@"\AppData\Local\Temp\",@"\AppData\Roaming\",@"\ProgramData\",@"\Users\Public\",@"\Downloads\"]);
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType in ("CreateRemoteThreadApiCall","CreateRemoteProcessApiCall","ReadProcessMemoryApiCall")
| where FileName in~ (BrowserBins)                          // target = browser
| where InitiatingProcessFileName !in~ (BrowserBins)        // injector != browser
| where InitiatingProcessFolderPath !startswith @"C:\Program Files"
   and InitiatingProcessFolderPath !startswith @"C:\Program Files (x86)"
   and InitiatingProcessFolderPath !startswith @"C:\Windows\System32"
   and InitiatingProcessFolderPath !startswith @"C:\Windows\SysWOW64"
| where InitiatingProcessFolderPath has_any (StagingPaths)
   or isempty(InitiatingProcessVersionInfoCompanyName)
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, ActionType, InitiatingProcessAccountName,
          InjectorImage = InitiatingProcessFolderPath,
          InjectorCmd = InitiatingProcessCommandLine,
          InjectorSHA256 = InitiatingProcessSHA256,
          InjectorCompany = InitiatingProcessVersionInfoCompanyName,
          TargetBrowser = FileName, TargetProcessId = ProcessId,
          AdditionalFields
| order by Timestamp desc
```

### [LLM] Remus hidden-desktop browser fallback — Chromium spawned by non-browser binary in user staging path

`UC_9_9` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.parent_process) as parent_cmd values(Processes.parent_process_path) as parent_path from datamodel=Endpoint.Processes where Processes.process_name IN ("chrome.exe","msedge.exe","brave.exe","opera.exe") (Processes.parent_process_path="*\\AppData\\Local\\Temp\\*" OR Processes.parent_process_path="*\\AppData\\Roaming\\*" OR Processes.parent_process_path="*\\ProgramData\\*" OR Processes.parent_process_path="*\\Users\\Public\\*" OR Processes.parent_process_path="*\\Downloads\\*") Processes.parent_process_name!="explorer.exe" Processes.parent_process_name!="chrome.exe" Processes.parent_process_name!="msedge.exe" Processes.parent_process_name!="brave.exe" Processes.parent_process_name!="opera.exe" Processes.parent_process_name!="runtimebroker.exe" Processes.parent_process_name!="svchost.exe" Processes.parent_process_name!="userinit.exe" Processes.parent_process_name!="taskhostw.exe" Processes.user!="*$" by host Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | where firstTime>=relative_time(now(),"-7d@d")
```

**Defender KQL:**
```kql
// Remus hidden-desktop browser fallback — Chromium spawned by user-staging-path parent
let BrowserBins = dynamic(["chrome.exe","msedge.exe","brave.exe","opera.exe","vivaldi.exe"]);
let LegitParents = dynamic([
    "explorer.exe","runtimebroker.exe","svchost.exe","userinit.exe",
    "taskhostw.exe","sihost.exe","searchapp.exe","startmenuexperiencehost.exe",
    "applicationframehost.exe","chrome.exe","msedge.exe","brave.exe",
    "opera.exe","vivaldi.exe","outlook.exe","teams.exe","slack.exe",
    "setup.exe","msiexec.exe","googleupdate.exe","msedgeupdate.exe"]);
let StagingPaths = dynamic([@"\AppData\Local\Temp\",@"\AppData\Roaming\",@"\ProgramData\",@"\Users\Public\",@"\Downloads\"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ (BrowserBins)
| where InitiatingProcessFileName !in~ (LegitParents)
| where InitiatingProcessFolderPath has_any (StagingPaths)
| where InitiatingProcessAccountName !endswith "$"
// Remus typical fallback uses these flags when launching the hidden browser
| extend HiddenLaunchHints = ProcessCommandLine has_any (
    "--user-data-dir=","--no-startup-window","--headless","--disable-gpu",
    "--remote-debugging-port","--profile-directory=")
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentSHA256 = InitiatingProcessSHA256,
          ParentCmd = InitiatingProcessCommandLine,
          ParentCompany = InitiatingProcessVersionInfoCompanyName,
          ChildBrowser = FileName, ChildCmd = ProcessCommandLine,
          HiddenLaunchHints
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

### Infostealer — non-browser process accessing browser cookie/login DBs

`UC_BROWSER_STEALER` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\Google\Chrome\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Google\Chrome\User Data\*\Cookies*"
        OR Filesystem.file_path="*\Microsoft\Edge\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\logins.json*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\cookies.sqlite*")
      AND NOT Filesystem.process_name IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where FolderPath has_any (@"\Google\Chrome\User Data\", @"\Microsoft\Edge\User Data\", @"\Mozilla\Firefox\Profiles\")
| where FileName in~ ("Login Data","Cookies","logins.json","cookies.sqlite")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
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

### RMM tool installed by non-IT user — remote-access utility for hands-on-keyboard

`UC_RMM_TOOLS` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe","kaseya*.exe")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe")
   or FileName matches regex @"(?i)kaseya.*\.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
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

Severity classified as **HIGH** based on: 10 use case(s) fired, 17 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

# [CRIT] EtherRAT Distribution Spoofing Administrative Tools via GitHub Facades

**Source:** The Hacker News
**Published:** 2026-04-30
**Article:** https://thehackernews.com/2026/04/etherrat-distribution-spoofing.html

## Threat Profile

EtherRAT Distribution Spoofing Administrative Tools via GitHub Facades 
 The Hacker News  Apr 30, 2026 Threat Intelligence / Enterprise Security 
Intro 
A sophisticated, high-resilience malicious campaign was identified by Atos Threat Research Center (TRC) in March 2026. This operation specifically targets the high-privilege professional accounts of enterprise administrators, DevOps engineers, and security analysts by impersonating administrative utilities they rely on for daily operations. By…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-33626`
- **CVE:** `CVE-2026-32202`
- **CVE:** `CVE-2026-3854`
- **IPv4 (defanged):** `135.125.255.55`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1219** — Remote Access Software
- **T1195.002** — Compromise Software Supply Chain
- **T1547.001** — Persistence (article-specific)
- **T1218.007** — System Binary Proxy Execution: Msiexec
- **T1105** — Ingress Tool Transfer
- **T1027.010** — Obfuscated Files or Information: Command Obfuscation
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1027.013** — Obfuscated Files or Information: Encrypted/Encoded File
- **T1140** — Deobfuscate/Decode Files or Information
- **T1620** — Reflective Code Loading
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1102.001** — Web Service: Dead Drop Resolver
- **T1568** — Dynamic Resolution

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] EtherRAT MSI dropper: msiexec-spawned cmd downloads Node.js runtime via curl to %LOCALAPPDATA%

`UC_65_10` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent values(Processes.parent_process) as parent_cmd values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.process_name=curl.exe (Processes.parent_process_name=cmd.exe OR Processes.parent_process_name=msiexec.exe) Processes.process="*nodejs.org/dist/*" (Processes.process="*AppData\\Local\\*" OR Processes.process="*%LOCALAPPDATA%*" OR Processes.process="*-o *") by host Processes.process_name Processes.parent_process_name Processes.process_id | `drop_dm_object_name(Processes)` | where like(parent_cmd,"%msiexec%") OR like(parent_cmd,"%Installer%") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// EtherRAT Stage-0 — curl pulling Node.js runtime under MSI ancestry
let _suspicious_curl =
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName =~ "curl.exe"
    | where ProcessCommandLine has "nodejs.org"                      // article: download from official distribution endpoint
    | where ProcessCommandLine has_any (@"\AppData\Local\", "%LOCALAPPDATA%")  // article: build-specific staging dir under LocalAppData
    | where InitiatingProcessFileName =~ "cmd.exe"                   // article: heavily-obfuscated .cmd is the entry point
    | project Timestamp, DeviceId, DeviceName, AccountName,
              CurlCmd = ProcessCommandLine,
              CmdParentCmd = InitiatingProcessCommandLine,
              CmdParentId = InitiatingProcessId,
              CmdGrandparent = InitiatingProcessParentFileName;
_suspicious_curl
| where CmdGrandparent =~ "msiexec.exe"                              // article: cmd launched by MSI CustomAction
| project Timestamp, DeviceName, AccountName, CmdGrandparent,
          CmdParentCmd, CurlCmd
```

### [LLM] EtherRAT Node.js loader executing AES-encrypted payload with non-script extension from %LOCALAPPDATA%

`UC_65_11` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process) as parent_cmd values(Processes.process_path) as image values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.process_name=node.exe Processes.parent_process_name=cmd.exe (Processes.process_path="*\\AppData\\Local\\*" OR Processes.process="*\\AppData\\Local\\*") (Processes.process="*.bak*" OR Processes.process="*.cfg*" OR Processes.process="*.xml*" OR Processes.process="*.tmp*" OR Processes.process="*.bin*" OR Processes.process="*.dat*" OR Processes.process="*.log*") by host Processes.process_name Processes.parent_process_name Processes.process_id | `drop_dm_object_name(Processes)` | rex field=cmdline "(?<payload_ext>\.(bak|cfg|xml|tmp|bin|dat|log))(?:\"|\s|$)" | where isnotnull(payload_ext) | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// EtherRAT Stage-1 — node.exe in LocalAppData fed a non-.js encrypted payload
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "node.exe"
| where InitiatingProcessFileName =~ "cmd.exe"                       // article: stage 0 .cmd hands off to node.exe
| where FolderPath has @"\AppData\Local\"                            // article: build-specific runtime subdir under LocalAppData
| where ProcessCommandLine matches regex @"(?i)\.(bak|cfg|xml|tmp|bin|dat|log)(\"|\s|$)"  // article tables 1-4: per-sample randomised extensions for stage-1
| project Timestamp, DeviceName, AccountName,
          NodeImage = FolderPath,
          NodeCmd  = ProcessCommandLine,
          DropperCmd = InitiatingProcessCommandLine,
          DropperParent = InitiatingProcessParentFileName
| order by Timestamp desc
```

### [LLM] EtherRAT EtherHiding C2 — node.exe contacting public Ethereum JSON-RPC endpoints (eth_call DDR)

`UC_65_12` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dest values(All_Traffic.dest_port) as dport values(All_Traffic.app) as app from datamodel=Network_Traffic.All_Traffic where (All_Traffic.app=node.exe OR All_Traffic.process_name=node.exe) (All_Traffic.dest="mainnet.infura.io" OR All_Traffic.dest="*.infura.io" OR All_Traffic.dest="rpc.ankr.com" OR All_Traffic.dest="*.ankr.com" OR All_Traffic.dest="cloudflare-eth.com" OR All_Traffic.dest="ethereum-rpc.publicnode.com" OR All_Traffic.dest="eth.llamarpc.com" OR All_Traffic.dest="eth.public-rpc.com" OR All_Traffic.dest="rpc.flashbots.net" OR All_Traffic.dest="ethereum.publicnode.com") by host All_Traffic.src All_Traffic.user All_Traffic.dest All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// EtherRAT EtherHiding — public Ethereum JSON-RPC contact from node.exe (the deployed RAT)
let _eth_rpc_fqdns = dynamic([
    "mainnet.infura.io", "sepolia.infura.io", "goerli.infura.io",
    "rpc.ankr.com", "eth.public-rpc.com",
    "cloudflare-eth.com",
    "ethereum-rpc.publicnode.com", "ethereum.publicnode.com",
    "eth.llamarpc.com", "rpc.flashbots.net",
    "eth-mainnet.g.alchemy.com"
]);
let _net = DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessFileName =~ "node.exe"                  // EtherRAT runtime is Node.js (article)
    | where RemoteIPType == "Public"
    | where RemoteUrl in~ (_eth_rpc_fqdns)
       or _eth_rpc_fqdns has_any (RemoteUrl)
    | project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort,
              NodePath = InitiatingProcessFolderPath,
              NodeCmd  = InitiatingProcessCommandLine;
let _dns = DeviceEvents
    | where Timestamp > ago(7d)
    | where ActionType == "DnsQueryResponse"
    | where InitiatingProcessFileName =~ "node.exe"
    | extend Q = tostring(parse_json(AdditionalFields).QueryName)
    | where Q has_any (_eth_rpc_fqdns)
    | project Timestamp, DeviceName, RemoteUrl=Q, RemoteIP="<dns>", RemotePort=53,
              NodePath = InitiatingProcessFolderPath,
              NodeCmd  = InitiatingProcessCommandLine;
union isfuzzy=true _net, _dns
| where NodePath has @"\AppData\Local\"                              // narrow to the EtherRAT staging location
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

### Suspicious browser extension installation

`UC_BROWSER_EXT` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Registry
    where (Registry.registry_path="*\Software\Google\Chrome\Extensions\*"
        OR Registry.registry_path="*\Software\Microsoft\Edge\Extensions\*"
        OR Registry.registry_path="*\Software\Mozilla\Firefox\Extensions\*")
    by Registry.dest, Registry.registry_path, Registry.registry_value_data, Registry.registry_value_name, Registry.user
| `drop_dm_object_name(Registry)`
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where RegistryKey has_any ("\Software\Google\Chrome\Extensions\","\Software\Microsoft\Edge\Extensions\","\Software\Mozilla\Firefox\Extensions\")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessAccountName
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

### Article-specific behavioural hunt — EtherRAT Distribution Spoofing Administrative Tools via GitHub Facades

`UC_65_9` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — EtherRAT Distribution Spoofing Administrative Tools via GitHub Facades ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js","vw80iqxy.cmd","conhost.exe"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("node.js","vw80iqxy.cmd","conhost.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — EtherRAT Distribution Spoofing Administrative Tools via GitHub Facades
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js", "vw80iqxy.cmd", "conhost.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("node.js", "vw80iqxy.cmd", "conhost.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `135.125.255.55`

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-33626`, `CVE-2026-32202`, `CVE-2026-3854`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 13 use case(s) fired, 25 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

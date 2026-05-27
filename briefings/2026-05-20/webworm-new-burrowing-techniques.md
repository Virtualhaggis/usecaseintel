# [CRIT] Webworm: New burrowing techniques

**Source:** ESET WeLiveSecurity
**Published:** 2026-05-20
**Article:** https://www.welivesecurity.com/en/eset-research/webworm-new-burrowing-techniques/

## Threat Profile

Webworm: New burrowing techniques 
ESET Research
Webworm: New burrowing techniques ESET researchers describe new tools and techniques that the Webworm APT group recently added to its arsenal
Eric Howard 
20 May 2026 
 •  
, 
20 min. read 
ESET researchers analyzed the 2025 activity of Webworm, a China-aligned APT group that started out targeting organizations in Asia, but has recently shifted its focus to Europe. Even though this is our first public blogpost on the group, we have been observing …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2017-7692`
- **IPv4 (defanged):** `45.77.13.67`
- **IPv4 (defanged):** `64.176.85.158`
- **IPv4 (defanged):** `104.243.23.43`
- **IPv4 (defanged):** `108.61.200.151`
- **IPv4 (defanged):** `144.168.60.233`
- **Domain (defanged):** `github.com/anjsdgasdf/WordPress`
- **SHA1:** `CB4E50433336707381429707F59C3CBE8D497D98`
- **SHA1:** `1DF40A4A31B30B62EC33DC6FECC2C4408302ADC7`
- **SHA1:** `7DCFE9EE25841DFD58D3D6871BF867FE32141DFB`
- **SHA1:** `77F1970D620216C5FFF4E14A6CCC13FCCC267217`
- **SHA1:** `948159A7FC2E688386864BEA59FD40DFFC4B24D6`
- **SHA1:** `A3C077BDF8898E612CCD65BC82E7960834ADB2A9`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1190** — Exploit Public-Facing Application
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1053.005** — Scheduled Task
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1219** — Remote Access Software
- **T1195.002** — Compromise Software Supply Chain
- **T1053.005** — Persistence (article-specific)
- **T1547.001** — Persistence (article-specific)
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1102.002** — Web Service: Bidirectional Communication
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1567.002** — Exfiltration Over Web Service: Exfiltration to Cloud Storage
- **T1105** — Ingress Tool Transfer
- **T1090.001** — Proxy: Internal Proxy
- **T1572** — Protocol Tunneling

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] EchoCreep Discord API beacon from non-browser process (Webworm 2025)

`UC_116_10` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest IN ("discord.com","discordapp.com","discord.gg","cdn.discordapp.com") OR All_Traffic.url IN ("*discord.com/api/v9/*","*discord.com/api/v10/*","*discordapp.com/api/*")) by All_Traffic.src,All_Traffic.dest,All_Traffic.user,All_Traffic.process_name,All_Traffic.url,_time | `drop_dm_object_name(All_Traffic)` | search NOT (process_name IN ("*\\chrome.exe","*\\msedge.exe","*\\firefox.exe","*\\brave.exe","*\\opera.exe","*\\iexplore.exe","*\\Discord.exe","*\\DiscordPTB.exe","*\\DiscordCanary.exe","*\\Spotify.exe","*\\slack.exe","*\\Teams.exe")) | stats min(_time) as first_seen max(_time) as last_seen sum(count) as conn_count values(url) as urls dc(_time) as connection_buckets by src,user,process_name,dest | where conn_count>=3
```

**Defender KQL:**
```kql
let LookbackDays = 7d;
DeviceNetworkEvents
| where Timestamp > ago(LookbackDays)
| where RemoteUrl has_any ("discord.com","discordapp.com","discord.gg","cdn.discordapp.com")
   or RemoteUrl has_any ("/api/v9/","/api/v10/")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","iexplore.exe","Discord.exe","DiscordPTB.exe","DiscordCanary.exe","Spotify.exe","slack.exe","Teams.exe","ms-teams.exe","WebexTeams.exe")
| where InitiatingProcessAccountName !endswith "$"
| summarize ConnCount = count(),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp),
            SampleUrl = any(RemoteUrl),
            SampleCmd = any(InitiatingProcessCommandLine),
            DistinctRemoteIPs = dcount(RemoteIP)
          by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath
| where ConnCount >= 3
| order by FirstSeen desc
```

### [LLM] GraphWorm OneDrive /createUploadSession C2 from non-Office process

`UC_116_11` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="graph.microsoft.com" OR All_Traffic.url IN ("*graph.microsoft.com/v1.0/me/drive/items/*createUploadSession*","*graph.microsoft.com/v1.0/drives/*createUploadSession*","*graph.microsoft.com/v1.0/me/drive/root:*")) by All_Traffic.src,All_Traffic.dest,All_Traffic.user,All_Traffic.process_name,All_Traffic.url,_time | `drop_dm_object_name(All_Traffic)` | search NOT (process_name IN ("*\\msedge.exe","*\\chrome.exe","*\\firefox.exe","*\\OneDrive.exe","*\\OneDriveStandaloneUpdater.exe","*\\Teams.exe","*\\ms-teams.exe","*\\WINWORD.EXE","*\\EXCEL.EXE","*\\POWERPNT.EXE","*\\OUTLOOK.EXE","*\\ONENOTE.EXE","*\\Outlook.exe")) | stats min(_time) as first_seen max(_time) as last_seen sum(count) as conn_count values(url) as urls by src,user,process_name,dest
```

**Defender KQL:**
```kql
let LookbackDays = 7d;
DeviceNetworkEvents
| where Timestamp > ago(LookbackDays)
| where RemoteUrl has "graph.microsoft.com"
   and (RemoteUrl has "createUploadSession" or RemoteUrl has "/me/drive/items" or RemoteUrl has "/drives/" or RemoteUrl has "/me/drive/root:")
| where InitiatingProcessFileName !in~ ("msedge.exe","chrome.exe","firefox.exe","OneDrive.exe","OneDriveStandaloneUpdater.exe","Teams.exe","ms-teams.exe","WINWORD.EXE","EXCEL.EXE","POWERPNT.EXE","OUTLOOK.EXE","ONENOTE.EXE","Outlook.exe","officeclicktorun.exe","backgroundtaskhost.exe")
| where InitiatingProcessAccountName !endswith "$"
| summarize ConnCount = count(),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp),
            SampleUrl = any(RemoteUrl),
            SampleCmd = any(InitiatingProcessCommandLine)
          by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by FirstSeen desc
```

### [LLM] WormFrp / Webworm Amazon S3 staging bucket access (wamanharipethe / whpjewellers)

`UC_116_12` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest IN ("wamanharipethe.s3.ap-south-1.amazonaws.com","whpjewellers.s3.amazonaws.com","wamanharipethe.s3.amazonaws.com") OR All_Traffic.url IN ("*wamanharipethe.s3*amazonaws.com*","*whpjewellers.s3*amazonaws.com*")) by All_Traffic.src,All_Traffic.dest,All_Traffic.user,All_Traffic.process_name,All_Traffic.url,_time | `drop_dm_object_name(All_Traffic)` | stats min(_time) as first_seen max(_time) as last_seen sum(count) as conn_count values(url) as urls values(process_name) as processes by src,user,dest | append [ | tstats summariesonly=true count from datamodel=Network_Resolution.DNS where (DNS.query IN ("wamanharipethe.s3.ap-south-1.amazonaws.com","whpjewellers.s3.amazonaws.com","wamanharipethe.s3.amazonaws.com") OR DNS.query="*wamanharipethe*" OR DNS.query="*whpjewellers*") by DNS.src,DNS.query,_time | `drop_dm_object_name(DNS)` | rename query as dest src as src | stats min(_time) as first_seen max(_time) as last_seen sum(count) as conn_count by src,dest ]
```

**Defender KQL:**
```kql
let WebwormBuckets = dynamic(["wamanharipethe.s3.ap-south-1.amazonaws.com","whpjewellers.s3.amazonaws.com","wamanharipethe.s3.amazonaws.com"]);
let WebwormBucketSubstrings = dynamic(["wamanharipethe","whpjewellers"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any (WebwormBucketSubstrings)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, ActionType
| union (
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "DnsQueryResponse" or ActionType has "Dns"
| where AdditionalFields has_any (WebwormBucketSubstrings) or RemoteUrl has_any (WebwormBucketSubstrings)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteUrl=coalesce(RemoteUrl,tostring(AdditionalFields)), RemoteIP, RemotePort=toint(0), ActionType
)
| order by Timestamp desc
```

### [LLM] Webworm 2025 IOC match — known C2 IPs (Vultr/IT7) and file hashes

`UC_116_13` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_ip IN ("45.77.13.67","64.176.85.158","104.243.23.43","108.61.200.151","144.168.60.233") OR All_Traffic.src_ip IN ("45.77.13.67","64.176.85.158","104.243.23.43","108.61.200.151","144.168.60.233")) by All_Traffic.src,All_Traffic.dest_ip,All_Traffic.dest_port,All_Traffic.user,All_Traffic.process_name,_time | `drop_dm_object_name(All_Traffic)` | append [ | tstats summariesonly=true count from datamodel=Endpoint.Filesystem where (Filesystem.file_hash IN ("CB4E50433336707381429707F59C3CBE8D497D98","1DF40A4A31B30B62EC33DC6FECC2C4408302ADC7","7DCFE9EE25841DFD58D3D6871BF867FE32141DFB","77F1970D620216C5FFF4E14A6CCC13FCCC267217","948159A7FC2E688386864BEA59FD40DFFC4B24D6","A3C077BDF8898E612CCD65BC82E7960834ADB2A9")) by Filesystem.dest,Filesystem.file_name,Filesystem.file_path,Filesystem.file_hash,_time | `drop_dm_object_name(Filesystem)` ] | append [ | tstats summariesonly=true count from datamodel=Endpoint.Processes where (Processes.process_hash IN ("CB4E50433336707381429707F59C3CBE8D497D98","1DF40A4A31B30B62EC33DC6FECC2C4408302ADC7","7DCFE9EE25841DFD58D3D6871BF867FE32141DFB","77F1970D620216C5FFF4E14A6CCC13FCCC267217","948159A7FC2E688386864BEA59FD40DFFC4B24D6","A3C077BDF8898E612CCD65BC82E7960834ADB2A9")) by Processes.dest,Processes.process_name,Processes.process_path,Processes.process_hash,Processes.user,_time | `drop_dm_object_name(Processes)` ]
```

**Defender KQL:**
```kql
let WebwormIPs = dynamic(["45.77.13.67","64.176.85.158","104.243.23.43","108.61.200.151","144.168.60.233"]);
let WebwormHashes = dynamic(["CB4E50433336707381429707F59C3CBE8D497D98","1DF40A4A31B30B62EC33DC6FECC2C4408302ADC7","7DCFE9EE25841DFD58D3D6871BF867FE32141DFB","77F1970D620216C5FFF4E14A6CCC13FCCC267217","948159A7FC2E688386864BEA59FD40DFFC4B24D6","A3C077BDF8898E612CCD65BC82E7960834ADB2A9"]);
union
(DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (WebwormIPs)
| project Timestamp, DeviceName, IndicatorType="IP", Indicator=RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName
),
(DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA1 in (WebwormHashes)
| project Timestamp, DeviceName, IndicatorType="SHA1", Indicator=SHA1, RemotePort=toint(0), InitiatingProcessFileName, InitiatingProcessFolderPath=FolderPath, InitiatingProcessCommandLine=InitiatingProcessCommandLine, InitiatingProcessAccountName
),
(DeviceProcessEvents
| where Timestamp > ago(30d)
| where SHA1 in (WebwormHashes) or InitiatingProcessSHA1 in (WebwormHashes)
| project Timestamp, DeviceName, IndicatorType="SHA1", Indicator=coalesce(SHA1,InitiatingProcessSHA1), RemotePort=toint(0), InitiatingProcessFileName=FileName, InitiatingProcessFolderPath=FolderPath, InitiatingProcessCommandLine=ProcessCommandLine, InitiatingProcessAccountName=AccountName
)
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

### Article-specific behavioural hunt — Webworm: New burrowing techniques

`UC_116_9` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Webworm: New burrowing techniques ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("secretsdump.py","searchapp.exe","ssh.exe","svc.exe","0316.exe","dsocks.exe"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("secretsdump.py","searchapp.exe","ssh.exe","svc.exe","0316.exe","dsocks.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Webworm: New burrowing techniques
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("secretsdump.py", "searchapp.exe", "ssh.exe", "svc.exe", "0316.exe", "dsocks.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("secretsdump.py", "searchapp.exe", "ssh.exe", "svc.exe", "0316.exe", "dsocks.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `45.77.13.67`, `64.176.85.158`, `104.243.23.43`, `108.61.200.151`, `144.168.60.233`, `github.com/anjsdgasdf/WordPress`

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2017-7692`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `CB4E50433336707381429707F59C3CBE8D497D98`, `1DF40A4A31B30B62EC33DC6FECC2C4408302ADC7`, `7DCFE9EE25841DFD58D3D6871BF867FE32141DFB`, `77F1970D620216C5FFF4E14A6CCC13FCCC267217`, `948159A7FC2E688386864BEA59FD40DFFC4B24D6`, `A3C077BDF8898E612CCD65BC82E7960834ADB2A9`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 14 use case(s) fired, 20 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

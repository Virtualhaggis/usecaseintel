# [CRIT] Webworm Deploys EchoCreep and GraphWorm Backdoors Using Discord and MS Graph API

**Source:** The Hacker News
**Published:** 2026-05-20
**Article:** https://thehackernews.com/2026/05/webworm-deploys-echocreep-and-graphworm.html

## Threat Profile

Webworm Deploys EchoCreep and GraphWorm Backdoors Using Discord and MS Graph API 
 Ravie Lakshmanan  May 20, 2026 Malware / Cybercrime 
Cybersecurity researchers have flagged fresh activity from a China-aligned threat actor known as Webworm in 2025, deploying custom backdoors that employ Discord and Microsoft Graph API for command-and-control (C2 or C&C) communications.
Webworm, first publicly documented by Broadcom-owned Symantec in September 2022, is assessed to be active since at least 2022…

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
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1027** — Obfuscated Files or Information
- **T1053.005** — Scheduled Task/Job: Scheduled Task
- **T1547.001** — Registry Run Keys / Startup Folder
- **T1102.002** — Web Service: Bidirectional Communication
- **T1567.002** — Exfiltration to Cloud Storage
- **T1105** — Ingress Tool Transfer
- **T1608.001** — Stage Capabilities: Upload Malware
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1074.001** — Local Data Staging
- **T1090** — Proxy
- **T1572** — Protocol Tunneling
- **T1102.001** — Web Service: Dead Drop Resolver

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] EchoCreep persistence via 'MicrosoftSSHUpdate' scheduled task

`UC_54_7` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="schtasks.exe" OR Processes.process_name="powershell.exe" OR Processes.process_name="pwsh.exe") Processes.process="*MicrosoftSSHUpdate*" by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | where NOT match(user, "\$$") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName =~ "schtasks.exe" or FileName in~ ("powershell.exe","pwsh.exe","cmd.exe"))
| where ProcessCommandLine has "MicrosoftSSHUpdate"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
          InitiatingProcessSHA256, SHA256
| order by Timestamp desc
```

### [LLM] GraphWorm OneDrive Microsoft Graph API C2 from non-Office process

`UC_54_8` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count values(Web.url) as urls min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where Web.url="*graph.microsoft.com*" Web.process_name!="onedrive.exe" Web.process_name!="outlook.exe" Web.process_name!="winword.exe" Web.process_name!="excel.exe" Web.process_name!="powerpnt.exe" Web.process_name!="teams.exe" Web.process_name!="msedge.exe" Web.process_name!="chrome.exe" Web.process_name!="firefox.exe" Web.process_name!="msoia.exe" Web.process_name!="onenote.exe" by Web.src Web.user Web.process_name Web.url | `drop_dm_object_name(Web)` | where NOT match(process_name, "(?i)(onedrive|outlook|word|excel|powerpnt|teams|edge|chrome|firefox|onenote|msoia|searchapp|searchindexer)") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let OfficeStack = dynamic(["onedrive.exe","outlook.exe","winword.exe","excel.exe","powerpnt.exe","onenote.exe","teams.exe","ms-teams.exe","msedge.exe","chrome.exe","firefox.exe","brave.exe","msoia.exe","officeclicktorun.exe","searchapp.exe","searchindexer.exe","explorer.exe","backgroundtaskhost.exe","runtimebroker.exe","olk.exe","sharepoint.exe","msaccess.exe","microsoftedgeupdate.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has "graph.microsoft.com"
| where InitiatingProcessFileName !in~ (OfficeStack)
| where InitiatingProcessFolderPath !startswith "C:\\Program Files\\Microsoft Office\\"
| where InitiatingProcessFolderPath !startswith "C:\\Program Files (x86)\\Microsoft Office\\"
| summarize ConnCount = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp), Urls = make_set(RemoteUrl, 5) by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256, InitiatingProcessCommandLine
| order by ConnCount desc
```

### [LLM] EchoCreep Discord API C2 channel from non-browser, non-Discord process

`UC_54_9` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count values(Web.url) as urls min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*discord.com*" OR Web.url="*discordapp.com*" OR Web.url="*discord-cdn.com*" OR Web.url="*cdn.discordapp.com*") Web.process_name!="discord.exe" Web.process_name!="update.exe" Web.process_name!="msedge.exe" Web.process_name!="chrome.exe" Web.process_name!="firefox.exe" Web.process_name!="brave.exe" Web.process_name!="opera.exe" by Web.src Web.user Web.process_name Web.url | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let BrowserOrDiscord = dynamic(["discord.exe","update.exe","discordcanary.exe","discordptb.exe","msedge.exe","chrome.exe","firefox.exe","brave.exe","opera.exe","vivaldi.exe","slack.exe","msteams.exe","teams.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteUrl has_any ("discord.com","discordapp.com","cdn.discordapp.com","discord-cdn.com","discord.media")
| where InitiatingProcessFileName !in~ (BrowserOrDiscord)
| where InitiatingProcessFolderPath !startswith "C:\\Users\\" or InitiatingProcessFolderPath !contains "\\AppData\\Local\\Discord\\"
| summarize ConnCount = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp), Urls = make_set(RemoteUrl, 5), Ports = make_set(RemotePort, 5) by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256, InitiatingProcessCommandLine
| order by ConnCount desc
```

### [LLM] Webworm GitHub staging repo access (anjsdgasdf/WordPress)

`UC_54_10` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count values(Web.url) as urls min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*anjsdgasdf/WordPress*" OR Web.url="*github.com/anjsdgasdf*" OR Web.url="*raw.githubusercontent.com/anjsdgasdf*" OR Web.url="*codeload.github.com/anjsdgasdf*") by Web.src Web.user Web.process_name Web.url Web.http_user_agent | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(180d)
| where RemoteUrl has_any ("anjsdgasdf/WordPress","github.com/anjsdgasdf","raw.githubusercontent.com/anjsdgasdf","codeload.github.com/anjsdgasdf")
   or RemoteUrl has "anjsdgasdf"
| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteUrl, RemoteIP, RemotePort,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
          InitiatingProcessSHA256
| order by Timestamp desc
```

### [LLM] GraphWorm beacon_shell_output.txt artifact on disk

`UC_54_11` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name="beacon_shell_output.txt" by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.process_name Filesystem.action | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(60d)
| where FileName =~ "beacon_shell_output.txt" or PreviousFileName =~ "beacon_shell_output.txt"
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, PreviousFolderPath, PreviousFileName,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
          InitiatingProcessSHA256, SHA256
| order by Timestamp desc
```

### [LLM] Webworm C2 IP connection on Vultr/IT7 infrastructure

`UC_54_12` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count values(All_Traffic.dest_port) as ports values(All_Traffic.app) as apps min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest IN ("45.77.13.67","64.176.85.158","104.243.23.43","108.61.200.151","144.168.60.233") by All_Traffic.src All_Traffic.user All_Traffic.dest All_Traffic.app | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let WebwormC2 = dynamic(["45.77.13.67","64.176.85.158","104.243.23.43","108.61.200.151","144.168.60.233"]);
let WebwormSHA1 = dynamic(["CB4E50433336707381429707F59C3CBE8D497D98","1DF40A4A31B30B62EC33DC6FECC2C4408302ADC7","7DCFE9EE25841DFD58D3D6871BF867FE32141DFB","77F1970D620216C5FFF4E14A6CCC13FCCC267217","948159A7FC2E688386864BEA59FD40DFFC4B24D6","A3C077BDF8898E612CCD65BC82E7960834ADB2A9"]);
union isfuzzy=true
(
  DeviceNetworkEvents
  | where Timestamp > ago(180d)
  | where RemoteIP in (WebwormC2)
  | project Timestamp, DeviceName, AccountName, RemoteIP, RemotePort, RemoteUrl,
            InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
            InitiatingProcessSHA1, InitiatingProcessSHA256, Signal="C2_IP"
),
(
  DeviceFileEvents
  | where Timestamp > ago(180d)
  | where SHA1 in (WebwormSHA1) or InitiatingProcessSHA1 in (WebwormSHA1)
  | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, RemoteIP="", RemotePort=int(null), RemoteUrl=FileOriginUrl,
            InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
            InitiatingProcessSHA1, InitiatingProcessSHA256, Signal="SHA1_HASH"
)
| order by Timestamp desc
```

### [LLM] WormFrp configuration retrieval from compromised Amazon S3 bucket

`UC_54_13` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count values(Web.url) as urls min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*wamanharipethe.s3.ap-south-1.amazonaws.com*" OR Web.url="*wamanharipethe.s3.amazonaws.com*" OR Web.url="*s3.ap-south-1.amazonaws.com/wamanharipethe*") by Web.src Web.user Web.process_name Web.url Web.http_user_agent | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(180d)
| where RemoteUrl has_any ("wamanharipethe.s3.ap-south-1.amazonaws.com","wamanharipethe.s3.amazonaws.com","s3.ap-south-1.amazonaws.com/wamanharipethe")
   or RemoteUrl has "wamanharipethe"
| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteUrl, RemoteIP, RemotePort,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
          InitiatingProcessSHA256
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `45.77.13.67`, `64.176.85.158`, `104.243.23.43`, `108.61.200.151`, `144.168.60.233`, `github.com/anjsdgasdf/WordPress`

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2017-7692`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `CB4E50433336707381429707F59C3CBE8D497D98`, `1DF40A4A31B30B62EC33DC6FECC2C4408302ADC7`, `7DCFE9EE25841DFD58D3D6871BF867FE32141DFB`, `77F1970D620216C5FFF4E14A6CCC13FCCC267217`, `948159A7FC2E688386864BEA59FD40DFFC4B24D6`, `A3C077BDF8898E612CCD65BC82E7960834ADB2A9`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 14 use case(s) fired, 21 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

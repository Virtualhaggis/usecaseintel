# [CRIT] OctLurk and SilkLurk: newly identified tailored backdoors in cyber-espionage campaign in Central Asia

**Source:** Securelist (Kaspersky)
**Published:** 2026-07-30
**Article:** https://securelist.com/octlurk-silklurk-backdoors-central-asia/120840/

## Threat Profile

Table of Contents
Introduction 
OctLurk 
OctLurk Deployment 
LurkPoxy Deployment 
OctLurk loader 
OctLurk backdoor 
Post-compromise activity 
Victim fingerprinting 
Event log collection 
Credential harvesting 
Impacket — secretsdump 
Keylogger 
Browser Password Decryptor 
Remote access : Pandora FMS agents (Pandora RC agent) 
Network scan: FSCAN 
Email harvesting 
LurkProxy 
SilkLurk 
Deployment 
SilkLurk loader 
SilkLurk backdoor 
Post-compromise activity 
Second-stage payload 
PlugX 
Infrastru…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `45.138.157.165`
- **IPv4 (defanged):** `154.196.162.76`
- **IPv4 (defanged):** `95.179.210.138`
- **IPv4 (defanged):** `45.77.136.228`
- **IPv4 (defanged):** `95.179.141.26`
- **IPv4 (defanged):** `45.32.152.50`
- **IPv4 (defanged):** `212.11.39.138`
- **IPv4 (defanged):** `195.86.120.2`
- **IPv4 (defanged):** `154.196.187.73`
- **IPv4 (defanged):** `45.61.149.112`
- **IPv4 (defanged):** `64.7.198.130`
- **Domain (defanged):** `dns.multitoconference.com`
- **Domain (defanged):** `tj.tajikistandip.com`
- **Domain (defanged):** `fm01.clouddevicemetrics.com`
- **Domain (defanged):** `confbase.mdpsupport.net`
- **Domain (defanged):** `digital.leroymerlin.com`
- **Domain (defanged):** `api2.annoyingremote.com`
- **Domain (defanged):** `about.blsouqs.com`
- **Domain (defanged):** `ssl.blsouqs.com`
- **Domain (defanged):** `dns.ssentialserv.xyz`
- **Domain (defanged):** `tyhbgtyuj.gleeze.com`
- **Domain (defanged):** `wedfcvbn.gleeze.com`
- **Domain (defanged):** `rgnojb.casacam.net`
- **Domain (defanged):** `ctyuhjerf.kozow.com`
- **Domain (defanged):** `uyhvfredc.accesscam.org`
- **Domain (defanged):** `gycudore.kozow.com`
- **MD5:** `082d49ef9f14e6811d68c7e0e82e5069`
- **MD5:** `f4578e869a735cfad691f927bae3e638`
- **MD5:** `7c2f64461bb519c6cbf1fc687675514c`
- **MD5:** `8269d6ba1b6842f9152c90cf7add9b93`
- **MD5:** `3c9a1ba8e0c7475706adc6376e9d7b7c`
- **MD5:** `ef59aad625eebda8650aec5820d6ce69`
- **MD5:** `a0cc7accc79abb0287aaba825d0351f0`
- **MD5:** `a56cce62930a6bee80d679b4c495a340`
- **MD5:** `1415a78b75de7db4ba3d1e61d7db4501`
- **MD5:** `a4d550a3ba0cd073fe3839b99d98a7a8`
- **MD5:** `32a5985543433a4f60da2fafd873b927`
- **MD5:** `2a571f6cee42a17d873f4c942649813f`
- **MD5:** `37dc84e4bcad92fa28f1e7778d088283`
- **MD5:** `cf903e4a1629aa0582fd0363b5786676`
- **MD5:** `18dc8bff47cc282508354771d0c8cf8c`
- **MD5:** `9a1dd1d96481d61934dcc2d568971d06`
- **MD5:** `6ecf84fb18f6747ed08d7598364d853a`
- **MD5:** `b874123a80fc4f40e06872b9cb54ebc6`
- **MD5:** `45cf5916fab4272a1313c26e67aa9220`
- **MD5:** `4e6d5c4770d5a822d7fcce6a74f7ad73`
- **MD5:** `5e26df131ff0a679a0a2699b723b46e3`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1053.005** — Scheduled Task
- **T1543.003** — Windows Service
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1219** — Remote Access Software
- **T1053.005** — Persistence (article-specific)
- **T1059.003** — Windows Command Shell
- **T1055** — Process Injection
- **T1573.001** — Symmetric Cryptography
- **T1614.001** — System Language Discovery
- **T1033** — System Owner/User Discovery
- **T1057** — Process Discovery

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### OctLurk persistence: 'GoogleUpDate' scheduled task executing Videos\1.bat

`UC_103_12` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name=schtasks.exe AND Processes.process="*GoogleUpDate*") OR Processes.process="*\\Videos\\1.bat*" by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName =~ "schtasks.exe" and ProcessCommandLine has "GoogleUpDate")
    or ProcessCommandLine has @"\Videos\1.bat"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256, MD5
| order by Timestamp desc
```

### OctLurk/LurkProxy service DLL side-load via RegisterService ServiceMain

`UC_103_13` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where Endpoint.Registry.registry_path="*\\Services\\*" AND ((Endpoint.Registry.registry_value_name=ServiceMain AND Endpoint.Registry.registry_value_data=RegisterService) OR (Endpoint.Registry.registry_value_name=ServiceDll AND (Endpoint.Registry.registry_value_data="*oleasapi.dll*" OR Endpoint.Registry.registry_value_data="*msbasesysdc.dll*"))) by Endpoint.Registry.dest Endpoint.Registry.registry_path Endpoint.Registry.registry_value_name Endpoint.Registry.registry_value_data
| `drop_dm_object_name(Registry)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryKey has @"\Services\"
| where (RegistryValueName =~ "ServiceMain" and RegistryValueData =~ "RegisterService")
    or (RegistryValueName =~ "ServiceDll" and RegistryValueData has_any ("oleasapi.dll","msbasesysdc.dll"))
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### OctLurk/SilkLurk/LurkProxy C2 beacon to campaign infrastructure

`UC_103_14` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip IN ("45.138.157.165","154.196.162.76","95.179.210.138","45.77.136.228","95.179.141.26","45.32.152.50","212.11.39.138","195.86.120.2","154.196.187.73","45.61.149.112","64.7.198.130") by All_Traffic.src All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
let c2Domains = dynamic(["dns.multitoconference.com","tj.tajikistandip.com","fm01.clouddevicemetrics.com","confbase.mdpsupport.net","digital.leroymerlin.com","api2.annoyingremote.com","about.blsouqs.com","ssl.blsouqs.com","dns.ssentialserv.xyz","tyhbgtyuj.gleeze.com","wedfcvbn.gleeze.com","rgnojb.casacam.net","ctyuhjerf.kozow.com","uyhvfredc.accesscam.org","gycudore.kozow.com"]);
let c2Ips = dynamic(["45.138.157.165","154.196.162.76","95.179.210.138","45.77.136.228","95.179.141.26","45.32.152.50","212.11.39.138","195.86.120.2","154.196.187.73","45.61.149.112","64.7.198.130"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl in~ (c2Domains) or RemoteIP in (c2Ips)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessAccountName
| order by Timestamp desc
```

### OctLurk Command Shell plugin post-compromise recon cluster (chcp 1256 + session enum)

`UC_103_15` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count values(Processes.process) as commands dc(Processes.process_name) as distinct_cmds min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name=chcp.com AND Processes.process="*1256*") OR Processes.process_name=qwinsta.exe OR (Processes.process_name=klist.exe AND Processes.process="*sessions*") OR (Processes.process_name=tasklist.exe AND Processes.process="*/V*") OR Processes.process="*$PSVersionTable*" by Processes.dest _time span=1h
| `drop_dm_object_name(Processes)`
| where distinct_cmds>=3
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where AccountName !endswith "$"
| where (FileName =~ "chcp.com" and ProcessCommandLine has "1256")
    or FileName =~ "qwinsta.exe"
    or (FileName =~ "klist.exe" and ProcessCommandLine has "sessions")
    or (FileName =~ "tasklist.exe" and ProcessCommandLine has "/V")
    or (FileName in~ ("powershell.exe","pwsh.exe") and ProcessCommandLine has "$PSVersionTable")
| summarize DistinctCmds = dcount(FileName), Cmds = make_set(ProcessCommandLine),
            Parents = make_set(InitiatingProcessFileName), FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
            by DeviceName, bin(Timestamp, 1h)
| where DistinctCmds >= 3
| order by LastSeen desc
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

### Service install for persistence — sc.exe / new service registry write

`UC_SERVICE_PERSIST` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name="sc.exe" AND Processes.process="*create*"
      AND (Processes.process="*\Users\*" OR Processes.process="*\AppData\*"
        OR Processes.process="*\ProgramData\*" OR Processes.process="*\Temp\*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| append
    [| tstats `summariesonly` count from datamodel=Endpoint.Registry
        where Registry.registry_path="*\\SYSTEM\\CurrentControlSet\\Services\\*"
          AND Registry.registry_value_name="ImagePath"
          AND (Registry.registry_value_data="*\Users\*"
            OR Registry.registry_value_data="*\AppData\*"
            OR Registry.registry_value_data="*\Temp\*")
        by Registry.dest, Registry.registry_path, Registry.registry_value_data, Registry.user
     | `drop_dm_object_name(Registry)`]
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName =~ "sc.exe" and ProcessCommandLine has "create"
| where ProcessCommandLine matches regex @"(?i)(\Users\|\AppData\|\ProgramData\|\Temp\)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```

### Phishing-link click correlated to endpoint execution

`UC_PHISH_LINK` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Phishing-link click that drives endpoint execution within 60s ```
| tstats `summariesonly` earliest(_time) AS click_time
    from datamodel=Web
    where Web.action="allowed"
    by Web.src, Web.user, Web.dest, Web.url
| `drop_dm_object_name(Web)`
| rename user AS recipient, dest AS clicked_domain, url AS clicked_url
| join type=inner recipient
    [| tstats `summariesonly` count
         from datamodel=Email.All_Email
         where All_Email.action="delivered" AND All_Email.url!="-"
         by All_Email.recipient, All_Email.src_user, All_Email.url, All_Email.subject
     | `drop_dm_object_name(All_Email)`
     | rex field=url "https?://(?<email_domain>[^/]+)"
     | rename recipient AS recipient]
| join type=inner src
    [| tstats `summariesonly` earliest(_time) AS exec_time
         values(Processes.process) AS exec_cmd, values(Processes.process_name) AS exec_proc
         from datamodel=Endpoint.Processes
         where Processes.parent_process_name IN ("chrome.exe","msedge.exe","firefox.exe",
                                                   "outlook.exe","brave.exe","arc.exe")
           AND Processes.process_name IN ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe",
                                            "rundll32.exe","regsvr32.exe","wscript.exe",
                                            "cscript.exe","bitsadmin.exe","certutil.exe",
                                            "curl.exe","wget.exe")
         by Processes.dest, Processes.user
     | `drop_dm_object_name(Processes)`
     | rename dest AS src]
| eval delta_sec = exec_time - click_time
| where delta_sec >= 0 AND delta_sec <= 60
| table click_time, exec_time, delta_sec, recipient, src, src_user, subject,
        clicked_domain, clicked_url, exec_proc, exec_cmd
| sort - click_time
```

**Defender KQL:**
```kql
// Phishing-link click that drives endpoint execution within 60s.
// Far higher fidelity than "every clicked URL" — most legitimate clicks
// never spawn a non-browser child process, so the join eliminates the
// 99% of noise that makes a raw click query unactionable.
let LookbackDays = 7d;
let SuspectClicks = UrlClickEvents
    | where Timestamp > ago(LookbackDays)
    | where AccountName !endswith "$"
    | where ActionType in ("ClickAllowed","ClickedThrough")
    | join kind=inner (
        EmailEvents
        | where Timestamp > ago(LookbackDays)
        | where DeliveryAction == "Delivered"
        | where EmailDirection == "Inbound"
        | project NetworkMessageId, Subject, SenderFromAddress, SenderFromDomain,
                  RecipientEmailAddress, EmailTimestamp = Timestamp
      ) on NetworkMessageId
    | join kind=leftouter (
        EmailUrlInfo | project NetworkMessageId, Url, UrlDomain
      ) on NetworkMessageId, Url
    | project ClickTime = Timestamp, AccountUpn, IPAddress, Url, UrlDomain,
              Subject, SenderFromAddress, SenderFromDomain, RecipientEmailAddress,
              ActionType;
// Correlate to a non-browser child process spawned within 60 seconds on
// the recipient's device.
DeviceProcessEvents
| where Timestamp > ago(LookbackDays)
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe",
                                         "outlook.exe","brave.exe","arc.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe",
                        "rundll32.exe","regsvr32.exe","wscript.exe","cscript.exe",
                        "bitsadmin.exe","certutil.exe","curl.exe","wget.exe")
| join kind=inner SuspectClicks on $left.AccountName == $right.AccountUpn
| where Timestamp between (ClickTime .. ClickTime + 60s)
| project ClickTime, ProcessTime = Timestamp,
          DelaySec = datetime_diff('second', Timestamp, ClickTime),
          DeviceName, AccountName, RecipientEmailAddress, SenderFromAddress,
          Subject, Url, UrlDomain, ActionType,
          FileName, ProcessCommandLine, InitiatingProcessFileName
| order by ClickTime desc
```

### Fake CAPTCHA / clipboard-injected PowerShell (ClickFix / FakeCaptcha)

`UC_FAKECAPTCHA` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("explorer.exe","RuntimeBroker.exe")
      AND Processes.process_name IN ("powershell.exe","pwsh.exe","mshta.exe")
      AND (Processes.process="*iex*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*FromBase64*" OR Processes.process="*DownloadString*"
        OR Processes.process="*hxxp*" OR Processes.process="*curl*" OR Processes.process="*wget*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("explorer.exe","RuntimeBroker.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","mshta.exe")
| where ProcessCommandLine matches regex @"(?i)(iex|invoke-expression|frombase64|downloadstring|hxxp|curl |wget )"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
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

### Article-specific behavioural hunt — OctLurk and SilkLurk: newly identified tailored backdoors in cyber-espionage cam

`UC_103_11` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — OctLurk and SilkLurk: newly identified tailored backdoors in cyber-espionage cam ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("oleasapi.dll","auto.bat","msbasesysdc.dll","in.bat","adobe.exe","secretsdump.py","anydesk.exe","64.exe","fc.exe","netsetsvc.exe","nvgwls.exe","rtksmbus.exe","rtkngui64.exe","nvml.dll","vulkan-1.dll") OR Processes.process="*certutil -urlcache*" OR Processes.process_path="*C:\Windows\System32\cmd.exe*" OR Processes.process_path="*C:\windows\temp\in.bat*" OR Processes.process_path="*C:\Users\Public\Pictures\AnyDesk.exe*" OR Processes.process_path="*C:\Users\Public\Libraries\msect\dev0*" OR Processes.process_path="*C:\Users\Public\Libraries\msect\dev1*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*C:\Windows\System32\cmd.exe*" OR Filesystem.file_path="*C:\windows\temp\in.bat*" OR Filesystem.file_path="*C:\Users\Public\Pictures\AnyDesk.exe*" OR Filesystem.file_path="*C:\Users\Public\Libraries\msect\dev0*" OR Filesystem.file_path="*C:\Users\Public\Libraries\msect\dev1*" OR Filesystem.file_path="*%LOCALAPPDATA%\Google\Chrome\User*" OR Filesystem.file_path="*%APPDATA%\Mozilla\Firefox\Profiles\*" OR Filesystem.file_path="*C:\ProgramData\1.bat*" OR Filesystem.file_name IN ("oleasapi.dll","auto.bat","msbasesysdc.dll","in.bat","adobe.exe","secretsdump.py","anydesk.exe","64.exe","fc.exe","netsetsvc.exe","nvgwls.exe","rtksmbus.exe","rtkngui64.exe","nvml.dll","vulkan-1.dll"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
| append [
  | tstats `summariesonly` count
      from datamodel=Endpoint.Registry
      where Registry.action IN ("created","modified")
        AND (Registry.registry_path="*HKLM\\SOFTWARE\\Microsoft\\Windows*")
      by Registry.dest, Registry.process_name, Registry.registry_path,
         Registry.registry_value_name, Registry.registry_value_data
  | `drop_dm_object_name(Registry)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — OctLurk and SilkLurk: newly identified tailored backdoors in cyber-espionage cam
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("oleasapi.dll", "auto.bat", "msbasesysdc.dll", "in.bat", "adobe.exe", "secretsdump.py", "anydesk.exe", "64.exe", "fc.exe", "netsetsvc.exe", "nvgwls.exe", "rtksmbus.exe", "rtkngui64.exe", "nvml.dll", "vulkan-1.dll") or ProcessCommandLine has_any ("certutil -urlcache") or FolderPath has_any ("C:\Windows\System32\cmd.exe", "C:\windows\temp\in.bat", "C:\Users\Public\Pictures\AnyDesk.exe", "C:\Users\Public\Libraries\msect\dev0", "C:\Users\Public\Libraries\msect\dev1"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("C:\Windows\System32\cmd.exe", "C:\windows\temp\in.bat", "C:\Users\Public\Pictures\AnyDesk.exe", "C:\Users\Public\Libraries\msect\dev0", "C:\Users\Public\Libraries\msect\dev1", "%LOCALAPPDATA%\Google\Chrome\User", "%APPDATA%\Mozilla\Firefox\Profiles\", "C:\ProgramData\1.bat") or FileName in~ ("oleasapi.dll", "auto.bat", "msbasesysdc.dll", "in.bat", "adobe.exe", "secretsdump.py", "anydesk.exe", "64.exe", "fc.exe", "netsetsvc.exe", "nvgwls.exe", "rtksmbus.exe", "rtkngui64.exe", "nvml.dll", "vulkan-1.dll"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc

// Registry persistence locations named in the article
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryKey has_any ("HKLM\SOFTWARE\Microsoft\Windows")
| project Timestamp, DeviceName, AccountName, RegistryKey,
          RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `45.138.157.165`, `154.196.162.76`, `95.179.210.138`, `45.77.136.228`, `95.179.141.26`, `45.32.152.50`, `212.11.39.138`, `195.86.120.2` _(+18 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `082d49ef9f14e6811d68c7e0e82e5069`, `f4578e869a735cfad691f927bae3e638`, `7c2f64461bb519c6cbf1fc687675514c`, `8269d6ba1b6842f9152c90cf7add9b93`, `3c9a1ba8e0c7475706adc6376e9d7b7c`, `ef59aad625eebda8650aec5820d6ce69`, `a0cc7accc79abb0287aaba825d0351f0`, `a56cce62930a6bee80d679b4c495a340` _(+13 more)_


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 16 use case(s) fired, 22 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

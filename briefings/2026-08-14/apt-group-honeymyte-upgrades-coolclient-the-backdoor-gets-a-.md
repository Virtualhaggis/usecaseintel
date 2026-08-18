# [CRIT] APT group HoneyMyte upgrades CoolClient: the backdoor gets a kernel-level Windows rootkit

**Source:** Securelist (Kaspersky)
**Published:** 2026-08-14
**Article:** https://securelist.com/honeymyte-coolclient-driver-rootkit/121028/

## Threat Profile

Table of Contents
Introduction 
Technical analysis 
CoolClient components 
First stage: libngs.dll 
Second stage: loadcert.ini (before synchost.exe injection) 
Command handler 
Establishing AutoRun persistence 
Process injection into synchost.exe 
Service installation 
Administrator privilege check 
Elevated relaunch and UAC bypass 
Second stage: loadcert.ini (Injected Execution) 
Kernel-Mode driver deployment 
Driver initialization 
Cert.ini process injection 
Msagent.sys driver 
Driver configu…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `cloudtroe.giize.com`
- **Domain (defanged):** `employers.theworkpc.com`
- **Domain (defanged):** `freeread.casacam.net`
- **Domain (defanged):** `us.lenovoappstore.com`
- **Domain (defanged):** `sundanish.freeddns.org`
- **Domain (defanged):** `torinarlabs.webredirect.org`
- **Domain (defanged):** `news.dursamjbataar.org`
- **Domain (defanged):** `video.dursamjbataar.org`
- **Domain (defanged):** `black-popular.com`
- **Domain (defanged):** `whatismybestthing.com`
- **MD5:** `2d7c8780e97409770a9d4f31c66c9d63`
- **MD5:** `9460e150e1981d5c165043520c5c12fe`
- **MD5:** `9717f005c5fb98e08d2ad983d88f94ee`
- **MD5:** `f518d8e5fe70d9090f6280c68a95998f`
- **MD5:** `eb79558b037669792652a816e2c669de`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1053.005** — Scheduled Task
- **T1543.003** — Windows Service
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1053.005** — Persistence (article-specific)
- **T1543.003** — Persistence (article-specific)
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1564.001** — Hide Artifacts: Hidden Files and Directories
- **T1053.005** — Scheduled Task/Job: Scheduled Task
- **T1036.004** — Masquerading: Masquerade Task or Service
- **T1574.002** — Hijack Execution Flow: DLL Side-Loading
- **T1014** — Rootkit
- **T1543.003** — Create or Modify System Process: Windows Service
- **T1553.002** — Subvert Trust Controls: Code Signing
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1568** — Dynamic Resolution

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### HoneyMyte Defender exclusion for fake 'Microsoft\Windows Defender' path via WMIC MSFT_MpPreference

`UC_48_10` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=wmic.exe Processes.process="*MSFT_MpPreference*" Processes.process="*ExclusionPath*" Processes.process="*Microsoft\\Windows Defender*" by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName =~ "wmic.exe" or InitiatingProcessFileName =~ "wmic.exe") or ProcessCommandLine has "MSFT_MpPreference"
| where ProcessCommandLine has_all ("MSFT_MpPreference", "ExclusionPath")
| where ProcessCommandLine has @"Microsoft\Windows Defender"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### CoolClient sideloader staging: xcopy clones legit Windows Defender folder into fake Microsoft\Windows Defender dir

`UC_48_11` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=xcopy.exe Processes.process="*Windows Defender*" Processes.process="*Microsoft\\Windows Defender*" by Processes.dest Processes.user Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "xcopy.exe"
| where ProcessCommandLine has @"Windows Defender" and ProcessCommandLine has @"Microsoft\Windows Defender"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
| order by Timestamp desc
```

### CoolClient persistence: schtasks onstart SYSTEM task masquerading as 'Windows Defender ATP Service' running defender.exe

`UC_48_12` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=schtasks.exe Processes.process="*/create*" Processes.process="*Windows Defender Advanced Threat Protection Service*" Processes.process="*defender.exe*" by Processes.dest Processes.user Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has "Windows Defender Advanced Threat Protection Service"
| where ProcessCommandLine has "defender.exe"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### HoneyMyte DLL side-load: renamed Sangfor defender.exe loads malicious libngs.dll from fake Defender dir

`UC_48_13` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=defender.exe Processes.process_path="*\\Microsoft\\Windows Defender\\*" by Processes.dest Processes.user Processes.process_path Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName =~ "defender.exe"
| where FileName =~ "libngs.dll" or FolderPath has @"Microsoft\Windows Defender"
| where FileName =~ "libngs.dll"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, FileName, FolderPath, SHA256
| order by Timestamp desc
```

### CoolClient signed kernel rootkit: msagent.sys driver service install (Nanjing Ranyi cert)

`UC_48_14` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name=msagent.sys by Filesystem.dest Filesystem.file_path Filesystem.process_name Filesystem.user | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
union
(DeviceEvents
 | where Timestamp > ago(30d)
 | where ActionType == "ServiceInstalled"
 | where AdditionalFields has "msagent.sys"
 | project Timestamp, DeviceName, ActionType, AccountName, AdditionalFields, InitiatingProcessFileName, InitiatingProcessCommandLine),
(DeviceFileEvents
 | where Timestamp > ago(30d)
 | where FileName =~ "msagent.sys"
 | where ActionType in ("FileCreated","FileModified")
 | project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName=InitiatingProcessFileName, InitiatingProcessCommandLine=InitiatingProcessCommandLine)
| order by Timestamp desc
```

### CoolClient C2 beacon to HoneyMyte dynamic-DNS command-and-control domains

`UC_48_15` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query IN ("cloudtroe.giize.com","employers.theworkpc.com","freeread.casacam.net","us.lenovoappstore.com","sundanish.freeddns.org","torinarlabs.webredirect.org","news.dursamjbataar.org","video.dursamjbataar.org","black-popular.com","whatismybestthing.com") by DNS.src DNS.query | `drop_dm_object_name(DNS)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any ("cloudtroe.giize.com","employers.theworkpc.com","freeread.casacam.net","us.lenovoappstore.com","sundanish.freeddns.org","torinarlabs.webredirect.org","news.dursamjbataar.org","video.dursamjbataar.org","black-popular.com","whatismybestthing.com")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, RemoteUrl, RemoteIP, RemotePort
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

### Article-specific behavioural hunt — APT group HoneyMyte upgrades CoolClient: the backdoor gets a kernel-level Window

`UC_48_9` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — APT group HoneyMyte upgrades CoolClient: the backdoor gets a kernel-level Window ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("libngs.dll","synchost.exe","msagent.sys","defender.exe","sang.exe","libsrapc.dll","write.exe","360sd.exe","zhudongfangyu.exe","360desktopservice64.exe","escanmon.exe","winver.exe","computerdefaults.exe","ctxmui.dll") OR Processes.process_path="*C:\Windows\System32\winver.exe*" OR Processes.process_path="*C:\ProgramData\symantecdir\*" OR Processes.process_path="*C:\ProgramData\virtualstore\*" OR Processes.process_path="*C:\Windows\identitycrl\production\*" OR Processes.process_path="*C:\Windows\serviceprofiles\networkservice\*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*C:\Windows\System32\winver.exe*" OR Filesystem.file_path="*C:\ProgramData\symantecdir\*" OR Filesystem.file_path="*C:\ProgramData\virtualstore\*" OR Filesystem.file_path="*C:\Windows\identitycrl\production\*" OR Filesystem.file_path="*C:\Windows\serviceprofiles\networkservice\*" OR Filesystem.file_path="*\AppData\Local\viber24.8\*" OR Filesystem.file_path="*\AppData\Roaming\dsassistant\*" OR Filesystem.file_path="*C:\programdata\msdn\*" OR Filesystem.file_name IN ("libngs.dll","synchost.exe","msagent.sys","defender.exe","sang.exe","libsrapc.dll","write.exe","360sd.exe","zhudongfangyu.exe","360desktopservice64.exe","escanmon.exe","winver.exe","computerdefaults.exe","ctxmui.dll"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
| append [
  | tstats `summariesonly` count
      from datamodel=Endpoint.Registry
      where Registry.action IN ("created","modified")
        AND (Registry.registry_path="*HKLM\\SYSTEM\\RNG\\Wid_H1deF5Dirs*" OR Registry.registry_path="*HKLM\\SYSTEM\\CurrentControlSet\\Services\\msagent\\Instances*")
      by Registry.dest, Registry.process_name, Registry.registry_path,
         Registry.registry_value_name, Registry.registry_value_data
  | `drop_dm_object_name(Registry)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — APT group HoneyMyte upgrades CoolClient: the backdoor gets a kernel-level Window
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("libngs.dll", "synchost.exe", "msagent.sys", "defender.exe", "sang.exe", "libsrapc.dll", "write.exe", "360sd.exe", "zhudongfangyu.exe", "360desktopservice64.exe", "escanmon.exe", "winver.exe", "computerdefaults.exe", "ctxmui.dll") or FolderPath has_any ("C:\Windows\System32\winver.exe", "C:\ProgramData\symantecdir\", "C:\ProgramData\virtualstore\", "C:\Windows\identitycrl\production\", "C:\Windows\serviceprofiles\networkservice\"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("C:\Windows\System32\winver.exe", "C:\ProgramData\symantecdir\", "C:\ProgramData\virtualstore\", "C:\Windows\identitycrl\production\", "C:\Windows\serviceprofiles\networkservice\", "\AppData\Local\viber24.8\", "\AppData\Roaming\dsassistant\", "C:\programdata\msdn\") or FileName in~ ("libngs.dll", "synchost.exe", "msagent.sys", "defender.exe", "sang.exe", "libsrapc.dll", "write.exe", "360sd.exe", "zhudongfangyu.exe", "360desktopservice64.exe", "escanmon.exe", "winver.exe", "computerdefaults.exe", "ctxmui.dll"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc

// Registry persistence locations named in the article
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryKey has_any ("HKLM\SYSTEM\RNG\Wid_H1deF5Dirs", "HKLM\SYSTEM\CurrentControlSet\Services\msagent\Instances")
| project Timestamp, DeviceName, AccountName, RegistryKey,
          RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `cloudtroe.giize.com`, `employers.theworkpc.com`, `freeread.casacam.net`, `us.lenovoappstore.com`, `sundanish.freeddns.org`, `torinarlabs.webredirect.org`, `news.dursamjbataar.org`, `video.dursamjbataar.org` _(+2 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `2d7c8780e97409770a9d4f31c66c9d63`, `9460e150e1981d5c165043520c5c12fe`, `9717f005c5fb98e08d2ad983d88f94ee`, `f518d8e5fe70d9090f6280c68a95998f`, `eb79558b037669792652a816e2c669de`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 16 use case(s) fired, 25 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

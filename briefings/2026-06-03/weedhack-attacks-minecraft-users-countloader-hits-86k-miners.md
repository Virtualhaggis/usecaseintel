# [CRIT] Weedhack Attacks Minecraft Users, CountLoader Hits 86K, Miners Spread via Pirated Content

**Source:** The Hacker News
**Published:** 2026-06-03
**Article:** https://thehackernews.com/2026/06/weedhack-attacks-minecraft-users.html

## Threat Profile

Weedhack Attacks Minecraft Users, CountLoader Hits 86K, Miners Spread via Pirated Content 
 Ravie Lakshmanan  Jun 03, 2026 Cryptocurrency / SEO Poisoning 
Cybersecurity researchers have flagged a new campaign targeting Minecraft players via YouTube to spread malware capable of gaining control of victims' systems.
The Minecraft-focused malware-as-a-service (MaaS) campaign has been codenamed Weedhack by McAfee Labs, stating the activity has been active since January 2026 and impersonates Minecra…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `weedhack.to`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1027** — Obfuscated Files or Information
- **T1219** — Remote Access Software
- **T1195.002** — Compromise Software Supply Chain
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1071.004** — Application Layer Protocol: DNS
- **T1102** — Web Service
- **T1568** — Dynamic Resolution
- **T1105** — Ingress Tool Transfer
- **T1218.005** — System Binary Proxy Execution: Mshta
- **T1059.007** — JavaScript
- **T1091** — Replication Through Removable Media
- **T1547.009** — Boot or Logon Autostart Execution: Shortcut Modification
- **T1574.002** — Hijack Execution Flow: DLL Side-Loading
- **T1496** — Resource Hijacking
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1562.012** — Impair Defenses: Disable or Modify Linux Audit System

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Weedhack DonutDupe.jar launched via java.exe (Minecraft MaaS first stage)

`UC_15_11` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("java.exe","javaw.exe","javaws.exe") (Processes.process="*DonutDupe.jar*" OR Processes.process="*DonutDupe*\.jar*") by Processes.dest Processes.user Processes.parent_process_name Processes.process Processes.process_path Processes.process_hash _time | `drop_dm_object_name(Processes)` | where like(process,"%DonutDupe%") | sort 0 - _time
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("java.exe","javaw.exe","javaws.exe")
| where ProcessCommandLine has "DonutDupe" and ProcessCommandLine has ".jar"
| project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### [LLM] Weedhack C2 dashboard contact: outbound to weedhack[.]to

`UC_15_12` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query="*weedhack.to*" by DNS.src DNS.query DNS.answer _time | `drop_dm_object_name(DNS)` | append [| tstats summariesonly=true count from datamodel=Web.Web where Web.url="*weedhack.to*" by Web.src Web.dest Web.url Web.user _time | `drop_dm_object_name(Web)`] | sort 0 - _time
```

**Defender KQL:**
```kql
union
( DeviceNetworkEvents
  | where Timestamp > ago(30d)
  | where RemoteUrl has "weedhack.to"
  | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort ),
( DeviceEvents
  | where Timestamp > ago(30d)
  | where ActionType == "DnsQueryResponse"
  | where AdditionalFields has "weedhack.to"
  | project Timestamp, DeviceName, InitiatingProcessFileName, AdditionalFields )
| order by Timestamp desc
```

### [LLM] Weedhack EtherHiding: java.exe contacts public Ethereum RPC endpoints

`UC_15_13` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("java.exe","javaw.exe","javaws.exe") by Processes.dest Processes.process_id Processes.user _time | `drop_dm_object_name(Processes)` | join type=inner dest [| tstats summariesonly=true count from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_host="mainnet.infura.io" OR All_Traffic.dest_host="cloudflare-eth.com" OR All_Traffic.dest_host="rpc.ankr.com" OR All_Traffic.dest_host="eth-mainnet.g.alchemy.com" OR All_Traffic.dest_host="eth.llamarpc.com" OR All_Traffic.dest_host="ethereum.publicnode.com" OR All_Traffic.dest_host="rpc.flashbots.net") by All_Traffic.src All_Traffic.dest_host All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)` | rename src as dest]
```

**Defender KQL:**
```kql
let EthRpc = dynamic(["mainnet.infura.io","cloudflare-eth.com","rpc.ankr.com","eth-mainnet.g.alchemy.com","eth.llamarpc.com","ethereum.publicnode.com","rpc.flashbots.net","api.etherscan.io"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("java.exe","javaw.exe","javaws.exe")
| where RemoteUrl has_any (EthRpc) or tostring(parse_url(RemoteUrl).Host) has_any (EthRpc)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### [LLM] Weedhack multi-stage JAR drops: Elevator/SecurityManager/Component.jar

`UC_15_14` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name="Elevator.jar" OR Filesystem.file_name="SecurityManager.jar" OR Filesystem.file_name="Component.jar") by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.process_name Filesystem.file_hash _time | `drop_dm_object_name(Filesystem)` | sort 0 - _time
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileRenamed")
| where FileName in~ ("Elevator.jar","SecurityManager.jar","Component.jar")
| project Timestamp, DeviceName, FolderPath, FileName, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, FileOriginUrl
| order by Timestamp desc
```

### [LLM] CountLoader: EXE → PowerShell → mshta.exe obfuscated JS chain

`UC_15_15` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="mshta.exe" Processes.parent_process_name IN ("powershell.exe","pwsh.exe") by Processes.dest Processes.user Processes.process Processes.parent_process Processes.process_hash _time | `drop_dm_object_name(Processes)` | where match(process,"(?i)(javascript:|vbscript:|http[s]?://|\\.hta|new\s+ActiveXObject|WScript\.Shell)")
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "mshta.exe"
| where InitiatingProcessFileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)(javascript:|vbscript:|http[s]?://|\.hta\b|new\s+ActiveXObject|WScript\.Shell)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, SHA256
| order by Timestamp desc
```

### [LLM] CountLoader USB propagation: scripts/EXEs written to removable media

`UC_15_16` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name="autorun.inf" OR Filesystem.file_name="*.lnk" OR Filesystem.file_name="*.hta" OR Filesystem.file_name="*.js") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_name _time | `drop_dm_object_name(Filesystem)` | where match(file_path,"(?i)^[D-Z]:\\\\") | search NOT process_name IN ("explorer.exe","OneDrive.exe")
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileRenamed")
| where FolderPath matches regex @"^[D-Z]:\\"
| where FileName =~ "autorun.inf" or FileName endswith ".lnk" or FileName endswith ".hta" or FileName endswith ".js" or FileName endswith ".vbs"
| where InitiatingProcessFileName !in~ ("explorer.exe","OneDrive.exe","Dropbox.exe","GoogleDriveFS.exe")
| summarize FileCount=dcount(FileName), Files=make_set(FileName,20), SamplePath=any(FolderPath), arg_max(Timestamp,*) by DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, bin(Timestamp,5m)
| where FileCount >= 2
| order by Timestamp desc
```

### [LLM] Pirated-miner DLL side-load via HLS Installer.874.exe

`UC_15_17` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="HLS Installer.874.exe" OR Processes.process="*HLS Installer.874.exe*") by Processes.dest Processes.user Processes.process Processes.process_path Processes.process_hash _time | `drop_dm_object_name(Processes)` | sort 0 - _time
```

**Defender KQL:**
```kql
let HlsProcs = DeviceProcessEvents
    | where Timestamp > ago(90d)
    | where FileName =~ "HLS Installer.874.exe"
    | project ProcTime=Timestamp, DeviceName, ProcessId, FolderPath, AccountName, SHA256, ProcessCommandLine;
let SideLoads = DeviceImageLoadEvents
    | where Timestamp > ago(90d)
    | where InitiatingProcessFileName =~ "HLS Installer.874.exe"
    | where FolderPath !startswith "C:\\Windows\\" and FolderPath !startswith "C:\\Program Files\\"
    | where InitiatingProcessVersionInfoCompanyName != "Microsoft Corporation"
    | project LoadTime=Timestamp, DeviceName, LoadedDll=FileName, LoadedPath=FolderPath, LoadedSHA256=SHA256, InitiatingProcessId;
HlsProcs
| union SideLoads
| order by coalesce(ProcTime, LoadTime) desc
```

### [LLM] Pirated-miner: Defender exclusion add + MRT.exe termination + sleep disable

`UC_15_18` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*Add-MpPreference*ExclusionPath*" OR Processes.process="*Add-MpPreference*ExclusionProcess*" OR Processes.process="*Set-MpPreference*DisableRealtimeMonitoring*" OR (Processes.process="*taskkill*" AND Processes.process="*MRT*") OR (Processes.process_name="powercfg.exe" AND (Processes.process="*hibernate*off*" OR Processes.process="*-change*standby-timeout*0*" OR Processes.process="*monitor-timeout*0*"))) by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name _time | `drop_dm_object_name(Processes)` | sort 0 - _time
```

**Defender KQL:**
```kql
let Win = 30m;
let DefenderEx = DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where ProcessCommandLine has_any ("Add-MpPreference","Set-MpPreference")
    | where ProcessCommandLine has_any ("ExclusionPath","ExclusionProcess","ExclusionExtension","DisableRealtimeMonitoring","DisableBehaviorMonitoring")
    | project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, EvtType="DefenderExclusion";
let MrtKill = DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where (FileName =~ "taskkill.exe" and ProcessCommandLine has "MRT")
         or (FileName =~ "sc.exe" and ProcessCommandLine has "MRT")
         or (FileName =~ "powershell.exe" and ProcessCommandLine has "Stop-Process" and ProcessCommandLine has "MRT")
    | project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, EvtType="MRTKill";
let PowerCfg = DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName =~ "powercfg.exe"
    | where ProcessCommandLine has_any ("hibernate off","standby-timeout","monitor-timeout","-h off")
    | project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, EvtType="PowerCfg";
DefenderEx | union MrtKill, PowerCfg
| summarize EvtTypes=make_set(EvtType), Cmds=make_set(ProcessCommandLine,10), arg_max(Timestamp,*) by DeviceName, bin(Timestamp, Win)
| where array_length(EvtTypes) >= 2
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

### Email attachment opened from external sender

`UC_PHISH_ATTACH` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count
    from datamodel=Email.All_Email
    where All_Email.file_name!="-"
    by All_Email.src_user, All_Email.recipient, All_Email.file_name, All_Email.subject
| rename All_Email.recipient as user
| join type=inner user
    [| tstats `summariesonly` count
        from datamodel=Endpoint.Processes
        where Processes.parent_process_name IN ("OUTLOOK.EXE","winword.exe","excel.exe","powerpnt.exe")
          AND Processes.process_name IN ("cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe")
        by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
     | rename Processes.user as user]
```

**Defender KQL:**
```kql
let LookbackDays = 7d;
let MalAttachments = EmailAttachmentInfo
    | where Timestamp > ago(LookbackDays)
    | where AccountName !endswith "$"
    | project NetworkMessageId, RecipientEmailAddress,
              AttachmentFileName = FileName, AttachmentSHA256 = SHA256;
DeviceProcessEvents
| where Timestamp > ago(LookbackDays)
| where InitiatingProcessFileName in~ ("OUTLOOK.EXE","winword.exe","excel.exe","powerpnt.exe")
| where FileName in~ ("cmd.exe","powershell.exe","wscript.exe","cscript.exe",
                      "mshta.exe","rundll32.exe","regsvr32.exe")
| join kind=inner MalAttachments on $left.AccountUpn == $right.RecipientEmailAddress
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, AttachmentFileName, AttachmentSHA256
```

### Office app spawning script/LOLBin child process

`UC_OFFICE_CHILD` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe","mspub.exe","visio.exe")
      AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","wmic.exe","bitsadmin.exe","certutil.exe")
    by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe","mspub.exe","visio.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","wmic.exe","bitsadmin.exe","certutil.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
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

### Article-specific behavioural hunt — Weedhack Attacks Minecraft Users, CountLoader Hits 86K, Miners Spread via Pirate

`UC_15_10` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Weedhack Attacks Minecraft Users, CountLoader Hits 86K, Miners Spread via Pirate ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("donutdupe.jar","elevator.jar","securitymanager.jar","component.jar","installer.874.exe"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("donutdupe.jar","elevator.jar","securitymanager.jar","component.jar","installer.874.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Weedhack Attacks Minecraft Users, CountLoader Hits 86K, Miners Spread via Pirate
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("donutdupe.jar", "elevator.jar", "securitymanager.jar", "component.jar", "installer.874.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("donutdupe.jar", "elevator.jar", "securitymanager.jar", "component.jar", "installer.874.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `weedhack.to`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 19 use case(s) fired, 31 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

# [CRIT] Silver Fox uses the new ABCDoor backdoor to target organizations in Russia and India

**Source:** Securelist (Kaspersky)
**Published:** 2026-04-30
**Article:** https://securelist.com/silver-fox-tax-notification-campaign/119575/

## Threat Profile

Table of Contents
Email campaign 
RustSL loader 
Silver Fox RustSL 
The steganography.rs module 
Encrypted malicious payload format 
The guard.rs module 
Phantom Persistence 
Attack chain and payloads 
Custom ValleyRAT modules 
ABCDoor Python backdoor 
ABCDoor versions 
Evolution of ABCDoor distribution methods 
Victims 
Conclusion 
Detection by Kaspersky solutions 
Indicators of compromise 
Authors
Anton Kargin 
Vladimir Gursky 
Victoria Vlasova 
Anna Lazaricheva 
In December 2025, we detected …

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `abc.haijing88.com`
- **MD5:** `e6362a81991323e198a463a8ce255533`
- **MD5:** `2c5a1dd4cb53287fe0ed14e0b7b7b1b7`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1053.005** — Scheduled Task
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1053.005** — Persistence (article-specific)
- **T1547.001** — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- **T1112** — Modify Registry
- **T1614.001** — System Location Discovery: System Language Discovery
- **T1016** — System Network Configuration Discovery
- **T1480.001** — Execution Guardrails: Environmental Keying
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1571** — Non-Standard Port
- **T1105** — Ingress Tool Transfer

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Silver Fox RustSL Phantom Persistence — RunOnce 'Application Restart #' registered by csrss.exe pointing to user-writable path

`UC_232_10` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Registry.registry_value_data) as registry_value_data values(Registry.process_name) as process_name from datamodel=Endpoint.Registry where Registry.registry_path="*\\Microsoft\\Windows\\CurrentVersion\\RunOnce*" Registry.registry_value_name="Application Restart #*" by Registry.dest Registry.registry_key_name Registry.registry_value_name Registry.user | `drop_dm_object_name(Registry)` | where NOT match(registry_value_data, "(?i)^\"?(C:\\\\Program Files|C:\\\\Program Files \\(x86\\)|C:\\\\Windows\\\\System32|C:\\\\Windows\\\\SysWOW64|C:\\\\Windows\\\\Microsoft\\.NET)") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// Silver Fox / RustSL Phantom Persistence — csrss.exe writes RunOnce 'Application Restart #N' on behalf of the malware
let _trusted_prefixes = dynamic([@"C:\Program Files\", @"C:\Program Files (x86)\", @"C:\Windows\System32\", @"C:\Windows\SysWOW64\", @"C:\Windows\Microsoft.NET\"]);
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryKey has @"\Microsoft\Windows\CurrentVersion\RunOnce"
| where RegistryValueName startswith "Application Restart #"
| where InitiatingProcessFileName =~ "csrss.exe"   // Phantom Persistence triggers csrss to write the RunOnce on behalf of the abuser
| extend ValueLower = tolower(RegistryValueData)
| where not(ValueLower startswith @"""c:\program files")
   and not(ValueLower startswith @"""c:\program files (x86)")
   and not(ValueLower startswith @"c:\program files\")
   and not(ValueLower startswith @"c:\program files (x86)\")
   and not(ValueLower startswith @"c:\windows\system32\")
   and not(ValueLower startswith @"c:\windows\syswow64\")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessAccountName
| order by Timestamp desc
```

### [LLM] RustSL guard.rs geofencing — single process queries 3+ public IP-geolocation services in a short window

`UC_232_11` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count values(Web.url) as urls dc(Web.url) as service_count from datamodel=Web.Web where (Web.url="*ip-api.com*" OR Web.url="*ipwho.is*" OR Web.url="*ipinfo.io*" OR Web.url="*ipapi.co*" OR Web.url="*geoplugin.net*") by Web.dest Web.src Web.process Web.user _time span=5m | `drop_dm_object_name(Web)` | eval distinct_geo_services=mvcount(mvdedup(mvfilter(match(urls, "(ip-api\.com|ipwho\.is|ipinfo\.io|ipapi\.co|geoplugin\.net)")))) | where service_count>=3
```

**Defender KQL:**
```kql
// RustSL guard.rs — same process pings 3+ of the article's IP-geolocation reflectors within 5 minutes
let _services = dynamic(["ip-api.com","ipwho.is","ipinfo.io","ipapi.co","geoplugin.net"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIPType == "Public"
| where isnotempty(RemoteUrl)
| extend Service = case(
    RemoteUrl has "ip-api.com", "ip-api.com",
    RemoteUrl has "ipwho.is", "ipwho.is",
    RemoteUrl has "ipinfo.io", "ipinfo.io",
    RemoteUrl has "ipapi.co", "ipapi.co",
    RemoteUrl has "geoplugin.net", "geoplugin.net",
    "")
| where Service != ""
| summarize Services = make_set(Service),
            ServiceCount = dcount(Service),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp),
            ConnCount = count()
            by DeviceId, DeviceName, InitiatingProcessFileName, InitiatingProcessSHA256, InitiatingProcessFolderPath, bin(Timestamp, 5m)
| where ServiceCount >= 3                       // 3+ of the 5 reflectors guard.rs uses
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","safari.exe","iexplore.exe","curl.exe")  // browser noise
| order by FirstSeen desc
```

### [LLM] Silver Fox January-2026 campaign IOC sweep — ValleyRAT C2 207.56.138.28:6666 + RustSL distribution domains/hashes

`UC_232_12` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_ip="207.56.138.28" OR All_Traffic.dest_ip="154.82.81.205" OR All_Traffic.dest_ip="154.82.81.192" OR All_Traffic.dest_ip="45.118.133.203" OR All_Traffic.dest_ip="108.187.37.85" OR All_Traffic.dest_ip="108.187.42.63" OR All_Traffic.dest_ip="108.187.41.221" OR All_Traffic.dest_ip="139.180.128.251") by All_Traffic.src All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name(All_Traffic)` | append [| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_hash IN ("e6362a81991323e198a463a8ce255533","2c5a1dd4cb53287fe0ed14e0b7b7b1b7","fc546acf1735127db05fb5bc354093e0","4a5195a38a458cdd2c1b5ab13af3b393","e66bae6e8621db2a835fa6721c3e5bbe","2375193669e243e830ef5794226352e7","5b998a5bc5ad1c550564294034d4a62c","c50c980d3f4b7ed970f083b0d37a6a6a")) by Processes.dest Processes.user Processes.process_name Processes.process_hash Processes.parent_process_name | `drop_dm_object_name(Processes)`] | append [| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where (DNS.query="abc.haijing88.com" OR DNS.query="mcagov.cc" OR DNS.query="abc.fetish-friends.com" OR DNS.query="vnc.kcii2.com" OR DNS.query="abc.3mkorealtd.com") by DNS.src DNS.query DNS.answer | `drop_dm_object_name(DNS)`] | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// Silver Fox Jan-2026 IOC sweep — C2 IPs, RustSL distribution domains, and loader hashes
let _ips = dynamic(["207.56.138.28","154.82.81.205","154.82.81.192","45.118.133.203","108.187.37.85","108.187.42.63","108.187.41.221","139.180.128.251"]);
let _domains = dynamic(["abc.haijing88.com","mcagov.cc","abc.fetish-friends.com","vnc.kcii2.com","abc.3mkorealtd.com"]);
let _md5s = dynamic(["e6362a81991323e198a463a8ce255533","2c5a1dd4cb53287fe0ed14e0b7b7b1b7","fc546acf1735127db05fb5bc354093e0","4a5195a38a458cdd2c1b5ab13af3b393","e66bae6e8621db2a835fa6721c3e5bbe","2375193669e243e830ef5794226352e7","5b998a5bc5ad1c550564294034d4a62c","c50c980d3f4b7ed970f083b0d37a6a6a"]);
let _net = DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteIP in (_ips) or (isnotempty(RemoteUrl) and _domains has_any (RemoteUrl))
    | project Timestamp, DeviceName, AccountUpn=InitiatingProcessAccountUpn, IndicatorType="network", Indicator=coalesce(RemoteUrl, RemoteIP), RemotePort, ProcImage=InitiatingProcessFolderPath, ProcCmd=InitiatingProcessCommandLine, SHA256=InitiatingProcessSHA256;
let _proc = DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where MD5 in (_md5s) or InitiatingProcessMD5 in (_md5s)
    | project Timestamp, DeviceName, AccountUpn, IndicatorType="process_hash", Indicator=coalesce(MD5, InitiatingProcessMD5), RemotePort=int(null), ProcImage=FolderPath, ProcCmd=ProcessCommandLine, SHA256;
let _file = DeviceFileEvents
    | where Timestamp > ago(30d)
    | where MD5 in (_md5s)
    | project Timestamp, DeviceName, AccountUpn=InitiatingProcessAccountUpn, IndicatorType="file_hash", Indicator=MD5, RemotePort=int(null), ProcImage=FolderPath, ProcCmd=InitiatingProcessCommandLine, SHA256;
union _net, _proc, _file
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

### Article-specific behavioural hunt — Silver Fox uses the new ABCDoor backdoor to target organizations in Russia and I

`UC_232_9` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Silver Fox uses the new ABCDoor backdoor to target organizations in Russia and I ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("file.exe","online-module.dll","login-module.dll","curl.exe","ffmpeg.exe","update.bat","pythonw.exe","__main__.py","main.py","path_to_pythonw.exe","update.ps1","suvidha.exe","gstsuvidha.exe","remoteinstaller_20250803165259_whatsapp.exe","remoteinstaller_20250806_004447_jiqi.exe") OR Processes.process="*-WindowStyle Hidden*" OR Processes.process_path="*C:\Users\Administrator\Desktop\bat\Release\winos4.0*" OR Processes.process_path="*%LOCALAPPDATA%\appclient\111.zip*" OR Processes.process_path="*%LOCALAPPDATA%\appclient\111.zip.*" OR Processes.process_path="*\AppData\Local\appclient\update.bat*" OR Processes.process_path="*C:\ProgramData\Tailscale.*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*C:\Users\Administrator\Desktop\bat\Release\winos4.0*" OR Filesystem.file_path="*%LOCALAPPDATA%\appclient\111.zip*" OR Filesystem.file_path="*%LOCALAPPDATA%\appclient\111.zip.*" OR Filesystem.file_path="*\AppData\Local\appclient\update.bat*" OR Filesystem.file_path="*C:\ProgramData\Tailscale.*" OR Filesystem.file_path="*C:\ProgramData\Tailscale*" OR Filesystem.file_path="*\AppData\Local\appclient\python\pythonw.exe*" OR Filesystem.file_path="*%LOCALAPPDATA%\applogs\device.log.*" OR Filesystem.file_name IN ("file.exe","online-module.dll","login-module.dll","curl.exe","ffmpeg.exe","update.bat","pythonw.exe","__main__.py","main.py","path_to_pythonw.exe","update.ps1","suvidha.exe","gstsuvidha.exe","remoteinstaller_20250803165259_whatsapp.exe","remoteinstaller_20250806_004447_jiqi.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Silver Fox uses the new ABCDoor backdoor to target organizations in Russia and I
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("file.exe", "online-module.dll", "login-module.dll", "curl.exe", "ffmpeg.exe", "update.bat", "pythonw.exe", "__main__.py", "main.py", "path_to_pythonw.exe", "update.ps1", "suvidha.exe", "gstsuvidha.exe", "remoteinstaller_20250803165259_whatsapp.exe", "remoteinstaller_20250806_004447_jiqi.exe") or ProcessCommandLine has_any ("-WindowStyle Hidden") or FolderPath has_any ("C:\Users\Administrator\Desktop\bat\Release\winos4.0", "%LOCALAPPDATA%\appclient\111.zip", "%LOCALAPPDATA%\appclient\111.zip.", "\AppData\Local\appclient\update.bat", "C:\ProgramData\Tailscale."))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("C:\Users\Administrator\Desktop\bat\Release\winos4.0", "%LOCALAPPDATA%\appclient\111.zip", "%LOCALAPPDATA%\appclient\111.zip.", "\AppData\Local\appclient\update.bat", "C:\ProgramData\Tailscale.", "C:\ProgramData\Tailscale", "\AppData\Local\appclient\python\pythonw.exe", "%LOCALAPPDATA%\applogs\device.log.") or FileName in~ ("file.exe", "online-module.dll", "login-module.dll", "curl.exe", "ffmpeg.exe", "update.bat", "pythonw.exe", "__main__.py", "main.py", "path_to_pythonw.exe", "update.ps1", "suvidha.exe", "gstsuvidha.exe", "remoteinstaller_20250803165259_whatsapp.exe", "remoteinstaller_20250806_004447_jiqi.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `abc.haijing88.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `e6362a81991323e198a463a8ce255533`, `2c5a1dd4cb53287fe0ed14e0b7b7b1b7`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 13 use case(s) fired, 22 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

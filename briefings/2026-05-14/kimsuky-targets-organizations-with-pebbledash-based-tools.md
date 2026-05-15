# [CRIT] Kimsuky targets organizations with PebbleDash-based tools

**Source:** Securelist (Kaspersky)
**Published:** 2026-05-14
**Article:** https://securelist.com/kimsuky-appleseed-pebbledash-campaigns/119785/

## Threat Profile

Table of Contents
Executive summary 
Background 
Initial access 
Deployed malware 
HelloDoor: first Rust-based PebbleDash variant 
httpMalice: latest backdoor variant of PebbleDash 
MemLoad downloads httpTroy 
AppleSeed 
HappyDoor 
Post-exploitation 
VSCode (launched by the JSE dropper) 
VSCode (launched by VSCode installer) 
DWAgent 
Infrastructure 
Victims 
Attribution 
Conclusion 
Indicators of compromise 
File hashes 
Domains and IPs 
Authors
Sojun Ryu 
Over the past few months, we have cond…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `female-disorder-beta-metropolitan.trycloudflare.com`
- **Domain (defanged):** `file.bigcloud.n-e.kr`
- **Domain (defanged):** `vscode.dev`
- **Domain (defanged):** `www.yespp.co.kr`
- **Domain (defanged):** `out.php`
- **Domain (defanged):** `node896147.dwservice.net`
- **Domain (defanged):** `node828765.dwservice.net`
- **Domain (defanged):** `node484265.dwservice.net`
- **Domain (defanged):** `www.dwservice.net`
- **Domain (defanged):** `naedomain.hankook`
- **Domain (defanged):** `opedromos1.r-e.kr`
- **Domain (defanged):** `morames.r-e.kr`
- **Domain (defanged):** `load.ssangyongcne.o-r.kr`
- **Domain (defanged):** `load.yju.o-r.kr`
- **Domain (defanged):** `attach.docucloud.o-r.kr`
- **Domain (defanged):** `load.supershop.o-r.kr`
- **Domain (defanged):** `load.erasecloud.n-e.kr`
- **Domain (defanged):** `cms.spaceyou.o-r.kr`
- **Domain (defanged):** `erp.spaceme.p-e.kr`
- **Domain (defanged):** `load.auraria.org`
- **Domain (defanged):** `www.pyrotech.co.kr`
- **Domain (defanged):** `newjo-imd.com`
- **SHA1:** `bf9252a2fb45be6893dd8870c0bf37e2e1766d61`
- **SHA1:** `1e3c50d64110be466c0b4a45222e81d2c9352888`
- **MD5:** `995a0a49ae4b244928b3f67e2bfd7a6e`
- **MD5:** `52f1ff082e981cbdfd1f045c6021c63f`
- **MD5:** `65fc9f06de5603e2c1af9b4f288bb22c`
- **MD5:** `8e15c4d4f71bdd9dbc48cd2cabc87806`
- **MD5:** `8983ffa6da23e0b99ccc58c17b9788c7`
- **MD5:** `9fe43e08c8f446554340f972dac8a68c`
- **MD5:** `c19aeaedbbfc4e029f7e9bdface495b9`
- **MD5:** `a7f0a18ac87e982d6f32f7a715e12532`
- **MD5:** `f4465403f9693939fe9c439f0ab33610`
- **MD5:** `5c373c2116ab4a615e622f577e22e9be`
- **MD5:** `d1ec20144c83bba921243e72c517da5e`
- **MD5:** `58ac2f65e335922be3f60e57099dc8a3`
- **MD5:** `f73ba062116ea9f37d072aa41c7f5108`
- **MD5:** `7e0825019d0de0c1c4a1673f94043ddb`
- **MD5:** `08160acf08fccecde7b34090db18b321`
- **MD5:** `94faed9af49c98a89c8acc55e97276c9`
- **MD5:** `c42ae004badddd3017adadbdd1421e00`
- **MD5:** `9ca5f93a732f404bbb2cee848f5bbda0`
- **MD5:** `678fb1a87af525c33ba2492552d5c0e2`

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
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1053.005** — Persistence (article-specific)
- **T1547.001** — Persistence (article-specific)
- **T1547.001** — Registry Run Keys / Startup Folder
- **T1218.010** — System Binary Proxy Execution: Regsvr32
- **T1543.003** — Create or Modify System Process: Windows Service
- **T1218.011** — System Binary Proxy Execution: Rundll32
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1059.005** — Command and Scripting Interpreter: Visual Basic
- **T1140** — Deobfuscate/Decode Files or Information
- **T1564.003** — Hide Artifacts: Hidden Window

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Kimsuky HelloDoor 'tdll' Run-key persistence with regsvr32 loader

`UC_54_13` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where Registry.registry_path="*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\tdll" Registry.registry_value_data="*regsvr32*" Registry.registry_value_data="*/s*" by host Registry.user Registry.registry_path Registry.registry_value_name Registry.registry_value_data Registry.process_name Registry.process_path
| `drop_dm_object_name(Registry)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryKey has @"\Software\Microsoft\Windows\CurrentVersion\Run"
| where RegistryValueName =~ "tdll"
| where RegistryValueData has "regsvr32" and RegistryValueData has "/s"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RegistryKey, RegistryValueName, RegistryValueData
| order by Timestamp desc
```

### [LLM] Kimsuky httpMalice persistence: 'Everything 1.9a-/1.8a-' Run-key or CacheDB service install

`UC_54_14` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where Registry.registry_path="*\\CurrentVersion\\Run*" (Registry.registry_value_name="Everything 1.9a-*" OR Registry.registry_value_name="Everything 1.8a-*") by host Registry.user Registry.registry_value_name Registry.registry_value_data
| `drop_dm_object_name(Registry)`
| eval signal="httpMalice Run key (Everything 1.9a-/1.8a-)"
| append [
    | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Services where Services.service_name="CacheDB" Services.service_path="*rundll32*,load*" by host Services.service_name Services.service_path Services.start_mode
    | `drop_dm_object_name(Services)`
    | eval signal="httpMalice CacheDB service install"
  ]
```

**Defender KQL:**
```kql
union
(DeviceRegistryEvents
  | where Timestamp > ago(7d)
  | where ActionType in ("RegistryValueSet","RegistryKeyCreated")
  | where RegistryKey has @"\Software\Microsoft\Windows\CurrentVersion\Run"
  | where RegistryValueName matches regex @"(?i)^Everything 1\.[89]a-\d+$"
  | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine,
            Signal = "httpMalice RunKey (Everything 1.9a-/1.8a-)",
            Detail = strcat(RegistryValueName, " => ", RegistryValueData)),
(DeviceEvents
  | where Timestamp > ago(7d)
  | where ActionType == "ServiceInstalled"
  | extend AF = parse_json(AdditionalFields)
  | extend SvcName = tostring(AF.ServiceName), SvcImage = tostring(AF.ServiceFileName)
  | where SvcName =~ "CacheDB"
  | where SvcImage has "rundll32" and SvcImage has ",load"
  | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine,
            Signal = "httpMalice CacheDB service install",
            Detail = SvcImage)
| order by Timestamp desc
```

### [LLM] Kimsuky JSE dropper: wscript -> powershell hidden + certutil -decode chain

`UC_54_15` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="powershell.exe" Processes.process="*windowstyle*hidden*" Processes.process="*certutil*-decode*" by host Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| where match(parent_process_name, "(?i)wscript\.exe|cscript\.exe|explorer\.exe")
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has "windowstyle" and ProcessCommandLine has "hidden"
| where ProcessCommandLine has "certutil" and ProcessCommandLine has "-decode"
| where InitiatingProcessFileName in~ ("wscript.exe","cscript.exe","explorer.exe","cmd.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName in~ ("regsvr32.exe","rundll32.exe")
    | where InitiatingProcessFileName =~ "powershell.exe"
    | where FolderPath has @"C:\ProgramData" or ProcessCommandLine has @"C:\ProgramData"
    | project FollowOnTime = Timestamp, DeviceName, FollowOnCmd = ProcessCommandLine, FollowOnFile = FileName
  ) on DeviceName
| where isnull(FollowOnTime) or FollowOnTime between (Timestamp .. Timestamp + 5m)
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

### Article-specific behavioural hunt — Kimsuky targets organizations with PebbleDash-based tools

`UC_54_12` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Kimsuky targets organizations with PebbleDash-based tools ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN (".hwp.jse","hwpx.jse",".hwpx.jse","security_20260126.scr","pdf.jse","hyun-jung.pdf.jse","memloader.dll","unrar.exe","dwagsvc.exe","secu.scr","xipbkmaw.exe") OR Processes.process="*-WindowStyle Hidden*" OR Processes.process_path="*C:\programdata\unrar.exe*" OR Processes.process_path="*C:\programdata\1.zip*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*C:\programdata\unrar.exe*" OR Filesystem.file_path="*C:\programdata\1.zip*" OR Filesystem.file_name IN (".hwp.jse","hwpx.jse",".hwpx.jse","security_20260126.scr","pdf.jse","hyun-jung.pdf.jse","memloader.dll","unrar.exe","dwagsvc.exe","secu.scr","xipbkmaw.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Kimsuky targets organizations with PebbleDash-based tools
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ (".hwp.jse", "hwpx.jse", ".hwpx.jse", "security_20260126.scr", "pdf.jse", "hyun-jung.pdf.jse", "memloader.dll", "unrar.exe", "dwagsvc.exe", "secu.scr", "xipbkmaw.exe") or ProcessCommandLine has_any ("-WindowStyle Hidden") or FolderPath has_any ("C:\programdata\unrar.exe", "C:\programdata\1.zip"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("C:\programdata\unrar.exe", "C:\programdata\1.zip") or FileName in~ (".hwp.jse", "hwpx.jse", ".hwpx.jse", "security_20260126.scr", "pdf.jse", "hyun-jung.pdf.jse", "memloader.dll", "unrar.exe", "dwagsvc.exe", "secu.scr", "xipbkmaw.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `female-disorder-beta-metropolitan.trycloudflare.com`, `file.bigcloud.n-e.kr`, `vscode.dev`, `www.yespp.co.kr`, `out.php`, `node896147.dwservice.net`, `node828765.dwservice.net`, `node484265.dwservice.net` _(+14 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `bf9252a2fb45be6893dd8870c0bf37e2e1766d61`, `1e3c50d64110be466c0b4a45222e81d2c9352888`, `995a0a49ae4b244928b3f67e2bfd7a6e`, `52f1ff082e981cbdfd1f045c6021c63f`, `65fc9f06de5603e2c1af9b4f288bb22c`, `8e15c4d4f71bdd9dbc48cd2cabc87806`, `8983ffa6da23e0b99ccc58c17b9788c7`, `9fe43e08c8f446554340f972dac8a68c` _(+13 more)_


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 16 use case(s) fired, 28 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

# [HIGH] Google DoubleClick Abused in New Malspam Campaign to Deliver DesckVB RAT

**Source:** The Hacker News
**Published:** 2026-06-03
**Article:** https://thehackernews.com/2026/06/google-doubleclick-abused-in-new.html

## Threat Profile

Google DoubleClick Abused in New Malspam Campaign to Deliver DesckVB RAT 
 Ravie Lakshmanan  Jun 03, 2026 Malware / Microsoft Defender 
Cybersecurity researchers have flagged a new malspam campaign that makes use of Google's DoubleClick domain as a way to evade detection and ultimately deliver a remote access trojan (RAT) named DesckVB RAT .
"Before the victim ever reaches attacker-controlled infrastructure, the lure routes through DoubleClick, a legitimate Google-owned domain that many securi…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `23.186.113.60`
- **IPv4 (defanged):** `45.156.87.226`
- **Domain (defanged):** `manikandan83.mysynology.net`
- **Domain (defanged):** `andrefelipedonascime1768785037020.1552093.meusitehostgator.com.br`
- **Domain (defanged):** `pastee.dev`
- **SHA256:** `220e11c678bcba151545ce19398e08b8802103bfbbc11696f3301ea8fa38190c`
- **SHA256:** `347621f7a3392939d9bdbe8a6c9fda30ba9d3f23cb6733484da8e2993772b7f3`
- **SHA256:** `a675f5a396de1fa732a9d83993884b397f02921bbcf34346fbed32c8f4053064`
- **SHA256:** `affb29980bc9564f1b03fe977e9ca5c7adf254656d639632c4d14e34aa4fdff6`
- **SHA256:** `ff051dde71487ea459899920ef7014dad8eee4df308eb360555f3e22232c9367`
- **MD5:** `138f29a9190acad9c392cc6fe37104b8`
- **MD5:** `f040a81be4d3b3584b79036d77794c16`
- **MD5:** `fd684ea48cb97714d4f8a0c741cf862b`
- **MD5:** `f17ed8c5c54bae6c74d0d793d7c7a72a`
- **MD5:** `a624f6cb9ccd4106f91e58049163c757`

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
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1102** — Web Service
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1105** — Ingress Tool Transfer
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1547.001** — Boot or Logon Autostart: Registry Run Keys / Startup Folder
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1095** — Non-Application Layer Protocol

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] HTML attachment with meta-refresh redirect via Google DoubleClick to malspam landing

`UC_31_10` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Email where Email.file_name="*.html" OR Email.file_name="*.htm" by Email.src_user Email.recipient Email.message_id Email.file_name Email.file_hash | `drop_dm_object_name(Email)` | join type=inner message_id [| tstats `summariesonly` count from datamodel=Web where Web.url="*doubleclick.net*" OR Web.url="*ad.doubleclick.net*" by Web.src Web.user Web.url Web.message_id | `drop_dm_object_name(Web)`] | where lastTime - firstTime < 600
```

**Defender KQL:**
```kql
let LookbackDays = 7d;
let HtmlAttachments = EmailAttachmentInfo
    | where Timestamp > ago(LookbackDays)
    | where FileName endswith ".html" or FileName endswith ".htm"
    | project EmailTime = Timestamp, NetworkMessageId, RecipientEmailAddress, FileName, SHA256;
let DoubleClickClicks = UrlClickEvents
    | where Timestamp > ago(LookbackDays)
    | where Url has_any ("doubleclick.net", "ad.doubleclick.net", "googleadservices.com")
    | where ActionType in ("ClickAllowed", "ClickedThrough");
HtmlAttachments
| join kind=inner DoubleClickClicks on $left.RecipientEmailAddress == $right.AccountUpn
| where Timestamp between (EmailTime .. EmailTime + 30m)
| project EmailTime, ClickTime = Timestamp, RecipientEmailAddress, FileName, AttachmentSHA256 = SHA256, Url, NetworkMessageId
| order by EmailTime desc
```

### [LLM] ZIP-borne JavaScript loader spawning PowerShell from user Downloads

`UC_31_11` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("wscript.exe","cscript.exe") AND Processes.process_name="powershell.exe" AND (Processes.parent_process LIKE "%\\Downloads\\%" OR Processes.parent_process LIKE "%\\Temp\\%" OR Processes.parent_process LIKE "%.js%") by Processes.dest Processes.user Processes.parent_process Processes.process Processes.process_hash | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("wscript.exe", "cscript.exe")
| where FileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe")
| where InitiatingProcessCommandLine has_any (".js", ".jse", ".vbs", ".wsf")
| where InitiatingProcessFolderPath has_any (@"\Downloads\", @"\Temp\", @"\AppData\Local\Temp\", @"\AppData\Roaming\")
| where InitiatingProcessParentFileName in~ ("explorer.exe", "7zG.exe", "WinRAR.exe", "7zFM.exe", "chrome.exe", "msedge.exe", "firefox.exe")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          GrandparentImage = InitiatingProcessParentFileName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd = InitiatingProcessCommandLine,
          ChildImage = FolderPath,
          ChildCmd = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### [LLM] PowerShell fetching DesckVB .NET loader from pastee.dev

`UC_31_12` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where (Network_Traffic.app="powershell.exe" OR Network_Traffic.process_name="powershell.exe") AND (Network_Traffic.dest_host="pastee.dev" OR Network_Traffic.url="*pastee.dev*") by Network_Traffic.src Network_Traffic.user Network_Traffic.dest Network_Traffic.dest_host Network_Traffic.dest_port | `drop_dm_object_name(Network_Traffic)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("powershell.exe", "pwsh.exe")
| where RemoteUrl has "pastee.dev" or RemoteUrl endswith "pastee.dev"
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          RemoteUrl, RemoteIP, RemotePort,
          InitiatingProcessParentFileName
| order by Timestamp desc
```

### [LLM] DesckVB Defender exclusion configuration via Add-MpPreference / WMIC

`UC_31_13` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("powershell.exe","pwsh.exe","cmd.exe") AND (Processes.process LIKE "%Add-MpPreference%" OR Processes.process LIKE "%Set-MpPreference%") AND (Processes.process LIKE "%ExclusionPath%" OR Processes.process LIKE "%ExclusionProcess%" OR Processes.process LIKE "%ExclusionExtension%" OR Processes.process LIKE "%DisableRealtimeMonitoring%") by Processes.dest Processes.user Processes.parent_process_name Processes.process | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe")
| where ProcessCommandLine has_any ("Add-MpPreference", "Set-MpPreference")
| where ProcessCommandLine has_any ("ExclusionPath", "ExclusionProcess", "ExclusionExtension", "DisableRealtimeMonitoring", "DisableIOAVProtection", "DisableBehaviorMonitoring")
| where InitiatingProcessParentFileName !in~ ("gpscript.exe", "SenseIR.exe", "MsSense.exe", "MpCmdRun.exe")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessParentFileName,
          InitiatingImage = InitiatingProcessFileName,
          ProcessCommandLine,
          ProcessIntegrityLevel
| order by Timestamp desc
```

### [LLM] DesckVB persistence via Run/RunOnce + Startup folder loader drop

`UC_31_14` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
(| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where (Registry.registry_path LIKE "%\\CurrentVersion\\Run%" OR Registry.registry_path LIKE "%\\CurrentVersion\\RunOnce%") AND (Registry.registry_value_data LIKE "%\\AppData\\%" OR Registry.registry_value_data LIKE "%\\ProgramData\\%" OR Registry.registry_value_data LIKE "%\\Temp\\%") AND Registry.process_name IN ("powershell.exe","pwsh.exe","wscript.exe","cscript.exe") by Registry.dest Registry.user Registry.process_name Registry.registry_path Registry.registry_value_name Registry.registry_value_data | `drop_dm_object_name(Registry)`) | append [| tstats `summariesonly` count from datamodel=Endpoint.Filesystem where Filesystem.file_path LIKE "%\\Start Menu\\Programs\\Startup\\%" AND Filesystem.process_name IN ("powershell.exe","pwsh.exe","wscript.exe") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path Filesystem.file_name | `drop_dm_object_name(Filesystem)`]
```

**Defender KQL:**
```kql
let LookbackDays = 7d;
let RunKeys = DeviceRegistryEvents
    | where Timestamp > ago(LookbackDays)
    | where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
    | where RegistryKey has_any (@"\CurrentVersion\Run", @"\CurrentVersion\RunOnce")
    | where RegistryValueData has_any (@"\AppData\", @"\ProgramData\", @"\Temp\", @"\Public\")
    | where InitiatingProcessFileName in~ ("powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "cmd.exe", "regsvr32.exe", "rundll32.exe")
    | where InitiatingProcessAccountName !endswith "$"
    | project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName, 
              Vector = "RunKey", 
              ParentImage = InitiatingProcessParentFileName,
              Image = InitiatingProcessFileName,
              ImageCmd = InitiatingProcessCommandLine,
              KeyPath = RegistryKey,
              ValueName = RegistryValueName,
              ValueData = RegistryValueData;
let StartupDrops = DeviceFileEvents
    | where Timestamp > ago(LookbackDays)
    | where ActionType in ("FileCreated", "FileRenamed")
    | where FolderPath has @"\Start Menu\Programs\Startup\"
    | where InitiatingProcessFileName in~ ("powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "cmd.exe")
    | where InitiatingProcessAccountName !endswith "$"
    | project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName,
              Vector = "StartupFolder",
              ParentImage = InitiatingProcessParentFileName,
              Image = InitiatingProcessFileName,
              ImageCmd = InitiatingProcessCommandLine,
              KeyPath = FolderPath,
              ValueName = FileName,
              ValueData = SHA256;
RunKeys
| union StartupDrops
| order by Timestamp desc
```

### [LLM] DesckVB C2 raw TCP beacon to known infrastructure (IPs + DDNS + hostgator domain)

`UC_31_15` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where (Network_Traffic.dest IN ("23.186.113.60","45.156.87.226") OR Network_Traffic.dest_host IN ("manikandan83.mysynology.net","andrefelipedonascime1768785037020.1552093.meusitehostgator.com.br","pastee.dev") OR Network_Traffic.url="*manikandan83.mysynology.net*" OR Network_Traffic.url="*1552093.meusitehostgator.com.br*") by Network_Traffic.src Network_Traffic.user Network_Traffic.dest Network_Traffic.dest_host Network_Traffic.dest_port Network_Traffic.transport Network_Traffic.app | `drop_dm_object_name(Network_Traffic)`
```

**Defender KQL:**
```kql
let DesckVBIPs = dynamic(["23.186.113.60", "45.156.87.226"]);
let DesckVBDomains = dynamic(["manikandan83.mysynology.net", "andrefelipedonascime1768785037020.1552093.meusitehostgator.com.br", "pastee.dev"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (DesckVBIPs)
    or RemoteUrl has_any (DesckVBDomains)
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName,
          RemoteIP, RemoteUrl, RemotePort, Protocol,
          InitiatingProcessFolderPath, InitiatingProcessSHA256
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `23.186.113.60`, `45.156.87.226`, `manikandan83.mysynology.net`, `andrefelipedonascime1768785037020.1552093.meusitehostgator.com.br`, `pastee.dev`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `220e11c678bcba151545ce19398e08b8802103bfbbc11696f3301ea8fa38190c`, `347621f7a3392939d9bdbe8a6c9fda30ba9d3f23cb6733484da8e2993772b7f3`, `a675f5a396de1fa732a9d83993884b397f02921bbcf34346fbed32c8f4053064`, `affb29980bc9564f1b03fe977e9ca5c7adf254656d639632c4d14e34aa4fdff6`, `ff051dde71487ea459899920ef7014dad8eee4df308eb360555f3e22232c9367`, `138f29a9190acad9c392cc6fe37104b8`, `f040a81be4d3b3584b79036d77794c16`, `fd684ea48cb97714d4f8a0c741cf862b` _(+2 more)_


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 16 use case(s) fired, 23 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

# [CRIT] Hackers Deploy VIP Keylogger Through Phishing Emails Masquerading as Business Documents

**Source:** Cyber Security News
**Published:** 2026-05-28
**Article:** https://cybersecuritynews.com/hackers-deploy-vip-keylogger-through-phishing-emails/

## Threat Profile

Home Cyber Security News 
Hackers Deploy VIP Keylogger Through Phishing Emails Masquerading as Business Documents 
By Tushar Subhra Dutta 
May 28, 2026 
Hackers are using deceptive phishing emails dressed up as routine business documents to spread a dangerous malware strain known as VIP Keylogger. 
The campaign has been active for months, with attackers showing absolutely no signs of slowing down. VIP Keylogger is part of a broader wave of information-stealing malware that has taken over the thr…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `vault88x.secure-efficient2.su`
- **SHA256:** `95e6c6c13f65217f41c371abf6d03594b2bfed2259a1813bb4222fb2d3c32745`
- **SHA256:** `07ee41817b9f338719bea03676ab607349cc3accba0dddb800f6276a01cfdd9f`
- **SHA256:** `2df582bb41d1e6f0a6d44e8dbc1d8bca8e3d332bb268685b9dfc381a566c63a6`
- **SHA256:** `8d1f59c65ebe64d0e817ffe7ecbf1d5a4bc3768d896c934b00dfd57263c3fe15`
- **SHA256:** `8d5de337baa0b0938e4283324d3b1e8ccbdeed694aab3b6118910476200c621b`
- **SHA256:** `14b25dfcc6e7f69992b3f5543bcc9ebe86bd0b682e211f49cb62c019d8e9bc4d`
- **SHA256:** `28613bfb4e866186133235a88e318df3059b01001f297ad6a524eab0885305a5`
- **SHA256:** `d2ab8dcab70822c839912cb672e93de459e5608bea210c78a1be56b54cbd8f81`
- **SHA256:** `9bca7a3ac404807c63670141a3459eac24450e0cffbe1066cd3c8b503a917170`
- **SHA256:** `9905c76ccf4ebdd12e1df63047a3206026073781d885165e82d298656b5f4937`
- **SHA256:** `927c6d68f6413e437e4a919b2007f6a2ade32be71f80467856ce19a0325b63eb`
- **SHA256:** `ae6918bfe8774e1ec1ec34f3db26e7e548dd0dc33a4e6fa80970e0bd2ba7ad9d`
- **SHA256:** `a2862e4d2c722c7bfc86aa6c2c589455659b7a4ce6bb15ae55706df40e0f1f4e`
- **SHA256:** `cbdecb69250504d0b00bf3a9ac2209e3f6000553aa0e8980489b8d88106af6b7`
- **SHA256:** `b79d5ad4a4b03f9b153d27d356c6e62648fa87c2c378af407b894ed66119b921`
- **SHA256:** `2801ccd00ad4c93afcc23b9f8e5f56a8ddef81c1f4b331978d9b288a69f8ce4d`
- **SHA256:** `93cca0789e92ef11ccc9abd411bdc621a34138aaee4db3241f5266bccc7eac78`

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
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1547.004** — Boot or Logon Autostart Execution: Winlogon Helper DLL / Logon Scripts
- **T1112** — Modify Registry
- **T1140** — Deobfuscate/Decode Files or Information
- **T1055.012** — Process Injection: Process Hollowing
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1105** — Ingress Tool Transfer
- **T1027.003** — Obfuscated Files or Information: Steganography
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1059.005** — Command and Scripting Interpreter: Visual Basic
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1016** — System Network Configuration Discovery
- **T1016.001** — Internet Connection Discovery
- **T1497.001** — Virtualization/Sandbox Evasion: System Checks

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] VIP Keylogger persistence via UserInitMprLogonScript registry value

`UC_3_9` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Registry.registry_value_data) as registry_value_data values(Registry.process_name) as process_name from datamodel=Endpoint.Registry where Registry.registry_path="*\\Environment\\UserInitMprLogonScript*" OR Registry.registry_value_name="UserInitMprLogonScript" by Registry.dest Registry.user Registry.registry_path Registry.registry_value_name | `drop_dm_object_name(Registry)` | where isnotnull(registry_value_data) AND registry_value_data!="" | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryValueName =~ "UserInitMprLogonScript"
| where isnotempty(RegistryValueData)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, RegistryKey, RegistryValueName, RegistryValueData
| order by Timestamp desc
```

### [LLM] VIP Keylogger PowerShell stager hidden in INTERNAL_DB_CACHE environment variable

`UC_3_10` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
(| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Registry.registry_value_data) as registry_value_data from datamodel=Endpoint.Registry where Registry.registry_value_name="INTERNAL_DB_CACHE" OR Registry.registry_path="*\\Environment\\INTERNAL_DB_CACHE*" by Registry.dest Registry.user Registry.process_name Registry.registry_value_name | `drop_dm_object_name(Registry)` | eval source_type="registry") | append [| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process from datamodel=Endpoint.Processes where Processes.process="*INTERNAL_DB_CACHE*" by Processes.dest Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | eval source_type="process"] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
union
(DeviceRegistryEvents
  | where Timestamp > ago(14d)
  | where RegistryValueName =~ "INTERNAL_DB_CACHE" or RegistryKey has @"\Environment\INTERNAL_DB_CACHE"
  | project Timestamp, DeviceName, Channel="Registry", Process=InitiatingProcessFileName, Cmd=InitiatingProcessCommandLine, Parent=InitiatingProcessParentFileName, Detail=strcat(RegistryKey, "\\", RegistryValueName), Payload=substring(RegistryValueData, 0, 256)),
(DeviceProcessEvents
  | where Timestamp > ago(14d)
  | where ProcessCommandLine has "INTERNAL_DB_CACHE"
  | project Timestamp, DeviceName, Channel="Process", Process=FileName, Cmd=ProcessCommandLine, Parent=InitiatingProcessFileName, Detail=InitiatingProcessCommandLine, Payload="")
| order by Timestamp desc
```

### [LLM] aspnet_compiler.exe making outbound public network connections (VIP Keylogger injection target)

`UC_3_11` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dest values(All_Traffic.dest_port) as dest_port values(All_Traffic.url) as url from datamodel=Network_Traffic.All_Traffic where All_Traffic.app="aspnet_compiler.exe" AND All_Traffic.dest_category!="internal" by All_Traffic.src All_Traffic.user All_Traffic.app | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "aspnet_compiler.exe"
| where RemoteIPType == "Public"
| where not(RemoteUrl has_any ("microsoft.com","windowsupdate.com","digicert.com","verisign.com"))
| project Timestamp, DeviceName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessParentFileName, RemoteIP, RemoteUrl, RemotePort, Protocol
| order by Timestamp desc
```

### [LLM] VIP Keylogger steganographic PNG payload download from vault88x.secure-efficient2.su

`UC_3_12` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.http_method) as http_method values(Web.user_agent) as ua values(Web.app) as app from datamodel=Web.Web where (Web.url="*vault88x.secure-efficient2.su*" OR Web.dest="vault88x.secure-efficient2.su" OR Web.url="*MSI_105759.png" OR Web.url="*img_085027.png" OR Web.url="*secure-efficient2.su*") by Web.src Web.user Web.dest | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any ("vault88x.secure-efficient2.su","secure-efficient2.su","MSI_105759.png","img_085027.png")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, RemoteIP, RemoteUrl, RemotePort
| order by Timestamp desc
```

### [LLM] VIP Keylogger loader chain: script-host parent spawning PowerShell that reads environment variables

`UC_3_13` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process) as parent_process from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("wscript.exe","cscript.exe","cmd.exe") AND Processes.process_name IN ("powershell.exe","pwsh.exe") AND (Processes.process="*$env:*" OR Processes.process="*[Environment]::GetEnvironmentVariable*" OR Processes.process="*gci env:*" OR Processes.process="*Get-ChildItem env:*" OR Processes.process="*INTERNAL_DB_CACHE*") AND (Processes.parent_process="*.vbs*" OR Processes.parent_process="*.js*" OR Processes.parent_process="*.bat*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("wscript.exe","cscript.exe","cmd.exe")
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any ("$env:","[Environment]::GetEnvironmentVariable","gci env:","Get-ChildItem env:","INTERNAL_DB_CACHE")
| where InitiatingProcessCommandLine has_any (".vbs",".js",".bat",".vbe",".jse")
| project Timestamp, DeviceName, AccountName, InitiatingProcessParentFileName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### [LLM] VIP Keylogger sandbox / geolocation reconnaissance via reallyfreegeoip and checkip.dyndns from non-browser process

`UC_3_14` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.app) as app from datamodel=Web.Web where (Web.url="*reallyfreegeoip.org/xml*" OR Web.url="*checkip.dyndns.org*" OR Web.dest IN ("reallyfreegeoip.org","checkip.dyndns.org")) AND NOT Web.app IN ("chrome.exe","msedge.exe","firefox.exe","iexplore.exe","brave.exe","opera.exe") by Web.src Web.user Web.dest Web.app | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has_any ("reallyfreegeoip.org/xml","checkip.dyndns.org") or RemoteUrl endswith "reallyfreegeoip.org" or RemoteUrl endswith "checkip.dyndns.org"
| where not(InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe","iexplore.exe","brave.exe","opera.exe","safari.exe"))
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, RemoteIP, RemoteUrl, RemotePort
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

### Article-specific behavioural hunt — Hackers Deploy VIP Keylogger Through Phishing Emails Masquerading as Business Do

`UC_3_8` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Hackers Deploy VIP Keylogger Through Phishing Emails Masquerading as Business Do ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("aspnet_compiler.exe"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("aspnet_compiler.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Hackers Deploy VIP Keylogger Through Phishing Emails Masquerading as Business Do
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("aspnet_compiler.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("aspnet_compiler.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `vault88x.secure-efficient2.su`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `95e6c6c13f65217f41c371abf6d03594b2bfed2259a1813bb4222fb2d3c32745`, `07ee41817b9f338719bea03676ab607349cc3accba0dddb800f6276a01cfdd9f`, `2df582bb41d1e6f0a6d44e8dbc1d8bca8e3d332bb268685b9dfc381a566c63a6`, `8d1f59c65ebe64d0e817ffe7ecbf1d5a4bc3768d896c934b00dfd57263c3fe15`, `8d5de337baa0b0938e4283324d3b1e8ccbdeed694aab3b6118910476200c621b`, `14b25dfcc6e7f69992b3f5543bcc9ebe86bd0b682e211f49cb62c019d8e9bc4d`, `28613bfb4e866186133235a88e318df3059b01001f297ad6a524eab0885305a5`, `d2ab8dcab70822c839912cb672e93de459e5608bea210c78a1be56b54cbd8f81` _(+9 more)_


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 15 use case(s) fired, 25 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

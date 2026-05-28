# [HIGH] New PureLogs Variant Uses MsBuild.exe Process Hollowing to Evade Detection

**Source:** Cyber Security News
**Published:** 2026-05-28
**Article:** https://cybersecuritynews.com/new-purelogs-variant-uses-msbuild-exe-process-hollowing/

## Threat Profile

Home Cyber Security News 
New PureLogs Variant Uses MsBuild.exe Process Hollowing to Evade Detection 
By Tushar Subhra Dutta 
May 28, 2026 




A new and dangerous version of the PureLogs information-stealing malware has emerged, raising serious concerns across the cybersecurity community. 
This variant takes a more evasive approach than its predecessors, using a carefully crafted chain of stages to reach victims without triggering standard security tools. What makes it stand out is how it w…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `77.83.39.211`
- **SHA256:** `3d510977d60a44322f88100b515f06cb5ed83babc64247068d1a489595faa6c5`
- **SHA256:** `670384fafb23140d96f2f8fe04a13fc8cc8e2a6e5e8c973e39b58d103c5fea92`
- **SHA256:** `b90988400cced319d260c4937f334ecc364785ed5c593cd2139965e62ca58173`
- **SHA256:** `e20b35a8c30e076cdd0e1df05ba1ff2e418dbd39a674f084787cc0af2fda9e95`
- **SHA256:** `07cd03e2082bcb0b890cc59ce4c770d1a095ac6f1ae9cf999f5542555c56f841`

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
- **T1053.005** — Scheduled Task
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1059.007** — JavaScript
- **T1620** — Reflective Code Loading
- **T1218.014** — MMC / MSBuild
- **T1055.012** — Process Hollowing
- **T1055** — Process Injection
- **T1552.001** — Credentials In Files
- **T1573.002** — Asymmetric Cryptography
- **T1041** — Exfiltration Over C2 Channel

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Purchase-order phishing delivering pankocrs.js JavaScript loader

`UC_0_11` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Email.All_Email where All_Email.file_name="pankocrs.js" OR (All_Email.file_name="*.js" AND (All_Email.subject IN ("*purchase order*","*invoice*","*PO #*","*quotation*"))) by All_Email.src_user All_Email.recipient All_Email.subject All_Email.file_name | `drop_dm_object_name(All_Email)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let lures = dynamic(["purchase order","purchase-order","invoice","quotation","PO#","order confirmation"]);
EmailAttachmentInfo
| where Timestamp > ago(14d)
| where FileName =~ "pankocrs.js" or (FileName endswith ".js" and FileType in~ ("js","javascript","zip","rar","7z"))
| join kind=inner (EmailEvents | where Timestamp > ago(14d)) on NetworkMessageId
| where FileName =~ "pankocrs.js" or Subject has_any (lures)
| project Timestamp, NetworkMessageId, SenderFromAddress, RecipientEmailAddress, Subject, FileName, FileType, SHA256, DeliveryAction
| order by Timestamp desc
```

### [LLM] wscript/cscript spawning PowerShell that loads .NET assembly (PureLogs stage 2)

`UC_0_12` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("wscript.exe","cscript.exe") AND Processes.process_name="powershell.exe" AND (Processes.parent_process="*pankocrs.js*" OR Processes.parent_process="*.js*" OR Processes.process="*ps_qnSEGUkU0LIY*" OR Processes.process="*Reflection.Assembly*" OR Processes.process="*Invoke-AssemblyMethod*" OR Processes.process="*IEX*") by host Processes.user Processes.parent_process Processes.process Processes.process_path | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("wscript.exe","cscript.exe")
| where FileName =~ "powershell.exe"
| where InitiatingProcessCommandLine has_any ("pankocrs.js",".js")
| where ProcessCommandLine has_any ("Reflection.Assembly","Invoke-AssemblyMethod","IEX","Invoke-Expression","FromBase64String","ps_qnSEGUkU0LIY")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### [LLM] PowerShell launching MsBuild.exe with no project file (PureLogs hollowing target)

`UC_0_13` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name="powershell.exe" AND Processes.process_name="MSBuild.exe" by host Processes.user Processes.parent_process Processes.process Processes.process_path | `drop_dm_object_name(Processes)` | search NOT process IN ("*.csproj*","*.sln*","*.xml*","*.proj*","*.vbproj*","*.targets*")
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName =~ "msbuild.exe"
| where InitiatingProcessFileName in~ ("powershell.exe","pwsh.exe","wscript.exe","cscript.exe")
| where not (ProcessCommandLine has_any (".csproj",".sln",".vbproj",".proj",".targets",".xml"))
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### [LLM] Cross-process injection (CreateRemoteThread / WriteProcessMemory) targeting MsBuild.exe

`UC_0_14` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="MSBuild.exe") by host Processes.parent_process_name Processes.process_name Processes.process Processes.user | `drop_dm_object_name(Processes)` | join host process_name [ search index=sysmon (EventCode=8 OR EventCode=10) TargetImage="*MSBuild.exe*" SourceImage!="*\\devenv.exe" SourceImage!="*\\dotnet.exe" SourceImage!="*\\VBCSCompiler.exe" | stats values(SourceImage) as InjectorImage values(EventCode) as InjectionEvents by host TargetImage ]
```

**Defender KQL:**
```kql
DeviceEvents
| where Timestamp > ago(14d)
| where ActionType in ("CreateRemoteThreadApiCall","ReadProcessMemoryApiCall","WriteToLsassProcessMemory","ProcessPrimaryTokenModified")
| where FileName =~ "msbuild.exe" or FolderPath has "\\MSBuild.exe"
| where InitiatingProcessFileName !in~ ("devenv.exe","dotnet.exe","VBCSCompiler.exe","MSBuild.exe")
| project Timestamp, DeviceName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, FolderPath, AdditionalFields
| order by Timestamp desc
```

### [LLM] MsBuild.exe reading browser Login Data / wallet / mail credential stores

`UC_0_15` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.process_name="MSBuild.exe" AND (Filesystem.file_path="*\\Microsoft\\Edge\\User Data\\*\\Login Data*" OR Filesystem.file_path="*\\Google\\Chrome\\User Data\\*\\Login Data*" OR Filesystem.file_path="*\\Mozilla\\Firefox\\Profiles\\*\\logins.json" OR Filesystem.file_path="*\\Exodus\\*" OR Filesystem.file_path="*\\Electrum\\wallets\\*" OR Filesystem.file_path="*\\Atomic\\*" OR Filesystem.file_path="*wallet.dat*" OR Filesystem.file_path="*\\Thunderbird\\Profiles\\*" OR Filesystem.file_path="*\\Foxmail\\*" OR Filesystem.file_path="*\\FileZilla\\recentservers.xml" OR Filesystem.file_path="*\\OpenVPN\\config\\*" OR Filesystem.file_path="*\\ProtonVPN\\*") by host Filesystem.user Filesystem.process_name Filesystem.file_path | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName =~ "msbuild.exe"
| where FolderPath has_any (
    "\\Microsoft\\Edge\\User Data\\",
    "\\Google\\Chrome\\User Data\\",
    "\\Mozilla\\Firefox\\Profiles\\",
    "\\BraveSoftware\\",
    "\\CocCoc\\",
    "\\Kinza\\",
    "\\Exodus\\",
    "\\Electrum\\wallets\\",
    "\\Atomic\\",
    "wallet.dat",
    "\\Thunderbird\\Profiles\\",
    "\\Foxmail\\",
    "\\FileZilla\\",
    "\\OpenVPN\\config\\",
    "\\ProtonVPN\\"
  )
  or FileName in~ ("Login Data","logins.json","wallet.dat","recentservers.xml","cookies.sqlite","key4.db")
| project Timestamp, DeviceName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, FolderPath
| order by Timestamp desc
```

### [LLM] MsBuild.exe HTTPS C2 beacon to 77.83.39.211 (PureLogs exfil)

`UC_0_16` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.app="MSBuild.exe" AND (All_Traffic.dest_ip="77.83.39.211" OR All_Traffic.dest_category="public") by host All_Traffic.user All_Traffic.app All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.bytes_out | `drop_dm_object_name(All_Traffic)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName =~ "msbuild.exe"
| where RemoteIPType == "Public"
| where RemoteIP == "77.83.39.211" or RemotePort in (443, 80, 8080, 8443)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, Protocol
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

### Article-specific behavioural hunt — New PureLogs Variant Uses MsBuild.exe Process Hollowing to Evade Detection

`UC_0_10` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — New PureLogs Variant Uses MsBuild.exe Process Hollowing to Evade Detection ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("msbuild.exe","pankocrs.js","ps_qnseguku0liy_1777592585573.ps1","zgsgkyyzqve.dll") OR Processes.process="*Invoke-Expression*" OR Processes.process_path="*%LocalAppData%\Microsoft\Edge\User*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*%LocalAppData%\Microsoft\Edge\User*" OR Filesystem.file_name IN ("msbuild.exe","pankocrs.js","ps_qnseguku0liy_1777592585573.ps1","zgsgkyyzqve.dll"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — New PureLogs Variant Uses MsBuild.exe Process Hollowing to Evade Detection
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("msbuild.exe", "pankocrs.js", "ps_qnseguku0liy_1777592585573.ps1", "zgsgkyyzqve.dll") or ProcessCommandLine has_any ("Invoke-Expression") or FolderPath has_any ("%LocalAppData%\Microsoft\Edge\User"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("%LocalAppData%\Microsoft\Edge\User") or FileName in~ ("msbuild.exe", "pankocrs.js", "ps_qnseguku0liy_1777592585573.ps1", "zgsgkyyzqve.dll"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `77.83.39.211`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `3d510977d60a44322f88100b515f06cb5ed83babc64247068d1a489595faa6c5`, `670384fafb23140d96f2f8fe04a13fc8cc8e2a6e5e8c973e39b58d103c5fea92`, `b90988400cced319d260c4937f334ecc364785ed5c593cd2139965e62ca58173`, `e20b35a8c30e076cdd0e1df05ba1ff2e418dbd39a674f084787cc0af2fda9e95`, `07cd03e2082bcb0b890cc59ce4c770d1a095ac6f1ae9cf999f5542555c56f841`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 17 use case(s) fired, 23 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

# [HIGH] MiniUpdate RAT Uses Azure-Hosted C2 Domains for Targeted Espionage Campaigns

**Source:** Cyber Security News
**Published:** 2026-05-25
**Article:** https://cybersecuritynews.com/miniupdate-rat-uses-azure-hosted-c2-domains/

## Threat Profile

Home Cyber Security News 
MiniUpdate RAT Uses Azure-Hosted C2 Domains for Targeted Espionage Campaigns 
By Tushar Subhra Dutta 
May 25, 2026 
A new wave of targeted espionage attacks has put technology professionals across the United States, Israel, and the United Arab Emirates on high alert. 
The threat comes from an Iran-linked hacking group deploying two families of remote access trojans through cleverly disguised recruitment lures and fake software installers. 
The campaign began as early as…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `buisness-centeral-transportation.com`
- **Domain (defanged):** `premierhealthadvisory.com`
- **Domain (defanged):** `ramiltonsfinance.com`
- **Domain (defanged):** `business-startup.org`
- **Domain (defanged):** `docspace-y4cumb.onlyoffice.com`
- **Domain (defanged):** `docspace-twpf0e.onlyoffice.com`
- **Domain (defanged):** `2117.filemail.com`
- **SHA256:** `44f4f7aca7f1d9bfdaf7b3736934cbe19f851a707662f8f0b0c49b383e054250`
- **SHA256:** `332ba2f0297dfb1599adecc3e9067893e7cf243aa23aedce4906a4c480574c17`
- **SHA256:** `0db36a04d304ad96f9e6f97b531934594cd95a5cea9ff2c9af249201089dc864`
- **SHA256:** `38bd137c672bd58d08c4f0502f993a6561e2c3411773d1ae57ee0151a0a9d11d`
- **SHA256:** `d4a7e9f107fe40c1a5d0139c6c6e25bf6bf57f61feff090bee28f476bb3cc3c2`
- **SHA256:** `bc3b44154518c5794ce639108e7b9c5fecb0c189607a26de1aaed518d890c7ad`
- **SHA256:** `74882085db2088356ed7f72f01e0404a0a98cda88ef56fb15ce74c1f36b26d27`
- **SHA256:** `9cf029daca89523d917dafed0568d11d00e45ec96b5b90b4a1f7fd4018c7da84`
- **SHA256:** `b19e06da580cf91691eda066ac9ee4b09c6e5dc26c367af12660fe1f9306eec4`
- **SHA256:** `8808c794c24367438f183e4be941876f1d3ecd0c8d2eb43b10d2380841d2283b`
- **SHA256:** `43dc62cef52ebdd69e79f10015b3e13890f26c058325c0ff139c70f8d8eadcfa`
- **SHA256:** `9e4a658e6d831c9e9bdfe11884a75b7c64812ed0a80e8495ddf6b316505acac1`

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
- **T1195.002** — Compromise Software Supply Chain
- **T1053.005** — Persistence (article-specific)
- **T1543.003** — Persistence (article-specific)
- **T1204.002** — Malicious File
- **T1574.002** — DLL Side-Loading
- **T1574.014** — AppDomainManager
- **T1562.006** — Indicator Blocking
- **T1583.006** — Web Services
- **T1105** — Ingress Tool Transfer
- **T1608.001** — Upload Malware

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Screening Serpens MiniUpdate/MiniJunk V2 known file hashes on disk or executed

`UC_14_11` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("44f4f7aca7f1d9bfdaf7b3736934cbe19f851a707662f8f0b0c49b383e054250","332ba2f0297dfb1599adecc3e9067893e7cf243aa23aedce4906a4c480574c17","0db36a04d304ad96f9e6f97b531934594cd95a5cea9ff2c9af249201089dc864","38bd137c672bd58d08c4f0502f993a6561e2c3411773d1ae57ee0151a0a9d11d","d4a7e9f107fe40c1a5d0139c6c6e25bf6bf57f61feff090bee28f476bb3cc3c2","bc3b44154518c5794ce639108e7b9c5fecb0c189607a26de1aaed518d890c7ad","74882085db2088356ed7f72f01e0404a0a98cda88ef56fb15ce74c1f36b26d27","9cf029daca89523d917dafed0568d11d00e45ec96b5b90b4a1f7fd4018c7da84","b19e06da580cf91691eda066ac9ee4b09c6e5dc26c367af12660fe1f9306eec4","8808c794c24367438f183e4be941876f1d3ecd0c8d2eb43b10d2380841d2283b","43dc62cef52ebdd69e79f10015b3e13890f26c058325c0ff139c70f8d8eadcfa") by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let badHashes = dynamic(["44f4f7aca7f1d9bfdaf7b3736934cbe19f851a707662f8f0b0c49b383e054250","332ba2f0297dfb1599adecc3e9067893e7cf243aa23aedce4906a4c480574c17","0db36a04d304ad96f9e6f97b531934594cd95a5cea9ff2c9af249201089dc864","38bd137c672bd58d08c4f0502f993a6561e2c3411773d1ae57ee0151a0a9d11d","d4a7e9f107fe40c1a5d0139c6c6e25bf6bf57f61feff090bee28f476bb3cc3c2","bc3b44154518c5794ce639108e7b9c5fecb0c189607a26de1aaed518d890c7ad","74882085db2088356ed7f72f01e0404a0a98cda88ef56fb15ce74c1f36b26d27","9cf029daca89523d917dafed0568d11d00e45ec96b5b90b4a1f7fd4018c7da84","b19e06da580cf91691eda066ac9ee4b09c6e5dc26c367af12660fe1f9306eec4","8808c794c24367438f183e4be941876f1d3ecd0c8d2eb43b10d2380841d2283b","43dc62cef52ebdd69e79f10015b3e13890f26c058325c0ff139c70f8d8eadcfa"]);
union
  (DeviceFileEvents | where Timestamp > ago(30d) | where SHA256 in (badHashes) | project Timestamp, DeviceName, Evt=ActionType, FileName, FolderPath, SHA256, Initiator=InitiatingProcessFileName, Acct=InitiatingProcessAccountName),
  (DeviceProcessEvents | where Timestamp > ago(30d) | where SHA256 in (badHashes) | project Timestamp, DeviceName, Evt="ProcessExec", FileName, FolderPath, SHA256, Initiator=InitiatingProcessFileName, Acct=AccountName)
| order by Timestamp desc
```

### [LLM] MiniUpdate/MiniJunk V2 DLL side-loading - trusted binary loads UpdateChecker/Connection/uevmonitor/unbcl DLL

`UC_14_12` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name IN ("UpdateChecker.dll","Connection.dll","uevmonitor.dll","unbcl.dll") OR Filesystem.file_hash IN ("0db36a04d304ad96f9e6f97b531934594cd95a5cea9ff2c9af249201089dc864","d4a7e9f107fe40c1a5d0139c6c6e25bf6bf57f61feff090bee28f476bb3cc3c2","bc3b44154518c5794ce639108e7b9c5fecb0c189607a26de1aaed518d890c7ad","9cf029daca89523d917dafed0568d11d00e45ec96b5b90b4a1f7fd4018c7da84","b19e06da580cf91691eda066ac9ee4b09c6e5dc26c367af12660fe1f9306eec4","43dc62cef52ebdd69e79f10015b3e13890f26c058325c0ff139c70f8d8eadcfa")) AND (Filesystem.file_path="*\\Users\\*" OR Filesystem.file_path="*\\Temp\\*" OR Filesystem.file_path="*\\AppData\\*" OR Filesystem.file_path="*\\ProgramData\\*") by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let dllHashes = dynamic(["0db36a04d304ad96f9e6f97b531934594cd95a5cea9ff2c9af249201089dc864","d4a7e9f107fe40c1a5d0139c6c6e25bf6bf57f61feff090bee28f476bb3cc3c2","bc3b44154518c5794ce639108e7b9c5fecb0c189607a26de1aaed518d890c7ad","9cf029daca89523d917dafed0568d11d00e45ec96b5b90b4a1f7fd4018c7da84","b19e06da580cf91691eda066ac9ee4b09c6e5dc26c367af12660fe1f9306eec4","43dc62cef52ebdd69e79f10015b3e13890f26c058325c0ff139c70f8d8eadcfa"]);
DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where FileName in~ ("UpdateChecker.dll","Connection.dll","uevmonitor.dll","unbcl.dll") or SHA256 in (dllHashes)
| where FolderPath has_any (@"\Users\", @"\Temp\", @"\AppData\", @"\ProgramData\", @"\Downloads\")
| project Timestamp, DeviceName, HostProcess=InitiatingProcessFileName, HostPath=InitiatingProcessFolderPath, HostCmd=InitiatingProcessCommandLine, LoadedDll=FileName, LoadedPath=FolderPath, SHA256
| order by Timestamp desc
```

### [LLM] AppDomainManager hijack - .NET .config dropped to disable ETW / bypass signature checks

`UC_14_13` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name="*.config" AND (Filesystem.file_path="*\\Users\\*" OR Filesystem.file_path="*\\Temp\\*" OR Filesystem.file_path="*\\AppData\\*" OR Filesystem.file_path="*\\Downloads\\*" OR Filesystem.file_path="*\\ProgramData\\*") by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)` | where process_name IN ("explorer.exe","7zFM.exe","7zG.exe","WinRAR.exe","Rar.exe","powershell.exe","cmd.exe") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FileName endswith ".config"
| where FolderPath has_any (@"\Users\", @"\AppData\", @"\Temp\", @"\Downloads\", @"\ProgramData\")
| where InitiatingProcessFileName in~ ("explorer.exe","7zFM.exe","7zG.exe","winrar.exe","rar.exe","powershell.exe","cmd.exe","wscript.exe")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### [LLM] MiniUpdate persistence - daily 09:30 scheduled task creation

`UC_14_14` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="schtasks.exe" AND Processes.process="*/create*" AND Processes.process="*09:30*" by Processes.dest Processes.user Processes.parent_process_name Processes.process | `drop_dm_object_name(Processes)` | where match(process,"(?i)/sc\s+daily") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create" and ProcessCommandLine has "09:30"
| where ProcessCommandLine has_any ("/sc daily","/SC DAILY","/sc DAILY")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, ProcessCommandLine
| order by Timestamp desc
```

### [LLM] Screening Serpens C2 beacon to per-target Azure (azurewebsites.net) and apex domains

`UC_14_15` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query IN ("licencemanagers.azurewebsites.net","licencesupporting.azurewebsites.net","peerdistsvcmanagers.azurewebsites.net","themesmanagers.azurewebsites.net","themesprovidermanagers.azurewebsites.net","nanomatrix.azurewebsites.net","quantumweave.azurewebsites.net","elementshift.azurewebsites.net","buisness-centeral.azurewebsites.net","buisness-centeral-transportation.azurewebsites.net","premierhealthadvisory.azurewebsites.net","premier-healthadvisory.azurewebsites.net","ramiltonsfinance.azurewebsites.net","ramiltons-finance.azurewebsites.net","business-startup.azurewebsites.net","buisness-centeral-transportation.com","premierhealthadvisory.com","ramiltonsfinance.com","business-startup.org") by DNS.src DNS.dest DNS.query | `drop_dm_object_name(DNS)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let c2 = dynamic(["licencemanagers.azurewebsites.net","licencesupporting.azurewebsites.net","peerdistsvcmanagers.azurewebsites.net","themesmanagers.azurewebsites.net","themesprovidermanagers.azurewebsites.net","nanomatrix.azurewebsites.net","quantumweave.azurewebsites.net","elementshift.azurewebsites.net","buisness-centeral.azurewebsites.net","buisness-centeral-transportation.azurewebsites.net","premierhealthadvisory.azurewebsites.net","premier-healthadvisory.azurewebsites.net","ramiltonsfinance.azurewebsites.net","ramiltons-finance.azurewebsites.net","business-startup.azurewebsites.net","buisness-centeral-transportation.com","premierhealthadvisory.com","ramiltonsfinance.com","business-startup.org"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any (c2)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessCommandLine
| order by Timestamp desc
```

### [LLM] MiniJunk V2 payload pull from ONLYOFFICE DocSpace and Filemail delivery URLs

`UC_14_16` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*docspace-y4cumb.onlyoffice.com*" OR Web.url="*docspace-twpf0e.onlyoffice.com*" OR Web.url="*2117.filemail.com/api/file/get*") AND (Web.url="*content.zip*" OR Web.url="*filekey=*") by Web.src Web.dest Web.url Web.http_user_agent | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any ("docspace-y4cumb.onlyoffice.com","docspace-twpf0e.onlyoffice.com","2117.filemail.com")
| where RemoteUrl has_any ("content.zip","/api/file/get","filekey=")
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessCommandLine
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

### Article-specific behavioural hunt — MiniUpdate RAT Uses Azure-Hosted C2 Domains for Targeted Espionage Campaigns

`UC_14_10` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — MiniUpdate RAT Uses Azure-Hosted C2 Domains for Targeted Espionage Campaigns ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("updatechecker.dll","uevmonitor.dll","unbcl.dll","connection.dll"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("updatechecker.dll","uevmonitor.dll","unbcl.dll","connection.dll"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — MiniUpdate RAT Uses Azure-Hosted C2 Domains for Targeted Espionage Campaigns
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("updatechecker.dll", "uevmonitor.dll", "unbcl.dll", "connection.dll"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("updatechecker.dll", "uevmonitor.dll", "unbcl.dll", "connection.dll"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `buisness-centeral-transportation.com`, `premierhealthadvisory.com`, `ramiltonsfinance.com`, `business-startup.org`, `docspace-y4cumb.onlyoffice.com`, `docspace-twpf0e.onlyoffice.com`, `2117.filemail.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `44f4f7aca7f1d9bfdaf7b3736934cbe19f851a707662f8f0b0c49b383e054250`, `332ba2f0297dfb1599adecc3e9067893e7cf243aa23aedce4906a4c480574c17`, `0db36a04d304ad96f9e6f97b531934594cd95a5cea9ff2c9af249201089dc864`, `38bd137c672bd58d08c4f0502f993a6561e2c3411773d1ae57ee0151a0a9d11d`, `d4a7e9f107fe40c1a5d0139c6c6e25bf6bf57f61feff090bee28f476bb3cc3c2`, `bc3b44154518c5794ce639108e7b9c5fecb0c189607a26de1aaed518d890c7ad`, `74882085db2088356ed7f72f01e0404a0a98cda88ef56fb15ce74c1f36b26d27`, `9cf029daca89523d917dafed0568d11d00e45ec96b5b90b4a1f7fd4018c7da84` _(+4 more)_


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 17 use case(s) fired, 23 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

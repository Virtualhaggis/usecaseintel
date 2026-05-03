# [CRIT] Attackers Abuse CAPTCHA and ClickFix Tactics to Boost Credential Theft Campaigns

**Source:** Cyber Security News
**Published:** 2026-05-01
**Article:** https://cybersecuritynews.com/attackers-abuse-captcha-and-clickfix-tactics/

## Threat Profile

Home Cyber Security News 
Attackers Abuse CAPTCHA and ClickFix Tactics to Boost Credential Theft Campaigns 
By Tushar Subhra Dutta 
May 1, 2026 
Cybercriminals are no longer relying on simple email tricks alone. Across the first quarter of 2026, attackers have been sharpening their approach by using CAPTCHA pages and ClickFix techniques to supercharge credential theft operations at an alarming scale. 
During Q1 2026, Microsoft Threat Intelligence tracked approximately 8.3 billion email-based phi…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1027.006** — HTML Smuggling
- **T1218.005** — Mshta
- **T1112** — Modify Registry

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] SVG email attachment opened by browser from Outlook cache (Q1 2026 CAPTCHA phishing wave)

`UC_21_7` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.file_name) as file_name from datamodel=Endpoint.Filesystem where Filesystem.action=created Filesystem.process_name=outlook.exe Filesystem.file_name="*.svg" Filesystem.file_path IN ("*\\Content.Outlook\\*","*\\INetCache\\Content.Outlook\\*","*\\Temporary Internet Files\\Content.Outlook\\*") by host Filesystem.user Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | join type=inner host [| tstats `summariesonly` count values(Processes.process) as svg_open_cmd from datamodel=Endpoint.Processes where Processes.parent_process_name=outlook.exe Processes.process_name IN ("msedge.exe","chrome.exe","firefox.exe","brave.exe","iexplore.exe","opera.exe") Processes.process="*.svg*" by host Processes.user | `drop_dm_object_name(Processes)`] | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let LookbackDays = 7d;
let OutlookSvgDrops = DeviceFileEvents
    | where Timestamp > ago(LookbackDays)
    | where ActionType == "FileCreated"
    | where InitiatingProcessFileName =~ "outlook.exe"
    | where FileName endswith ".svg"
    | where FolderPath has_any (@"\Content.Outlook\", @"\INetCache\Content.Outlook\", @"\Temporary Internet Files\Content.Outlook\")
    | project DropTime = Timestamp, DeviceId, DeviceName,
              SvgPath = FolderPath, SvgName = FileName, SvgSha256 = SHA256,
              UserName = InitiatingProcessAccountName;
OutlookSvgDrops
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(LookbackDays)
    | where InitiatingProcessFileName =~ "outlook.exe"
    | where FileName in~ ("msedge.exe","chrome.exe","firefox.exe","brave.exe","iexplore.exe","opera.exe")
    | where ProcessCommandLine has ".svg"
    | where ProcessCommandLine has_any (@"\Content.Outlook\", @"\INetCache\Content.Outlook\")
    | project BrowserTime = Timestamp, DeviceId, DeviceName,
              BrowserCmd = ProcessCommandLine, BrowserBin = FileName,
              UserName = AccountName
  ) on DeviceId
| where BrowserTime between (DropTime .. DropTime + 5m)
| project DropTime, BrowserTime,
          DelaySec = datetime_diff('second', BrowserTime, DropTime),
          DeviceName, UserName, SvgName, SvgPath, SvgSha256,
          BrowserBin, BrowserCmd
| order by BrowserTime desc
```

### [LLM] ClickFix RunMRU paste correlated to LOLBin spawn from explorer.exe within 60s

`UC_21_8` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process_cmd values(Processes.parent_process) as parent_cmd values(Processes.process_name) as process_name from datamodel=Endpoint.Processes where Processes.parent_process_name=explorer.exe Processes.process_name IN ("mshta.exe","powershell.exe","pwsh.exe","cmd.exe","rundll32.exe","regsvr32.exe","wscript.exe","cscript.exe","curl.exe","wget.exe","certutil.exe","bitsadmin.exe","finger.exe","msiexec.exe") (Processes.process="*http://*" OR Processes.process="*https://*" OR Processes.process="*iwr *" OR Processes.process="*irm *" OR Processes.process="*iex*" OR Processes.process="*Invoke-Expression*" OR Processes.process="*DownloadString*" OR Processes.process="*FromBase64String*" OR Processes.process="*-enc*" OR Processes.process="*-EncodedCommand*") by host Processes.user Processes.process_name Processes.process Processes.parent_process | `drop_dm_object_name(Processes)` | join type=inner host [| tstats `summariesonly` count values(Registry.registry_value_data) as runmru_value from datamodel=Endpoint.Registry where Registry.action=modified Registry.registry_path="*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU*" (Registry.registry_value_data="*http*" OR Registry.registry_value_data="*mshta*" OR Registry.registry_value_data="*powershell*" OR Registry.registry_value_data="*curl *" OR Registry.registry_value_data="*certutil*" OR Registry.registry_value_data="*rundll32*") by host Registry.user] | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let LookbackDays = 7d;
let WindowSec = 60;
let RunMRUClickFix = DeviceRegistryEvents
    | where Timestamp > ago(LookbackDays)
    | where ActionType == "RegistryValueSet"
    | where RegistryKey has @"\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
    | where RegistryValueName !~ "MRUList"
    | where RegistryValueData has_any ("http://","https://","mshta","powershell","pwsh","curl ","wget ","certutil","bitsadmin","rundll32","regsvr32","cscript","wscript","finger ","%comspec%","\\1")  // \\1 = the trailing MRU char
    | project RegTime = Timestamp, DeviceId, DeviceName,
              RunMRUUser = InitiatingProcessAccountName,
              RunMRUValue = RegistryValueData;
DeviceProcessEvents
| where Timestamp > ago(LookbackDays)
| where InitiatingProcessFileName =~ "explorer.exe"
| where AccountName !endswith "$"
| where FileName in~ ("mshta.exe","powershell.exe","pwsh.exe","cmd.exe","rundll32.exe","regsvr32.exe","wscript.exe","cscript.exe","curl.exe","wget.exe","certutil.exe","bitsadmin.exe","finger.exe","msiexec.exe")
| where ProcessCommandLine has_any ("http://","https://","iwr ","irm ","iex","Invoke-Expression","DownloadString","DownloadFile","FromBase64String","-enc","-EncodedCommand","-w hidden","-WindowStyle Hidden")
| join kind=inner RunMRUClickFix on DeviceId
| where Timestamp between (RegTime .. RegTime + WindowSec * 1s)
| project RegTime, ProcTime = Timestamp,
          DelaySec = datetime_diff('second', Timestamp, RegTime),
          DeviceName, AccountName,
          ChildBin = FileName, ChildCmd = ProcessCommandLine,
          RunMRUValue, RunMRUUser
| order by ProcTime desc
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


## Why this matters

Severity classified as **CRIT** based on: 9 use case(s) fired, 16 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

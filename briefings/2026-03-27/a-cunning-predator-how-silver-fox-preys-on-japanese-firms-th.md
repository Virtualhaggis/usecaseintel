# [HIGH] A cunning predator: How Silver Fox preys on Japanese firms this tax season

**Source:** ESET WeLiveSecurity
**Published:** 2026-03-27
**Article:** https://www.welivesecurity.com/en/business-security/cunning-predator-how-silver-fox-preys-japanese-firms-tax-season/

## Threat Profile

Japan has entered its annual tax filing and organizational change season, a period when companies generate a high volume of legitimate financial and HR‑related communications. A threat actor known as Silver Fox is actively exploiting this busy period by conducting a targeted spearphishing campaign against Japanese manufacturers and other businesses.
The ongoing campaign uses convincing phishing lures related to tax compliance violations, salary adjustments, job position changes, and employee sto…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `gofile.io`

## MITRE ATT&CK Techniques

- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1071** — Application Layer Protocol
- **T1548.002** — Abuse Elevation Control Mechanism: Bypass User Account Control
- **T1112** — Modify Registry
- **T1546.015** — Event Triggered Execution: Component Object Model Hijacking
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1547.001** — Registry Run Keys / Startup Folder

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Silver Fox Japanese tax/HR spearphishing with gofile.io or WeTransfer payload

`UC_156_5` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Email WHERE (All_Email.subject="*従業員持株会*" OR All_Email.subject="*人事異動*" OR All_Email.subject="*給与改定*" OR All_Email.subject="*給与調整*" OR All_Email.subject="*税務コンプライアンス*" OR All_Email.subject="*罰金通知*" OR All_Email.subject="*Salary Adjustment*" OR All_Email.subject="*Personnel Changes*" OR All_Email.subject="*ESOP*") BY All_Email.src_user All_Email.recipient All_Email.subject All_Email.file_name All_Email.url All_Email.message_id | `drop_dm_object_name("All_Email")` | where like(url,"%gofile.io%") OR like(url,"%wetransfer.com%") OR like(url,"%we.tl%") OR match(file_name,"(?i)\.(rar|zip|7z)$") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let suspectSubjects = dynamic(["従業員持株会","人事異動","給与改定","給与調整","税務コンプライアンス","罰金通知","Salary Adjustment","Personnel Changes","ESOP"]);
let suspectHosts = dynamic(["gofile.io","wetransfer.com","we.tl"]);
let candidates = EmailEvents
| where Timestamp > ago(30d)
| where Subject has_any (suspectSubjects);
candidates
| join kind=leftouter (EmailUrlInfo | project NetworkMessageId, Url, UrlDomain) on NetworkMessageId
| join kind=leftouter (EmailAttachmentInfo | project NetworkMessageId, FileName, FileType, SHA256) on NetworkMessageId
| where (UrlDomain has_any (suspectHosts)) or (FileName matches regex @"(?i)\.(rar|zip|7z)$")
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderMailFromDomain, RecipientEmailAddress, Subject, UrlDomain, Url, FileName, FileType, SHA256
| sort by Timestamp desc
```

### [LLM] ValleyRAT fodhelper UAC bypass via HKCU .pwn shell open command

`UC_156_6` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Registry WHERE (All_Registry.registry_path="*\\Software\\Classes\\.pwn\\Shell\\Open\\Command*" OR All_Registry.registry_path="*\\Software\\Classes\\ms-settings\\CurVer*") BY All_Registry.dest All_Registry.user All_Registry.registry_path All_Registry.registry_value_name All_Registry.registry_value_data All_Registry.process_name All_Registry.process_guid | `drop_dm_object_name("All_Registry")` | join type=outer dest [| tstats summariesonly=t count as fodhelper_spawns FROM datamodel=Endpoint.Processes WHERE Processes.process_name="fodhelper.exe" BY Processes.dest Processes.process_id Processes.parent_process_name | `drop_dm_object_name("Processes")`] | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let regHits = DeviceRegistryEvents
| where Timestamp > ago(7d)
| where (RegistryKey has @"\Software\Classes\.pwn\Shell\Open\Command")
   or (RegistryKey has @"\Software\Classes\ms-settings\CurVer" and RegistryValueData has ".pwn")
| project regTime=Timestamp, DeviceId, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessSHA256;
let fodSpawn = DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "fodhelper.exe"
| project fodTime=Timestamp, DeviceId, DeviceName, FileName, ProcessCommandLine, ProcessIntegrityLevel, InitiatingProcessFileName;
regHits
| join kind=leftouter fodSpawn on DeviceId
| where isnull(fodTime) or (fodTime between ((regTime) .. (regTime + 30m)))
| project regTime, DeviceName, RegistryKey, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine, fodTime, FileName, ProcessCommandLine, ProcessIntegrityLevel
| sort by regTime desc
```

### [LLM] ValleyRAT C2 configuration persistence in HKCU\Software\Console IpDate keys

`UC_156_7` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Registry WHERE (All_Registry.registry_path="*\\Software\\Console\\IpDate*" OR All_Registry.registry_path="*\\Software\\Console\\IpDateInfo*" OR All_Registry.registry_path="*\\Software\\Console\\SelfPath*") BY All_Registry.dest All_Registry.user All_Registry.registry_path All_Registry.registry_value_name All_Registry.registry_value_data All_Registry.process_name All_Registry.process_path | `drop_dm_object_name("All_Registry")` | eval likely_c2 = if(match(registry_value_data,"(?i)i:\d{1,3}(\.\d{1,3}){3}\|p:\d+"),1,0) | where likely_c2=1 OR registry_path="*\\IpDate*" | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where RegistryKey has @"\Software\Console" and (RegistryValueName in~ ("IpDate","IpDateInfo","SelfPath") or RegistryKey has_any ("IpDate","IpDateInfo","SelfPath"))
| extend likelyC2 = iff(RegistryValueData matches regex @"(?i)i:\d{1,3}(\.\d{1,3}){3}\|p:\d+", 1, 0)
| project Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData, likelyC2, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessSHA256
| join kind=leftouter (
    DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteUrl has "baidu.com" or RemotePort in (5689, 8080, 443)
    | summarize beacons=count(), distinctIPs=dcount(RemoteIP) by DeviceName, InitiatingProcessFileName
) on DeviceName
| sort by Timestamp desc
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
| where InitiatingProcessFileName in~ ("explorer.exe","RuntimeBroker.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","mshta.exe")
| where ProcessCommandLine matches regex @"(?i)(iex|invoke-expression|frombase64|downloadstring|hxxp|curl |wget )"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `gofile.io`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 8 use case(s) fired, 14 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

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
- **T1105** — Ingress Tool Transfer
- **T1547.001** — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- **T1112** — Modify Registry
- **T1027.013** — Encrypted/Encoded File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Silver Fox Japan tax-season lure: inbound email with Japanese HR/ESOP subject + gofile.io URL or RAR/ZIP

`UC_247_5` · phase: **delivery** · confidence: **High**

**Defender KQL:**
```kql
let LookbackDays = 14d;
let JpLureSubjectFragments = dynamic(["従業員持株会","人事異動","給与改定","給与調整","税務コンプライアンス","罰金通知","持株会規約"]);
let ArchiveTypes = dynamic(["rar","zip","RAR","ZIP","7z","7Z"]);
let SuspectMail = EmailEvents
    | where Timestamp > ago(LookbackDays)
    | where EmailDirection == "Inbound"
    | where DeliveryAction in ("Delivered","DeliveredAsSpam")
    | where Subject contains "従業員持株会"
        or Subject contains "人事異動"
        or Subject contains "給与改定"
        or Subject contains "給与調整"
        or Subject contains "税務コンプライアンス"
        or Subject contains "罰金通知"
        or Subject contains "持株会規約"
    | project Timestamp, NetworkMessageId, SenderFromAddress, SenderMailFromAddress, SenderDisplayName, RecipientEmailAddress, Subject, AuthenticationDetails;
let UrlSide = SuspectMail
    | join kind=inner (
        EmailUrlInfo
        | where Timestamp > ago(LookbackDays)
        | where UrlDomain has_any ("gofile.io","wetransfer.com","we.tl")
        | project NetworkMessageId, Url, UrlDomain, UrlLocation
      ) on NetworkMessageId
    | extend Vector = strcat("URL:", UrlDomain), Indicator = Url;
let AttachSide = SuspectMail
    | join kind=inner (
        EmailAttachmentInfo
        | where Timestamp > ago(LookbackDays)
        | where FileType in~ (ArchiveTypes) or FileName endswith ".rar" or FileName endswith ".zip" or FileName endswith ".7z"
        | project NetworkMessageId, FileName, FileType, SHA256, FileSize
      ) on NetworkMessageId
    | extend Vector = strcat("ATTACH:", FileType), Indicator = FileName;
union UrlSide, AttachSide
| project Timestamp, RecipientEmailAddress, SenderFromAddress, SenderMailFromAddress, SenderDisplayName, Subject, Vector, Indicator, NetworkMessageId
| order by Timestamp desc
```

### [LLM] gofile.io archive download by browser followed by extracted-EXE execution within 30 minutes

`UC_247_6` · phase: **install** · confidence: **Medium**

**Defender KQL:**
```kql
let LookbackDays = 7d;
let WindowMin = 30m;
let GofileDrops = DeviceFileEvents
    | where Timestamp > ago(LookbackDays)
    | where FileOriginUrl has_any ("gofile.io","wetransfer.com","we.tl")
    | where FileName endswith ".rar" or FileName endswith ".zip" or FileName endswith ".7z"
         or FileName endswith ".exe" or FileName endswith ".msi" or FileName endswith ".lnk" or FileName endswith ".iso"
    | project DropTime = Timestamp, DeviceId, DeviceName, DroppedFile = FileName, DroppedPath = FolderPath, DroppedSHA256 = SHA256, FileOriginUrl, InitiatingProcessFileName;
DeviceProcessEvents
| where Timestamp > ago(LookbackDays)
| where AccountName !endswith "$"
| where FolderPath has_any (@"\Users\", @"\AppData\Local\Temp\", @"\Downloads\", @"\Desktop\", @"\Public\")
| where FileName endswith ".exe" or FileName endswith ".dll" or FileName endswith ".scr"
| join kind=inner GofileDrops on DeviceId
| where Timestamp between (DropTime .. DropTime + WindowMin)
| where InitiatingProcessFileName in~ ("explorer.exe","7zg.exe","7zfm.exe","winrar.exe","rar.exe","unrar.exe","chrome.exe","msedge.exe","firefox.exe","outlook.exe")
| project Timestamp, DropTime, DelaySec = datetime_diff('second', Timestamp, DropTime), DeviceName, AccountName, DroppedFile, DroppedPath, FileOriginUrl, ExecutedFile = FileName, ExecutedPath = FolderPath, ExecutedSHA256 = SHA256, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

### [LLM] ValleyRAT registry-resident shellcode (HKCU\Console\0|1) and MyPythonApp Run-key persistence

`UC_247_7` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where (Registry.registry_path="*\\Console\\0*" OR Registry.registry_path="*\\Console\\1*") AND Registry.registry_value_name="d33f351a4aeea5e608853d1a56661059" by Registry.dest Registry.user Registry.registry_path Registry.registry_value_name Registry.registry_value_data Registry.process_guid 
| `drop_dm_object_name(Registry)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| append [| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where Registry.registry_path="*\\CurrentVersion\\Run*" AND Registry.registry_value_name="MyPythonApp" by Registry.dest Registry.user Registry.registry_path Registry.registry_value_name Registry.registry_value_data Registry.process_guid 
| `drop_dm_object_name(Registry)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)`]
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(14d)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where (RegistryKey has_cs @"\Console\0" or RegistryKey has_cs @"\Console\1") and RegistryValueName =~ "d33f351a4aeea5e608853d1a56661059"
    or (RegistryKey has @"\CurrentVersion\Run" and RegistryValueName =~ "MyPythonApp")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessSHA256, RegistryKey, RegistryValueName, RegistryValueType, RegistryValueData
| order by Timestamp desc
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `gofile.io`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 8 use case(s) fired, 13 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

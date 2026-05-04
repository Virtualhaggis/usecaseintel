# [CRIT] Microsoft Defender wrongly flags DigiCert certs as Trojan:Win32/Cerdigent.A!dha

**Source:** BleepingComputer
**Published:** 2026-05-03
**Article:** https://www.bleepingcomputer.com/news/security/microsoft-defender-wrongly-flags-digicert-certs-as-trojan-win32-cerdigentadha/

## Threat Profile

Microsoft Defender wrongly flags DigiCert certs as Trojan:Win32/Cerdigent.A!dha 
By Lawrence Abrams 
May 3, 2026
02:11 PM
0 
Microsoft Defender is detecting legitimate DigiCert root certificates as Trojan:Win32/Cerdigent.A!dha, resulting in widespread false-positive alerts, and in some cases, removing certificates from Windows.
According to cybersecurity expert Florian Roth , the issue first appeared after Microsoft added the detections to a Defender signature update on April 30th.
Today, admini…

## Indicators of Compromise (high-fidelity only)

- **SHA1:** `0563B8630D62D75ABBC8AB1E4BDFB5A899B24D43`
- **SHA1:** `DDFB16CD4931C973A2037D3FC83A4D7D775D05E4`

## MITRE ATT&CK Techniques

- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1553.004** — Subvert Trust Controls: Install Root Certificate
- **T1112** — Modify Registry
- **T1553.002** — Subvert Trust Controls: Code Signing
- **T1036.001** — Masquerading: Invalid Code Signature

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Microsoft Defender removes legitimate DigiCert root cert (Cerdigent.A!dha FP cleanup hunt)

`UC_7_7` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Registry.process_name) as process_name values(Registry.process_path) as process_path values(Registry.user) as user from datamodel=Endpoint.Registry where Registry.action IN ("deleted","modified") AND Registry.registry_path="*\\SOFTWARE\\Microsoft\\SystemCertificates\\AuthRoot\\Certificates\\*" AND (Registry.registry_path="*0563B8630D62D75ABBC8AB1E4BDFB5A899B24D43*" OR Registry.registry_path="*DDFB16CD4931C973A2037D3FC83A4D7D775D05E4*") AND (Registry.process_name="MsMpEng.exe" OR Registry.process_path="*\\Windows Defender\\*" OR Registry.process_path="*\\Microsoft\\Windows Defender\\Platform\\*") by Registry.dest Registry.registry_path Registry.process_name Registry.user | `drop_dm_object_name(Registry)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let _flagged_thumbprints = dynamic(["0563B8630D62D75ABBC8AB1E4BDFB5A899B24D43","DDFB16CD4931C973A2037D3FC83A4D7D775D05E4"]);
let _start = datetime(2026-04-30);  // Defender SI update that introduced the FP
DeviceRegistryEvents
| where Timestamp > _start
| where ActionType in ("RegistryKeyDeleted","RegistryValueDeleted","RegistryValueSet")
| where RegistryKey has @"\SOFTWARE\Microsoft\SystemCertificates\AuthRoot\Certificates\"
| where InitiatingProcessFileName =~ "MsMpEng.exe"
   or InitiatingProcessFolderPath has @"\Windows Defender\"
   or InitiatingProcessFolderPath has @"\Microsoft\Windows Defender\Platform\"
| extend Thumbprint = toupper(extract(@"\\Certificates\\([0-9A-Fa-f]{40})", 1, RegistryKey))
| where Thumbprint in (_flagged_thumbprints)
| project Timestamp, DeviceName, DeviceId, ActionType, RegistryKey, Thumbprint,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessVersionInfoProductVersion
| order by Timestamp asc
```

### [LLM] Zhong Stealer / GoldenEyeDog: signed-by-abused-vendor binary executing from non-vendor path

`UC_7_8` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.process_hash) as hashes values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where (Processes.process_company="Lenovo*" OR Processes.process_company="Kingston*" OR Processes.process_company="Shuttle*" OR Processes.process_company="Palit*" OR Processes.file_company_name="Lenovo*" OR Processes.file_company_name="Kingston*" OR Processes.file_company_name="Shuttle*" OR Processes.file_company_name="Palit*") AND (Processes.process_path="*\\AppData\\Local\\Temp\\*" OR Processes.process_path="*\\AppData\\Roaming\\*" OR Processes.process_path="*\\Users\\Public\\*" OR Processes.process_path="*\\ProgramData\\*" OR Processes.process_path="*\\Downloads\\*" OR Processes.process_path="*\\Windows\\Temp\\*") AND NOT (Processes.process_path="*\\Program Files\\Lenovo\\*" OR Processes.process_path="*\\Program Files (x86)\\Lenovo\\*" OR Processes.process_path="*\\Program Files\\Kingston*" OR Processes.process_path="*\\Program Files (x86)\\Kingston*") by Processes.dest Processes.user Processes.process_name Processes.process_path Processes.process_company | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let _abused_vendors = dynamic(["Lenovo","LENOVO","Lenovo Group Limited","Kingston Technology","Kingston Technology Company, Inc.","Kingston","Shuttle Inc","Shuttle Inc.","Palit Microsystems","Palit Microsystems Ltd."]);
let _staging_paths = dynamic([@"\AppData\Local\Temp\", @"\AppData\Roaming\", @"\Users\Public\", @"\ProgramData\", @"\Downloads\", @"\Windows\Temp\"]);
let _legit_vendor_paths = dynamic([@"\Program Files\Lenovo\", @"\Program Files (x86)\Lenovo\", @"\Program Files\Kingston", @"\Program Files (x86)\Kingston", @"\Program Files\Shuttle", @"\Program Files\Palit"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where AccountName !endswith "$"
| where ProcessVersionInfoCompanyName in~ (_abused_vendors)
| where FolderPath has_any (_staging_paths)
| where not(FolderPath has_any (_legit_vendor_paths))
| join kind=leftouter (
    DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteIPType == "Public"
    | where RemoteUrl has_any (".amazonaws.com",".s3.",".cloudfront.net",".blob.core.windows.net",".storage.googleapis.com")
    | project NetTime = Timestamp, DeviceId, InitiatingProcessId, RemoteUrl, RemoteIP, RemotePort
  ) on $left.DeviceId == $right.DeviceId, $left.ProcessId == $right.InitiatingProcessId
| where isempty(NetTime) or NetTime between (Timestamp .. Timestamp + 30m)
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256,
          ProcessVersionInfoCompanyName, ProcessVersionInfoProductName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          ProcessCommandLine, CloudEgressUrl = RemoteUrl, CloudEgressIP = RemoteIP
| order by Timestamp desc
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

### Article-specific behavioural hunt — Microsoft Defender wrongly flags DigiCert certs as Trojan:Win32/Cerdigent.A!dha

`UC_7_6` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Microsoft Defender wrongly flags DigiCert certs as Trojan:Win32/Cerdigent.A!dha ```
| append [
  | tstats `summariesonly` count
      from datamodel=Endpoint.Registry
      where Registry.action IN ("created","modified")
        AND (Registry.registry_path="*HKLM\\SOFTWARE\\Microsoft\\SystemCertificates\\AuthRoot\\Certificates\\*")
      by Registry.dest, Registry.process_name, Registry.registry_path,
         Registry.registry_value_name, Registry.registry_value_data
  | `drop_dm_object_name(Registry)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Microsoft Defender wrongly flags DigiCert certs as Trojan:Win32/Cerdigent.A!dha
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// Registry persistence locations named in the article
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryKey has_any ("HKLM\SOFTWARE\Microsoft\SystemCertificates\AuthRoot\Certificates\")
| project Timestamp, DeviceName, AccountName, RegistryKey,
          RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `0563B8630D62D75ABBC8AB1E4BDFB5A899B24D43`, `DDFB16CD4931C973A2037D3FC83A4D7D775D05E4`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 9 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

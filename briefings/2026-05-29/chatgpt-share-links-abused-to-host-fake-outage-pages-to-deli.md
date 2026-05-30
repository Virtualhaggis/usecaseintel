# [MED] ChatGPT share links abused to host fake outage pages to deliver malware

**Source:** BleepingComputer
**Published:** 2026-05-29
**Article:** https://www.bleepingcomputer.com/news/security/chatgpt-share-links-abused-to-host-fake-outage-pages-to-deliver-malware/

## Threat Profile

ChatGPT share links abused to host fake outage pages to deliver malware 
By Lawrence Abrams 
May 29, 2026
02:21 PM
0 
Threat actors are abusing ChatGPT's content-sharing feature to display fake OpenAI outage pages that direct users to download malware disguised as the ChatGPT desktop application.
The "LLMShare" campaign, discovered by Push Security , uses Google ads to direct users searching for ChatGPT to a malicious shared ChatGPT page hosted on chatgpt.com, allowing the attack to be delivered…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `188.137.246.189`
- **IPv4 (defanged):** `192.253.248.181`
- **IPv4 (defanged):** `172.94.9.250`
- **Domain (defanged):** `openew.app`
- **SHA256:** `c9e0e6985dca3a179c9bdea4e7b38f7dc57fe00ecedc2fd634256fc53bf2de2d`
- **SHA256:** `c0919e1999eaee67e67aeda0287722775afb04e9a9a0f727928b4d11265fb70b`

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
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1583.008** — Malvertising
- **T1204.001** — Malicious Link
- **T1105** — Ingress Tool Transfer
- **T1204.002** — Malicious File
- **T1036.005** — Match Legitimate Name or Location
- **T1497.001** — System Checks
- **T1082** — System Information Discovery
- **T1057** — Process Discovery

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] ChatGPT share-link to openew[.]app navigation chain (LLMShare lure)

`UC_16_7` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*chatgpt.com/s/*" OR Web.dest="openew.app" OR Web.url="*openew.app*") by Web.src Web.user Web.dest Web.url Web.http_referrer _time | `drop_dm_object_name(Web)` | eventstats count(eval(like(url,"%chatgpt.com/s/%"))) as chatgpt_share, count(eval(like(url,"%openew.app%") OR dest="openew.app")) as openew_hits by src user | where chatgpt_share>0 AND openew_hits>0 | sort 0 _time
```

**Defender KQL:**
```kql
let LookbackDays = 7d;
let WindowMin = 30m;
let ShareHits = DeviceNetworkEvents
    | where Timestamp > ago(LookbackDays)
    | where RemoteUrl has "chatgpt.com/s/"
    | project ShareTime = Timestamp, DeviceId, DeviceName,
              InitiatingProcessAccountName, InitiatingProcessFileName, ShareUrl = RemoteUrl;
DeviceNetworkEvents
| where Timestamp > ago(LookbackDays)
| where RemoteUrl has "openew.app" or RemoteUrl endswith "openew.app"
   or RemoteIP in ("188.137.246.189","192.253.248.181","172.94.9.250")
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
| join kind=inner ShareHits on DeviceId
| where Timestamp between (ShareTime .. ShareTime + WindowMin)
| project ShareTime, OpenewTime = Timestamp,
          DelaySec = datetime_diff('second', Timestamp, ShareTime),
          DeviceName, AccountName = InitiatingProcessAccountName,
          ShareUrl, OpenewUrl = RemoteUrl, RemoteIP, Browser = InitiatingProcessFileName
| order by OpenewTime desc
```

### [LLM] Browser download from openew[.]app or pinned LLMShare hosting IPs

`UC_16_8` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action=created AND (Filesystem.file_path="*\\Downloads\\*" OR Filesystem.file_path="*/Downloads/*") AND Filesystem.process_name IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe") AND (Filesystem.file_name="ChatGPT*" OR Filesystem.file_name="OpenAI*" OR Filesystem.file_name="*ChatGPT*.dmg" OR Filesystem.file_name="*ChatGPT*.exe") by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)` | sort 0 _time
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated"
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","safari")
| where FileOriginUrl has "openew.app"
   or FileOriginReferrerUrl has "openew.app"
   or FileOriginReferrerUrl has "chatgpt.com/s/"
   or FileOriginIP in ("188.137.246.189","192.253.248.181","172.94.9.250")
   or SHA256 in ("c9e0e6985dca3a179c9bdea4e7b38f7dc57fe00ecedc2fd634256fc53bf2de2d",
                 "c0919e1999eaee67e67aeda0287722775afb04e9a9a0f727928b4d11265fb70b")
| project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName,
          Browser = InitiatingProcessFileName,
          FileName, FolderPath, SHA256,
          FileOriginUrl, FileOriginReferrerUrl, FileOriginIP
| order by Timestamp desc
```

### [LLM] Execution of LLMShare ChatGPT-installer SHA256 (Windows / macOS)

`UC_16_9` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_hash IN ("c9e0e6985dca3a179c9bdea4e7b38f7dc57fe00ecedc2fd634256fc53bf2de2d","c0919e1999eaee67e67aeda0287722775afb04e9a9a0f727928b4d11265fb70b") by Processes.dest Processes.user Processes.process_name Processes.process Processes.process_hash Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | sort 0 _time
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where SHA256 in ("c9e0e6985dca3a179c9bdea4e7b38f7dc57fe00ecedc2fd634256fc53bf2de2d",
                   "c0919e1999eaee67e67aeda0287722775afb04e9a9a0f727928b4d11265fb70b")
   or InitiatingProcessSHA256 in ("c9e0e6985dca3a179c9bdea4e7b38f7dc57fe00ecedc2fd634256fc53bf2de2d",
                                  "c0919e1999eaee67e67aeda0287722775afb04e9a9a0f727928b4d11265fb70b")
| project Timestamp, DeviceName, AccountName,
          FileName, FolderPath, SHA256, ProcessCommandLine,
          ParentImage = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine
| order by Timestamp desc
```

### [LLM] LLMShare anti-VM discovery: WMI BIOS/Computer queries + HKLM\HARDWARE reads post-installer launch

`UC_16_10` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count values(Processes.process) as cmdlines values(Processes.process_name) as child_names dc(Processes.process_name) as nchildren min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_hash IN ("c0919e1999eaee67e67aeda0287722775afb04e9a9a0f727928b4d11265fb70b") OR (Processes.parent_process_name="ChatGPT*" AND Processes.process_name IN ("wmic.exe","systeminfo.exe","tasklist.exe","reg.exe")) by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process_hash _time | `drop_dm_object_name(Processes)` | where nchildren>=2 | sort 0 _time
```

**Defender KQL:**
```kql
let LookbackDays = 7d;
let Window = 5m;
let InstallerLaunch = DeviceProcessEvents
    | where Timestamp > ago(LookbackDays)
    | where SHA256 == "c0919e1999eaee67e67aeda0287722775afb04e9a9a0f727928b4d11265fb70b"
       or (FileName startswith "ChatGPT" and FolderPath has_any ("\\Downloads\\","\\Temp\\","\\AppData\\Local\\Temp\\"))
    | project InstallTime = Timestamp, DeviceId, DeviceName,
              InstallerPid = ProcessId, InstallerName = FileName,
              InstallerHash = SHA256;
let Children = DeviceProcessEvents
    | where Timestamp > ago(LookbackDays)
    | where FileName in~ ("wmic.exe","systeminfo.exe","tasklist.exe","reg.exe","cmd.exe","powershell.exe")
    | where ProcessCommandLine has_any ("Win32_ComputerSystem","Win32_BIOS","Win32_BaseBoard",
                                         "computersystem","bios","hypervisor",
                                         "HARDWARE\\DESCRIPTION\\System",
                                         "Enum\\PCI","VBOX","VMware","VirtualBox")
    | project Timestamp, DeviceId, FileName, ProcessCommandLine,
              InitiatingProcessId, InitiatingProcessFileName,
              InitiatingProcessSHA256;
InstallerLaunch
| join kind=inner Children on DeviceId
| where Timestamp between (InstallTime .. InstallTime + Window)
| where InitiatingProcessId == InstallerPid or InitiatingProcessSHA256 == InstallerHash
| project Timestamp, DeviceName, InstallerName, InstallerHash,
          DiscoveryBinary = FileName, DiscoveryCmd = ProcessCommandLine,
          DelaySec = datetime_diff('second', Timestamp, InstallTime)
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `188.137.246.189`, `192.253.248.181`, `172.94.9.250`, `openew.app`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `c9e0e6985dca3a179c9bdea4e7b38f7dc57fe00ecedc2fd634256fc53bf2de2d`, `c0919e1999eaee67e67aeda0287722775afb04e9a9a0f727928b4d11265fb70b`


## Why this matters

Severity classified as **MED** based on: IOCs present, 11 use case(s) fired, 20 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

# [CRIT] GoldenEyeDog Subgroup Linked to DigiCert Breach and Code-Signing Certificate Theft

**Source:** The Hacker News
**Published:** 2026-07-17
**Article:** https://thehackernews.com/2026/07/goldeneyedog-subgroup-linked-to.html

## Threat Profile

GoldenEyeDog Subgroup Linked to DigiCert Breach and Code-Signing Certificate Theft 
 Ravie Lakshmanan  Jul 17, 2026 Malware / Threat Intelligence 
Cybersecurity researchers have attributed the April 2026 DigiCert security incident to a threat activity cluster dubbed CylindricalCanine .
Expel, which shared technical details of the event, described the threat actor as a sub-group of GoldenEyeDog (aka APT-Q-27, Dragon Breath, and Miuuti Group), a Chinese cybercrime group known for its targeting o…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `82.23.186.8`
- **IPv4 (defanged):** `154.12.185.32`
- **IPv4 (defanged):** `45.144.227.12`
- **IPv4 (defanged):** `203.160.68.2`
- **IPv4 (defanged):** `154.12.185.30`
- **IPv4 (defanged):** `62.197.153.45`
- **IPv4 (defanged):** `45.144.227.29`
- **Domain (defanged):** `qaqkongtiao.com`
- **SHA256:** `da2c58308e860e57df4c46465fd1cfc68d41e8699b4871e9a9be3c434283d50b`
- **SHA256:** `82794015e2b40cc6e02d3c1d50241465c0cf2c2e4f0a7a2a8f880edaee203724`
- **SHA256:** `c65170be2bf4f0bd71b9044592c063eaa82f3d43fcbd8a81e30a959bcaad8ae5`
- **SHA256:** `2515b546125d20013237aeadec5873e6438ada611347035358059a77a32c54f5`
- **SHA256:** `1613a913d0384cbb958e9a8d6b00fffaf77c27d348ebc7886d6c563a6f22f2b7`
- **SHA256:** `395f835731d25803a791db984062dd5cfdcade6f95cc5d0f68d359af32f6258d`
- **SHA256:** `1c1528b546aa29be6614707cbe408cb4b46e8ed05bf3fe6b388b9f22a4ee37e2`
- **SHA256:** `4d5beb8efd4ade583c8ff730609f142550e8ed14c251bae1097c35a756ed39e6`
- **SHA256:** `96f401b80d3319f8285fa2bb7f0d66ca9055d349c044b78c27e339bcfb07cdf0`
- **SHA256:** `33b494eaaa6d7ed75eec74f8c8c866b6c42f59ca72b8517b3d4752c3313e617c`
- **SHA256:** `fc63f5dfc93f2358f4cba18cbdf99578fff5dac4cdd2de193a21f6041a0e01bc`
- **SHA256:** `fd4dd9904549c6655465331921a28330ad2b9ff1c99eb993edf2252001f1d107`
- **SHA256:** `3dd470e85fe77cd847ca59d1d08ec8ccebe9bd73fd2cf074c29d87ca2fd24e33`

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
- **T1566.004** — Phishing: Spearphishing Voice
- **T1566** — Phishing
- **T1219** — Remote Access Software
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1574.002** — Hijack Execution Flow: DLL Side-Loading
- **T1566.001** — Phishing: Spearphishing Attachment
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1555.003** — Credentials from Password Stores: Credentials from Web Browsers
- **T1005** — Data from Local System
- **T1553.002** — Subvert Trust Controls: Code Signing
- **T1588.003** — Obtain Capabilities: Code Signing Certificates

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Golden Gh0st Loader DLL side-load loading encrypted 'update.log' payload from user-writable path

`UC_81_12` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name="update.log" (Filesystem.file_path="*\\AppData\\*" OR Filesystem.file_path="*\\Temp\\*" OR Filesystem.file_path="*\\Public\\*" OR Filesystem.file_path="*\\ProgramData\\*") by Filesystem.dest Filesystem.file_path Filesystem.process_name Filesystem.file_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let Window = 14d; let SideloadHosts = DeviceImageLoadEvents | where Timestamp > ago(Window) | where FileName endswith ".dll" | where FolderPath has_any (@"\AppData\", @"\Users\Public\", @"\ProgramData\", @"\Temp\") | where InitiatingProcessFolderPath has_any (@"\AppData\", @"\Users\Public\", @"\ProgramData\", @"\Temp\") | project DllLoadTime=Timestamp, DeviceId, DeviceName, SideloadExe=InitiatingProcessFileName, SideloadExeFolder=InitiatingProcessFolderPath, RogueDll=FileName, DllFolder=FolderPath; DeviceFileEvents | where Timestamp > ago(Window) | where FileName =~ "update.log" | where FolderPath has_any (@"\AppData\", @"\Users\Public\", @"\ProgramData\", @"\Temp\") | project PayloadTime=Timestamp, DeviceId, PayloadPath=FolderPath, PayloadWriter=InitiatingProcessFileName | join kind=inner SideloadHosts on DeviceId | where abs(datetime_diff('minute', DllLoadTime, PayloadTime)) <= 30 | project PayloadTime, DllLoadTime, DeviceName, SideloadExe, SideloadExeFolder, RogueDll, DllFolder, PayloadPath, PayloadWriter | order by PayloadTime desc
```

### GoldenEyeDog .scr screensaver payload executed from download/archive path (support-chat delivery)

`UC_81_13` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="*.scr" (Processes.process_path="*\\Downloads\\*" OR Processes.process_path="*\\Temp\\*" OR Processes.process_path="*\\AppData\\*" OR Processes.process_path="*\\Public\\*" OR Processes.process_path="*\\Desktop\\*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.process_path | `drop_dm_object_name(Processes)` | search NOT process_path="C:\\Windows\\*" | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents | where Timestamp > ago(14d) | where AccountName !endswith "$" | where FileName endswith ".scr" | where FolderPath !startswith @"C:\Windows\" | where FolderPath has_any (@"\Downloads\", @"\Temp\", @"\AppData\", @"\Users\Public\", @"\Desktop\") or InitiatingProcessFileName in~ ("winrar.exe","7zfm.exe","7zg.exe","explorer.exe","chrome.exe","msedge.exe","firefox.exe","outlook.exe") | project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine | order by Timestamp desc
```

### Golden Gh0st RAT plaintext WebSocket C2 to qaqkongtiao.com / GoldenEyeDog IP set

`UC_81_14` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_ip IN ("82.23.186.8","154.12.185.32","45.144.227.12","203.160.68.2","154.12.185.30","62.197.153.45","45.144.227.29")) by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents | where Timestamp > ago(14d) | where RemoteUrl has "qaqkongtiao.com" or RemoteIP in ("82.23.186.8","154.12.185.32","45.144.227.12","203.160.68.2","154.12.185.30","62.197.153.45","45.144.227.29") | project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessCommandLine | order by Timestamp desc
```

### Golden Gh0st RAT browser/credential collection targeting 360, QQ and Skype data stores

`UC_81_15` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count values(Filesystem.file_path) as file_paths min(_time) as firstTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\360se*" OR Filesystem.file_path="*\\360Chrome*" OR Filesystem.file_path="*\\QQBrowser*" OR Filesystem.file_path="*\\Tencent\\QQBrowser*" OR Filesystem.file_path="*\\AppData\\Roaming\\Skype*") by Filesystem.dest Filesystem.process_name | `drop_dm_object_name(Filesystem)` | search NOT process_name IN ("360se.exe","360chrome.exe","qqbrowser.exe","skype.exe","chrome.exe","firefox.exe","msedge.exe","explorer.exe") | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents | where Timestamp > ago(14d) | where FolderPath has_any (@"\360se", @"\360Chrome", @"\360Browser", @"\Tencent\QQBrowser", @"\QQBrowser\User Data", @"\AppData\Roaming\Skype") | where InitiatingProcessFileName !in~ ("360se.exe","360chrome.exe","qqbrowser.exe","skype.exe","chrome.exe","firefox.exe","msedge.exe","explorer.exe") | where InitiatingProcessAccountName !endswith "$" | summarize FilesTouched=dcount(FolderPath), Paths=make_set(FolderPath, 20), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256 | order by FirstSeen desc
```

### Execution of stolen-cert-signed Zhong Stealer / Golden Gh0st RAT artifacts by SHA256

`UC_81_16` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_hash IN ("da2c58308e860e57df4c46465fd1cfc68d41e8699b4871e9a9be3c434283d50b","82794015e2b40cc6e02d3c1d50241465c0cf2c2e4f0a7a2a8f880edaee203724","c65170be2bf4f0bd71b9044592c063eaa82f3d43fcbd8a81e30a959bcaad8ae5","2515b546125d20013237aeadec5873e6438ada611347035358059a77a32c54f5","1613a913d0384cbb958e9a8d6b00fffaf77c27d348ebc7886d6c563a6f22f2b7","395f835731d25803a791db984062dd5cfdcade6f95cc5d0f68d359af32f6258d","1c1528b546aa29be6614707cbe408cb4b46e8ed05bf3fe6b388b9f22a4ee37e2","4d5beb8efd4ade583c8ff730609f142550e8ed14c251bae1097c35a756ed39e6","96f401b80d3319f8285fa2bb7f0d66ca9055d349c044b78c27e339bcfb07cdf0","33b494eaaa6d7ed75eec74f8c8c866b6c42f59ca72b8517b3d4752c3313e617c","fc63f5dfc93f2358f4cba18cbdf99578fff5dac4cdd2de193a21f6041a0e01bc","fd4dd9904549c6655465331921a28330ad2b9ff1c99eb993edf2252001f1d107","3dd470e85fe77cd847ca59d1d08ec8ccebe9bd73fd2cf074c29d87ca2fd24e33")) by Processes.dest Processes.user Processes.process_name Processes.process Processes.process_hash | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let BadHashes = dynamic(["da2c58308e860e57df4c46465fd1cfc68d41e8699b4871e9a9be3c434283d50b","82794015e2b40cc6e02d3c1d50241465c0cf2c2e4f0a7a2a8f880edaee203724","c65170be2bf4f0bd71b9044592c063eaa82f3d43fcbd8a81e30a959bcaad8ae5","2515b546125d20013237aeadec5873e6438ada611347035358059a77a32c54f5","1613a913d0384cbb958e9a8d6b00fffaf77c27d348ebc7886d6c563a6f22f2b7","395f835731d25803a791db984062dd5cfdcade6f95cc5d0f68d359af32f6258d","1c1528b546aa29be6614707cbe408cb4b46e8ed05bf3fe6b388b9f22a4ee37e2","4d5beb8efd4ade583c8ff730609f142550e8ed14c251bae1097c35a756ed39e6","96f401b80d3319f8285fa2bb7f0d66ca9055d349c044b78c27e339bcfb07cdf0","33b494eaaa6d7ed75eec74f8c8c866b6c42f59ca72b8517b3d4752c3313e617c","fc63f5dfc93f2358f4cba18cbdf99578fff5dac4cdd2de193a21f6041a0e01bc","fd4dd9904549c6655465331921a28330ad2b9ff1c99eb993edf2252001f1d107","3dd470e85fe77cd847ca59d1d08ec8ccebe9bd73fd2cf074c29d87ca2fd24e33"]); union (DeviceProcessEvents | where Timestamp > ago(30d) | where SHA256 in (BadHashes) | project Timestamp, DeviceName, AccountName, Source="ProcessExec", FileName, FolderPath, SHA256, CmdLine=ProcessCommandLine), (DeviceFileEvents | where Timestamp > ago(30d) | where SHA256 in (BadHashes) | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, Source="FileWrite", FileName, FolderPath, SHA256, CmdLine=InitiatingProcessCommandLine), (DeviceImageLoadEvents | where Timestamp > ago(30d) | where SHA256 in (BadHashes) | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, Source="ImageLoad", FileName, FolderPath, SHA256, CmdLine=InitiatingProcessCommandLine) | order by Timestamp desc
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

### Microsoft Teams external-tenant chat from unverified IT-helpdesk impersonator

`UC_TEAMS_VISHING` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`o365_management_activity`
  Workload=MicrosoftTeams Operation=MessageSent
  ExternalParticipants=*
| where match(SenderDisplayName, "(?i)(help.?desk|it.?support|service.?desk|tech.?support|admin)")
| stats count, earliest(_time) as firstTime, latest(_time) as lastTime
    by SenderUpn, SenderDisplayName, RecipientUpn, ChatId
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Microsoft Teams"
| where ActionType == "MessageSent"
| where RawEventData has "ExternalParticipants"
| extend SenderDisplayName = tostring(parse_json(RawEventData).SenderDisplayName)
| where SenderDisplayName matches regex @"(?i)(help.?desk|it.?support|service.?desk|tech.?support|admin)"
| project Timestamp, AccountDisplayName, IPAddress, ActivityType, SenderDisplayName, RawEventData
```

### RMM tool installed by non-IT user — remote-access utility for hands-on-keyboard

`UC_RMM_TOOLS` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe","kaseya*.exe")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe")
   or FileName matches regex @"(?i)kaseya.*\.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `82.23.186.8`, `154.12.185.32`, `45.144.227.12`, `203.160.68.2`, `154.12.185.30`, `62.197.153.45`, `45.144.227.29`, `qaqkongtiao.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `da2c58308e860e57df4c46465fd1cfc68d41e8699b4871e9a9be3c434283d50b`, `82794015e2b40cc6e02d3c1d50241465c0cf2c2e4f0a7a2a8f880edaee203724`, `c65170be2bf4f0bd71b9044592c063eaa82f3d43fcbd8a81e30a959bcaad8ae5`, `2515b546125d20013237aeadec5873e6438ada611347035358059a77a32c54f5`, `1613a913d0384cbb958e9a8d6b00fffaf77c27d348ebc7886d6c563a6f22f2b7`, `395f835731d25803a791db984062dd5cfdcade6f95cc5d0f68d359af32f6258d`, `1c1528b546aa29be6614707cbe408cb4b46e8ed05bf3fe6b388b9f22a4ee37e2`, `4d5beb8efd4ade583c8ff730609f142550e8ed14c251bae1097c35a756ed39e6` _(+5 more)_


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 17 use case(s) fired, 27 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

# [HIGH] China-Linked TA4922 Expands Phishing Attacks to U.K., Germany, Italy, and South Africa

**Source:** The Hacker News
**Published:** 2026-06-04
**Article:** https://thehackernews.com/2026/06/china-linked-ta4922-expands-phishing.html

## Threat Profile

China-Linked TA4922 Expands Phishing Attacks to UK, Germany, Italy, and South Africa 
 Ravie Lakshmanan  Jun 04, 2026 Malware / Cybercrime 
A new China-linked cybercrime group known as TA4922 has expanded its targeting focus to target European organizations in the U.K., Germany, Italy, and South Africa.
These efforts have been complemented by a "rapid operational tempo" and a continually evolving malware arsenal comprising known families like ValleyRAT (aka Winos 4.0) and Atlas RAT (aka AtlasC…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `206.238.115.58`
- **IPv4 (defanged):** `154.211.86.110`
- **IPv4 (defanged):** `43.156.77.97`
- **IPv4 (defanged):** `103.214.172.33`
- **IPv4 (defanged):** `18.139.83.110`
- **IPv4 (defanged):** `112.121.183.202`
- **Domain (defanged):** `ws.ztts88.cyou`
- **Domain (defanged):** `aeya388.club`
- **Domain (defanged):** `nwphotoblog.com`
- **SHA256:** `a648db354820ea4d02940cb1702b35974513b7aae83f6dffaacaac4ba31f9295`
- **SHA256:** `584a9448dda46bd590d7a2f86228100d2ae6e0d6d990c1a4459ed5ee28e07ae8`
- **SHA256:** `66a3836b9a17771bce2161f6b73cbc2494a91e49d6aa30d2d53711e8d10de60d`
- **SHA256:** `4fcfa88fffacbce30bbe2136753c9ab5a4c092940d2406fd9d44d5118e745b9d`
- **SHA256:** `a75eab31d7ff06b6864960ad7e633be3f9730ff3d3873e4539c8f425fc632dad`
- **SHA256:** `40b41979b317406f8abc601677a3b93aaf6ef8ab8ac188b8f383735e388f13b5`
- **SHA256:** `8c9b6542f73c5c7fe455b52f5101314407da4f65ff48e7ebf6896605e607c8d0`
- **SHA256:** `3119cf37b8267db8a2dcd11d9a83d5237d7ef1e42388e7c9afa2831b91da8a2d`
- **SHA256:** `314f4b59535d1b783e1c20c2be00f9e30f8ed27b2e21fad06a73b47ea43279ef`
- **SHA256:** `2d2a251a88632f010fd9671789746908eeccaa5bc5c0a5d25e4649efe4f5b15d`
- **SHA256:** `e0a6a71c605d9a4076147e9537f82f79f1e1eccadc874595160aa4637ff4088c`
- **SHA256:** `de82998ad5fcd63deae030803388e0fb4290d6223fda82368fd25b99b823f0d2`
- **SHA256:** `9d0a55c545c4147956db2c2667c4ed931a2875309147548b1dfdd216228f5f73`

## MITRE ATT&CK Techniques

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
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1071.004** — Application Layer Protocol: DNS
- **T1574.002** — Hijack Execution Flow: DLL Side-Loading
- **T1555.003** — Credentials from Password Stores: Credentials from Web Browsers
- **T1539** — Steal Web Session Cookie
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1105** — Ingress Tool Transfer

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### TA4922 Known C2 IPs and Domains (Proofpoint Jun-2026)

`UC_107_10` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src) as src values(All_Traffic.user) as user values(All_Traffic.app) as app from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip IN ("206.238.115.58","154.211.86.110","43.156.77.97","103.214.172.33","18.139.83.110","112.121.183.202") OR All_Traffic.dest IN ("ws.ztts88.cyou","aeya388.club","nwphotoblog.com") by All_Traffic.dest All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.transport
| `drop_dm_object_name(All_Traffic)`
| convert ctime(firstTime) ctime(lastTime)
| eval ioc_source="Proofpoint TA4922 2026-06-04"
```

**Defender KQL:**
```kql
let ta4922_ips = dynamic(["206.238.115.58","154.211.86.110","43.156.77.97","103.214.172.33","18.139.83.110","112.121.183.202"]);
let ta4922_domains = dynamic(["ws.ztts88.cyou","aeya388.club","nwphotoblog.com"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (ta4922_ips) or RemoteUrl has_any (ta4922_domains)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, Protocol
| order by Timestamp desc
```

### TA4922 Atlas RAT / RomulusLoader / SilentRunLoader Known SHA256 Execution

`UC_107_11` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.user) as user values(Processes.process) as process values(Processes.process_name) as process_name from datamodel=Endpoint.Processes where Processes.process_hash IN ("a648db354820ea4d02940cb1702b35974513b7aae83f6dffaacaac4ba31f9295","584a9448dda46bd590d7a2f86228100d2ae6e0d6d990c1a4459ed5ee28e07ae8","66a3836b9a17771bce2161f6b73cbc2494a91e49d6aa30d2d53711e8d10de60d","4fcfa88fffacbce30bbe2136753c9ab5a4c092940d2406fd9d44d5118e745b9d","a75eab31d7ff06b6864960ad7e633be3f9730ff3d3873e4539c8f425fc632dad","40b41979b317406f8abc601677a3b93aaf6ef8ab8ac188b8f383735e388f13b5","8c9b6542f73c5c7fe455b52f5101314407da4f65ff48e7ebf6896605e607c8d0","3119cf37b8267db8a2dcd11d9a83d5237d7ef1e42388e7c9afa2831b91da8a2d") by Processes.dest Processes.process_hash
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let ta4922_hashes = dynamic([
  "a648db354820ea4d02940cb1702b35974513b7aae83f6dffaacaac4ba31f9295",
  "584a9448dda46bd590d7a2f86228100d2ae6e0d6d990c1a4459ed5ee28e07ae8",
  "66a3836b9a17771bce2161f6b73cbc2494a91e49d6aa30d2d53711e8d10de60d",
  "4fcfa88fffacbce30bbe2136753c9ab5a4c092940d2406fd9d44d5118e745b9d",
  "a75eab31d7ff06b6864960ad7e633be3f9730ff3d3873e4539c8f425fc632dad",
  "40b41979b317406f8abc601677a3b93aaf6ef8ab8ac188b8f383735e388f13b5",
  "8c9b6542f73c5c7fe455b52f5101314407da4f65ff48e7ebf6896605e607c8d0",
  "3119cf37b8267db8a2dcd11d9a83d5237d7ef1e42388e7c9afa2831b91da8a2d"
]);
union isfuzzy=true
(DeviceProcessEvents
 | where Timestamp > ago(30d)
 | where SHA256 in (ta4922_hashes) or InitiatingProcessSHA256 in (ta4922_hashes)
 | project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine, InitiatingProcessFileName, EvidenceTable="ProcessEvents"),
(DeviceFileEvents
 | where Timestamp > ago(30d)
 | where SHA256 in (ta4922_hashes)
 | project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, EvidenceTable="FileEvents"),
(DeviceImageLoadEvents
 | where Timestamp > ago(30d)
 | where SHA256 in (ta4922_hashes)
 | project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, EvidenceTable="ImageLoad")
| order by Timestamp desc
```

### SilentRunLoader: Python process touching Chrome Login Data / Cookies / Local State

`UC_107_12` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as process_name values(Filesystem.process_path) as process_path values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\Google\\Chrome\\User Data\\Default\\Login Data*" OR Filesystem.file_path="*\\Google\\Chrome\\User Data\\Default\\Cookies*" OR Filesystem.file_path="*\\Google\\Chrome\\User Data\\Default\\Network\\Cookies*" OR Filesystem.file_path="*\\Google\\Chrome\\User Data\\Default\\Web Data*" OR Filesystem.file_path="*\\Google\\Chrome\\User Data\\Local State*") by Filesystem.dest Filesystem.file_name Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
| search (process_name IN ("python.exe","pythonw.exe","py.exe") OR process_path="*\\AppData\\Local\\Temp\\*" OR process_path="*\\AppData\\Roaming\\*" OR process_path="*\\Users\\Public\\*" OR process_path="*\\Downloads\\*")
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let ChromeArtifacts = dynamic([
  @"\Google\Chrome\User Data\Default\Login Data",
  @"\Google\Chrome\User Data\Default\Cookies",
  @"\Google\Chrome\User Data\Default\Network\Cookies",
  @"\Google\Chrome\User Data\Default\History",
  @"\Google\Chrome\User Data\Default\Web Data",
  @"\Google\Chrome\User Data\Local State"
]);
let StagingPaths = dynamic([@"\AppData\Local\Temp\", @"\AppData\Roaming\", @"\Users\Public\", @"\Downloads\", @"\ProgramData\"]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| where FolderPath has_any (ChromeArtifacts) or FileName in~ ("Login Data","Cookies","Local State","Web Data")
| where InitiatingProcessFileName in~ ("python.exe","pythonw.exe","py.exe")
   or InitiatingProcessFolderPath has_any (StagingPaths)
   or InitiatingProcessParentFileName in~ ("python.exe","pythonw.exe")
| where InitiatingProcessFileName !in~ ("chrome.exe","chromedriver.exe","msedge.exe","brave.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### RomulusLoader: AnyDesk or SyncFuture written/spawned from non-installer parent

`UC_107_13` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process) as parent_process values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.process_name IN ("AnyDesk.exe","SyncFuture.exe") by Processes.dest Processes.process_name Processes.parent_process_name Processes.process_path Processes.parent_process_path
| `drop_dm_object_name(Processes)`
| search NOT (parent_process_name IN ("msiexec.exe","setup.exe","installer.exe","explorer.exe","services.exe","wusa.exe","TrustedInstaller.exe","AnyDesk-Setup.exe","AnyDeskMSI.exe"))
  AND NOT (parent_process_path="*\\Program Files\\*" OR parent_process_path="*\\Program Files (x86)\\*")
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let LegitInstallers = dynamic(["msiexec.exe","setup.exe","installer.exe","explorer.exe","services.exe","wusa.exe","trustedinstaller.exe","anydesk-setup.exe","anydeskmsi.exe"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("AnyDesk.exe","SyncFuture.exe")
| where InitiatingProcessFileName !in~ (LegitInstallers)
| where InitiatingProcessFolderPath !startswith @"C:\Program Files"
| where InitiatingProcessFolderPath !startswith @"C:\Program Files (x86)"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessParentFileName, SHA256
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
  - IP / domain IOC(s): `206.238.115.58`, `154.211.86.110`, `43.156.77.97`, `103.214.172.33`, `18.139.83.110`, `112.121.183.202`, `ws.ztts88.cyou`, `aeya388.club` _(+1 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `a648db354820ea4d02940cb1702b35974513b7aae83f6dffaacaac4ba31f9295`, `584a9448dda46bd590d7a2f86228100d2ae6e0d6d990c1a4459ed5ee28e07ae8`, `66a3836b9a17771bce2161f6b73cbc2494a91e49d6aa30d2d53711e8d10de60d`, `4fcfa88fffacbce30bbe2136753c9ab5a4c092940d2406fd9d44d5118e745b9d`, `a75eab31d7ff06b6864960ad7e633be3f9730ff3d3873e4539c8f425fc632dad`, `40b41979b317406f8abc601677a3b93aaf6ef8ab8ac188b8f383735e388f13b5`, `8c9b6542f73c5c7fe455b52f5101314407da4f65ff48e7ebf6896605e607c8d0`, `3119cf37b8267db8a2dcd11d9a83d5237d7ef1e42388e7c9afa2831b91da8a2d` _(+5 more)_


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 14 use case(s) fired, 23 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

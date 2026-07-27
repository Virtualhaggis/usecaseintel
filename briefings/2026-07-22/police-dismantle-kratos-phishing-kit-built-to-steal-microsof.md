# [CRIT] Police Dismantle Kratos Phishing Kit Built to Steal Microsoft 365 Sessions and Bypass MFA

**Source:** The Hacker News
**Published:** 2026-07-22
**Article:** https://thehackernews.com/2026/07/police-dismantle-kratos-phishing-kit.html

## Threat Profile

Police Dismantle Kratos Phishing Kit Built to Steal Microsoft 365 Sessions and Bypass MFA 
 Swati Khandelwal  Jul 22, 2026 Law Enforcement / Cybercrime 
German and US law enforcement have taken down the core infrastructure of Kratos , described by German investigators as one of the world's most widely used criminal phishing kits, and Indonesian authorities arrested the man they say developed and ran it.
In a joint announcement on Monday, the Frankfurt public prosecutor's cybercrime unit (ZIT) …

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `41.128.0.142`
- **IPv4 (defanged):** `101.99.92.124`
- **IPv4 (defanged):** `185.125.100.81`
- **Domain (defanged):** `abal.my`
- **Domain (defanged):** `starwellmedia.com`
- **Domain (defanged):** `aabiz.de`
- **Domain (defanged):** `aspireglobal.ltd`
- **Domain (defanged):** `buenne.de`
- **Domain (defanged):** `dufllot.sbs`
- **Domain (defanged):** `enerdizerandtron.de`
- **Domain (defanged):** `espaciocf.de`
- **Domain (defanged):** `ihrsupportcenter.de`
- **Domain (defanged):** `ilersls.org`
- **Domain (defanged):** `aaalen.de`
- **Domain (defanged):** `rundwasser.de`
- **Domain (defanged):** `smartcontrolengineer.com`
- **Domain (defanged):** `sonnenbrillenspot.de`
- **Domain (defanged):** `trisrnareprjdocz.com`
- **Domain (defanged):** `razen.online`
- **Domain (defanged):** `theoceanac.online`
- **Domain (defanged):** `jumpast.es`
- **Domain (defanged):** `klenpare.com`
- **Domain (defanged):** `uvarnix.cfd`
- **Domain (defanged):** `xavon.sbs`
- **Domain (defanged):** `crm-technik.de`
- **Domain (defanged):** `dwbud.vilaribit.com`
- **Domain (defanged):** `sneakylog.store`
- **Domain (defanged):** `tesla-apply-job.com`
- **SHA256:** `c447e75f1029ed7a5882add16bcd13ad44be3bd47c93c830ff39185e23d25ebb`
- **SHA256:** `cd231b895bbcd7154b81df1e065bf02f1ec667b920c8b6d23308cd509833b5ea`
- **SHA256:** `949895df17148c5ea29f190d2619a14b3ec648425b9cc3c5a1423553c16f3898`
- **SHA256:** `9d1a1a5e3b5e5de8a6c76ded7a01fa01709d426232b0048c9ee6ba0c5c1b8b42`
- **SHA256:** `a3c298ccf2456989ceb080e661b01c3b00445902ae7bb3e58dad4d846334ff9c`
- **SHA256:** `5d91563b6acd54468ae282083cf9ee3d2c9b2daa45a8de9cb661c2195b9f6cbf`
- **SHA256:** `8c4e78b1bc0a0923fccc0cd2d7ca06023b6ab15af079e6b19d7d5d2fddc5488d`

## MITRE ATT&CK Techniques

- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1566.002** — Phishing: Spearphishing Link
- **T1557** — Adversary-in-the-Middle
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1583.001** — Acquire Infrastructure: Domains
- **T1550.001** — Use Alternate Authentication Material: Application Access Token
- **T1566.001** — Phishing: Spearphishing Attachment
- **T1114.003** — Email Collection: Email Forwarding Rule
- **T1564.008** — Hide Artifacts: Email Hiding Rules

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Kratos/SneakyLog phishing page fingerprint: barr.svg + lg.svg assets with next.php/save.php POST

`UC_84_13` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count values(Web.url) as urls values(Web.http_method) as methods min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.url="*barr.svg*" OR Web.url="*lg.svg*" OR Web.url="*next.php*" OR Web.url="*save.php*") by Web.src Web.dest Web.site Web.user | `drop_dm_object_name(Web)` | eval hasBarr=if(match(urls,"barr\.svg"),1,0), hasLg=if(match(urls,"lg\.svg"),1,0), hasPost=if(match(urls,"(next|save)\.php"),1,0) | where hasBarr=1 AND hasLg=1 | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let LookbackDays = 14d;
DeviceNetworkEvents
| where Timestamp > ago(LookbackDays)
| where isnotempty(RemoteUrl)
| where RemoteUrl has_any ("barr.svg","lg.svg","next.php","save.php")
| extend Asset = case(RemoteUrl has "barr.svg","barr.svg", RemoteUrl has "lg.svg","lg.svg", RemoteUrl has "next.php","next.php","save.php")
| extend Host = tostring(parse_url(RemoteUrl).Host)
| summarize Assets=make_set(Asset,10), Urls=make_set(RemoteUrl,25), FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Users=make_set(InitiatingProcessAccountName,10) by DeviceId, DeviceName, Host
| where set_has_element(Assets,"barr.svg") and set_has_element(Assets,"lg.svg")
| order by LastSeen desc
```

### Network/DNS callouts to disclosed Kratos (SneakyLog) takedown infrastructure

`UC_84_14` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_port) as ports from datamodel=Network_Traffic where (All_Traffic.dest_ip="41.128.0.142" OR All_Traffic.dest_ip="101.99.92.124" OR All_Traffic.dest_ip="185.125.100.81") by All_Traffic.src All_Traffic.dest_ip All_Traffic.user | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let kitIPs = dynamic(["41.128.0.142","101.99.92.124","185.125.100.81"]);
let kitDomains = dynamic(["abal.my","starwellmedia.com","aabiz.de","aspireglobal.ltd","buenne.de","dufllot.sbs","enerdizerandtron.de","espaciocf.de","ihrsupportcenter.de","ilersls.org","aaalen.de","rundwasser.de","smartcontrolengineer.com","sonnenbrillenspot.de","trisrnareprjdocz.com","razen.online","theoceanac.online","jumpast.es","klenpare.com","uvarnix.cfd"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (kitIPs) or RemoteUrl has_any (kitDomains)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessCommandLine
| order by Timestamp desc
```

### AiTM stolen-session token replay: successful M365 sign-in from Kratos IPs / anomalous-token risk

`UC_84_15` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Authentication.app) as apps from datamodel=Authentication where Authentication.action="success" (Authentication.src="41.128.0.142" OR Authentication.src="101.99.92.124" OR Authentication.src="185.125.100.81") by Authentication.user Authentication.src | `drop_dm_object_name(Authentication)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let kitIPs = dynamic(["41.128.0.142","101.99.92.124","185.125.100.81"]);
AADSignInEventsBeta
| where Timestamp > ago(30d)
| where ErrorCode == 0
| where IPAddress in (kitIPs) or RiskLevelDuringSignIn in ("high","medium")
| where IPAddress in (kitIPs) or RiskState in ("atRisk","confirmedCompromised")
| project Timestamp, AccountUpn, IPAddress, Country, City, Application, ResourceDisplayName, ClientAppUsed, IsInteractive, AuthenticationRequirement, ConditionalAccessStatus, RiskLevelDuringSignIn, RiskState, UserAgent
| order by Timestamp desc
```

### Tax/W-2 themed QR-code phishing email (SneakyLog delivery)

`UC_84_16` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Defender KQL:**
```kql
let LookbackDays = 30d;
EmailEvents
| where Timestamp > ago(LookbackDays)
| where EmailDirection == "Inbound" and DeliveryAction == "Delivered"
| where Subject has_any ("W-2","W2","tax","IRS","1099","payroll","tax form","tax statement","tax return")
| where AttachmentCount >= 1 and (UrlCount == 0 or UrlCount <= 1)
| join kind=inner (
    EmailAttachmentInfo
    | where FileType in~ ("png","jpg","jpeg","gif","pdf","svg","html","htm")
  ) on NetworkMessageId
| project Timestamp, SenderFromAddress, SenderMailFromDomain, RecipientEmailAddress, Subject, FileName, FileType, UrlCount, DeliveryAction
| order by Timestamp desc
```

### Post-compromise M365 inbox forwarding/rule creation from Kratos infrastructure (ATO→BEC)

`UC_84_17` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Defender KQL:**
```kql
let kitIPs = dynamic(["41.128.0.142","101.99.92.124","185.125.100.81"]);
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType in~ ("New-InboxRule","Set-InboxRule","UpdateInboxRules","Set-Mailbox")
| extend Raw = tostring(RawEventData)
| where IPAddress in (kitIPs)
   or Raw has_any ("ForwardTo","RedirectTo","ForwardAsAttachmentTo","DeleteMessage","MarkAsRead")
| project Timestamp, AccountDisplayName, AccountId, IPAddress, ActionType, Application, Raw
| order by Timestamp desc
```

### Suspicious browser extension installation

`UC_BROWSER_EXT` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Registry
    where (Registry.registry_path="*\Software\Google\Chrome\Extensions\*"
        OR Registry.registry_path="*\Software\Microsoft\Edge\Extensions\*"
        OR Registry.registry_path="*\Software\Mozilla\Firefox\Extensions\*")
    by Registry.dest, Registry.registry_path, Registry.registry_value_data, Registry.registry_value_name, Registry.user
| `drop_dm_object_name(Registry)`
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where RegistryKey has_any ("\Software\Google\Chrome\Extensions\","\Software\Microsoft\Edge\Extensions\","\Software\Mozilla\Firefox\Extensions\")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessAccountName
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

### Article-specific behavioural hunt — Police Dismantle Kratos Phishing Kit Built to Steal Microsoft 365 Sessions and B

`UC_84_12` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Police Dismantle Kratos Phishing Kit Built to Steal Microsoft 365 Sessions and B ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("node.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Police Dismantle Kratos Phishing Kit Built to Steal Microsoft 365 Sessions and B
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `41.128.0.142`, `101.99.92.124`, `185.125.100.81`, `abal.my`, `starwellmedia.com`, `aabiz.de`, `aspireglobal.ltd`, `buenne.de` _(+20 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `c447e75f1029ed7a5882add16bcd13ad44be3bd47c93c830ff39185e23d25ebb`, `cd231b895bbcd7154b81df1e065bf02f1ec667b920c8b6d23308cd509833b5ea`, `949895df17148c5ea29f190d2619a14b3ec648425b9cc3c5a1423553c16f3898`, `9d1a1a5e3b5e5de8a6c76ded7a01fa01709d426232b0048c9ee6ba0c5c1b8b42`, `a3c298ccf2456989ceb080e661b01c3b00445902ae7bb3e58dad4d846334ff9c`, `5d91563b6acd54468ae282083cf9ee3d2c9b2daa45a8de9cb661c2195b9f6cbf`, `8c4e78b1bc0a0923fccc0cd2d7ca06023b6ab15af079e6b19d7d5d2fddc5488d`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 18 use case(s) fired, 28 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

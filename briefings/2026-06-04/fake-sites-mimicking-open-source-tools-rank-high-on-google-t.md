# [HIGH] Fake Sites Mimicking Open-Source Tools Rank High on Google to Deliver Malware via TDS

**Source:** The Hacker News
**Published:** 2026-06-04
**Article:** https://thehackernews.com/2026/06/fake-sites-mimicking-open-source-tools.html

## Threat Profile

Fake Sites Mimicking Open-Source Tools Rank High on Google to Deliver Malware via TDS 
 Swati Khandelwal  Jun 04, 2026 Malware / Open Source 
Cybersecurity researchers have flagged a large-scale operation that impersonates open-source and freeware projects to funnel unsuspecting users through a Traffic Distribution System (TDS) and deliver malware families like Remus Stealer, AnimateClipper, and the SessionGate framework.
"The sites are well-designed and often look like legitimate project port…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `grpcurl.com`
- **Domain (defanged):** `ghidralite.com`
- **Domain (defanged):** `dcbbwymp1bhif.cloudfront.net`
- **Domain (defanged):** `d3jzqhqvnvdy34.cloudfront.net`
- **Domain (defanged):** `oundhertobeconisist.org`
- **Domain (defanged):** `trkscope.xyz`
- **Domain (defanged):** `file-enter-web.com`
- **Domain (defanged):** `realcubeoyogenmyfire.monster`
- **Domain (defanged):** `media.stellarcloudhub1.cfd`
- **Domain (defanged):** `ukentaspectsofoc.org`
- **Domain (defanged):** `ukankingwithea.com`
- **Domain (defanged):** `recipioapp.com`

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
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1583.008** — Acquire Infrastructure: Malvertising
- **T1608.006** — Stage Capabilities: SEO Poisoning
- **T1189** — Drive-by Compromise
- **T1218.011** — System Binary Proxy Execution: Rundll32
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1105** — Ingress Tool Transfer
- **T1555.003** — Credentials from Password Stores: Credentials from Web Browsers
- **T1005** — Data from Local System
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1218.005** — System Binary Proxy Execution: Mshta

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Outbound contact to fake open-source tool / TDS / CloudFront staging domains

`UC_75_10` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count, min(_time) as firstTime, max(_time) as lastTime FROM datamodel=Web WHERE (Web.url IN ("*grpcurl.com*","*ghidralite.com*","*dcbbwymp1bhif.cloudfront.net*","*d3jzqhqvnvdy34.cloudfront.net*","*oundhertobeconisist.org*","*trkscope.xyz*","*file-enter-web.com*","*realcubeoyogenmyfire.monster*")) BY Web.src, Web.dest, Web.url, Web.user, Web.http_user_agent | `drop_dm_object_name(Web)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let TDSDomains = dynamic(["grpcurl.com","ghidralite.com","dcbbwymp1bhif.cloudfront.net","d3jzqhqvnvdy34.cloudfront.net","oundhertobeconisist.org","trkscope.xyz","file-enter-web.com","realcubeoyogenmyfire.monster"]);
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteUrl has_any (TDSDomains)
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, RemoteUrl, RemoteIP, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### [LLM] Browser-spawned executable/installer drop within 5 min of TDS site contact

`UC_75_11` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count, min(_time) as firstTime FROM datamodel=Endpoint.Filesystem WHERE Filesystem.action=created (Filesystem.file_path="*\\Downloads\\*" OR Filesystem.file_path="*\\AppData\\Local\\Temp\\*" OR Filesystem.file_path="*\\AppData\\Roaming\\*") (Filesystem.file_name="*.exe" OR Filesystem.file_name="*.msi" OR Filesystem.file_name="*.dll" OR Filesystem.file_name="*.zip") (Filesystem.process_name="chrome.exe" OR Filesystem.process_name="msedge.exe" OR Filesystem.process_name="firefox.exe" OR Filesystem.process_name="brave.exe" OR Filesystem.process_name="opera.exe") BY Filesystem.dest, Filesystem.user, Filesystem.process_name, Filesystem.file_name, Filesystem.file_path | `drop_dm_object_name(Filesystem)` | join type=inner dest [| tstats summariesonly=t min(_time) as TouchTime FROM datamodel=Web WHERE (Web.url IN ("*grpcurl.com*","*ghidralite.com*","*dcbbwymp1bhif.cloudfront.net*","*d3jzqhqvnvdy34.cloudfront.net*","*oundhertobeconisist.org*","*trkscope.xyz*","*file-enter-web.com*","*realcubeoyogenmyfire.monster*")) BY Web.src, Web.url | `drop_dm_object_name(Web)` | rename src as dest] | where firstTime >= TouchTime AND firstTime <= TouchTime + 300
```

**Defender KQL:**
```kql
let LookbackDays = 7d;
let TDSDomains = dynamic(["grpcurl.com","ghidralite.com","dcbbwymp1bhif.cloudfront.net","d3jzqhqvnvdy34.cloudfront.net","oundhertobeconisist.org","trkscope.xyz","file-enter-web.com","realcubeoyogenmyfire.monster"]);
let TDSTouches = DeviceNetworkEvents
  | where Timestamp > ago(LookbackDays)
  | where RemoteUrl has_any (TDSDomains)
  | project TouchTime=Timestamp, DeviceId, DeviceName, RemoteUrl;
DeviceFileEvents
| where Timestamp > ago(LookbackDays)
| where ActionType == "FileCreated"
| where FolderPath has_any (@"\Downloads\", @"\AppData\Local\Temp\", @"\AppData\Roaming\")
| where FileName endswith ".exe" or FileName endswith ".msi" or FileName endswith ".dll" or FileName endswith ".zip" or FileName endswith ".js"
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
| join kind=inner TDSTouches on DeviceId
| where Timestamp between (TouchTime .. TouchTime + 5m)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FileName, FolderPath, SHA256, FileOriginUrl, RemoteUrl, TouchTime
| order by Timestamp desc
```

### [LLM] SessionGate final-stage rundll32 spawning cmd.exe to fetch and silently execute next-stage payload

`UC_75_12` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count, min(_time) as firstTime, max(_time) as lastTime FROM datamodel=Endpoint.Processes WHERE Processes.parent_process_name="rundll32.exe" Processes.process_name="cmd.exe" (Processes.process IN ("*http://*","*https://*","*curl *","*certutil*","*bitsadmin*","*powershell*","*Invoke-WebRequest*","*iwr *") OR Processes.parent_process IN ("*\\AppData\\Local\\Temp\\*","*\\AppData\\Roaming\\*","*\\Users\\Public\\*")) BY Processes.dest, Processes.user, Processes.parent_process, Processes.process, Processes.process_hash | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName =~ "rundll32.exe"
| where FileName =~ "cmd.exe"
| where ProcessCommandLine has_any ("http://","https://","curl ","certutil","bitsadmin","powershell","Invoke-WebRequest","iwr ")
   or InitiatingProcessCommandLine has_any (@"\AppData\Local\Temp\", @"\AppData\Roaming\", @"\Users\Public\")
| where not(InitiatingProcessCommandLine has_any ("printui.dll","shell32.dll,Control_RunDLL","mshtml.dll,PrintHTML"))
| project Timestamp, DeviceName, AccountName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, ProcessCommandLine, InitiatingProcessSHA256, SHA256
| order by Timestamp desc
```

### [LLM] Remus/Lumma Stealer browser-credential and crypto-wallet directory enumeration

`UC_75_13` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count, dc(Filesystem.file_path) as FilesTouched, values(Filesystem.file_path) as Paths, min(_time) as firstTime, max(_time) as lastTime FROM datamodel=Endpoint.Filesystem WHERE (Filesystem.file_path IN ("*\\AppData\\Roaming\\Exodus\\*","*\\AppData\\Roaming\\Electrum\\*","*\\AppData\\Roaming\\Atomic\\*","*\\AppData\\Roaming\\Ledger Live\\*","*\\AppData\\Local\\Coinomi\\*","*\\AppData\\Roaming\\Zcash\\*","*\\AppData\\Roaming\\Bitcoin\\*","*\\Google\\Chrome\\User Data\\Default\\Login Data*","*\\Microsoft\\Edge\\User Data\\Default\\Login Data*","*\\Mozilla\\Firefox\\Profiles*","*\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Login Data*")) Filesystem.process_name!="chrome.exe" Filesystem.process_name!="msedge.exe" Filesystem.process_name!="firefox.exe" Filesystem.process_name!="brave.exe" Filesystem.process_name!="explorer.exe" Filesystem.process_name!="SearchIndexer.exe" Filesystem.process_name!="MsMpEng.exe" Filesystem.process_name!="svchost.exe" BY Filesystem.dest, Filesystem.user, Filesystem.process_name, Filesystem.process_hash | `drop_dm_object_name(Filesystem)` | where FilesTouched >= 3 | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let WindowDays = 7d;
let WalletPaths = dynamic([@"\AppData\Roaming\Exodus\",@"\AppData\Roaming\Electrum\",@"\AppData\Roaming\Atomic\",@"\AppData\Roaming\Ledger Live\",@"\AppData\Local\Coinomi\",@"\AppData\Roaming\Zcash\",@"\AppData\Roaming\Bitcoin\"]);
let CredPaths = dynamic([@"\Google\Chrome\User Data\Default\Login Data",@"\Microsoft\Edge\User Data\Default\Login Data",@"\Mozilla\Firefox\Profiles",@"\BraveSoftware\Brave-Browser\User Data\Default\Login Data"]);
let LegitProcs = dynamic(["chrome.exe","msedge.exe","firefox.exe","brave.exe","explorer.exe","SearchIndexer.exe","MsMpEng.exe","svchost.exe","Bitwarden.exe","1Password.exe"]);
DeviceFileEvents
| where Timestamp > ago(WindowDays)
| where FolderPath has_any (WalletPaths) or FolderPath has_any (CredPaths)
| where not(InitiatingProcessFileName in~ (LegitProcs))
| summarize FilesTouched=dcount(strcat(FolderPath, FileName)),
            SamplePaths=make_set(strcat(FolderPath, FileName), 10),
            FirstSeen=min(Timestamp), LastSeen=max(Timestamp)
            by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessSHA256
| where FilesTouched >= 3
| order by LastSeen desc
```

### [LLM] AnimateClipper ClickFix paste-to-run via explorer.exe spawning mshta/powershell/cmd

`UC_75_14` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count, min(_time) as firstTime, max(_time) as lastTime FROM datamodel=Endpoint.Processes WHERE Processes.parent_process_name="explorer.exe" (Processes.process_name IN ("mshta.exe","powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe")) (Processes.process IN ("*http://*","*https://*","*FromBase64String*","*DownloadString*","*DownloadFile*","*IEX*","*Invoke-Expression*","*-EncodedCommand*","*-enc *","*javascript:*","*mshtml:*","*Set-Clipboard*")) BY Processes.dest, Processes.user, Processes.parent_process, Processes.process, Processes.process_hash | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "explorer.exe"
| where FileName in~ ("mshta.exe","powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe")
| where ProcessCommandLine has_any ("http://","https://","FromBase64String","DownloadString","DownloadFile","IEX","Invoke-Expression","-EncodedCommand","-enc ","javascript:","mshtml:","Set-Clipboard","hidden")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine, SHA256
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `grpcurl.com`, `ghidralite.com`, `dcbbwymp1bhif.cloudfront.net`, `d3jzqhqvnvdy34.cloudfront.net`, `oundhertobeconisist.org`, `trkscope.xyz`, `file-enter-web.com`, `realcubeoyogenmyfire.monster` _(+4 more)_


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 15 use case(s) fired, 26 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

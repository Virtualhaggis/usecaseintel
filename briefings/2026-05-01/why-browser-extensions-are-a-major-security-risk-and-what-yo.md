# [CRIT] Why browser extensions are a major security risk and what you can do about it

**Source:** Aikido
**Published:** 2026-05-01
**Article:** https://www.aikido.dev/blog/browser-extension-security

## Threat Profile

Blog Guides & Best Practices Why browser extensions are a major security risk and what you can do about it Why browser extensions are a major security risk and what you can do about it Written by Dania Durnas Published on: May 1, 2026 Much of a developer’s work now lives in the browser, with tabs for GitHub, cloud consoles, CI/CD, and internal tools all authenticated and open at once. Browser extensions sit on top of this environment with broad permissions, often including access to page content…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

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
- **T1195.002** — Compromise Software Supply Chain
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1102.002** — Web Service: Bidirectional Communication
- **T1195.001** — Supply Chain Compromise: Compromise Software Dependencies and Development Tools
- **T1547** — Boot or Logon Autostart Execution

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Cyberhaven-cluster malicious Chrome extension C2 beacon to cyberhavenext[.]pro / Vultr IPs

`UC_197_7` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Network_Traffic.app) as app values(Network_Traffic.dest_port) as dest_port from datamodel=Network_Traffic.All_Traffic where (Network_Traffic.dest_ip IN ("149.28.124.84","45.76.225.148") OR Network_Traffic.dest="cyberhavenext.pro" OR Network_Traffic.dest="*.cyberhavenext.pro" OR Network_Traffic.url="*cyberhavenext.pro*") by Network_Traffic.src Network_Traffic.user Network_Traffic.dest Network_Traffic.dest_ip
| `drop_dm_object_name(Network_Traffic)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
let _bad_ips = dynamic(["149.28.124.84","45.76.225.148"]);
let _bad_domains = dynamic(["cyberhavenext.pro"]);
let _browsers = dynamic(["chrome.exe","msedge.exe","brave.exe","opera.exe","arc.exe","vivaldi.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (_bad_ips)
   or RemoteUrl has_any (_bad_domains)
| where InitiatingProcessFileName in~ (_browsers)
   or InitiatingProcessParentFileName in~ (_browsers)
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          RemoteIP, RemoteUrl, RemotePort,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, InitiatingProcessSHA256
| order by Timestamp desc
```

### [LLM] GlassWorm — VS Code / Cursor process polling Solana mainnet RPC for C2

`UC_197_8` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Network_Traffic.dest_ip) as dest_ips dc(_time) as distinctSeconds from datamodel=Network_Traffic.All_Traffic where Network_Traffic.dest IN ("api.mainnet-beta.solana.com","solana-rpc.publicnode.com","rpc.helius.xyz","solana-api.projectserum.com","*.mainnet-beta.solana.com") AND Network_Traffic.app IN ("Code.exe","code.exe","Cursor.exe","cursor.exe","Windsurf.exe","Code - Insiders.exe") by Network_Traffic.src Network_Traffic.user Network_Traffic.app Network_Traffic.dest
| `drop_dm_object_name(Network_Traffic)`
| where count >= 20 AND distinctSeconds >= 5
| convert ctime(firstTime) ctime(lastTime)
| sort - count
```

**Defender KQL:**
```kql
let _solana_hosts = dynamic(["mainnet-beta.solana.com","solana-rpc.publicnode.com","rpc.helius.xyz","solana-api.projectserum.com","api.devnet.solana.com"]);
let _ides = dynamic(["code.exe","cursor.exe","windsurf.exe","code - insiders.exe","code-insiders.exe","vscodium.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ (_ides)
| where RemoteUrl has_any (_solana_hosts)
| summarize ConnectionCount = count(),
            DistinctMinutes  = dcount(bin(Timestamp, 1m)),
            FirstSeen        = min(Timestamp),
            LastSeen         = max(Timestamp),
            SampleRemoteIPs  = make_set(RemoteIP, 5),
            SampleCmd        = any(InitiatingProcessCommandLine)
            by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteUrl
| where DistinctMinutes >= 5    // sustained polling, not a one-off lookup
| order by ConnectionCount desc
```

### [LLM] Non-browser process writing manifest.json / background.js into Chrome / Edge extension folder

`UC_197_9` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths values(Filesystem.file_hash) as hashes from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\Google\\Chrome\\User Data\\*\\Extensions\\*" OR Filesystem.file_path="*\\Microsoft\\Edge\\User Data\\*\\Extensions\\*" OR Filesystem.file_path="*\\BraveSoftware\\Brave-Browser\\User Data\\*\\Extensions\\*") AND Filesystem.file_name IN ("manifest.json","background.js","service-worker.js","content.js") AND NOT Filesystem.process_name IN ("chrome.exe","msedge.exe","brave.exe","opera.exe","arc.exe","vivaldi.exe","msiexec.exe","setup.exe","GoogleUpdate.exe","MicrosoftEdgeUpdate.exe") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
let _ext_paths = dynamic([
    @"\Google\Chrome\User Data\Default\Extensions\",
    @"\Google\Chrome\User Data\Default\Local Extension Settings\",
    @"\Microsoft\Edge\User Data\Default\Extensions\",
    @"\Microsoft\Edge\User Data\Default\Local Extension Settings\",
    @"\BraveSoftware\Brave-Browser\User Data\Default\Extensions\"]);
let _legit_writers = dynamic(["chrome.exe","msedge.exe","brave.exe","opera.exe","arc.exe","vivaldi.exe","msiexec.exe","setup.exe","googleupdate.exe","microsoftedgeupdate.exe","installer.exe"]);
let _ext_files = dynamic(["manifest.json","background.js","service-worker.js","content.js","contentscript.js"]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified")
| where FolderPath has_any (_ext_paths)
| where FileName in~ (_ext_files)
| where InitiatingProcessFileName !in~ (_legit_writers)
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          FolderPath, FileName, SHA256,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessSHA256
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


## Why this matters

Severity classified as **CRIT** based on: 10 use case(s) fired, 17 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

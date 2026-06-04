# [CRIT] JINX-0164 Targets Cryptocurrency Firms with Fake Recruiter Lures and macOS Malware

**Source:** The Hacker News
**Published:** 2026-05-28
**Article:** https://thehackernews.com/2026/05/jinx-0164-targets-cryptocurrency-firms.html

## Threat Profile

JINX-0164 Targets Cryptocurrency Firms with Fake Recruiter Lures and macOS Malware 
 Ravie Lakshmanan  May 28, 2026 Supply Chain Attack / Malware 
A new campaign orchestrated by a previously undocumented threat actor has targeted cryptocurrency organizations with an aim to facilitate digital asset theft using recruitment-themed social engineering and bespoke macOS malware.
"These campaigns leveraged sophisticated social engineering techniques, custom macOS malware, and deep targeting of CI/CD …

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `185.100.85.250`
- **IPv4 (defanged):** `84.32.83.250`
- **IPv4 (defanged):** `163.172.53.20`
- **IPv4 (defanged):** `185.100.85.98`
- **IPv4 (defanged):** `153.92.126.84`
- **IPv4 (defanged):** `45.45.217.242`
- **IPv4 (defanged):** `89.36.224.5`
- **IPv4 (defanged):** `208.115.220.17`
- **IPv4 (defanged):** `185.175.59.85`
- **Domain (defanged):** `apple.driver-store.com`
- **Domain (defanged):** `driver-store.com`
- **Domain (defanged):** `windows.driver-store.com`
- **Domain (defanged):** `driver-updater.net`
- **Domain (defanged):** `driver-hub.net`
- **Domain (defanged):** `apple.driver-hub.net`
- **Domain (defanged):** `driver-update.io`
- **Domain (defanged):** `apple.driver-update.io`
- **Domain (defanged):** `drvstore.com`
- **Domain (defanged):** `live.us.org`
- **Domain (defanged):** `team.live.us.org`
- **Domain (defanged):** `teams.live.us.org`
- **Domain (defanged):** `teams.us.org`
- **Domain (defanged):** `teams.cam`
- **Domain (defanged):** `teamicrosoft.com`
- **Domain (defanged):** `bitget-meeting.com`
- **Domain (defanged):** `us03-slack.online`
- **Domain (defanged):** `slktest.live`
- **Domain (defanged):** `live.ong`
- **Domain (defanged):** `retesta.live`
- **Domain (defanged):** `datahub.ink`
- **Domain (defanged):** `cloud-sync.online`
- **Domain (defanged):** `byte-io.us`
- **SHA256:** `65cba741fe30fa4799fb9002ea8de6d96042a59159dd7c3419c766af24c835e6`
- **SHA256:** `0b1a36a31b952341a534fe24890f1ed2921ee259773cff46e4f6273b8c4d5d21`
- **SHA256:** `e8ee6f5145c9d503c5130bfc6585567f6e19d409158c3c0ca0b259f1875b15f4`
- **SHA256:** `3e3901519c2305fbe9d5483b7234c25c6d2b562512916481d96f26b849c39fdb`
- **SHA256:** `0a8ab3d16b12d3a453ee5a3208fe04744ad54514ef8ea27bb8fe32679efad270`
- **SHA256:** `a35d2b67fa478a7174e308b43ce30bf69b3bc6f44fa76197fdf95fc2fbc1cf5b`
- **SHA256:** `9c2ce925133a3bf5a924063bbef8df49918d5b7258695c1894cd18c75970157a`
- **SHA256:** `402625ec79e3573a80b6de9b33fc1e503e3c7803603cd958ddd515fb0549007c`
- **SHA256:** `b6cab0b3aa8e56e2427f486c74588d598ae58bb0cbc0eda6939fe171cb0aed17`
- **SHA256:** `d4e863f9818bfb2f1dd932df6441dff204e6142c3bdb55b298cb08dc7b6a0c62`
- **SHA256:** `c6ef82d2864dfd26f117a1ef5602679153423f2742970a7949cec72722f0a01e`
- **SHA256:** `2a10ffe0367bb1b26ba2c3bc600892c21074725c0b8c9dc9161e6ceb33915460`

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
- **T1219** — Remote Access Software
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1568** — Dynamic Resolution
- **T1583.001** — Acquire Infrastructure: Domains
- **T1543.001** — Create or Modify System Process: Launch Agent
- **T1543.004** — Create or Modify System Process: Launch Daemon
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1566.002** — Phishing: Spearphishing Link
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1105** — Ingress Tool Transfer
- **T1555.001** — Credentials from Password Stores: Keychain
- **T1555.003** — Credentials from Password Stores: Credentials from Web Browsers
- **T1552.004** — Unsecured Credentials: Private Keys
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1027.013** — Obfuscated Files or Information: Encrypted/Encoded File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] JINX-0164 C2 communication to fake driver-store infrastructure

`UC_118_10` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.dest) as dest_host values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as app from datamodel=Network_Traffic where (All_Traffic.dest_ip IN ("185.100.85.250","84.32.83.250","163.172.53.20","185.100.85.98","153.92.126.84","45.45.217.242","89.36.224.5","208.115.220.17") OR All_Traffic.dest IN ("*driver-store.com","*driver-hub.net","*driver-update.io","*driver-updater.net")) by All_Traffic.src host index | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let JinxDomains = dynamic(["driver-store.com","driver-hub.net","driver-update.io","driver-updater.net"]);
let JinxIPs = dynamic(["185.100.85.250","84.32.83.250","163.172.53.20","185.100.85.98","153.92.126.84","45.45.217.242","89.36.224.5","208.115.220.17"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (JinxIPs)
   or RemoteUrl has_any (JinxDomains)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName, RemoteIP, RemoteUrl, RemotePort, Protocol
| order by Timestamp desc
```

### [LLM] AUDIOFIX persistence: ChromeUpdater binary loaded via launchctl on macOS

`UC_118_11` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.process_path) as process_path values(Processes.user) as user values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where ((Processes.process_name="launchctl" AND Processes.process="*ChromeUpdater*") OR Processes.process_name="ChromeUpdater" OR Processes.process_path="*ChromeUpdater*") by host Processes.process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | append [| tstats `summariesonly` count from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/Library/LaunchAgents/*" OR Filesystem.file_path="*/Library/LaunchDaemons/*") (Filesystem.file_name="*ChromeUpdater*" OR Filesystem.file_path="*ChromeUpdater*") by host Filesystem.file_path Filesystem.file_name Filesystem.process_name | `drop_dm_object_name(Filesystem)`]
```

**Defender KQL:**
```kql
union
  (DeviceProcessEvents
   | where Timestamp > ago(30d)
   | where (FileName =~ "launchctl" and ProcessCommandLine has "ChromeUpdater")
        or FileName =~ "ChromeUpdater"
        or FolderPath has "/ChromeUpdater"
   | project Timestamp, DeviceName, AccountName, EventKind="ProcessExec", FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, SHA256),
  (DeviceFileEvents
   | where Timestamp > ago(30d)
   | where ActionType in ("FileCreated","FileRenamed","FileModified")
   | where (FolderPath has_any ("/Library/LaunchAgents/","/Library/LaunchDaemons/","/LaunchAgents/","/LaunchDaemons/") and (FileName has "ChromeUpdater" or FileName endswith ".plist"))
        or FileName =~ "ChromeUpdater"
   | where InitiatingProcessFileName !in~ ("GoogleSoftwareUpdate","GoogleSoftwareUpdateAgent","GoogleSoftwareUpdateDaemon")
   | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, EventKind="FileWrite", FileName, FolderPath, ProcessCommandLine="", InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, SHA256)
| order by Timestamp desc
```

### [LLM] JINX-0164 AUDIOFIX delivery: shell payload retrieved from driver-store family domain

`UC_118_12` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.user) as user values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where Processes.process_name IN ("curl","wget","bash","zsh","sh","osascript") (Processes.process="*driver-store.com*" OR Processes.process="*driver-hub.net*" OR Processes.process="*driver-update.io*" OR Processes.process="*driver-updater.net*") by host Processes.process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("curl","wget","bash","zsh","sh","osascript")
| where ProcessCommandLine has_any ("driver-store.com","driver-hub.net","driver-update.io","driver-updater.net")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### [LLM] AUDIOFIX credential staging: Python parent invoking security/sqlite3/keychain extraction on macOS

`UC_118_13` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.parent_process_name="python*" Processes.process_name IN ("security","sqlite3","plutil","ditto","cp","mv","tar","zip","openssl","base64") (Processes.process="*login.keychain*" OR Processes.process="*keychain-db*" OR Processes.process="*find-generic-password*" OR Processes.process="*find-internet-password*" OR Processes.process="*Local Extension Settings*" OR Processes.process="*MetaMask*" OR Processes.process="*Phantom*" OR Processes.process="*/Discord*" OR Processes.process="*/Slack*" OR Processes.process="*/Telegram*" OR Processes.process="*/.ssh/*" OR Processes.process="*Bitwarden*" OR Processes.process="*1Password*") by host Processes.parent_process_name Processes.process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName matches regex @"^python[0-9.]*$"
| where FileName in~ ("security","sqlite3","plutil","ditto","cp","mv","tar","zip","openssl","base64")
| where ProcessCommandLine has_any (
    "login.keychain",
    "keychain-db",
    "find-generic-password",
    "find-internet-password",
    "Local Extension Settings",
    "/Discord",
    "/Slack",
    "/Telegram",
    "/.ssh/",
    "MetaMask",
    "Phantom",
    "Bitwarden",
    "1Password",
    "nkbihfbeogaeaoehlefnkodbefgpgknn",
    "fhbohimaelbohpjbbldcngcnapndodjp",
    "ejbalbakoplchlghecdalmeeeajnimhm")
| summarize DistinctTargets = dcount(ProcessCommandLine), SampleCmds = make_set(ProcessCommandLine, 8), FirstSeen = min(Timestamp), LastSeen = max(Timestamp), ChildBins = make_set(FileName) by DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
| where DistinctTargets >= 2
| order by LastSeen desc
```

### [LLM] Supply chain: install or runtime import of poisoned @velora-dex/sdk@9.4.1 (MiniRAT dropper)

`UC_118_14` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.user) as user values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where Processes.process_name IN ("npm","node","yarn","pnpm","npx") (Processes.process="*@velora-dex/sdk*" OR Processes.process="*velora-dex+sdk*") by host Processes.process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | append [| tstats `summariesonly` count from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*node_modules/@velora-dex/sdk*" OR Filesystem.file_path="*node_modules/.pnpm/@velora-dex+sdk@9.4.1*") by host Filesystem.file_path Filesystem.file_name Filesystem.process_name | `drop_dm_object_name(Filesystem)`]
```

**Defender KQL:**
```kql
union
  (DeviceProcessEvents
   | where Timestamp > ago(60d)
   | where FileName in~ ("npm","node","yarn","pnpm","npx")
        or InitiatingProcessFileName in~ ("npm","node","yarn","pnpm","npx")
   | where ProcessCommandLine has "@velora-dex/sdk"
        or ProcessCommandLine has "velora-dex+sdk"
        or InitiatingProcessCommandLine has "@velora-dex/sdk"
   | project Timestamp, DeviceName, AccountName, EventKind="ProcessExec", FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName),
  (DeviceFileEvents
   | where Timestamp > ago(60d)
   | where FolderPath has_any ("node_modules/@velora-dex/sdk","node_modules/.pnpm/@velora-dex+sdk@9.4.1","@velora-dex\\sdk")
   | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, EventKind="FileWrite", FileName, FolderPath, ProcessCommandLine="", InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName="")
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
  - IP / domain IOC(s): `185.100.85.250`, `84.32.83.250`, `163.172.53.20`, `185.100.85.98`, `153.92.126.84`, `45.45.217.242`, `89.36.224.5`, `208.115.220.17` _(+24 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `65cba741fe30fa4799fb9002ea8de6d96042a59159dd7c3419c766af24c835e6`, `0b1a36a31b952341a534fe24890f1ed2921ee259773cff46e4f6273b8c4d5d21`, `e8ee6f5145c9d503c5130bfc6585567f6e19d409158c3c0ca0b259f1875b15f4`, `3e3901519c2305fbe9d5483b7234c25c6d2b562512916481d96f26b849c39fdb`, `0a8ab3d16b12d3a453ee5a3208fe04744ad54514ef8ea27bb8fe32679efad270`, `a35d2b67fa478a7174e308b43ce30bf69b3bc6f44fa76197fdf95fc2fbc1cf5b`, `9c2ce925133a3bf5a924063bbef8df49918d5b7258695c1894cd18c75970157a`, `402625ec79e3573a80b6de9b33fc1e503e3c7803603cd958ddd515fb0549007c` _(+4 more)_


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 15 use case(s) fired, 31 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

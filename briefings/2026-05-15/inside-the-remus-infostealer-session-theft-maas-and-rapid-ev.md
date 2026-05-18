# [HIGH] Inside the REMUS Infostealer: Session Theft, MaaS, and Rapid Evolution

**Source:** BleepingComputer
**Published:** 2026-05-15
**Article:** https://www.bleepingcomputer.com/news/security/inside-the-remus-infostealer-session-theft-maas-and-rapid-evolution/

## Threat Profile

Inside the REMUS Infostealer: Session Theft, MaaS, and Rapid Evolution 
Sponsored by Flare 
May 15, 2026
10:02 AM
0 
In recent months, a new infostealer malware known as REMUS has emerged across the cybercrime landscape, drawing attention from security researchers and malware analysts. Several technical analyses published in recent months focused on the malware’s capabilities, infrastructure, and similarities to Lumma Stealer, including browser targeting mechanisms, and credential theft function…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1204.002** — User Execution: Malicious File
- **T1102.001** — Web Service: Dead Drop Resolver
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1568** — Dynamic Resolution
- **T1555.005** — Credentials from Password Stores: Password Managers
- **T1005** — Data from Local System

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] REMUS infostealer known sample SHA256 hash hunt

`UC_26_4` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.process_path) as process_path values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where Processes.process_hash IN ("cfcb21d8df942918f7a74b99f2cccf7e54e2a6dd1ea6de60897ff0026a26b5c4","352721b32ec1c8349985ceccfec8d1ca6e3e6cc12f83350c4ae1a75477588bc2") by Processes.dest Processes.user Processes.process_name Processes.process_hash | `drop_dm_object_name(Processes)` | append [| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("cfcb21d8df942918f7a74b99f2cccf7e54e2a6dd1ea6de60897ff0026a26b5c4","352721b32ec1c8349985ceccfec8d1ca6e3e6cc12f83350c4ae1a75477588bc2") by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.file_hash | `drop_dm_object_name(Filesystem)`] | convert ctime(firstTime), ctime(lastTime)
```

**Defender KQL:**
```kql
let RemusHashes = dynamic(["cfcb21d8df942918f7a74b99f2cccf7e54e2a6dd1ea6de60897ff0026a26b5c4","352721b32ec1c8349985ceccfec8d1ca6e3e6cc12f83350c4ae1a75477588bc2"]);
union isfuzzy=true
(DeviceProcessEvents
 | where Timestamp > ago(30d)
 | where SHA256 in~ (RemusHashes)
 | project Timestamp, DeviceName, AccountName, Source="ProcessExec", FileName, FolderPath, SHA256, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine),
(DeviceFileEvents
 | where Timestamp > ago(30d)
 | where SHA256 in~ (RemusHashes)
 | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, Source="FileWrite", FileName, FolderPath, SHA256, ProcessCommandLine=InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine),
(DeviceImageLoadEvents
 | where Timestamp > ago(30d)
 | where SHA256 in~ (RemusHashes)
 | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, Source="ImageLoad", FileName, FolderPath, SHA256, ProcessCommandLine=InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine="")
| order by Timestamp desc
```

### [LLM] Ethereum JSON-RPC blockchain C2 resolution by non-wallet process (REMUS dead-drop)

`UC_26_5` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as app from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest IN ("*.cloudflare-eth.com","*.infura.io","*.g.alchemy.com","*.ankr.com","*.publicnode.com","*.llamarpc.com","*.pokt.network","*.flashbots.net","*.builder0x69.io","*.mycryptoapi.com") OR All_Traffic.url="*eth_call*" OR All_Traffic.url="*eth_getStorageAt*") AND NOT (All_Traffic.app IN ("chrome.exe","msedge.exe","brave.exe","firefox.exe","opera.exe","vivaldi.exe","arc.exe","yandex.exe","metamask.exe","exodus.exe","atomic.exe","phantom.exe","ledger live.exe","trezor suite.exe")) by All_Traffic.src All_Traffic.user All_Traffic.dest All_Traffic.app | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime), ctime(lastTime)
```

**Defender KQL:**
```kql
let EthRpcHosts = dynamic(["cloudflare-eth.com","infura.io","g.alchemy.com","rpc.ankr.com","publicnode.com","llamarpc.com","pokt.network","flashbots.net","builder0x69.io","mycryptoapi.com","chainnodes.org","blastapi.io","nodereal.io","quiknode.pro"]);
let KnownEthClients = dynamic(["chrome.exe","msedge.exe","brave.exe","firefox.exe","opera.exe","operagx.exe","vivaldi.exe","arc.exe","yandex.exe","msedgewebview2.exe","metamask.exe","exodus.exe","atomic.exe","phantom.exe","ledger live.exe","trezor suite.exe","frame.exe","rabby.exe","node.exe","hardhat.exe","geth.exe","foundry.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType in ("ConnectionSuccess","ConnectionAttempt","HttpConnectionInspected")
| where RemoteIPType == "Public"
| where isnotempty(RemoteUrl)
| extend HostLower = tolower(RemoteUrl)
| where HostLower has_any (EthRpcHosts)
| where InitiatingProcessFileName !in~ (KnownEthClients)
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessSHA256,
          RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### [LLM] Password-manager browser-extension IndexedDB access by non-browser process (REMUS PWM collection)

`UC_26_6` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.file_name) as file_name from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\IndexedDB\\chrome-extension_aeblfdkhhhdcdjpifhhbdiojplfjncoa_*" OR Filesystem.file_path="*\\IndexedDB\\chrome-extension_gejiddohjgogedgjnonbofjigllpkmbf_*" OR Filesystem.file_path="*\\IndexedDB\\chrome-extension_dppgmdbiimibapkepcbdbmkaabgiofem_*" OR Filesystem.file_path="*\\IndexedDB\\chrome-extension_hdokiejnpimakedhajhdlcegeplioahd_*" OR Filesystem.file_path="*\\IndexedDB\\chrome-extension_bbcinlkgjjkejfdpemiealijmmooekmp_*" OR Filesystem.file_path="*\\IndexedDB\\chrome-extension_nngceckbapebfimnlniiiahkandclblb_*" OR Filesystem.file_path="*\\IndexedDB\\chrome-extension_jbkfoedolllekgbhcbcoahefnbanhhlh_*") AND NOT (Filesystem.process_name IN ("chrome.exe","msedge.exe","brave.exe","opera.exe","operagx.exe","vivaldi.exe","arc.exe","yandex.exe","msedgewebview2.exe","1Password.exe","Bitwarden.exe","LastPass.exe")) by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.process_path | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime), ctime(lastTime)
```

**Defender KQL:**
```kql
let PwmExtensionIds = dynamic([
  "aeblfdkhhhdcdjpifhhbdiojplfjncoa",  // 1Password legacy Chrome
  "gejiddohjgogedgjnonbofjigllpkmbf",  // 1Password 7/8 Chrome
  "dppgmdbiimibapkepcbdbmkaabgiofem",  // 1Password Edge
  "hdokiejnpimakedhajhdlcegeplioahd",  // LastPass Chrome
  "bbcinlkgjjkejfdpemiealijmmooekmp",  // LastPass Edge
  "nngceckbapebfimnlniiiahkandclblb",  // Bitwarden Chrome
  "jbkfoedolllekgbhcbcoahefnbanhhlh"   // Bitwarden Edge
]);
let LegitProcesses = dynamic(["chrome.exe","msedge.exe","brave.exe","opera.exe","operagx.exe","vivaldi.exe","arc.exe","yandex.exe","msedgewebview2.exe","1password.exe","bitwarden.exe","lastpass.exe","msmpeng.exe","mssense.exe","sense.exe"]);
union isfuzzy=true
(DeviceFileEvents
 | where Timestamp > ago(7d)
 | where ActionType in ("FileCreated","FileModified","FileRenamed")
 | where FolderPath has_any (PwmExtensionIds)
     or PreviousFolderPath has_any (PwmExtensionIds)
     or FileName has_any (PwmExtensionIds)
 | where InitiatingProcessFileName !in~ (LegitProcesses)
 | where InitiatingProcessAccountName !endswith "$"
 | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName,
           Source="FileEvent", ActionType, FolderPath, FileName, PreviousFolderPath,
           BadProcess=InitiatingProcessFileName, BadProcessPath=InitiatingProcessFolderPath,
           BadProcessCmd=InitiatingProcessCommandLine, BadProcessSHA256=InitiatingProcessSHA256),
(DeviceProcessEvents
 | where Timestamp > ago(7d)
 | where ProcessCommandLine has "IndexedDB" and ProcessCommandLine has "chrome-extension_"
 | where ProcessCommandLine has_any (PwmExtensionIds)
 | where FileName !in~ (LegitProcesses)
 | where AccountName !endswith "$"
 | project Timestamp, DeviceName, AccountName,
           Source="ProcessCmdLine", ActionType="ProcessCreated", FolderPath, FileName="", PreviousFolderPath="",
           BadProcess=FileName, BadProcessPath=FolderPath,
           BadProcessCmd=ProcessCommandLine, BadProcessSHA256=SHA256)
| order by Timestamp desc
```

### [LLM] Browser session cookie / Login Data / Discord / Telegram token read by non-application process (REMUS session theft)

`UC_26_7` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.file_name) as file_name from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\User Data\\Default\\Login Data*" OR Filesystem.file_path="*\\User Data\\Default\\Network\\Cookies*" OR Filesystem.file_path="*\\User Data\\Local State*" OR Filesystem.file_path="*\\User Data\\Default\\Web Data*" OR Filesystem.file_name="cookies.sqlite" OR Filesystem.file_name="logins.json" OR Filesystem.file_name="key4.db" OR Filesystem.file_path="*\\discord\\Local Storage\\leveldb\\*" OR Filesystem.file_path="*\\discordcanary\\Local Storage\\leveldb\\*" OR Filesystem.file_path="*\\discordptb\\Local Storage\\leveldb\\*" OR Filesystem.file_path="*\\Telegram Desktop\\tdata\\*" OR Filesystem.file_name="loginusers.vdf" OR Filesystem.file_name="ssfn*") AND NOT (Filesystem.process_name IN ("chrome.exe","msedge.exe","brave.exe","firefox.exe","opera.exe","vivaldi.exe","arc.exe","msedgewebview2.exe","discord.exe","discordcanary.exe","discordptb.exe","update.exe","telegram.exe","telegramdesktop.exe","steam.exe","steamservice.exe","steamwebhelper.exe","riotclientservices.exe","riotclientux.exe","msmpeng.exe","mssense.exe")) by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.process_path | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime), ctime(lastTime)
```

**Defender KQL:**
```kql
let CredFiles = dynamic(["\\User Data\\Default\\Login Data","\\User Data\\Default\\Network\\Cookies","\\User Data\\Default\\Cookies","\\User Data\\Local State","\\User Data\\Default\\Web Data","cookies.sqlite","logins.json","key4.db","key3.db","\\discord\\Local Storage\\leveldb\\","\\discordcanary\\Local Storage\\leveldb\\","\\discordptb\\Local Storage\\leveldb\\","\\Telegram Desktop\\tdata\\","loginusers.vdf","config.vdf","ssfn"]);
let LegitOwners = dynamic(["chrome.exe","msedge.exe","brave.exe","firefox.exe","opera.exe","operagx.exe","vivaldi.exe","arc.exe","yandex.exe","msedgewebview2.exe","discord.exe","discordcanary.exe","discordptb.exe","update.exe","squirrel.exe","telegram.exe","telegramdesktop.exe","steam.exe","steamservice.exe","steamwebhelper.exe","riotclientservices.exe","riotclientux.exe","msmpeng.exe","mssense.exe","sense.exe","sensendr.exe","sentinelagent.exe","csfalconservice.exe","csfalcon.exe"]);
union isfuzzy=true
(DeviceFileEvents
 | where Timestamp > ago(7d)
 | where ActionType in ("FileCreated","FileModified","FileRenamed")
 | where FolderPath has_any (CredFiles) or FileName has_any (CredFiles)
     or PreviousFolderPath has_any (CredFiles) or PreviousFileName has_any (CredFiles)
 | where InitiatingProcessFileName !in~ (LegitOwners)
 | where InitiatingProcessAccountName !endswith "$"
 | where InitiatingProcessIntegrityLevel !in~ ("System")
 | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName,
           Source="FileEvent", ActionType, FolderPath, FileName, PreviousFolderPath, PreviousFileName,
           BadProcess=InitiatingProcessFileName, BadProcessPath=InitiatingProcessFolderPath,
           BadProcessCmd=InitiatingProcessCommandLine, BadProcessSHA256=InitiatingProcessSHA256),
(DeviceProcessEvents
 | where Timestamp > ago(7d)
 | where ProcessCommandLine has_any (CredFiles)
 | where FileName !in~ (LegitOwners)
 | where AccountName !endswith "$"
 | project Timestamp, DeviceName, AccountName,
           Source="ProcessCmdLine", ActionType="ProcessCreated", FolderPath, FileName="", PreviousFolderPath="", PreviousFileName="",
           BadProcess=FileName, BadProcessPath=FolderPath,
           BadProcessCmd=ProcessCommandLine, BadProcessSHA256=SHA256)
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


## Why this matters

Severity classified as **HIGH** based on: 8 use case(s) fired, 14 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

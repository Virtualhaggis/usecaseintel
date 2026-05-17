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
- **T1555.005** — Credentials from Password Stores: Password Managers
- **T1083** — File and Directory Discovery
- **T1567** — Exfiltration Over Web Service
- **T1102** — Web Service
- **T1550.004** — Use Alternate Authentication Material: Web Session Cookie
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1090.002** — External Proxy

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] REMUS-style password manager IndexedDB access by non-browser process (1P/LastPass/Bitwarden)

`UC_20_4` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_paths values(Filesystem.file_name) as file_names values(Filesystem.action) as actions from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*aeblfdkhhhdcdjpifhhbdiojplfjncoa*" OR Filesystem.file_path="*aomjjhallfgjeglblehebfpbcfeobpgk*" OR Filesystem.file_path="*nngceckbapebfimnlniiiahkandclblb*" OR Filesystem.file_path="*jbkfoedolllekgbhcbcoahefnbanhhlh*" OR Filesystem.file_path="*hdokiejnpimakedhajhdlcegeplioahd*") AND (Filesystem.file_path="*\\Local Extension Settings\\*" OR Filesystem.file_path="*\\IndexedDB\\chrome-extension_*" OR Filesystem.file_path="*\\Local Storage\\leveldb\\*") AND Filesystem.process_name!="chrome.exe" AND Filesystem.process_name!="msedge.exe" AND Filesystem.process_name!="firefox.exe" AND Filesystem.process_name!="brave.exe" AND Filesystem.process_name!="opera.exe" AND Filesystem.process_name!="vivaldi.exe" AND Filesystem.process_name!="arc.exe" by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.process_path Filesystem.process_guid | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let pm_ext_ids = dynamic(["aeblfdkhhhdcdjpifhhbdiojplfjncoa","aomjjhallfgjeglblehebfpbcfeobpgk","nngceckbapebfimnlniiiahkandclblb","jbkfoedolllekgbhcbcoahefnbanhhlh","hdokiejnpimakedhajhdlcegeplioahd"]);
let browsers = dynamic(["chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","vivaldi.exe","arc.exe","iexplore.exe"]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where InitiatingProcessFileName !in~ (browsers)
| where FolderPath has_any (pm_ext_ids)
| where FolderPath has_any (@"\Local Extension Settings\", @"\IndexedDB\chrome-extension_", @"\Local Storage\leveldb\")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessSHA256, ActionType, FileName, FolderPath
| order by Timestamp desc
```

### [LLM] Browser credential store read followed by Telegram API egress within 5 min (REMUS exfil chain)

`UC_20_5` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as cred_time values(Filesystem.file_path) as cred_paths values(Filesystem.process_name) as cred_process from datamodel=Endpoint.Filesystem where (Filesystem.file_name IN ("Login Data","Cookies","Local State","Web Data","key4.db","cookies.sqlite","logins.json","formhistory.sqlite") OR Filesystem.file_path="*\\Local Extension Settings\\*" OR Filesystem.file_path="*\\IndexedDB\\chrome-extension_*") AND (Filesystem.file_path="*\\Chrome\\User Data\\*" OR Filesystem.file_path="*\\Edge\\User Data\\*" OR Filesystem.file_path="*\\Firefox\\Profiles\\*" OR Filesystem.file_path="*\\Mozilla\\Firefox\\Profiles\\*" OR Filesystem.file_path="*\\BraveSoftware\\Brave-Browser\\User Data\\*") AND Filesystem.process_name!="chrome.exe" AND Filesystem.process_name!="msedge.exe" AND Filesystem.process_name!="firefox.exe" AND Filesystem.process_name!="brave.exe" AND Filesystem.process_name!="opera.exe" AND Filesystem.process_name!="vivaldi.exe" by Filesystem.dest Filesystem.user Filesystem.process_guid | `drop_dm_object_name(Filesystem)` | join type=inner dest [ | tstats summariesonly=t count min(_time) as net_time values(All_Traffic.dest) as remote_host values(All_Traffic.dest_ip) as remote_ip values(All_Traffic.app) as net_process from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="api.telegram.org" OR All_Traffic.dest="t.me" OR All_Traffic.dest="*telegram.org") AND All_Traffic.app!="telegram.exe" AND All_Traffic.app!="tdesktop.exe" AND All_Traffic.app!="chrome.exe" AND All_Traffic.app!="msedge.exe" AND All_Traffic.app!="firefox.exe" AND All_Traffic.app!="brave.exe" by All_Traffic.src | rename All_Traffic.src as dest ] | where net_time >= cred_time AND (net_time - cred_time) <= 300 | eval delay_sec = net_time - cred_time | table dest user cred_process cred_paths net_process remote_host remote_ip delay_sec
```

**Defender KQL:**
```kql
let LookbackDays = 7d;
let WindowSec = 300;
let browsers = dynamic(["chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","vivaldi.exe","arc.exe"]);
let CredAccess = DeviceFileEvents
    | where Timestamp > ago(LookbackDays)
    | where InitiatingProcessFileName !in~ (browsers)
    | where InitiatingProcessAccountName !endswith "$"
    | where FolderPath has_any (@"\Chrome\User Data\", @"\Edge\User Data\", @"\Firefox\Profiles\", @"\Mozilla\Firefox\Profiles\", @"\BraveSoftware\Brave-Browser\User Data\")
    | where FileName in~ ("Login Data","Cookies","Web Data","Local State","key4.db","cookies.sqlite","logins.json","formhistory.sqlite")
        or FolderPath has_any (@"\Local Extension Settings\", @"\IndexedDB\chrome-extension_")
    | project CredTime = Timestamp, DeviceId, DeviceName, AccountName = InitiatingProcessAccountName, StealerProcess = InitiatingProcessFileName, StealerCmd = InitiatingProcessCommandLine, StealerHash = InitiatingProcessSHA256, StealerPid = InitiatingProcessId, AccessedFile = strcat(FolderPath, FileName);
DeviceNetworkEvents
| where Timestamp > ago(LookbackDays)
| where RemoteUrl has_any ("api.telegram.org","t.me","telegram.org")
| where InitiatingProcessFileName !in~ ("telegram.exe","tdesktop.exe","updater.exe","chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","vivaldi.exe")
| join kind=inner CredAccess on DeviceId
| where Timestamp between (CredTime .. CredTime + WindowSec * 1s)
| extend DelaySec = datetime_diff('second', Timestamp, CredTime)
| project CredTime, NetworkTime = Timestamp, DelaySec, DeviceName, AccountName, StealerProcess, StealerCmd, StealerHash, AccessedFile, RemoteUrl, RemoteIP, RemotePort, NetProcess = InitiatingProcessFileName, NetProcessHash = InitiatingProcessSHA256, NetProcessCmd = InitiatingProcessCommandLine
| order by NetworkTime desc
```

### [LLM] Post-stealer cookie-satisfied Entra ID sign-in from new ASN/anonymizer (REMUS session replay)

`UC_20_6` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as stealer_time values(Filesystem.process_name) as stealer_process values(Filesystem.file_name) as stealer_files from datamodel=Endpoint.Filesystem where (Filesystem.file_name IN ("Login Data","Cookies","Local State","key4.db","cookies.sqlite") OR Filesystem.file_path="*\\Local Extension Settings\\*") AND (Filesystem.file_path="*\\Chrome\\User Data\\*" OR Filesystem.file_path="*\\Edge\\User Data\\*" OR Filesystem.file_path="*\\Firefox\\Profiles\\*") AND Filesystem.process_name!="chrome.exe" AND Filesystem.process_name!="msedge.exe" AND Filesystem.process_name!="firefox.exe" AND Filesystem.process_name!="brave.exe" by Filesystem.dest Filesystem.user | `drop_dm_object_name(Filesystem)` | rename user as src_user dest as victim_host | join type=inner src_user [ | tstats summariesonly=t count min(_time) as signin_time values(Authentication.src) as signin_ip values(Authentication.app) as signin_app values(Authentication.signature) as signature from datamodel=Authentication where Authentication.action="success" AND (Authentication.signature="*previously satisfied*" OR Authentication.signature="*satisfied by claim*" OR Authentication.signature="*satisfied by token*") by Authentication.user | rename Authentication.user as src_user ] | where signin_time >= stealer_time AND (signin_time - stealer_time) <= 14400 | eval delay_min = round((signin_time - stealer_time)/60, 1) | table src_user victim_host stealer_process stealer_files signin_ip signin_app signature delay_min
```

**Defender KQL:**
```kql
let LookbackDays = 7d;
let WindowMin = 240;
let browsers = dynamic(["chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","vivaldi.exe","arc.exe"]);
let Stealer = DeviceFileEvents
    | where Timestamp > ago(LookbackDays)
    | where InitiatingProcessFileName !in~ (browsers)
    | where InitiatingProcessAccountName !endswith "$"
    | where FolderPath has_any (@"\Chrome\User Data\", @"\Edge\User Data\", @"\Firefox\Profiles\")
    | where FileName in~ ("Login Data","Cookies","Local State","key4.db","cookies.sqlite")
        or FolderPath has_any (@"\Local Extension Settings\", @"\IndexedDB\chrome-extension_")
    | summarize StealerTime = min(Timestamp), StealerProcess = any(InitiatingProcessFileName), StealerHash = any(InitiatingProcessSHA256) by DeviceName, AccountUpn = InitiatingProcessAccountUpn
    | where isnotempty(AccountUpn);
AADSignInEventsBeta
| where Timestamp > ago(LookbackDays)
| where ErrorCode == 0
| where ClientAppUsed in ("Browser","Mobile Apps and Desktop clients")
| extend AuthDetails = tostring(AuthenticationDetails)
| where AuthDetails has_any ("Previously satisfied","satisfied by claim","satisfied by token")
    or AuthenticationRequirement =~ "singleFactorAuthentication"
| join kind=inner Stealer on AccountUpn
| where Timestamp between (StealerTime .. StealerTime + WindowMin * 1m)
| where IsAnonymousProxy == true
    or Country !in ("US","GB","CA","IE","AU","NL","DE","FR")
| extend DelayMin = datetime_diff('minute', Timestamp, StealerTime)
| project StealerTime, SignInTime = Timestamp, DelayMin, AccountUpn, VictimHost = DeviceName, StealerProcess, StealerHash, SignInIP = IPAddress, Country, City, Application, ApplicationId, IsAnonymousProxy, RiskLevelDuringSignIn, AuthDetails
| order by SignInTime desc
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

Severity classified as **HIGH** based on: 7 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

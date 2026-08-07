# [CRIT] Hedge fund cyberattacks tied to BlackFile-linked UNC6671 extortion group

**Source:** BleepingComputer
**Published:** 2026-08-06
**Article:** https://www.bleepingcomputer.com/news/security/hedge-fund-cyberattacks-tied-to-blackfile-linked-unc6671-extortion-group/

## Threat Profile

Hedge fund cyberattacks tied to BlackFile-linked UNC6671 extortion group 
By Lawrence Abrams 
August 6, 2026
04:07 PM
0 
A recent wave of cyberattacks targeting hedge funds, private-equity firms, and other financial organizations has been linked to UNC6671, an extortion group reportedly associated with the BlackFile campaign extortion group.
The attribution comes after Reuters  and Bloomberg reported that Point72 Asset Management, Millennium Management, Two Sigma Investments, Citadel, and severa…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `31.7.56.61`
- **IPv4 (defanged):** `31.7.56.52`
- **IPv4 (defanged):** `193.34.212.132`
- **IPv4 (defanged):** `185.178.208.153`
- **IPv4 (defanged):** `23.234.75.84`
- **IPv4 (defanged):** `195.140.213.114`
- **IPv4 (defanged):** `195.140.213.115`
- **IPv4 (defanged):** `107.128.45.122`
- **IPv4 (defanged):** `76.103.148.180`
- **IPv4 (defanged):** `38.42.59.171`
- **IPv4 (defanged):** `47.218.103.146`
- **Domain (defanged):** `myoktasso.com`
- **Domain (defanged):** `mypasskeysso.com`
- **Domain (defanged):** `setupssopasskey.com`
- **Domain (defanged):** `mspasskey.com`
- **Domain (defanged):** `activatepasskey.com`
- **Domain (defanged):** `enrollpasskey.com`
- **Domain (defanged):** `keyokta.com`
- **Domain (defanged):** `oktaenroll.com`
- **Domain (defanged):** `oktaportalsso.com`
- **Domain (defanged):** `passkeyportal.com`
- **Domain (defanged):** `portalpasskey.com`
- **Domain (defanged):** `passkeyportalsetup.com`
- **Domain (defanged):** `addoktapasskey.com`
- **Domain (defanged):** `deploypasskey.com`
- **Domain (defanged):** `passkeydeploy.com`
- **Domain (defanged):** `activatemypasskey.com`
- **Domain (defanged):** `registerpasskey.com`
- **Domain (defanged):** `createpasskey.com`
- **Domain (defanged):** `passkeyadd.com`
- **Domain (defanged):** `passkeyregister.com`
- **Domain (defanged):** `passkeycenter.com`
- **Domain (defanged):** `secureauthpasskey.com`
- **Domain (defanged):** `passkeyrollout.com`
- **Domain (defanged):** `setpasskey.com`
- **Domain (defanged):** `passkeyokta.com`
- **Domain (defanged):** `passkeyset.com`
- **Domain (defanged):** `createmypasskey.com`
- **Domain (defanged):** `newpasskey.com`
- **Domain (defanged):** `passkeysupport.com`
- **Domain (defanged):** `sqfepjvmrd.xyz`

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
- **T1071** — Application Layer Protocol
- **T1566.004** — Phishing: Spearphishing Voice
- **T1557** — Adversary-in-the-Middle
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1550.004** — Use Alternate Authentication Material: Web Session Cookie
- **T1530** — Data from Cloud Storage
- **T1119** — Automated Collection
- **T1567.002** — Exfiltration to Cloud Storage
- **T1526** — Cloud Service Discovery
- **T1070.008** — Email Collection: Clear Mailbox Data
- **T1070.004** — Indicator Removal: File Deletion

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### UNC6671 passkey/Okta AiTM phishing domain resolution from endpoints

`UC_9_5` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution where DNS.query IN ("myoktasso.com","*.myoktasso.com","mypasskeysso.com","*.mypasskeysso.com","setupssopasskey.com","*.setupssopasskey.com","mspasskey.com","*.mspasskey.com","activatepasskey.com","*.activatepasskey.com","enrollpasskey.com","*.enrollpasskey.com","keyokta.com","*.keyokta.com","oktaenroll.com","*.oktaenroll.com","oktaportalsso.com","*.oktaportalsso.com","passkeyportal.com","*.passkeyportal.com","portalpasskey.com","*.portalpasskey.com","passkeyportalsetup.com","*.passkeyportalsetup.com","addoktapasskey.com","*.addoktapasskey.com","deploypasskey.com","*.deploypasskey.com","passkeydeploy.com","*.passkeydeploy.com","activatemypasskey.com","*.activatemypasskey.com","registerpasskey.com","*.registerpasskey.com","createpasskey.com","*.createpasskey.com","passkeyadd.com","*.passkeyadd.com","passkeyregister.com","*.passkeyregister.com") by DNS.src DNS.query DNS.dest | `drop_dm_object_name(DNS)` | `ctime(firstTime)` | `ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents | where Timestamp > ago(30d) | where RemoteUrl has_any ("myoktasso.com","mypasskeysso.com","setupssopasskey.com","mspasskey.com","activatepasskey.com","enrollpasskey.com","keyokta.com","oktaenroll.com","oktaportalsso.com","passkeyportal.com","portalpasskey.com","passkeyportalsetup.com","addoktapasskey.com","deploypasskey.com","passkeydeploy.com","activatemypasskey.com","registerpasskey.com","createpasskey.com","passkeyadd.com","passkeyregister.com") | project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteUrl, RemoteIP, InitiatingProcessCommandLine | order by Timestamp desc
```

### M365/Okta sign-in from UNC6671 AiTM proxy & residential-proxy infrastructure

`UC_9_6` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Authentication where Authentication.src IN ("31.7.56.61","31.7.56.52","193.34.212.132","185.178.208.153","23.234.75.84","195.140.213.114","195.140.213.115","107.128.45.122","76.103.148.180","38.42.59.171","47.218.103.146") by Authentication.user Authentication.src Authentication.app Authentication.action | `drop_dm_object_name(Authentication)` | `ctime(firstTime)` | `ctime(lastTime)`
```

**Defender KQL:**
```kql
AADSignInEventsBeta | where Timestamp > ago(30d) | where IPAddress in ("31.7.56.61","31.7.56.52","193.34.212.132","185.178.208.153","23.234.75.84","195.140.213.114","195.140.213.115","107.128.45.122","76.103.148.180","38.42.59.171","47.218.103.146") | project Timestamp, AccountUpn, Application, IPAddress, Country, City, ClientAppUsed, UserAgent, ErrorCode, ConditionalAccessStatus, IsInteractive | order by Timestamp desc
```

### Automated bulk cloud data exfiltration via python-requests / PowerShell user-agents

`UC_9_7` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count values(Web.dest) as dests from datamodel=Web where (Web.http_user_agent IN ("python-requests*","WindowsPowerShell/5.1*") OR Web.src IN ("23.234.75.84","195.140.213.114","195.140.213.115")) AND Web.action="allowed" by Web.user Web.src Web.http_user_agent _time span=15m | `drop_dm_object_name(Web)` | where count >= 50
```

**Defender KQL:**
```kql
CloudAppEvents | where Timestamp > ago(14d) | where ActionType has_any ("FileDownloaded","FileSyncDownloadedFull","FileAccessed","Download") | where UserAgent has_any ("python-requests","WindowsPowerShell/5.1","python-httpx") or IPAddress in ("23.234.75.84","195.140.213.114","195.140.213.115") | summarize Downloads = count(), DistinctObjects = dcount(ObjectName), Apps = make_set(Application, 20), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by AccountObjectId, AccountDisplayName, IPAddress, UserAgent, bin(Timestamp, 15m) | where Downloads >= 50
```

### Rapid multi-cloud SSO application enumeration after single sign-in

`UC_9_8` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true dc(Authentication.app) as app_count values(Authentication.app) as apps values(Authentication.src) as src from datamodel=Authentication where Authentication.action="success" by Authentication.user _time span=10m | where app_count >= 8
```

**Defender KQL:**
```kql
AADSignInEventsBeta | where Timestamp > ago(14d) | where ErrorCode == 0 | summarize AppCount = dcount(ApplicationId), Apps = make_set(Application, 50), IPs = make_set(IPAddress, 10), FirstApp = min(Timestamp), LastApp = max(Timestamp) by AccountUpn, bin(Timestamp, 10m) | where AppCount >= 8
```

### Post-compromise deletion of security & password-reset emails from mailbox

`UC_9_9` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Defender KQL:**
```kql
CloudAppEvents | where Timestamp > ago(14d) | where Application in~ ("Microsoft Exchange Online","Exchange Online") | where ActionType has_any ("SoftDelete","HardDelete","MoveToDeletedItems","Delete message") | summarize Deletes = count(), Subjects = make_set(ObjectName, 25), Sources = make_set(IPAddress, 10), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by AccountObjectId, AccountDisplayName, bin(Timestamp, 10m) | where Deletes >= 3
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `31.7.56.61`, `31.7.56.52`, `193.34.212.132`, `185.178.208.153`, `23.234.75.84`, `195.140.213.114`, `195.140.213.115`, `107.128.45.122` _(+33 more)_


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 10 use case(s) fired, 20 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

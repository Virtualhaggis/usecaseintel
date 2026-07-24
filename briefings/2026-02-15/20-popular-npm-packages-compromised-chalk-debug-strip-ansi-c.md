# [HIGH] 20+ Popular NPM Packages Compromised (Chalk, Debug, Strip-ANSI, Color-Convert, Wrap-ANSI...)

**Source:** StepSecurity
**Published:** 2026-02-15
**Article:** https://www.stepsecurity.io/blog/20-popular-npm-packages-compromised-chalk-debug-strip-ansi-color-convert-wrap-ansi

## Threat Profile

Back to Blog Threat Intel 20+ Popular NPM Packages Compromised (Chalk, Debug, Strip-ANSI, Color-Convert, Wrap-ANSI...) Massive NPM supply chain attack targets cryptocurrency users through compromised maintainer account - affecting packages downloaded billions of times weekly including debug, chalk, ansi-styles, color-convert, strip-ansi and 15+ other critical JavaScript packages. Malicious code injected to steal cryptocurrency wallets and redirect blockchain transactions. Varun Sharma View Linke…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1005** — Data from Local System
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
- **T1195.002** — Compromise Software Supply Chain
- **T1656** — Impersonation
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1568** — Dynamic Resolution
- **T1567** — Exfiltration Over Web Service

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Phishing email impersonating npm support from typosquatted npmjs.help domain

`UC_632_7` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Email.recipient) as recipients values(All_Email.subject) as subjects values(All_Email.src_user) as src_user from datamodel=Email where All_Email.src_user_domain="npmjs.help" OR All_Email.src_user="support@npmjs.help" OR All_Email.url="*npmjs.help*" by All_Email.recipient | `drop_dm_object_name(All_Email)`
```

**Defender KQL:**
```kql
// Qix npm phishing — sender domain npmjs.help (legitimate domain is npmjs.com)
let LookbackDays = 30d;
let PhishDomains = dynamic(["npmjs.help"]);
let MailHits =
    EmailEvents
    | where Timestamp > ago(LookbackDays)
    | where SenderMailFromDomain in~ (PhishDomains)
       or SenderFromDomain in~ (PhishDomains)
       or SenderMailFromAddress endswith "@npmjs.help"
       or SenderFromAddress endswith "@npmjs.help"
    | project Timestamp, NetworkMessageId, RecipientEmailAddress,
              SenderMailFromAddress, SenderFromAddress, Subject,
              DeliveryAction, DeliveryLocation, ThreatTypes, UrlCount;
let UrlHits =
    EmailUrlInfo
    | where Timestamp > ago(LookbackDays)
    | where Url has "npmjs.help"
    | project Timestamp, NetworkMessageId, Url, UrlDomain;
MailHits
| join kind=leftouter UrlHits on NetworkMessageId
| project Timestamp, RecipientEmailAddress, SenderMailFromAddress,
          SenderFromAddress, Subject, DeliveryAction, DeliveryLocation,
          ThreatTypes, Url, NetworkMessageId
| order by Timestamp desc
```

### Install of Qix-compromised npm package@version (chalk 5.6.1, debug 4.4.2, ansi-styles 6.2.2 et al.)

`UC_632_8` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.process_name IN ("npm.exe","npm-cli.js","yarn.exe","pnpm.exe","node.exe") OR Processes.parent_process_name IN ("npm.exe","yarn.exe","pnpm.exe")) AND Processes.process IN ("*chalk@5.6.1*","*debug@4.4.2*","*ansi-styles@6.2.2*","*ansi-regex@6.2.1*","*strip-ansi@7.1.1*","*color-convert@3.1.1*","*color-name@2.0.1*","*color@5.0.1*","*color-string@2.1.1*","*supports-color@10.2.1*","*wrap-ansi@9.0.1*","*slice-ansi@7.1.1*","*is-arrayish@0.3.3*","*simple-swizzle@0.2.3*","*supports-hyperlinks@4.1.1*","*has-ansi@6.0.1*","*chalk-template@1.1.1*","*backslash@0.2.1*","*error-ex@1.3.3*") by host Processes.user Processes.process_name | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
// Qix npm compromise — install of one of the 19 malicious package@version pairs
let LookbackDays = 60d;
let BadVersions = dynamic([
    "chalk@5.6.1", "debug@4.4.2", "ansi-styles@6.2.2",
    "ansi-regex@6.2.1", "strip-ansi@7.1.1", "color-convert@3.1.1",
    "color-name@2.0.1", "color@5.0.1", "color-string@2.1.1",
    "supports-color@10.2.1", "wrap-ansi@9.0.1", "slice-ansi@7.1.1",
    "is-arrayish@0.3.3", "simple-swizzle@0.2.3", "supports-hyperlinks@4.1.1",
    "has-ansi@6.0.1", "chalk-template@1.1.1", "backslash@0.2.1",
    "error-ex@1.3.3"
]);
let CmdHits =
    DeviceProcessEvents
    | where Timestamp > ago(LookbackDays)
    | where FileName in~ ("npm.exe","npm.cmd","yarn.exe","yarn.cmd","pnpm.exe","pnpm.cmd","node.exe")
         or InitiatingProcessFileName in~ ("npm.exe","yarn.exe","pnpm.exe","node.exe")
    | where ProcessCommandLine has_any (BadVersions)
         or InitiatingProcessCommandLine has_any (BadVersions)
    | project Timestamp, DeviceName, AccountName,
              FileName, ProcessCommandLine,
              ParentName = InitiatingProcessFileName,
              ParentCmd  = InitiatingProcessCommandLine,
              Source = "cmdline";
let FileHits =
    DeviceFileEvents
    | where Timestamp > ago(LookbackDays)
    | where ActionType in~ ("FileCreated","FileModified")
    | where (FolderPath has @"\node_modules\chalk\"     and FileName =~ "package.json")
         or (FolderPath has @"\node_modules\debug\"     and FileName =~ "package.json")
         or (FolderPath has @"\node_modules\ansi-styles\" and FileName =~ "package.json")
         or (FolderPath has @"\node_modules\color\"     and FileName =~ "package.json")
         or (FileName =~ "package-lock.json")
    | project Timestamp, DeviceName, AccountName,
              FileName = strcat(FolderPath, "\\", FileName), ProcessCommandLine = InitiatingProcessCommandLine,
              ParentName = InitiatingProcessFileName, ParentCmd = InitiatingProcessParentFileName,
              Source = "file";
union CmdHits, FileHits
| order by Timestamp desc
```

### Egress to Qix npm phishing/exfil infrastructure (npmjs.help, publicvm.com, BunnyCDN buckets)

`UC_632_9` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src) as src values(All_Traffic.dest) as dest values(All_Traffic.dest_port) as dest_port from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="185.7.81.108" OR All_Traffic.dest_host IN ("npmjs.help","*.npmjs.help","websocket-api2.publicvm.com","static-mw-host.b-cdn.net","img-data-backup.b-cdn.net") OR All_Traffic.url IN ("*npmjs.help*","*websocket-api2.publicvm.com*","*static-mw-host.b-cdn.net*","*img-data-backup.b-cdn.net*")) by All_Traffic.src All_Traffic.dest All_Traffic.dest_host
```

**Defender KQL:**
```kql
// Qix npm compromise — egress to phishing/exfil infrastructure
let LookbackDays = 60d;
let BadHosts = dynamic([
    "npmjs.help",
    "websocket-api2.publicvm.com",
    "static-mw-host.b-cdn.net",
    "img-data-backup.b-cdn.net"
]);
let BadIPs = dynamic(["185.7.81.108"]);
DeviceNetworkEvents
| where Timestamp > ago(LookbackDays)
| where RemoteUrl has_any (BadHosts)
     or RemoteIP in (BadIPs)
| project Timestamp, DeviceName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessAccountUpn,
          RemoteUrl, RemoteIP, RemotePort, ActionType
| order by Timestamp desc
```

### Crypto-wallet file/keystore access by non-wallet process

`UC_CRYPTO_WALLET` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\Ethereum\keystore\*"
        OR Filesystem.file_path="*\Bitcoin\wallet.dat"
        OR Filesystem.file_path="*\Exodus\exodus.wallet*"
        OR Filesystem.file_path="*\Electrum\wallets\*"
        OR Filesystem.file_path="*\MetaMask\*"
        OR Filesystem.file_path="*\Phantom\*"
        OR Filesystem.file_path="*\Atomic\Local Storage\*")
      AND NOT Filesystem.process_name IN ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where FolderPath has_any (@"\Ethereum\keystore\", @"\Bitcoin\", @"\Exodus\", @"\Electrum\wallets\", @"\MetaMask\", @"\Phantom\", @"\Atomic\Local Storage\")
| where InitiatingProcessFileName !in~ ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
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

Severity classified as **HIGH** based on: 10 use case(s) fired, 17 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

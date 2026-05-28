# [HIGH] Threat Actors Spoofing FIFA Websites to Steal Name, Home Address, and Phone Number

**Source:** Cyber Security News
**Published:** 2026-05-28
**Article:** https://cybersecuritynews.com/spoofing-fifa-websites-to-steal/

## Threat Profile

Home Cyber Security News 
Threat Actors Spoofing FIFA Websites to Steal Name, Home Address, and Phone Number 
By Abinaya 
May 28, 2026 




Threat actors are actively spoofing official FIFA websites ahead of the 2026 FIFA World Cup , targeting unsuspecting users to steal sensitive personal data, including names, home addresses, and phone numbers.
According to the FBI, attackers are creating highly convincing replica websites that mimic the legitimate FIFA domain, www.fifa.com, using techniqu…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `fifa.cab`
- **Domain (defanged):** `fifa.pink`
- **Domain (defanged):** `fifa.pub`
- **Domain (defanged):** `fifa.ceo`
- **Domain (defanged):** `wvvw-fifa.com`
- **Domain (defanged):** `fifa-com.com`
- **Domain (defanged):** `jobs-fifa.com`
- **Domain (defanged):** `fifa-careerhub.com`
- **Domain (defanged):** `fifaworldcup-careers.com`
- **Domain (defanged):** `fifa-ticket.live`
- **Domain (defanged):** `worldcup26ticket.com`

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
- **T1071** — Application Layer Protocol
- **T1566.002** — Phishing: Spearphishing Link
- **T1583.001** — Acquire Infrastructure: Domains
- **T1598.003** — Phishing for Information: Spearphishing Link
- **T1056.003** — Input Capture: Web Portal Capture

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Network egress to FBI-listed FIFA 2026 World Cup spoofed domains (PSA I-052726)

`UC_3_6` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.user) as user from datamodel=Web where Web.url IN ("*fifa.cab*","*fifa.pink*","*fifa.pub*","*fifa.ceo*","*wvvw-fifa.com*","*fifa-com.com*","*jobs-fifa.com*","*fifa-careerhub.com*","*fifaworldcup-careers.com*","*fifa-ticket.live*","*worldcup26ticket.com*") by Web.src Web.dest host | `drop_dm_object_name(Web)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let SpoofedFifaDomains = dynamic(["fifa.cab","fifa.pink","fifa.pub","fifa.ceo","wvvw-fifa.com","fifa-com.com","jobs-fifa.com","fifa-careerhub.com","fifaworldcup-careers.com","fifa-ticket.live","worldcup26ticket.com"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where isnotempty(RemoteUrl)
| where RemoteUrl has_any (SpoofedFifaDomains)
| where not(RemoteUrl has_any (dynamic(["www.fifa.com","fifa.com/"])))
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### [LLM] Inbound email from FIFA typosquat sender domains (FBI PSA I-052726)

`UC_3_7` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(All_Email.src_user) as sender values(All_Email.recipient) as recipient values(All_Email.subject) as subject from datamodel=Email where All_Email.src_user IN ("*@fifa.cab","*@fifa.pink","*@fifa.pub","*@fifa.ceo","*@wvvw-fifa.com","*@fifa-com.com","*@jobs-fifa.com","*@fifa-careerhub.com","*@fifaworldcup-careers.com","*@fifa-ticket.live","*@worldcup26ticket.com") OR All_Email.url IN ("*fifa.cab*","*fifa.pink*","*fifa.pub*","*fifa.ceo*","*wvvw-fifa.com*","*fifa-com.com*","*jobs-fifa.com*","*fifa-careerhub.com*","*fifaworldcup-careers.com*","*fifa-ticket.live*","*worldcup26ticket.com*") by All_Email.recipient host | `drop_dm_object_name(All_Email)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let SpoofedFifaDomains = dynamic(["fifa.cab","fifa.pink","fifa.pub","fifa.ceo","wvvw-fifa.com","fifa-com.com","jobs-fifa.com","fifa-careerhub.com","fifaworldcup-careers.com","fifa-ticket.live","worldcup26ticket.com"]);
let SuspectMail = EmailEvents
  | where Timestamp > ago(14d)
  | where SenderFromDomain has_any (SpoofedFifaDomains)
     or SenderMailFromDomain has_any (SpoofedFifaDomains);
let SuspectUrls = EmailUrlInfo
  | where Timestamp > ago(14d)
  | where UrlDomain has_any (SpoofedFifaDomains) or Url has_any (SpoofedFifaDomains);
SuspectMail
| join kind=fullouter SuspectUrls on NetworkMessageId
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderFromDomain, RecipientEmailAddress, Subject, DeliveryAction, Url, UrlDomain
| order by Timestamp desc
```

### [LLM] User click-through to FIFA spoofed domain followed by HTTP POST (PII submission)

`UC_3_8` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.user) as user values(Web.http_method) as method from datamodel=Web where Web.url IN ("*fifa.cab*","*fifa.pink*","*fifa.pub*","*fifa.ceo*","*wvvw-fifa.com*","*fifa-com.com*","*jobs-fifa.com*","*fifa-careerhub.com*","*fifaworldcup-careers.com*","*fifa-ticket.live*","*worldcup26ticket.com*") AND Web.http_method=POST by Web.src Web.user host | `drop_dm_object_name(Web)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let LookbackDays = 7d;
let WindowSeconds = 300;
let SpoofedFifaDomains = dynamic(["fifa.cab","fifa.pink","fifa.pub","fifa.ceo","wvvw-fifa.com","fifa-com.com","jobs-fifa.com","fifa-careerhub.com","fifaworldcup-careers.com","fifa-ticket.live","worldcup26ticket.com"]);
let Clicks = UrlClickEvents
  | where Timestamp > ago(LookbackDays)
  | where ActionType in ("ClickAllowed","ClickedThrough")
  | where Url has_any (SpoofedFifaDomains)
  | project ClickTime = Timestamp, AccountUpn, Url, NetworkMessageId;
DeviceNetworkEvents
| where Timestamp > ago(LookbackDays)
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
| where RemoteUrl has_any (SpoofedFifaDomains)
| join kind=inner Clicks on $left.InitiatingProcessAccountUpn == $right.AccountUpn
| where Timestamp between (ClickTime .. ClickTime + WindowSeconds * 1s)
| project ClickTime, EgressTime = Timestamp,
          DelaySec = datetime_diff('second', Timestamp, ClickTime),
          DeviceName, AccountUpn = InitiatingProcessAccountUpn,
          Url, RemoteUrl, InitiatingProcessFileName
| order by ClickTime desc
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `fifa.cab`, `fifa.pink`, `fifa.pub`, `fifa.ceo`, `wvvw-fifa.com`, `fifa-com.com`, `jobs-fifa.com`, `fifa-careerhub.com` _(+3 more)_


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 9 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

# [HIGH] Hacker claims 3.6 million Azure account records stolen from major companies

**Source:** BleepingComputer
**Published:** 2026-08-17
**Article:** https://www.bleepingcomputer.com/news/security/hacker-claims-36-million-azure-account-records-stolen-from-major-companies/

## Threat Profile

Hacker claims 3.6 million Azure account records stolen from major companies 
By Ionut Ilascu 
August 17, 2026
03:35 PM
0 
A threat actor is selling employee databases allegedly stolen from the Microsoft Azure infrastructure of multiple Fortune 500 companies after gaining access using compromised credentials.
​Starting July 31st, multiple posts from someone using the alias “TheHatman” advertised data dumps from major organizations, including McDonald's, Gap Inc., Vodafone, Tata Consultancy Servic…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `anonfilesnew.com`

## MITRE ATT&CK Techniques

- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1071** — Application Layer Protocol
- **T1110.003** — Brute Force: Password Spraying
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1621** — Multi-Factor Authentication Request Generation
- **T1087.004** — Account Discovery: Cloud Account
- **T1526** — Cloud Service Discovery
- **T1567** — Exfiltration Over Web Service

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Entra ID password spray: many distinct accounts failing auth from few source IPs

`UC_6_5` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true dc(Authentication.user) as failed_users count as attempts from datamodel=Authentication where Authentication.action=failure AND Authentication.signature_id=50126 by Authentication.src Authentication.app _time span=30m
| `drop_dm_object_name(Authentication)`
| where failed_users >= 20
| sort - failed_users
```

**Defender KQL:**
```kql
AADSignInEventsBeta
| where Timestamp > ago(1h)
| where ErrorCode == 50126   // invalid username or password
| summarize FailedUsers = dcount(AccountUpn), Attempts = count(), SampleUsers = make_set(AccountUpn, 50) by IPAddress, Application, bin(Timestamp, 30m)
| where FailedUsers >= 20     // 20 = spray breadth threshold (few passwords, many accounts)
| order by FailedUsers desc
```

### Entra ID MFA fatigue: burst of MFA-challenge failures followed by a successful MFA sign-in

`UC_6_6` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Authentication where Authentication.signature_id IN (50074,50076,50088,50158) by Authentication.user Authentication.src _time span=15m
| `drop_dm_object_name(Authentication)`
| where count >= 5
| sort - count
```

**Defender KQL:**
```kql
let Window = 2h;
let Fatigue = AADSignInEventsBeta
    | where Timestamp > ago(Window)
    | where ErrorCode in (50074, 50076, 50088, 50158)   // MFA challenge failed / required / telecom-limit / ext-security-challenge not satisfied
    | summarize MfaPrompts = count(), FirstPrompt = min(Timestamp), LastPrompt = max(Timestamp) by AccountUpn, IPAddress
    | where MfaPrompts >= 5;   // 5 = push-bombing burst floor
AADSignInEventsBeta
| where Timestamp > ago(Window)
| where ErrorCode == 0
| where AuthenticationRequirement == "multiFactorAuthentication"
| join kind=inner Fatigue on AccountUpn
| where Timestamp between (FirstPrompt .. LastPrompt + 30m)
| project SuccessTime = Timestamp, AccountUpn, SuccessIP = IPAddress, PromptIP = IPAddress1, MfaPrompts, FirstPrompt, LastPrompt, Application
| order by MfaPrompts desc
```

### First-time Entra directory enumeration via Graph/PowerShell CLI tooling by a user

`UC_6_7` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count values(Authentication.src) as src from datamodel=Authentication where Authentication.action=success AND (Authentication.app="Microsoft Graph Command Line Tools" OR Authentication.app="Azure Active Directory PowerShell" OR Authentication.app="Microsoft Azure PowerShell" OR Authentication.app="Graph Explorer" OR Authentication.app="Azure CLI") by Authentication.user Authentication.app
| `drop_dm_object_name(Authentication)`
| sort - count
```

**Defender KQL:**
```kql
let Baseline = AADSignInEventsBeta
    | where Timestamp between (ago(30d) .. ago(1d))
    | where Application in ("Microsoft Graph Command Line Tools","Azure Active Directory PowerShell","Microsoft Azure PowerShell","Graph Explorer","Azure CLI")
    | distinct AccountUpn, Application;
AADSignInEventsBeta
| where Timestamp > ago(1d)
| where ErrorCode == 0
| where Application in ("Microsoft Graph Command Line Tools","Azure Active Directory PowerShell","Microsoft Azure PowerShell","Graph Explorer","Azure CLI")
| join kind=leftanti Baseline on AccountUpn, Application
| project Timestamp, AccountUpn, Application, IPAddress, ResourceDisplayName, ClientAppUsed, Country
| order by Timestamp desc
```

### Endpoint egress/DNS to anonfilesnew.com anonymous file host (TheHatman sample staging)

`UC_6_8` · phase: **actions** · confidence: **Low** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Network_Resolution where Network_Resolution.query="*anonfilesnew.com*" by Network_Resolution.src Network_Resolution.query _time span=1h
| `drop_dm_object_name(Network_Resolution)`
| sort - count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "anonfilesnew.com"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `anonfilesnew.com`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 9 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

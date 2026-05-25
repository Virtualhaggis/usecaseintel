# [CRIT] Anthropic’s Claude Mythos Preview Uncovers 10,000+ 0-Days in Project Glasswing

**Source:** Cyber Security News
**Published:** 2026-05-23
**Article:** https://cybersecuritynews.com/anthropics-claude-mythos-preview-0-days/

## Threat Profile

Home Cyber Security News 
Anthropic’s Claude Mythos Preview Uncovers 10,000+ 0-Days in Project Glasswing 
By Guru Baran 
May 23, 2026 
Anthropic has revealed the staggering initial results of Project Glasswing, a collaborative cybersecurity initiative designed to secure critical infrastructure using advanced AI before malicious actors can exploit it.
In its first month, the project leveraged the unreleased Claude Mythos Preview model to autonomously discover over 10,000 high- and critical-severi…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-5194`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1195.002** — Compromise Software Supply Chain
- **T1587.004** — Develop Capabilities: Exploits
- **T1557** — Adversary-in-the-Middle
- **T1553.004** — Subvert Trust Controls: Install Root Certificate
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1557.002** — Adversary-in-the-Middle: ARP Cache Poisoning
- **T1556.004** — Modify Authentication Process: Network Device Authentication
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1114.003** — Email Collection: Email Forwarding Rule
- **T1564.008** — Hide Artifacts: Email Hiding Rules
- **T1565.002** — Data Manipulation: Transmitted Data Manipulation

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Vulnerable wolfSSL versions in inventory exposing CVE-2026-5194 cert-forgery flaw

`UC_16_5` · phase: **weapon** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, values(Vulnerabilities.signature) as signature, values(Vulnerabilities.severity) as severity, values(Vulnerabilities.url) as url from datamodel=Vulnerabilities.Vulnerabilities where Vulnerabilities.cve="CVE-2026-5194" OR (Vulnerabilities.signature="wolfssl*" Vulnerabilities.signature!="wolfssl 5.9.1*" Vulnerabilities.signature!="wolfssl 5.10*" Vulnerabilities.signature!="wolfssl 5.11*") by Vulnerabilities.dest Vulnerabilities.cve
| `drop_dm_object_name(Vulnerabilities)`
| where severity IN ("critical","high")
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where Timestamp > ago(1d)
| where CveId == "CVE-2026-5194"
   or (SoftwareName has "wolfssl" and not (SoftwareVersion startswith "5.9.1" or SoftwareVersion startswith "5.10" or SoftwareVersion startswith "5.11" or SoftwareVersion startswith "6."))
| join kind=leftouter (DeviceInfo | where Timestamp > ago(1d) | summarize arg_max(Timestamp, IsInternetFacing, PublicIP, OSPlatform) by DeviceId) on DeviceId
| project Timestamp, DeviceName, IsInternetFacing, PublicIP, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate, AffectedSoftwareSku
| order by IsInternetFacing desc, VulnerabilitySeverityLevel asc
```

### [LLM] Banking/webmail TLS connections from corporate hosts to never-before-seen destination IPs (forged-cert AitM proxy)

`UC_16_6` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, values(All_Traffic.app) as app, values(All_Traffic.dest_port) as dest_port from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port=443 (All_Traffic.dest_category="banking" OR All_Traffic.dest_category="webmail" OR All_Traffic.dest_hostname IN ("outlook.office.com","login.microsoftonline.com","outlook.office365.com","mail.google.com","accounts.google.com","chase.com","wellsfargo.com","bankofamerica.com","citi.com","hsbc.com")) by All_Traffic.src All_Traffic.dest_hostname All_Traffic.dest_ip _time span=10m
| `drop_dm_object_name(All_Traffic)`
| `first_time_seen(dest_hostname,dest_ip)`
| where firstTime > relative_time(now(),"-1h@h")
```

**Defender KQL:**
```kql
let WindowDays = 30d;
let SensitiveBrands = dynamic(["outlook.office.com","outlook.office365.com","login.microsoftonline.com","mail.google.com","accounts.google.com","chase.com","wellsfargo.com","bankofamerica.com","citi.com","hsbc.com"]);
let Baseline = DeviceNetworkEvents
    | where Timestamp between (ago(WindowDays) .. ago(1h))
    | where RemoteIPType == "Public" and RemotePort == 443
    | where RemoteUrl has_any (SensitiveBrands)
    | summarize BaselineHosts = dcount(DeviceName) by RemoteUrl, RemoteIP
    | where BaselineHosts >= 3;
DeviceNetworkEvents
| where Timestamp > ago(1h)
| where RemoteIPType == "Public" and RemotePort == 443
| where RemoteUrl has_any (SensitiveBrands)
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","outlook.exe","thunderbird.exe","teams.exe")
| join kind=leftanti Baseline on RemoteUrl, RemoteIP
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### [LLM] Successful M365/banking sign-in from ASN never previously seen for the user

`UC_16_7` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Authentication.Authentication where Authentication.action="success" Authentication.app IN ("Office 365 Exchange Online","Outlook on the web","OfficeHome","Microsoft Office 365 Portal","Office365 Shell WCSS-Client") by Authentication.user Authentication.src Authentication.src_ip Authentication.app _time span=10m
| `drop_dm_object_name(Authentication)`
| `first_time_seen(user,src_ip)`
| where firstTime > relative_time(now(),"-1h@h")
```

**Defender KQL:**
```kql
let WindowDays = 30d;
let SensitiveApps = dynamic(["Office 365 Exchange Online","Outlook on the web","OfficeHome","Microsoft Office 365 Portal","Office365 Shell WCSS-Client","Microsoft Authentication Broker"]);
let Baseline = AADSignInEventsBeta
    | where Timestamp between (ago(WindowDays) .. ago(1h))
    | where ErrorCode == 0
    | summarize BaselineIPs = make_set(IPAddress, 500), BaselineCountries = make_set(Country, 50) by AccountUpn;
AADSignInEventsBeta
| where Timestamp > ago(1h)
| where ErrorCode == 0
| where Application in~ (SensitiveApps) or ResourceDisplayName in~ (SensitiveApps)
| lookup kind=leftouter Baseline on AccountUpn
| extend NewIp = not(set_has_element(BaselineIPs, IPAddress)),
         NewCountry = not(set_has_element(BaselineCountries, Country))
| where NewIp == true and (NewCountry == true or RiskLevelDuringSignIn in ("medium","high") or IsAnonymousProxy == true)
| where AccountUpn !endswith "$" and AccountUpn !contains "sync_"
| project Timestamp, AccountUpn, IPAddress, Country, City, Application, ResourceDisplayName, RiskLevelDuringSignIn, RiskState, IsAnonymousProxy, ConditionalAccessStatus, UserAgent, Browser
| order by Timestamp desc
```

### [LLM] Mailbox forwarding/inbox rule created within 30 min of an anomalous Entra sign-in

`UC_16_8` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, values(All_Changes.command) as command, values(All_Changes.object) as object from datamodel=Change.All_Changes where All_Changes.command IN ("New-InboxRule","Set-InboxRule","UpdateInboxRules","New-TransportRule","Set-Mailbox") by All_Changes.user All_Changes.src _time span=5m
| `drop_dm_object_name(All_Changes)`
| rename _time as rule_time
| join type=inner user [
    | tstats summariesonly=true latest(_time) as signin_time, latest(Authentication.src_ip) as signin_ip, latest(Authentication.signature) as risk from datamodel=Authentication.Authentication where Authentication.action="success" Authentication.app IN ("Office 365 Exchange Online","Outlook on the web","OfficeHome") (Authentication.signature IN ("medium","high") OR Authentication.is_new_src=true) by Authentication.user
    | `drop_dm_object_name(Authentication)` | rename Authentication.user as user ]
| eval delta_min=(rule_time - signin_time)/60
| where delta_min>=0 AND delta_min<=30
```

**Defender KQL:**
```kql
let WindowMinutes = 30m;
let RiskySignIns = AADSignInEventsBeta
    | where Timestamp > ago(1d)
    | where ErrorCode == 0
    | where RiskLevelDuringSignIn in ("medium","high") or IsAnonymousProxy == true or RiskState in ("atRisk","confirmedCompromised")
    | project SignInTime = Timestamp, AccountObjectId, AccountUpn, SignInIp = IPAddress, SignInCountry = Country, RiskLevelDuringSignIn;
CloudAppEvents
| where Timestamp > ago(1d)
| where Application has "Exchange" or Application has "Office 365"
| where ActionType has_any ("New-InboxRule","Set-InboxRule","UpdateInboxRules","New-TransportRule","Set-Mailbox")
| extend Raw = tostring(RawEventData)
| where Raw has_any ("ForwardTo","ForwardingSmtpAddress","RedirectTo","DeleteMessage","MoveToFolder","MarkAsRead")
| join kind=inner RiskySignIns on AccountObjectId
| where Timestamp between (SignInTime .. SignInTime + WindowMinutes)
| project Timestamp, SignInTime, MinutesSinceSignIn = datetime_diff('minute', Timestamp, SignInTime), AccountUpn, SignInIp, SignInCountry, RiskLevelDuringSignIn, ActionType, ObjectName, ActivityType, Raw
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

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-5194`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 9 use case(s) fired, 19 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

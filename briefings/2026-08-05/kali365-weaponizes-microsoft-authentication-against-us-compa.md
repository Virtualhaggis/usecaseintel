# [CRIT] Kali365 Weaponizes Microsoft Authentication Against US Companies: New Enterprise Risk

**Source:** The Hacker News
**Published:** 2026-08-05
**Article:** https://thehackernews.com/2026/08/kali365-weaponizes-microsoft.html

## Threat Profile

Kali365 Weaponizes Microsoft Authentication Against US Companies: New Enterprise Risk 
 The Hacker News  Aug 05, 2026 Phishing / Identity Security 
Kali365 is turning a legitimate Microsoft login into a gateway to corporate data.
The phishing kit targets US organizations with attacker-controlled device codes that victims approve on Microsoft's real authentication page. Once access and refresh tokens are issued, attackers may retain access to email, documents, and cloud resources, creating a di…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `bluefoodtruths.xyz`
- **Domain (defanged):** `flexiscalesystems.de`
- **Domain (defanged):** `guardedwebsolutions.de`
- **Domain (defanged):** `proforcstaffing.com`
- **Domain (defanged):** `reputationboosters.de`
- **Domain (defanged):** `guardextion.online`
- **Domain (defanged):** `prowebsitemakers.de`
- **Domain (defanged):** `onlinebrandinghub.de`
- **Domain (defanged):** `onsite-developments.net`
- **Domain (defanged):** `functionalityfirst.de`
- **Domain (defanged):** `buildyouronlineidentity.de`
- **Domain (defanged):** `flexievolve.de`
- **Domain (defanged):** `onlineidentityperfection.de`
- **Domain (defanged):** `guardwebsolutions.de`
- **Domain (defanged):** `securedecisionmaking.de`
- **Domain (defanged):** `modernwebbalance.de`
- **Domain (defanged):** `marketadaptabletech.de`
- **Domain (defanged):** `waschmaschinenmarkt.de`
- **Domain (defanged):** `hbaknoxvillecom.top`
- **Domain (defanged):** `brandswithintegrity.de`
- **Domain (defanged):** `turnideastoresults.de`
- **Domain (defanged):** `wellpults.com`
- **Domain (defanged):** `navigatingdigitalchange.de`
- **Domain (defanged):** `qualityfirstonline.de`
- **Domain (defanged):** `brandtrustmasters.de`
- **Domain (defanged):** `theconsistencyfactor.de`
- **Domain (defanged):** `reliablebusinesstech.de`
- **Domain (defanged):** `performancereputation.de`
- **Domain (defanged):** `dewdhurstlobl.com`
- **Domain (defanged):** `cloud-microsoft-drive-for-business.workers.dev`

## MITRE ATT&CK Techniques

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
- **T1071** — Application Layer Protocol
- **T1621** — Multi-Factor Authentication Request Generation
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1566.002** — Phishing: Spearphishing Link

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Kali365 device-code-flow authentication used by a standard M365 user

`UC_38_6` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
sourcetype="azure:aad:signin" "properties.authenticationProtocol"="deviceCode" "properties.status.errorCode"=0
| stats min(_time) as firstTime max(_time) as lastTime values("properties.ipAddress") as ipAddress values("properties.appDisplayName") as app values("properties.resourceDisplayName") as resource dc("properties.ipAddress") as ipCount by user
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where AuthenticationDetails has "deviceCode"   // device-code grant marker in the auth-detail JSON
| where ErrorCode == 0                            // completed sign-in => token issued
| where isnotempty(AccountUpn) and AccountUpn !endswith "$"
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            IPs = make_set(IPAddress, 20), Countries = make_set(Country, 20),
            Apps = make_set(Application, 10), Resources = make_set(ResourceDisplayName, 10)
            by AccountUpn, AccountDisplayName
| order by LastSeen desc
```

### Kali365 concurrent device-code sign-in: same user, 2+ IPs/countries in one hour

`UC_38_7` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
sourcetype="azure:aad:signin" "properties.authenticationProtocol"="deviceCode" "properties.status.errorCode"=0
| bin _time span=1h
| stats dc("properties.ipAddress") as ipCount dc("location.countryOrRegion") as countryCount values("properties.ipAddress") as ips values("location.countryOrRegion") as countries by user, _time
| where ipCount>=2 OR countryCount>=2
| sort - _time
```

**Defender KQL:**
```kql
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where AuthenticationDetails has "deviceCode"
| where ErrorCode == 0
| where isnotempty(AccountUpn) and AccountUpn !endswith "$"
| summarize IPs = dcount(IPAddress), Countries = dcount(Country),
            IPList = make_set(IPAddress, 20), CountryList = make_set(Country, 20),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
            by AccountUpn, bin(Timestamp, 1h)
| where IPs >= 2 or Countries >= 2   // victim approves locally, operator uses token from other infra
| order by LastSeen desc
```

### Host or mailbox contact with Kali365 lure domains (SharePoint/OneDrive/DocuSign decoys)

`UC_38_8` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution where DNS.query IN ("bluefoodtruths.xyz","flexiscalesystems.de","guardedwebsolutions.de","proforcstaffing.com","reputationboosters.de","guardextion.online","prowebsitemakers.de","onlinebrandinghub.de","onsite-developments.net","functionalityfirst.de","buildyouronlineidentity.de","flexievolve.de","onlineidentityperfection.de","guardwebsolutions.de","securedecisionmaking.de","modernwebbalance.de","marketadaptabletech.de","waschmaschinenmarkt.de","hbaknoxvillecom.top","brandswithintegrity.de") by DNS.src DNS.query
| `drop_dm_object_name(DNS)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
let Kali365Domains = dynamic(["bluefoodtruths.xyz","flexiscalesystems.de","guardedwebsolutions.de","proforcstaffing.com","reputationboosters.de","guardextion.online","prowebsitemakers.de","onlinebrandinghub.de","onsite-developments.net","functionalityfirst.de","buildyouronlineidentity.de","flexievolve.de","onlineidentityperfection.de","guardwebsolutions.de","securedecisionmaking.de","modernwebbalance.de","marketadaptabletech.de","waschmaschinenmarkt.de","hbaknoxvillecom.top","brandswithintegrity.de"]);
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where isnotempty(RemoteUrl)
| where RemoteUrl has_any (Kali365Domains)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName,
          RemoteUrl, RemoteIP, RemotePort, InitiatingProcessCommandLine
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `bluefoodtruths.xyz`, `flexiscalesystems.de`, `guardedwebsolutions.de`, `proforcstaffing.com`, `reputationboosters.de`, `guardextion.online`, `prowebsitemakers.de`, `onlinebrandinghub.de` _(+22 more)_


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 9 use case(s) fired, 14 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

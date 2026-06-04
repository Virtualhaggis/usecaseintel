# [CRIT] Beyond the Zero-Day: See Your Network Like an Attacker | Webinar with HD Moore

**Source:** The Hacker News
**Published:** 2026-06-03
**Article:** https://thehackernews.com/2026/06/beyond-zero-day-see-your-network-like.html

## Threat Profile

Microsoft 365 Android Apps Let Any App Steal Account Tokens via Leftover Debug Flag 
 Swati Khandelwal  Jun 03, 2026 Vulnerability / Mobile Security 
A development flag left switched on in production builds of several Microsoft 365 Android apps disabled the check that limits account-token sharing to trusted Microsoft apps.
Any other app on the same phone could ask for the signed-in user's token and get it, then read email, open files, browse the calendar, and send messages as that user. No pas…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-41100`
- **CVE:** `CVE-2026-41101`
- **CVE:** `CVE-2026-41102`
- **CVE:** `CVE-2026-42832`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
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
- **T1474.002** — Compromise Software Supply Chain (Mobile)
- **T1550.001** — Use Alternate Authentication Material: Application Access Token
- **T1606.002** — Forge Web Credentials: SAML Tokens

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Unpatched Microsoft 365 Android apps below FlagLeft fix build 16.0.19822.20190

`UC_15_6` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, values(Vulnerabilities.signature) as cve_signatures, latest(Vulnerabilities.severity) as severity from datamodel=Vulnerabilities.Vulnerabilities where Vulnerabilities.cve IN ("CVE-2026-41100","CVE-2026-41101","CVE-2026-41102","CVE-2026-42832") by Vulnerabilities.dest, Vulnerabilities.cve, Vulnerabilities.signature
| `drop_dm_object_name(Vulnerabilities)`
| sort - count
```

**Defender KQL:**
```kql
// FlagLeft — Android devices on a Microsoft 365 build older than 16.0.19822.20190
DeviceTvmSoftwareInventory
| where OSPlatform =~ "Android"
| where SoftwareVendor has "Microsoft"
| where SoftwareName has_any ("Word","PowerPoint","Excel","Microsoft 365 Copilot","Copilot","OneNote","Loop")
| extend Parts = split(SoftwareVersion, ".")
| extend Major = toint(Parts[0]), Minor = toint(Parts[1]), Build = toint(Parts[2]), Revision = toint(Parts[3])
| where Major == 16 and Minor == 0 and (Build < 19822 or (Build == 19822 and Revision < 20190))
| join kind=leftouter (DeviceInfo | where OSPlatform =~ "Android" | summarize arg_max(Timestamp, LoggedOnUsers, IsAzureADJoined, JoinType) by DeviceId) on DeviceId
| project Timestamp, DeviceId, DeviceName, OSPlatform, OSVersion, SoftwareName, SoftwareVersion, JoinType, LoggedOnUsers
| order by Timestamp desc
```

### [LLM] FOCI refresh-token sign-in from non-compliant Android device (FlagLeft post-theft replay)

`UC_15_7` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, values(Authentication.src) as src_ips, values(Authentication.user_agent) as user_agents, min(_time) as first_seen, max(_time) as last_seen from datamodel=Authentication.Authentication where Authentication.signature_id="MicrosoftEntra" AND Authentication.app IN ("Microsoft Word","Microsoft PowerPoint","Microsoft Excel","Microsoft 365 Copilot","Microsoft OneNote","Microsoft Loop","Microsoft Office") AND Authentication.user_agent="*Android*" AND Authentication.action="success" by Authentication.user, Authentication.app, Authentication.dest
| `drop_dm_object_name(Authentication)`
| search NOT (dest IN ("Compliant","Managed","AzureAd","Workplace"))
| sort - last_seen
```

**Defender KQL:**
```kql
// FlagLeft replay — FOCI refresh from unmanaged Android into an affected M365 mobile app
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where OSPlatform =~ "Android"
| where Application in~ ("Microsoft Word","Microsoft PowerPoint","Microsoft Excel","Microsoft 365 Copilot","Microsoft OneNote","Microsoft Loop","Microsoft Office")
| where ErrorCode == 0                              // successful auth
| where IsInteractive == false                       // refresh-token (FOCI FRT) flow, not a password sign-in
| where (DeviceTrustType !in~ ("Compliant","Managed","AzureAd","Workplace")) or isempty(DeviceTrustType)
| where AccountUpn !endswith "#EXT#" and not(AccountUpn endswith "$")
| extend DayCountForUser = toscalar(AADSignInEventsBeta | where Timestamp between (ago(30d) .. ago(7d)) | where AccountUpn == AccountUpn | summarize dcount(bin(Timestamp,1d)))
| project Timestamp, AccountUpn, Application, ApplicationId, IPAddress, Country, City, UserAgent, OSPlatform, DeviceTrustType, IsCompliantUser, AadDeviceId, ClientAppUsed, RiskLevelDuringSignIn, RiskState, TokenIssuerType
| order by Timestamp desc
```

### [LLM] FOCI cross-app token chaining: one Android device authenticates to 3+ affected Office mobile apps

`UC_15_8` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` dc(Authentication.app) as app_fanout, values(Authentication.app) as apps, values(Authentication.src) as src_ips, min(_time) as first_seen, max(_time) as last_seen from datamodel=Authentication.Authentication where Authentication.signature_id="MicrosoftEntra" AND Authentication.app IN ("Microsoft Word","Microsoft PowerPoint","Microsoft Excel","Microsoft 365 Copilot","Microsoft OneNote","Microsoft Loop","Microsoft Office") AND Authentication.user_agent="*Android*" AND Authentication.action="success" by Authentication.user, _time span=30m
| `drop_dm_object_name(Authentication)`
| where app_fanout >= 3
```

**Defender KQL:**
```kql
// FlagLeft chaining — single unmanaged Android session fans out across 3+ FOCI sibling apps in 30 min
AADSignInEventsBeta
| where Timestamp > ago(1d)
| where OSPlatform =~ "Android"
| where Application in~ ("Microsoft Word","Microsoft PowerPoint","Microsoft Excel","Microsoft 365 Copilot","Microsoft OneNote","Microsoft Loop","Microsoft Office")
| where ErrorCode == 0
| where (DeviceTrustType !in~ ("Compliant","Managed","AzureAd","Workplace")) or isempty(DeviceTrustType)
| where AccountUpn !endswith "$"
| summarize AppFanOut = dcount(Application),
            Apps = make_set(Application),
            DistinctIPs = make_set(IPAddress, 5),
            DistinctUAs = make_set(UserAgent, 5),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp),
            SignInCount = count()
            by AccountUpn, AadDeviceId, bin(Timestamp, 30m)
| where AppFanOut >= 3                  // 3+ FOCI family apps within 30 min — empirical threshold; real users rarely cross-pivot this fast on mobile
| order by AppFanOut desc, LastSeen desc
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-41100`, `CVE-2026-41101`, `CVE-2026-41102`, `CVE-2026-42832`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 9 use case(s) fired, 14 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

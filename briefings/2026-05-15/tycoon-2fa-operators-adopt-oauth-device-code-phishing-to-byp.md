# [CRIT] Tycoon 2FA Operators Adopt OAuth Device Code Phishing to Bypass MFA

**Source:** Cyber Security News
**Published:** 2026-05-15
**Article:** https://cybersecuritynews.com/tycoon-2fa-operators-adopt-oauth-device-code/

## Threat Profile

Home Cyber Security News 
Tycoon 2FA Operators Adopt OAuth Device Code Phishing to Bypass MFA 
By Tushar Subhra Dutta 
May 15, 2026 




Cybercriminals behind the Tycoon 2FA phishing kit have added a powerful new weapon to their playbook. 
By combining their well-known phishing infrastructure with OAuth Device Code abuse, they can now steal access to Microsoft 365 accounts without ever capturing a single password. 
The Tycoon 2FA phishing kit first gained attention as a Phishing-as-a-Service…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `events.trustifi.com`
- **Domain (defanged):** `cookies.28gholland.workers.dev`
- **Domain (defanged):** `shivacrio.com`
- **Domain (defanged):** `fijothi.com`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1566.002** — Phishing: Spearphishing Link
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1550.001** — Use Alternate Authentication Material: Application Access Token
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1102** — Web Service

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] OAuth Device Code phishing: node/undici UA against Microsoft Authentication Broker AppId (Tycoon 2FA)

`UC_0_7` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`summariesonly` | tstats count min(_time) as firstTime max(_time) as lastTime values(Authentication.src) as src values(Authentication.user_agent) as ua from datamodel=Authentication where Authentication.app="29d9ed98-a469-4536-ade2-f981bc1d605e" (Authentication.user_agent="node" OR Authentication.user_agent="undici" OR Authentication.user_agent="node*") by Authentication.user Authentication.signature Authentication.dest | `drop_dm_object_name(Authentication)` | where firstTime >= relative_time(now(), "-7d@d")
```

**Defender KQL:**
```kql
// Tycoon 2FA OAuth device-code operator polling — node/undici UA on Microsoft Authentication Broker AppId
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where ApplicationId == "29d9ed98-a469-4536-ade2-f981bc1d605e"   // Microsoft Authentication Broker — eSentire IOC
| where UserAgent in~ ("node", "undici")                          // operator Node.js backend fingerprint
   or UserAgent startswith "node/" or UserAgent startswith "undici/"
| where ErrorCode == 0                                            // successful token issuance
| project Timestamp, AccountUpn, AccountObjectId, IPAddress, Country,
          ApplicationId, Application, ResourceDisplayName,
          UserAgent, ClientAppUsed, IsInteractive, ConditionalAccessStatus,
          RiskLevelDuringSignIn, AuthenticationRequirement
| order by Timestamp desc
```

### [LLM] Successful M365 sign-in originating from Tycoon 2FA operator Alibaba Cloud ASN 45102

`UC_0_8` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`summariesonly` | tstats count min(_time) as firstTime max(_time) as lastTime values(Authentication.user_agent) as ua values(Authentication.app) as app from datamodel=Authentication where Authentication.signature_id="AAD" (Authentication.src="47.90.180.205" OR Authentication.src="47.252.11.99" OR Authentication.src_asn=45102 OR Authentication.src_asn_name="ALIBABA-US-NET") Authentication.action="success" by Authentication.user Authentication.dest Authentication.src | `drop_dm_object_name(Authentication)` | where firstTime >= relative_time(now(), "-14d@d")
```

**Defender KQL:**
```kql
// Tycoon 2FA operator-side M365 access from Alibaba AS45102 (eSentire IOCs, since ~2026-04-10)
let _opIPs = dynamic(["47.90.180.205","47.252.11.99"]);
let _opAppIds = dynamic([
    "29d9ed98-a469-4536-ade2-f981bc1d605e",   // Microsoft Authentication Broker
    "4765445b-32c6-49b0-83e6-1d93765276ca"    // OfficeHome — primary AppId for credential-relay variant
]);
AADSignInEventsBeta
| where Timestamp > ago(14d)
| where ErrorCode == 0
| where IPAddress in (_opIPs)                              // exact operator IPs
    or (ApplicationId in (_opAppIds) and IPAddress startswith "47.")  // ASN heuristic for AS45102 (47.0.0.0/8 Alibaba block)
| project Timestamp, AccountUpn, AccountObjectId, IPAddress, Country, City,
          ApplicationId, Application, ResourceDisplayName,
          UserAgent, ClientAppUsed, IsInteractive,
          ConditionalAccessStatus, RiskLevelDuringSignIn, RiskState
| order by Timestamp desc
```

### [LLM] Endpoint contact with Tycoon 2FA Layer-2 / Check Domain / C2 staging hosts

`UC_0_9` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`summariesonly` | tstats count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.user) as user values(Web.src) as src from datamodel=Web where (Web.url="*cookies.28gholland.workers.dev*" OR Web.url="*shivacrio.com/bytecore*" OR Web.url="*fijothi.com/*" OR Web.dest="fijothi.com" OR Web.dest="shivacrio.com" OR Web.dest="cookies.28gholland.workers.dev") by Web.dest Web.src | `drop_dm_object_name(Web)` | where firstTime >= relative_time(now(), "-14d@d")
```

**Defender KQL:**
```kql
// Tycoon 2FA Layer-2 / Check Domain / backend C2 contact (eSentire IOCs, April 2026 campaign)
let _tycoonHosts = dynamic([
    "cookies.28gholland.workers.dev",  // Cloudflare Workers delivery point
    "shivacrio.com",                    // Check Domain gate (bytecore~tx1j8 path)
    "fijothi.com"                       // AES-CBC encrypted backend C2
]);
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteUrl has_any (_tycoonHosts)
   or (RemoteUrl has "shivacrio.com" and RemoteUrl has "bytecore")
   or RemoteUrl matches regex @"(?i)fijothi\.com/[A-Za-z]{50,}"   // long opaque path = AES-CBC session blob
| project Timestamp, DeviceName, DeviceId,
          InitiatingProcessAccountName, InitiatingProcessAccountUpn,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          RemoteUrl, RemoteIP, RemotePort, ActionType
| order by Timestamp desc
```

### Beaconing — periodic outbound to small set of destinations

`UC_BEACONING` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, values(All_Traffic.dest_port) AS ports
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.action="allowed" AND All_Traffic.dest_category!="internal"
    by _time span=10s, All_Traffic.src, All_Traffic.dest
| `drop_dm_object_name(All_Traffic)`
| streamstats current=f last(_time) AS prev_time by src, dest
| eval delta = _time - prev_time
| stats avg(delta) AS avg_delta stdev(delta) AS sd_delta count by src, dest
| where count > 30 AND sd_delta < 5 AND avg_delta>=30 AND avg_delta<=600
| sort - count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteIPType == "Public" and ActionType == "ConnectionSuccess"
| project DeviceName, RemoteIP, RemotePort, Timestamp
| sort by DeviceName asc, RemoteIP asc, RemotePort asc, Timestamp asc
| extend prev_dev = prev(DeviceName, 1), prev_ip = prev(RemoteIP, 1),
         prev_port = prev(RemotePort, 1), prev_ts = prev(Timestamp, 1)
| where DeviceName == prev_dev and RemoteIP == prev_ip and RemotePort == prev_port
| extend delta_sec = datetime_diff('second', Timestamp, prev_ts)
| summarize conn_count = count(), avg_delta = avg(delta_sec), stdev_delta = stdev(delta_sec)
    by DeviceName, RemoteIP, RemotePort
| where conn_count > 30 and avg_delta between (30.0 .. 600.0) and stdev_delta < 5.0
| order by conn_count desc
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

### Article-specific behavioural hunt — Tycoon 2FA Operators Adopt OAuth Device Code Phishing to Bypass MFA

`UC_0_6` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Tycoon 2FA Operators Adopt OAuth Device Code Phishing to Bypass MFA ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("node.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Tycoon 2FA Operators Adopt OAuth Device Code Phishing to Bypass MFA
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `events.trustifi.com`, `cookies.28gholland.workers.dev`, `shivacrio.com`, `fijothi.com`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 10 use case(s) fired, 17 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

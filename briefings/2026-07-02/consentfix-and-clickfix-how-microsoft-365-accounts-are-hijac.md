# [CRIT] ConsentFix and ClickFix: How Microsoft 365 Accounts are Hijacked in 3 Seconds

**Source:** BleepingComputer
**Published:** 2026-07-02
**Article:** https://www.bleepingcomputer.com/news/security/consentfix-and-clickfix-how-microsoft-365-accounts-are-hijacked-in-3-seconds/

## Threat Profile

ConsentFix and ClickFix: How Microsoft 365 Accounts are Hijacked in 3 Seconds 
Sponsored by Huntress Labs 
July 2, 2026
10:00 AM
0 
It can start with something as mundane as dragging a link into your browser. Three seconds later, a threat actor has the tokens needed to take over your Microsoft 365 account, and you never did anything that traditional security awareness training would flag. You just followed what looked like a normal set of instructions.
That's the defining characteristic of moder…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `security-updater.com`

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
- **T1027** — Obfuscated Files or Information
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1071** — Application Layer Protocol
- **T1550.001** — Use Alternate Authentication Material: Application Access Token
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1204** — User Execution
- **T1105** — Ingress Tool Transfer
- **T1566.002** — Phishing: Spearphishing Link
- **T1114.003** — Email Collection: Email Forwarding Rule
- **T1564.008** — Hide Artifacts: Email Hiding Rules

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### ConsentFix: interactive browser sign-in to Azure CLI / dev-tool first-party app

`UC_47_10` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Authentication.Authentication where (Authentication.app IN ("04b07795-8ddb-461a-bbee-02f9e1bf7b46","1950a258-227b-4e31-a9cf-717495945fc2","aebc6443-996d-45c2-90f0-388ff96faa56","04f0c124-f2bc-4f59-8241-bf6df9866bbd","12128f48-ec9e-42f0-b203-ea49fb6af367")) by Authentication.user Authentication.app Authentication.src Authentication.action _time | `drop_dm_object_name(Authentication)` | where action="success" | convert ctime(firstTime) | convert ctime(lastTime)
```

**Defender KQL:**
```kql
let VulnerableFirstPartyApps = dynamic(["04b07795-8ddb-461a-bbee-02f9e1bf7b46","1950a258-227b-4e31-a9cf-717495945fc2","aebc6443-996d-45c2-90f0-388ff96faa56","04f0c124-f2bc-4f59-8241-bf6df9866bbd","12128f48-ec9e-42f0-b203-ea49fb6af367"]);
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where ApplicationId in (VulnerableFirstPartyApps)   // Azure CLI + dev-tool public clients abused by ConsentFix
| where IsInteractive == true
| where ErrorCode == 0
| where ClientAppUsed == "Browser"                    // interactive browser flow = the lure, not native CLI use
| project Timestamp, AccountUpn, AccountDisplayName, Application, ApplicationId, IPAddress, Country, City, UserAgent, Browser, DeviceName
| order by Timestamp desc
```

### ConsentFix: Azure CLI token redemption from divergent IP within 10 min of interactive sign-in

`UC_47_11` · phase: **actions** · confidence: **High** · AI-generated for this article

**Defender KQL:**
```kql
let AppScope = dynamic(["04b07795-8ddb-461a-bbee-02f9e1bf7b46","1950a258-227b-4e31-a9cf-717495945fc2","aebc6443-996d-45c2-90f0-388ff96faa56","04f0c124-f2bc-4f59-8241-bf6df9866bbd","12128f48-ec9e-42f0-b203-ea49fb6af367"]);
let Interactive = AADSignInEventsBeta
    | where Timestamp > ago(7d)
    | where ApplicationId in (AppScope)
    | where IsInteractive == true and ErrorCode == 0
    | project VictimTime = Timestamp, AccountObjectId, AccountUpn, ApplicationId, VictimIP = IPAddress, VictimCountry = Country;
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where ApplicationId in (AppScope)
| where IsInteractive == false and ErrorCode == 0
| project RedeemTime = Timestamp, AccountObjectId, ApplicationId, RedeemIP = IPAddress, RedeemCountry = Country, RedeemUserAgent = UserAgent
| join kind=inner Interactive on AccountObjectId, ApplicationId
| where RedeemTime between (VictimTime .. VictimTime + 10m)   // 10-min human-delayed redemption window (Push Security)
| where RedeemIP != VictimIP                                  // attacker infra differs from victim device
| project VictimTime, RedeemTime, DelaySec = datetime_diff('second', RedeemTime, VictimTime), AccountUpn, ApplicationId, VictimIP, VictimCountry, RedeemIP, RedeemCountry, RedeemUserAgent
| order by VictimTime desc
```

### ClickFix: PowerShell/mshta download-execute spawned from Run dialog (explorer parent)

`UC_47_12` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name="explorer.exe") (Processes.process_name IN ("powershell.exe","pwsh.exe","mshta.exe","cmd.exe","curl.exe","wscript.exe","cscript.exe")) (Processes.process IN ("*iwr*","*invoke-webrequest*","*IEX*","*DownloadString*","*DownloadFile*","*mshta http*","*-w hidden*","*-windowstyle hidden*","*FromBase64String*","*.hta*","*curl *","*certutil*","*http://*","*https://*")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process _time | `drop_dm_object_name(Processes)` | where user!="*$" | convert ctime(firstTime) | convert ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName =~ "explorer.exe"   // Win+R Run dialog / double-click origin
| where FileName in~ ("powershell.exe","pwsh.exe","mshta.exe","cmd.exe","curl.exe","wscript.exe","cscript.exe")
| where ProcessCommandLine has_any ("iwr","invoke-webrequest","iex","invoke-expression","downloadstring","downloadfile","mshta http","-w hidden","-windowstyle hidden","-nop","frombase64string",".hta","curl ","certutil","start-bitstransfer","http://","https://")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### ConsentFix lure delivery: inbound email link to DocSend/Dropbox or ConsentFix phishing infra

`UC_47_13` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Defender KQL:**
```kql
let LureDomains = dynamic(["docsend.com","dropbox.com","dropboxusercontent.com"]);
let ConsentFixInfra = dynamic(["trustpointassurance.com","fastwaycheck.com","previewcentral.com","security-updater.com"]);
EmailEvents
| where Timestamp > ago(14d)
| where EmailDirection == "Inbound" and DeliveryAction == "Delivered"
| join kind=inner (
    EmailUrlInfo
    | where Timestamp > ago(14d)
    | project NetworkMessageId, Url, UrlDomain
  ) on NetworkMessageId
| where UrlDomain has_any (LureDomains) or UrlDomain has_any (ConsentFixInfra)
| extend Verdict = iff(UrlDomain has_any (ConsentFixInfra), "ConsentFix-infra", "trusted-service-lure")
| project Timestamp, Verdict, SenderFromAddress, SenderMailFromDomain, RecipientEmailAddress, Subject, Url, UrlDomain, AuthenticationDetails
| order by Timestamp desc
```

### Post-session-theft mailbox abuse: auto-forwarding / inbox rule creation via stolen M365 session

`UC_47_14` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("New-InboxRule","Set-InboxRule","UpdateInboxRules","Set-Mailbox","New-TransportRule")
| extend Raw = tostring(RawEventData)
| where Raw has_any ("ForwardTo","ForwardAsAttachmentTo","RedirectTo","DeliverToMailboxAndForward","DeleteMessage","MoveToFolder")
| project Timestamp, AccountDisplayName, AccountObjectId, ActionType, Application, IPAddress, CountryCode, UserAgent, ObjectName, RawEventData
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

### PowerShell encoded / obfuscated command

`UC_PS_OBFUSCATED` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("powershell.exe","pwsh.exe")
      AND (Processes.process="*-enc *" OR Processes.process="*EncodedCommand*"
        OR Processes.process="*FromBase64String*" OR Processes.process="*-nop*"
        OR Processes.process="*-w hidden*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*IEX(*" OR Processes.process="*DownloadString*"
        OR Processes.process="*Net.WebClient*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)(-enc|encodedcommand|frombase64string|-nop|-w\s+hidden|invoke-expression|iex\s*\(|downloadstring|net\.webclient)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

### Ransomware-style mass file rename / extension change

`UC_RANSOM_ENCRYPT` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, dc(Filesystem.file_name) AS files
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("modified","renamed")
    by Filesystem.dest, Filesystem.user, _time span=1m
| `drop_dm_object_name(Filesystem)`
| where files > 200
| sort - files
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where InitiatingProcessAccountName !endswith "$"
| where ActionType in ("FileRenamed","FileModified")
| summarize files = dcount(FileName) by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 1m)
| where files > 200    // empirical: > 200 unique-file renames in 1m by one account on one host
                       //            is well above the P99 of legitimate bulk-tooling
| order by files desc
```

### LSASS process access / dump (credential theft)

`UC_LSASS` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process="*lsass*" OR Processes.process="*sekurlsa*"
        OR Processes.process="*MiniDump*" OR Processes.process="*comsvcs.dll*MiniDump*"
        OR Processes.process="*procdump*lsass*")
       OR (Processes.process_name="rundll32.exe" AND Processes.process="*comsvcs*MiniDump*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsSense.exe","MsMpEng.exe","csrss.exe",
                                          "svchost.exe","wininit.exe","services.exe",
                                          "lsm.exe","SearchProtocolHost.exe")
| project Timestamp, DeviceName, ActionType, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, AccountName
| order by Timestamp desc
```

### Remote service execution — PsExec / SMB lateral movement

`UC_LATERAL_PSEXEC` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
       OR (Processes.process_name="wmic.exe" AND Processes.process="*/node:*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
   or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `security-updater.com`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 15 use case(s) fired, 24 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

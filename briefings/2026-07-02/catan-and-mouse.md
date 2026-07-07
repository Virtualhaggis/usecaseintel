# [HIGH] Catan and Mouse

**Source:** Cisco Talos
**Published:** 2026-07-02
**Article:** https://blog.talosintelligence.com/catan-and-mouse/

## Threat Profile

Catan and Mouse 
By 
William Largent 
Thursday, July 2, 2026 14:00
Threat Source newsletter
Welcome to this week’s edition of the Threat Source newsletter.  
“I do not know everything; still many things I understand.” 
― Madeleine L'Engle, A Wrinkle in Time  “Don't try to comprehend with your mind. Your minds are very limited. Use your intuition.” 
― Madeleine L'Engle, A Wind in the Door  The World Cup. The 4 th  of July as the US turns 250. Dungeon Crawler Carl. LeBron moving on. Wimbledon. AI.…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-48558`
- **Domain (defanged):** `dashboard-bl.pamconj.com`
- **Domain (defanged):** `spx.pamconj.com`
- **Domain (defanged):** `clear90489058903-document.workers.dev`
- **SHA256:** `9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507`
- **SHA256:** `9896a6fcb9bb5ac1ec5297b4a65be3f647589adf7c37b45f3f7466decd6a4a7f`
- **SHA256:** `afc8a00883a4ea07df2dc1d4ed02f8a23b35c9456413b438a2d9ce3ae5076638`
- **SHA256:** `c0ad494457dcd9e964378760fb6aca86a23622045bca851d8f3ab49ec33978fe`
- **SHA256:** `853baab97b1f3b03c1ffa55797e87867f5fb7ce33457411f56afd270cb395453`
- **MD5:** `2915b3f8b703eb744fc54c81f4a9c67f`
- **MD5:** `38de5b216c33833af710e88f7f64fc98`
- **MD5:** `cc4d231df34e57f59eb970353c7d9de2`
- **MD5:** `bf9672ec85283fdf002d83662f0b08b7`
- **MD5:** `41acb30b9d662d48b7b4fc0ac3d4b79f`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1566.002** — Phishing: Spearphishing Link
- **T1102** — Web Service
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1098.005** — Account Manipulation: Device Registration
- **T1528** — Steal Application Access Token
- **T1114.003** — Email Collection: Email Forwarding Rule
- **T1564.008** — Hide Artifacts: Email Hiding Rules

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### ARToken/EvilTokens PhaaS infrastructure contact (pamconj.com panel + Cloudflare Worker lure)

`UC_58_7` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query IN ("dashboard-bl.pamconj.com","spx.pamconj.com","clear90489058903-document.workers.dev","*.pamconj.com") by DNS.src DNS.query DNS.answer | `drop_dm_object_name(DNS)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
let ARTokenDomains = dynamic(["dashboard-bl.pamconj.com","spx.pamconj.com","clear90489058903-document.workers.dev","pamconj.com"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any (ARTokenDomains)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessSHA256, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Entra ID device registration = ARToken PRT persistence after device-code token theft

`UC_58_8` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(14d)
| where ActionType in ("Add registered owner to device","Add registered users to device","Register device","Add device")
| extend Ip = tostring(IPAddress)
| project Timestamp, ActionType, AccountDisplayName, AccountObjectId, Ip, CountryCode, City, ObjectName, ObjectType
| order by Timestamp desc
```

### ARToken BEC toolkit: inbox forwarding/hiding rule creation on compromised M365 mailbox

`UC_58_9` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(14d)
| where ActionType in ("New-InboxRule","Set-InboxRule","UpdateInboxRules")
| where RawEventData has_any ("ForwardTo","ForwardAsAttachmentTo","RedirectTo","DeleteMessage","MoveToFolder")
| project Timestamp, ActionType, AccountDisplayName, AccountObjectId, IPAddress, CountryCode, ObjectName, RawEventData
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

### Article-specific behavioural hunt — Catan and Mouse

`UC_58_6` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Catan and Mouse ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("vid001.exe","sample.exe","autopico.exe","signinfoconsole.exe"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("vid001.exe","sample.exe","autopico.exe","signinfoconsole.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Catan and Mouse
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("vid001.exe", "sample.exe", "autopico.exe", "signinfoconsole.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("vid001.exe", "sample.exe", "autopico.exe", "signinfoconsole.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-48558`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `dashboard-bl.pamconj.com`, `spx.pamconj.com`, `clear90489058903-document.workers.dev`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507`, `9896a6fcb9bb5ac1ec5297b4a65be3f647589adf7c37b45f3f7466decd6a4a7f`, `afc8a00883a4ea07df2dc1d4ed02f8a23b35c9456413b438a2d9ce3ae5076638`, `c0ad494457dcd9e964378760fb6aca86a23622045bca851d8f3ab49ec33978fe`, `853baab97b1f3b03c1ffa55797e87867f5fb7ce33457411f56afd270cb395453`, `2915b3f8b703eb744fc54c81f4a9c67f`, `38de5b216c33833af710e88f7f64fc98`, `cc4d231df34e57f59eb970353c7d9de2` _(+2 more)_


## Why this matters

Severity classified as **HIGH** based on: CVE present, IOCs present, 10 use case(s) fired, 17 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

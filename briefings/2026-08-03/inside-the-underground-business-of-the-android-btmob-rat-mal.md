# [HIGH] Inside the Underground Business of the Android BTMOB RAT malware

**Source:** BleepingComputer
**Published:** 2026-08-03
**Article:** https://www.bleepingcomputer.com/news/security/inside-the-underground-business-of-btmob-rat/

## Threat Profile

Inside the Underground Business of the Android BTMOB RAT malware 
Sponsored by Flare 
August 3, 2026
10:45 AM
0 
The Android RAT’s official operation is surrounded by cheaper resellers, alleged source-code vendors, independent server owners, and possible impersonators. 
BTMOB has been  covered by several cybersecurity publications, primarily through technical analyses of the malware and its capabilities, but much less has been reported about the ecosystem that has developed around it.
Activity o…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1437.001** — Application Layer Protocol: Web Protocols
- **T1571** — Non-Standard Port
- **T1521** — Encrypted Channel
- **T1660** — Phishing
- **T1407** — Download New Code at Runtime

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### BTMOB Android RAT C2 beacon to server.yaarsa.com / 78.135.93.123

`UC_44_4` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest="78.135.93.123" by All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port, All_Traffic.app | `drop_dm_object_name(All_Traffic)` | append [ | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query="server.yaarsa.com" by DNS.src, DNS.query | `drop_dm_object_name(DNS)` ] | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "78.135.93.123" or RemoteUrl has "server.yaarsa.com"
| project Timestamp, DeviceName, DeviceId, ActionType, RemoteIP, RemoteUrl, RemotePort, Protocol, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### BTMOB RAT C2 URI path /yaarsa/private/ and WebSocket /con endpoint

`UC_44_5` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*/yaarsa/private/*" OR Web.url="*server.yaarsa.com/con*") by Web.src, Web.dest, Web.url, Web.http_user_agent | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "/yaarsa/private/" or (RemoteUrl has "server.yaarsa.com" and RemoteUrl has "/con")
| project Timestamp, DeviceName, DeviceId, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### BTMOB RAT APK sample hash observed on managed endpoint

`UC_44_6` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("8dbfcf6b67ee6c5821564bf4228099beaf5f40e4a87118cbb1e52d8f01312f40","c522a752519580c37574684d86abfe3c4666ac72d837825ac21d6cfe937d7817","13341c5171c34d846f6d0859e8c45d8a898eb332da41ab62bcae7519368d2248","b053a3d68abb27e91c2caf5412de7868fe50c7506e1f9314fee4c26285db7f59","bb20f2bfb78fd5a2ff4693939d061368949cd717b8033b6facba82df26b31a1a","a4c15afd6cb79b66fce3532907e65ccd13c8140a3cb26cc334138775f7a6aebd","061fdbf0c61a29d31406887a40b4f6a551600f7366a711ecce6063f61965308d","937e77d2a910a1452f951d2de6f614a6219e707c40b6789ccf31cac0d82868cc","9141e25b93d315843399a757cddb63af55bdbdd4094fba4a6b2bbea89bf9ecf9","b724ca474c2bca77573e071524bd5500f0355c8b6b8bb432dcc2d8664ed2d073","6ce41ee43a5d5f773203cfcf810c0208246f0b27505d49b270288751a747f5a3","8548600b4e461580fe32fea6c1e233a5862483ca9a617d79fdea001ebf5556cc","8df615fa33dcd7aa81adc640ac42a6a9a4a2bebbb5308f1d8a35afa169e99229","186cd8d9998d6c4e2d12a1370056ba910a6f8a2176c8b0c9362a868830fcfb07","071d3ad980ea77a9041c580015b2796d3d5d471c2fc1039c8f381501efb3cda0","04241bc4ce9cece5644cd7f8f86ede7def5cb6122b2f3b5760c2c3556da34a7d","2b725322f9a019b0106a084694c18fbb8604cf64c65182153c4d67ff3adf4e48","2b307f11ae418931674156425c47ff1c0645fb0b160290cd358599708ff62668") by Filesystem.dest, Filesystem.file_name, Filesystem.file_path, Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(90d)
| where SHA256 in ("8dbfcf6b67ee6c5821564bf4228099beaf5f40e4a87118cbb1e52d8f01312f40","c522a752519580c37574684d86abfe3c4666ac72d837825ac21d6cfe937d7817","13341c5171c34d846f6d0859e8c45d8a898eb332da41ab62bcae7519368d2248","b053a3d68abb27e91c2caf5412de7868fe50c7506e1f9314fee4c26285db7f59","bb20f2bfb78fd5a2ff4693939d061368949cd717b8033b6facba82df26b31a1a","a4c15afd6cb79b66fce3532907e65ccd13c8140a3cb26cc334138775f7a6aebd","061fdbf0c61a29d31406887a40b4f6a551600f7366a711ecce6063f61965308d","937e77d2a910a1452f951d2de6f614a6219e707c40b6789ccf31cac0d82868cc","9141e25b93d315843399a757cddb63af55bdbdd4094fba4a6b2bbea89bf9ecf9","b724ca474c2bca77573e071524bd5500f0355c8b6b8bb432dcc2d8664ed2d073","6ce41ee43a5d5f773203cfcf810c0208246f0b27505d49b270288751a747f5a3","8548600b4e461580fe32fea6c1e233a5862483ca9a617d79fdea001ebf5556cc","8df615fa33dcd7aa81adc640ac42a6a9a4a2bebbb5308f1d8a35afa169e99229","186cd8d9998d6c4e2d12a1370056ba910a6f8a2176c8b0c9362a868830fcfb07","071d3ad980ea77a9041c580015b2796d3d5d471c2fc1039c8f381501efb3cda0","04241bc4ce9cece5644cd7f8f86ede7def5cb6122b2f3b5760c2c3556da34a7d","2b725322f9a019b0106a084694c18fbb8604cf64c65182153c4d67ff3adf4e48","2b307f11ae418931674156425c47ff1c0645fb0b160290cd358599708ff62668")
| project Timestamp, DeviceName, DeviceId, ActionType, FileName, FolderPath, SHA256, FileOriginUrl, InitiatingProcessFileName, InitiatingProcessAccountName
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

### Article-specific behavioural hunt — Inside the Underground Business of the Android BTMOB RAT malware

`UC_44_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Inside the Underground Business of the Android BTMOB RAT malware ```
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
// Article-specific bespoke detection — Inside the Underground Business of the Android BTMOB RAT malware
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


## Why this matters

Severity classified as **HIGH** based on: 7 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

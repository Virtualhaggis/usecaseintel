# [CRIT] TELESHIM Abuses Telegram for C2 in Attacks Against Middle East Governments

**Source:** The Hacker News
**Published:** 2026-07-27
**Article:** https://thehackernews.com/2026/07/teleshim-abuses-telegram-for-c2-in.html

## Threat Profile

TELESHIM Abuses Telegram for C2 in Attacks Against Middle East Governments 
 Ravie Lakshmanan  Jul 27, 2026 Cyber Attack / Threat Intelligence 
Cybersecurity researchers have flagged fresh malicious cyber activity by a threat actor with ties to East Asia targeting government entities in the Middle East.
The intrusions have resulted in the deployment of previously unreported malware families dubbed TELESHIM, MIXEDKEY, and BINDCLOAK, according to Zscaler ThreatLabz. The cybersecurity firm said i…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `cert.hypersnet.com`
- **Domain (defanged):** `ssl.blsouqs.com`
- **SHA256:** `789fd11285642861190dc074c1e9a5957073f1a2afebd5160f9cc907f7f320bd`
- **SHA256:** `c84542ac30cbe9bb8bd648bad323c37801023bf9451c1c0990452466e084340f`
- **SHA256:** `32529043d15e9111ba284f1d8a9e4b3f58e071c6b69c8f271d4d02feacd44e66`
- **SHA256:** `db11ff3f37a8b2aa25c480871504b886a6364167ecb501eacf7345f6bbf9582b`
- **SHA256:** `5c2fe953da53da66fbcbb3be0fd6b63907c10714c337f287b2fc258857bbff6d`
- **SHA256:** `cac1f37beaa814461f7709a073aeec468c74e5d70f7d693a9e367ece4a3a78be`
- **SHA256:** `0637069c7052118fd5c0f1113541bdd35e5f71cd9689f2516045da152c6fa8d9`
- **SHA256:** `3b3eaea783fd6dab90f0408274bf8a9c49adbdc70c0efd70658d65b0e1684a3f`
- **MD5:** `7cbc51ada1a4aec88660ec32c408114b`
- **MD5:** `3f60d53a2b5737d77e058d9e33cbe9eb`
- **MD5:** `28b47bdf16d7af6f8ec21218eac9145a`
- **MD5:** `78a4f8574830bf7fbaf63d7da09be2b8`
- **MD5:** `7a14a99d70d42d3f7bf72f843185fc07`

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
- **T1053.005** — Scheduled Task
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1053.005** — Persistence (article-specific)
- **T1204.002** — Malicious File
- **T1574.002** — DLL Side-Loading
- **T1497** — Virtualization/Sandbox Evasion
- **T1102.002** — Bidirectional Communication
- **T1567** — Exfiltration Over Web Service
- **T1041** — Exfiltration Over C2 Channel
- **T1620** — Reflective Code Loading
- **T1480.001** — Environmental Keying

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### ISO-delivered signed RegSchdTask.exe executed from non-standard/removable path

`UC_63_9` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="RegSchdTask.exe" NOT (Processes.process_path="*\\Program Files\\*" OR Processes.process_path="*\\Program Files (x86)\\*" OR Processes.process_path="*\\Windows\\*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process_path Processes.process Processes.process_hash | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "RegSchdTask.exe"
| where not(FolderPath has_any (@"\Program Files\", @"\Program Files (x86)\", @"\Windows\"))
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
| order by Timestamp desc
```

### TELESHIM DLL side-load: RegSchdTask.exe loads rogue AsTaskSched.dll

`UC_63_10` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name="AsTaskSched.dll" NOT (Filesystem.file_path="*\\Windows\\System32\\*" OR Filesystem.file_path="*\\Program Files\\*") by Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.file_hash Filesystem.process_name | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName =~ "RegSchdTask.exe"
| where FileName =~ "AsTaskSched.dll"
| where not(FolderPath has_any (@"\Windows\System32\", @"\Program Files\"))
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, FileName, FolderPath, SHA256, MD5
| order by Timestamp desc
```

### Telegram Bot API used for C2 by non-browser/non-messaging process

`UC_63_11` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where (DNS.query="api.telegram.org" OR DNS.query="core.telegram.org") by DNS.src DNS.query DNS.answer | `drop_dm_object_name(DNS)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteUrl has_any ("api.telegram.org","core.telegram.org")
| where InitiatingProcessFileName !in~ ("telegram.exe","chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","iexplore.exe","teams.exe","ms-teams.exe")
| where InitiatingProcessAccountName !endswith "$"
| summarize FirstSeen=min(Timestamp), Count=count(), Ports=make_set(RemotePort), SampleUrl=any(RemoteUrl) by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256
| order by FirstSeen desc
```

### TELESHIM/MIXEDKEY sideload host binary beacons to Telegram (C2 + exfil)

`UC_63_12` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.app="RegSchdTask.exe" OR All_Traffic.app="GoProAlertService.exe") All_Traffic.direction="outbound" by All_Traffic.src All_Traffic.app All_Traffic.dest All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("RegSchdTask.exe","GoProAlertService.exe")
| where RemoteUrl has "telegram.org" or RemoteUrl has_any ("api.telegram.org","core.telegram.org")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessSHA256
| order by Timestamp desc
```

### MIXEDKEY encrypted payload: .PCPKEY file dropped on disk

`UC_63_13` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name="*.PCPKEY" by Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.file_hash Filesystem.process_name | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName endswith ".PCPKEY"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
| order by Timestamp desc
```

### BINDCLOAK C2 beacon to cert.hypersnet.com / ssl.blsouqs.com

`UC_63_14` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where (DNS.query="cert.hypersnet.com" OR DNS.query="ssl.blsouqs.com") by DNS.src DNS.query DNS.answer | `drop_dm_object_name(DNS)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any ("cert.hypersnet.com","ssl.blsouqs.com")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessSHA256
| order by Timestamp desc
```

### TELESHIM/MIXEDKEY/BINDCLOAK known-bad file hash execution

`UC_63_15` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_hash IN ("789fd11285642861190dc074c1e9a5957073f1a2afebd5160f9cc907f7f320bd","c84542ac30cbe9bb8bd648bad323c37801023bf9451c1c0990452466e084340f","32529043d15e9111ba284f1d8a9e4b3f58e071c6b69c8f271d4d02feacd44e66","db11ff3f37a8b2aa25c480871504b886a6364167ecb501eacf7345f6bbf9582b","5c2fe953da53da66fbcbb3be0fd6b63907c10714c337f287b2fc258857bbff6d","cac1f37beaa814461f7709a073aeec468c74e5d70f7d693a9e367ece4a3a78be","0637069c7052118fd5c0f1113541bdd35e5f71cd9689f2516045da152c6fa8d9","3b3eaea783fd6dab90f0408274bf8a9c49adbdc70c0efd70658d65b0e1684a3f","7cbc51ada1a4aec88660ec32c408114b","3f60d53a2b5737d77e058d9e33cbe9eb","28b47bdf16d7af6f8ec21218eac9145a","78a4f8574830bf7fbaf63d7da09be2b8","7a14a99d70d42d3f7bf72f843185fc07") by Processes.dest Processes.user Processes.process_name Processes.process_path Processes.process_hash | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let badSHA256 = dynamic(["789fd11285642861190dc074c1e9a5957073f1a2afebd5160f9cc907f7f320bd","c84542ac30cbe9bb8bd648bad323c37801023bf9451c1c0990452466e084340f","32529043d15e9111ba284f1d8a9e4b3f58e071c6b69c8f271d4d02feacd44e66","db11ff3f37a8b2aa25c480871504b886a6364167ecb501eacf7345f6bbf9582b","5c2fe953da53da66fbcbb3be0fd6b63907c10714c337f287b2fc258857bbff6d","cac1f37beaa814461f7709a073aeec468c74e5d70f7d693a9e367ece4a3a78be","0637069c7052118fd5c0f1113541bdd35e5f71cd9689f2516045da152c6fa8d9","3b3eaea783fd6dab90f0408274bf8a9c49adbdc70c0efd70658d65b0e1684a3f"]);
let badMD5 = dynamic(["7cbc51ada1a4aec88660ec32c408114b","3f60d53a2b5737d77e058d9e33cbe9eb","28b47bdf16d7af6f8ec21218eac9145a","78a4f8574830bf7fbaf63d7da09be2b8","7a14a99d70d42d3f7bf72f843185fc07"]);
union
 (DeviceProcessEvents | where Timestamp > ago(30d) | where SHA256 in~ (badSHA256) or MD5 in~ (badMD5) | extend Source="Process"),
 (DeviceImageLoadEvents | where Timestamp > ago(30d) | where SHA256 in~ (badSHA256) or MD5 in~ (badMD5) | extend Source="ImageLoad"),
 (DeviceFileEvents | where Timestamp > ago(30d) | where SHA256 in~ (badSHA256) or MD5 in~ (badMD5) | extend Source="FileEvent")
| project Timestamp, Source, DeviceName, FileName, FolderPath, SHA256, MD5, InitiatingProcessFileName, InitiatingProcessFolderPath
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

### Scheduled task created with suspicious image / encoded args

`UC_SCHEDULED_TASK` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name="schtasks.exe" AND Processes.process="*/create*"
      AND (Processes.process="*powershell*" OR Processes.process="*cmd.exe*"
        OR Processes.process="*rundll32*" OR Processes.process="*-enc*"
        OR Processes.process="*FromBase64*" OR Processes.process="*\Users\Public*"
        OR Processes.process="*\AppData\*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has_any ("powershell","cmd.exe","rundll32","-enc","FromBase64","\Users\Public","\AppData\")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
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

### Article-specific behavioural hunt — TELESHIM Abuses Telegram for C2 in Attacks Against Middle East Governments

`UC_63_8` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — TELESHIM Abuses Telegram for C2 in Attacks Against Middle East Governments ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("regschdtask.exe","astasksched.dll","goproalertservice.exe","pthreadvc2.dll"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("regschdtask.exe","astasksched.dll","goproalertservice.exe","pthreadvc2.dll"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — TELESHIM Abuses Telegram for C2 in Attacks Against Middle East Governments
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("regschdtask.exe", "astasksched.dll", "goproalertservice.exe", "pthreadvc2.dll"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("regschdtask.exe", "astasksched.dll", "goproalertservice.exe", "pthreadvc2.dll"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `cert.hypersnet.com`, `ssl.blsouqs.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `789fd11285642861190dc074c1e9a5957073f1a2afebd5160f9cc907f7f320bd`, `c84542ac30cbe9bb8bd648bad323c37801023bf9451c1c0990452466e084340f`, `32529043d15e9111ba284f1d8a9e4b3f58e071c6b69c8f271d4d02feacd44e66`, `db11ff3f37a8b2aa25c480871504b886a6364167ecb501eacf7345f6bbf9582b`, `5c2fe953da53da66fbcbb3be0fd6b63907c10714c337f287b2fc258857bbff6d`, `cac1f37beaa814461f7709a073aeec468c74e5d70f7d693a9e367ece4a3a78be`, `0637069c7052118fd5c0f1113541bdd35e5f71cd9689f2516045da152c6fa8d9`, `3b3eaea783fd6dab90f0408274bf8a9c49adbdc70c0efd70658d65b0e1684a3f` _(+5 more)_


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 16 use case(s) fired, 22 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

# [CRIT] China-Aligned Groups Ramp Up Attacks: Dragon Weave Hits Czech Republic & Taiwan

**Source:** The Hacker News
**Published:** 2026-06-01
**Article:** https://thehackernews.com/2026/06/china-aligned-groups-ramp-up-attacks.html

## Threat Profile

China-Aligned Groups Ramp Up Attacks: Dragon Weave Hits Czech Republic & Taiwan 
 Ravie Lakshmanan  Jun 01, 2026 Endpoint Security / Threat Intelligence 
A new cyber espionage campaign codenamed Operation Dragon Weave has been observed targeting officials and citizens in the Czech Republic and Taiwan to deliver an AdaptixC2 agent.
According to Seqrite Labs, targets of the campaign include government, research, academic, technology, and financial services sectors. The activity entails distribut…

## Indicators of Compromise (high-fidelity only)

- **SHA256:** `096372d19b4787e989f44e04c5ecc29885aa927c34ae8666628d6c0eb20bb447`
- **SHA256:** `1c56228cbd1bdebb9e5ea55c2749150fee06c865ede4a3754e8bd6843e51d2d4`
- **SHA256:** `080ab9bc2893ba7bad354551604a667af40ed2ae2d042d2323c2bd9ad3122192`
- **SHA256:** `5ed14c2b7f7433a1a72dd6b668413f935a217ba10b69d89b774a82990fa12fe1`
- **SHA256:** `61f7d9cd2d8ce7df950639b23ce90085b300b0c6dd0d8d934bba8fdecb670f15`
- **SHA256:** `24aa4e780ccd66cef13da9ef98c32954105cf2a32ec643efab0ba1aa2d6352f4`
- **SHA256:** `02542a49b3bd6bd2795afb67840acb4557b17e017f7503dd03ebe3aeeb28720e`
- **SHA256:** `8ae7c82a3e4f742777e590b25a1c563d19bd9bcba2a387d004aae72c4b2828f9`
- **SHA256:** `047687548605734348792e2a9d771b6cba42facd0d0d7d44d778290a25848574`
- **SHA256:** `a4e9f9919d62589b57cfa08c9ccb89e386b09f683271373413cd8e8c8c7d1c5a`
- **SHA256:** `823d5969db3f3b72ebbdce1b78752717ea849884a0fb40d86146416c38e128de`
- **SHA256:** `783661d0f7edb338d2d50be087764d82dbbc9ee7989ddc57db1801e4ec9045b0`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
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
- **T1195.002** — Compromise Software Supply Chain
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1027.013** — Obfuscated Files or Information: Encrypted/Encoded File
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1574.002** — Hijack Execution Flow: DLL Side-Loading
- **T1027.009** — Embedded Payloads
- **T1102.003** — Web Service: One-Way Communication
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1567.002** — Exfiltration to Cloud Storage
- **T1105** — Ingress Tool Transfer

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] LNK-spawned PowerShell extracts RuntimeBroker_update.exe from DAT file (Dragon Weave)

`UC_114_10` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.process_name IN ("powershell.exe","pwsh.exe") (Processes.process="*RuntimeBroker_update.exe*" OR (Processes.process="*.dat*" AND (Processes.process="*Get-Content*" OR Processes.process="*[System.IO.File]::ReadAllBytes*" OR Processes.process="*WriteAllBytes*"))) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name | `drop_dm_object_name(Processes)` | where match(parent_process_name,"(?i)explorer\.exe|cmd\.exe|wscript\.exe")
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe","pwsh.exe")
| where InitiatingProcessFileName in~ ("explorer.exe","cmd.exe","wscript.exe")
| where ProcessCommandLine has "RuntimeBroker_update.exe"
   or (ProcessCommandLine has ".dat" and ProcessCommandLine has_any ("ReadAllBytes","WriteAllBytes","Get-Content","FromBase64String","[IO.File]"))
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### [LLM] RuntimeBroker_update.exe masquerading binary execution (Dragon Weave / RUSTCLOAK loader)

`UC_114_11` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.parent_process_name) as parent values(Processes.process_path) as path values(Processes.process) as cmdline values(Processes.process_hash) as sha256 from datamodel=Endpoint.Processes where Processes.process_name="RuntimeBroker_update.exe" by Processes.dest Processes.user Processes.process_name | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "RuntimeBroker_update.exe"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, SHA256, MD5
| order by Timestamp desc
```

### [LLM] UnityPlayer.dll side-loaded by RuntimeBroker_update.exe (RUSTCLOAK)

`UC_114_12` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`sysmon` EventCode=7 ImageLoaded="*\\UnityPlayer.dll" Image="*\\RuntimeBroker_update.exe" | stats min(_time) as firstTime max(_time) as lastTime count values(ImageLoaded) as dll values(ProcessGuid) as pguid values(CommandLine) as cmdline by host, user, Image | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where FileName =~ "UnityPlayer.dll"
| where InitiatingProcessFileName =~ "RuntimeBroker_update.exe"
| project Timestamp, DeviceName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessSHA256
| order by Timestamp desc
```

### [LLM] AZUREVEIL AdaptixC2 dead-drop to Azure Blob Storage from atypical process

`UC_114_13` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dest values(All_Traffic.dest_port) as port values(All_Traffic.bytes_in) as bin values(All_Traffic.bytes_out) as bout from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_host="*.blob.core.windows.net" by All_Traffic.src All_Traffic.app All_Traffic.process_name | `drop_dm_object_name(All_Traffic)` | where match(process_name,"(?i)RuntimeBroker_update\.exe") OR NOT match(process_name,"(?i)^(azcopy|storageexplorer|msedge|chrome|firefox|onedrive|teams|outlook|excel|word|powerpnt|powershell|pwsh|az\.exe|aws|backup)")
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl endswith ".blob.core.windows.net" or RemoteUrl contains ".blob.core.windows.net/"
| where InitiatingProcessFileName =~ "RuntimeBroker_update.exe"
   or (InitiatingProcessFolderPath startswith "C:\\Users\\" or InitiatingProcessFolderPath startswith "C:\\ProgramData\\" or InitiatingProcessFolderPath startswith "C:\\Windows\\Temp\\")
| where InitiatingProcessFileName !in~ ("azcopy.exe","StorageExplorer.exe","msedge.exe","chrome.exe","firefox.exe","onedrive.exe","teams.exe","outlook.exe","excel.exe","winword.exe","powerpnt.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessSHA256, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### [LLM] Operation Dragon Weave SHA256 IOC match (RUSTCLOAK/AZUREVEIL/RuntimeBroker_update)

`UC_114_14` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process_name) as proc values(Processes.process_path) as path values(Processes.process) as cmdline from datamodel=Endpoint.Processes where Processes.process_hash IN ("096372d19b4787e989f44e04c5ecc29885aa927c34ae8666628d6c0eb20bb447","1c56228cbd1bdebb9e5ea55c2749150fee06c865ede4a3754e8bd6843e51d2d4","080ab9bc2893ba7bad354551604a667af40ed2ae2d042d2323c2bd9ad3122192","5ed14c2b7f7433a1a72dd6b668413f935a217ba10b69d89b774a82990fa12fe1","61f7d9cd2d8ce7df950639b23ce90085b300b0c6dd0d8d934bba8fdecb670f15","24aa4e780ccd66cef13da9ef98c32954105cf2a32ec643efab0ba1aa2d6352f4","02542a49b3bd6bd2795afb67840acb4557b17e017f7503dd03ebe3aeeb28720e","8ae7c82a3e4f742777e590b25a1c563d19bd9bcba2a387d004aae72c4b2828f9") by Processes.dest Processes.user Processes.process_hash | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
let DragonWeaveHashes = dynamic([
  "096372d19b4787e989f44e04c5ecc29885aa927c34ae8666628d6c0eb20bb447",
  "1c56228cbd1bdebb9e5ea55c2749150fee06c865ede4a3754e8bd6843e51d2d4",
  "080ab9bc2893ba7bad354551604a667af40ed2ae2d042d2323c2bd9ad3122192",
  "5ed14c2b7f7433a1a72dd6b668413f935a217ba10b69d89b774a82990fa12fe1",
  "61f7d9cd2d8ce7df950639b23ce90085b300b0c6dd0d8d934bba8fdecb670f15",
  "24aa4e780ccd66cef13da9ef98c32954105cf2a32ec643efab0ba1aa2d6352f4",
  "02542a49b3bd6bd2795afb67840acb4557b17e017f7503dd03ebe3aeeb28720e",
  "8ae7c82a3e4f742777e590b25a1c563d19bd9bcba2a387d004aae72c4b2828f9"
]);
union
  (DeviceProcessEvents
   | where Timestamp > ago(90d)
   | where SHA256 in (DragonWeaveHashes) or InitiatingProcessSHA256 in (DragonWeaveHashes)
   | project Timestamp, DeviceName, AccountName, Source = "DeviceProcessEvents", FileName, FolderPath, SHA256, ProcessCommandLine),
  (DeviceFileEvents
   | where Timestamp > ago(90d)
   | where SHA256 in (DragonWeaveHashes)
   | project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName, Source = "DeviceFileEvents", FileName, FolderPath, SHA256, ProcessCommandLine = InitiatingProcessCommandLine),
  (DeviceImageLoadEvents
   | where Timestamp > ago(90d)
   | where SHA256 in (DragonWeaveHashes)
   | project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName, Source = "DeviceImageLoadEvents", FileName, FolderPath, SHA256, ProcessCommandLine = InitiatingProcessCommandLine)
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

### Article-specific behavioural hunt — China-Aligned Groups Ramp Up Attacks: Dragon Weave Hits Czech Republic & Taiwan

`UC_114_9` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — China-Aligned Groups Ramp Up Attacks: Dragon Weave Hits Czech Republic & Taiwan ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("runtimebroker_update.exe","unityplayer.dll"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("runtimebroker_update.exe","unityplayer.dll"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — China-Aligned Groups Ramp Up Attacks: Dragon Weave Hits Czech Republic & Taiwan
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("runtimebroker_update.exe", "unityplayer.dll"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("runtimebroker_update.exe", "unityplayer.dll"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `096372d19b4787e989f44e04c5ecc29885aa927c34ae8666628d6c0eb20bb447`, `1c56228cbd1bdebb9e5ea55c2749150fee06c865ede4a3754e8bd6843e51d2d4`, `080ab9bc2893ba7bad354551604a667af40ed2ae2d042d2323c2bd9ad3122192`, `5ed14c2b7f7433a1a72dd6b668413f935a217ba10b69d89b774a82990fa12fe1`, `61f7d9cd2d8ce7df950639b23ce90085b300b0c6dd0d8d934bba8fdecb670f15`, `24aa4e780ccd66cef13da9ef98c32954105cf2a32ec643efab0ba1aa2d6352f4`, `02542a49b3bd6bd2795afb67840acb4557b17e017f7503dd03ebe3aeeb28720e`, `8ae7c82a3e4f742777e590b25a1c563d19bd9bcba2a387d004aae72c4b2828f9` _(+4 more)_


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 15 use case(s) fired, 23 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

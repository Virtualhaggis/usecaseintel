# [CRIT] Armored Likho Targets Government Agencies, Power Sector with BusySnake Stealer

**Source:** The Hacker News
**Published:** 2026-07-03
**Article:** https://thehackernews.com/2026/07/armored-likho-targets-government.html

## Threat Profile

Armored Likho Targets Government Agencies, Power Sector with BusySnake Stealer 
 Ravie Lakshmanan  Jul 03, 2026 Infostealer / Cyber Espionage 
A previously undocumented threat actor known as Armored Likho has been attributed to cyber attacks targeting government agencies and the electric power sector across Russia, Brazil, and Kazakhstan.
"Armored Likho blends financially motivated campaigns targeting private individuals with targeted cyber espionage aimed at organizations," Kaspersky said in …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-9491`
- **IPv4 (defanged):** `159.198.41.140`
- **IPv4 (defanged):** `159.198.75.219`
- **IPv4 (defanged):** `159.198.32.222`
- **IPv4 (defanged):** `69.67.173.153`
- **Domain (defanged):** `winupdate.live`
- **Domain (defanged):** `arvax.xyz`
- **Domain (defanged):** `varenie.live`
- **Domain (defanged):** `lvl99.store`
- **Domain (defanged):** `onetoken.ink`
- **Domain (defanged):** `winupdate.ink`
- **Domain (defanged):** `grked.online`
- **Domain (defanged):** `ndrt.ink`
- **Domain (defanged):** `myboard.chickenkiller.com`
- **Domain (defanged):** `myboard.twilightparadox.com`
- **MD5:** `5D5C3E483C5E544260CE98FC29FBF192`
- **MD5:** `7141917CBA2EEE2B4D31107FACCF3A39`
- **MD5:** `F5C6434EE5F7578FAA3BC1257E1C9226`
- **MD5:** `C019797A00FD56EDB1F468AC0A598510`
- **MD5:** `A0EC7A8E61EFF3F445A7455B3AEF9FBB`
- **MD5:** `7DB9C688C620E54E8C69B7E52A7579FB`
- **MD5:** `90378881856ABFA47D7745C0A3EF9DC8`
- **MD5:** `1DBA3E505491A260A44C867902C3296E`
- **MD5:** `1096268FA2B3D454C86CF851CB782319`
- **MD5:** `F2AB09D7E7A375A192508A5014AA2EE4`
- **MD5:** `0041FD1B2358CD08DBCBC28EA8FC3D20`
- **MD5:** `894332174F536C2E1EFEDA05CBA79F8B`
- **MD5:** `78135F72AB148A0CC074F6B2DD51FFF6`
- **MD5:** `07213C419489C02791E8D67B91E404EF`
- **MD5:** `393B498F2114CABC0B29D5FCD9DC6723`
- **MD5:** `CF74AC018D158EA2C2CFA1B1D71D95BC`
- **MD5:** `2DFA1D949872C1B2F04952DD3E5F5D8F`
- **MD5:** `C7622A1EFFA27BBFEE6D6E03D6474343`
- **MD5:** `80B7700053E115D65365CE7330383320`
- **MD5:** `6B45DDB39A6E86229348DCBBA3857E7C`
- **MD5:** `006887732CA4A4A46A97989CF4DEEEF6`
- **MD5:** `732C31ACF971A81C7E51B2A3DAE82020`
- **MD5:** `DDFF82A115558584BBD7741D4FFB35B4`
- **MD5:** `8188B2F347B77D65D08CFB23808AC244`
- **MD5:** `E2550CFAD9DCC880BF04F6048F90868C`
- **MD5:** `FD2BDD8047ADDEE6FDE2F532DE181BFD`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
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
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1219** — Remote Access Software
- **T1059.005** — Command and Scripting Interpreter: Visual Basic
- **T1070.004** — Indicator Removal: File Deletion
- **T1203** — Exploitation for Client Execution
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1053.005** — Scheduled Task/Job: Scheduled Task
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1105** — Ingress Tool Transfer
- **T1572** — Protocol Tunneling
- **T1555.003** — Credentials from Password Stores: Web Browsers
- **T1074.001** — Data Staged: Local Data Staging

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Armored Likho dropper writes twin VBScript files (trace-eraser + scheduled-task launcher) from archive extract dir

`UC_41_16` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count dc(Filesystem.file_path) as vbs_paths values(Filesystem.file_name) as vbs_files min(_time) as firstTime from datamodel=Endpoint.Filesystem where Filesystem.action=created Filesystem.file_name="*.vbs" (Filesystem.file_path="*\\AppData\\Local\\Temp\\*" OR Filesystem.file_path="*\\AppData\\Roaming\\*" OR Filesystem.file_path="*\\Downloads\\*" OR Filesystem.file_path="*\\Public\\*") Filesystem.process_name="*.exe" by Filesystem.dest Filesystem.process_name Filesystem.user | `drop_dm_object_name(Filesystem)` | where vbs_paths>=2 | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType == "FileCreated"
| where FileName endswith ".vbs"
| where FolderPath has_any (@"\AppData\Local\Temp\", @"\AppData\Roaming\", @"\Downloads\", @"\Public\")
| where InitiatingProcessFileName endswith ".exe"
| where InitiatingProcessFolderPath has_any (@"\Temp\", @"\Downloads\", @"\AppData\")
| where InitiatingProcessAccountName !endswith "$"
| summarize VbsCount = dcount(FolderPath), Files = make_set(FileName, 10), FirstSeen = min(Timestamp)
    by DeviceName, InitiatingProcessFileName, InitiatingProcessSHA256, InitiatingProcessAccountName
| where VbsCount >= 2   // dropper drops BOTH the trace-eraser AND the scheduled-task launcher .vbs
| order by FirstSeen desc
```

### CVE-2025-9491 LNK exploitation: Explorer spawns obfuscated PowerShell loader + decoy document

`UC_41_17` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime values(Processes.process) as cmd from datamodel=Endpoint.Processes where Processes.parent_process_name=explorer.exe (Processes.process_name=powershell.exe OR Processes.process_name=pwsh.exe) (Processes.process="*hidden*" OR Processes.process="*-enc*" OR Processes.process="*FromBase64String*" OR Processes.process="*DownloadString*" OR Processes.process="*DownloadFile*" OR Processes.process="*IEX*" OR Processes.process="*Invoke-Expression*") by Processes.dest Processes.user Processes.process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName =~ "explorer.exe"
| where FileName in~ ("powershell.exe","pwsh.exe")
| where AccountName !endswith "$"
| extend Cmd = tolower(ProcessCommandLine)
| where Cmd has_any ("hidden","-enc","-e ","frombase64string","downloadstring","downloadfile","iex","invoke-expression")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### BusySnake persistence: VBScript (wscript/cscript) registers scheduled task launching pythonw/.pyw stealer

`UC_41_18` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime values(Processes.process) as cmd from datamodel=Endpoint.Processes where Processes.process_name=schtasks.exe Processes.process="*/create*" (Processes.parent_process_name=wscript.exe OR Processes.parent_process_name=cscript.exe OR Processes.process="*pythonw*" OR Processes.process="*.pyw*") by Processes.dest Processes.user Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("wscript.exe","cscript.exe")
    or ProcessCommandLine has_any ("pythonw",".pyw")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### BusySnake C2 beacon to Armored Likho infrastructure (named domains + IPs)

`UC_41_19` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime values(All_Traffic.dest) as dest values(All_Traffic.app) as app from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest IN ("159.198.41.140","159.198.75.219","159.198.32.222","69.67.173.153") OR All_Traffic.dest_host IN ("winupdate.live","arvax.xyz","varenie.live","lvl99.store","onetoken.ink","winupdate.ink","grked.online","ndrt.ink","myboard.chickenkiller.com","myboard.twilightparadox.com")) by All_Traffic.src All_Traffic.dest_host All_Traffic.dest | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl in~ ("winupdate.live","arvax.xyz","varenie.live","lvl99.store","onetoken.ink","winupdate.ink","grked.online","ndrt.ink","myboard.chickenkiller.com","myboard.twilightparadox.com")
    or RemoteIP in ("159.198.41.140","159.198.75.219","159.198.32.222","69.67.173.153")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### BusySnake deploys remote-access tooling: Python stealer spawns RustDesk / Go2Tunnel reverse SSH tunnel

`UC_41_20` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime values(Processes.process) as cmd from datamodel=Endpoint.Processes where (Processes.parent_process_name=pythonw.exe OR Processes.parent_process_name=python.exe) (Processes.process_name=rustdesk.exe OR Processes.process="*go2tunnel*" OR (Processes.process_name=ssh.exe AND Processes.process="*-R *")) by Processes.dest Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("pythonw.exe","python.exe")
| where AccountName !endswith "$"
| where (FileName =~ "rustdesk.exe")
    or (FileName =~ "ssh.exe" and ProcessCommandLine has "-R ")
    or (tolower(FileName) has "go2tunnel" or tolower(ProcessCommandLine) has "go2tunnel")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### BusySnake credential collection: pythonw stages browser cred stores, Telegram session, and crypto-wallet JSON

`UC_41_21` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime values(Filesystem.file_path) as paths from datamodel=Endpoint.Filesystem where (Filesystem.process_name=pythonw.exe OR Filesystem.process_name=python.exe) (Filesystem.file_name="Login Data" OR Filesystem.file_name="Cookies" OR Filesystem.file_name="cookies.sqlite" OR Filesystem.file_name="key4.db" OR Filesystem.file_name="logins.json" OR Filesystem.file_path="*\\Telegram Desktop\\tdata\\*") by Filesystem.dest Filesystem.user Filesystem.process_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("pythonw.exe","python.exe")
| where InitiatingProcessAccountName !endswith "$"
| where FileName in~ ("Login Data","Cookies","cookies.sqlite","key4.db","logins.json")
    or FolderPath has @"\Telegram Desktop\tdata\"
    or (FolderPath has_any (@"\Wallets\", @"\wallet\", @"\Ethereum\", @"\Bitcoin\") and FileName endswith ".json")
| summarize ArtifactTypes = dcount(FileName), Artifacts = make_set(FileName, 20), FirstSeen = min(Timestamp)
    by DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName
| order by FirstSeen desc
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

### Suspicious browser extension installation

`UC_BROWSER_EXT` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Registry
    where (Registry.registry_path="*\Software\Google\Chrome\Extensions\*"
        OR Registry.registry_path="*\Software\Microsoft\Edge\Extensions\*"
        OR Registry.registry_path="*\Software\Mozilla\Firefox\Extensions\*")
    by Registry.dest, Registry.registry_path, Registry.registry_value_data, Registry.registry_value_name, Registry.user
| `drop_dm_object_name(Registry)`
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where RegistryKey has_any ("\Software\Google\Chrome\Extensions\","\Software\Microsoft\Edge\Extensions\","\Software\Mozilla\Firefox\Extensions\")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessAccountName
```

### Infostealer — non-browser process accessing browser cookie/login DBs

`UC_BROWSER_STEALER` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\Google\Chrome\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Google\Chrome\User Data\*\Cookies*"
        OR Filesystem.file_path="*\Microsoft\Edge\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\logins.json*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\cookies.sqlite*")
      AND NOT Filesystem.process_name IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where FolderPath has_any (@"\Google\Chrome\User Data\", @"\Microsoft\Edge\User Data\", @"\Mozilla\Firefox\Profiles\")
| where FileName in~ ("Login Data","Cookies","logins.json","cookies.sqlite")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
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

### RMM tool installed by non-IT user — remote-access utility for hands-on-keyboard

`UC_RMM_TOOLS` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe","kaseya*.exe")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe")
   or FileName matches regex @"(?i)kaseya.*\.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `159.198.41.140`, `159.198.75.219`, `159.198.32.222`, `69.67.173.153`, `winupdate.live`, `arvax.xyz`, `varenie.live`, `lvl99.store` _(+6 more)_

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2025-9491`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `5D5C3E483C5E544260CE98FC29FBF192`, `7141917CBA2EEE2B4D31107FACCF3A39`, `F5C6434EE5F7578FAA3BC1257E1C9226`, `C019797A00FD56EDB1F468AC0A598510`, `A0EC7A8E61EFF3F445A7455B3AEF9FBB`, `7DB9C688C620E54E8C69B7E52A7579FB`, `90378881856ABFA47D7745C0A3EF9DC8`, `1DBA3E505491A260A44C867902C3296E` _(+18 more)_


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 22 use case(s) fired, 34 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

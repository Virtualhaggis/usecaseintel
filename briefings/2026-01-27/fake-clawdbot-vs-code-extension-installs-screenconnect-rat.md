# [HIGH] Fake Clawdbot VS Code Extension Installs ScreenConnect RAT

**Source:** Aikido
**Published:** 2026-01-27
**Article:** https://www.aikido.dev/blog/fake-clawdbot-vscode-extension-malware

## Threat Profile

Blog Vulnerabilities & Threats Fake Clawdbot VS Code Extension Installs ScreenConnect RAT Fake Clawdbot VS Code Extension Installs ScreenConnect RAT Written by Charlie Eriksen Published on: Jan 27, 2026 On January 27, 2026, our malware detection system flagged a new VS Code extension called " ClawdBot Agent " that immediately set off alarm bells. We confirmed the extension is a fully functional trojan: a working AI coding assistant on the surface, while silently dropping malware onto Windows mac…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `178.16.54.253`
- **IPv4 (defanged):** `179.43.176.32`
- **Domain (defanged):** `clawdbot.getintwopc.site`
- **Domain (defanged):** `darkgptprivate.com`
- **Domain (defanged):** `meeting.bulletmailer.net`
- **SHA256:** `e20b920c7af988aa215c95bbaa365d005dd673544ab7e3577b60fecf11dcdea2`
- **SHA256:** `d1e0c26774cb8beabaf64f119652719f673fb530368d5b2166178191ad5fcbea`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1005** — Data from Local System
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1053.005** — Scheduled Task
- **T1027** — Obfuscated Files or Information
- **T1219** — Remote Access Software
- **T1195.002** — Compromise Software Supply Chain
- **T1053.005** — Persistence (article-specific)
- **T1543.003** — Persistence (article-specific)
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1572** — Protocol Tunneling
- **T1543.003** — Create or Modify System Process: Windows Service
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1574.002** — Hijack Execution Flow: DLL Side-Loading
- **T1105** — Ingress Tool Transfer
- **T1027.002** — Software Packing
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1564.003** — Hide Artifacts: Hidden Window

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] ScreenConnect client beaconing to ClawdBot attacker relay (meeting.bulletmailer.net:8041)

`UC_567_14` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest IN ("178.16.54.253","179.43.176.32") OR All_Traffic.dest_host IN ("meeting.bulletmailer.net","clawdbot.getintwopc.site","darkgptprivate.com") OR (All_Traffic.dest_port=8041 AND All_Traffic.app IN ("ScreenConnect.ClientService.exe","ScreenConnect.WindowsBackstageShell.exe","ScreenConnect.WindowsFileManager.exe"))) by All_Traffic.src All_Traffic.user All_Traffic.app All_Traffic.dest All_Traffic.dest_host All_Traffic.dest_port
| `drop_dm_object_name(All_Traffic)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
let C2Hosts = dynamic(["meeting.bulletmailer.net","clawdbot.getintwopc.site","darkgptprivate.com"]);
let C2IPs = dynamic(["178.16.54.253","179.43.176.32"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (C2IPs)
   or (isnotempty(RemoteUrl) and RemoteUrl has_any (C2Hosts))
   or (RemotePort == 8041 and InitiatingProcessFileName startswith "ScreenConnect.")
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort
| order by Timestamp desc
```

### [LLM] Weaponised ScreenConnect install path with attacker instance GUID 083e4d30c7ea44f7

`UC_567_15` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_name) as files values(Filesystem.process_name) as procs from datamodel=Endpoint.Filesystem where Filesystem.file_path="*ScreenConnect Client (083e4d30c7ea44f7)*" by Filesystem.dest Filesystem.user Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
| append [| tstats summariesonly=true count from datamodel=Endpoint.Processes where Processes.process_path="*ScreenConnect Client (083e4d30c7ea44f7)*" by Processes.dest Processes.user Processes.process_name Processes.process_path Processes.process]
| convert ctime(firstTime) ctime(lastTime)
| sort - firstTime
```

**Defender KQL:**
```kql
let GUID = "083e4d30c7ea44f7";
union isfuzzy=true
  (DeviceFileEvents
     | where Timestamp > ago(30d)
     | where FolderPath has GUID
     | project Timestamp, DeviceName, Source="FileEvent", ActionType, FileName, FolderPath, SHA256,
               InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName=InitiatingProcessAccountName),
  (DeviceProcessEvents
     | where Timestamp > ago(30d)
     | where FolderPath has GUID or InitiatingProcessFolderPath has GUID
     | project Timestamp, DeviceName, Source="ProcessEvent", ActionType, FileName, FolderPath, SHA256,
               InitiatingProcessFileName, InitiatingProcessCommandLine=ProcessCommandLine, AccountName)
| order by Timestamp desc
```

### [LLM] DWrite.dll Rust sideloader dropped outside Windows directory (ClawdBot redundant payload)

`UC_567_16` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as procs values(Filesystem.file_path) as paths from datamodel=Endpoint.Filesystem where Filesystem.file_name="DWrite.dll" AND NOT Filesystem.file_path IN ("*\\Windows\\System32\\*","*\\Windows\\SysWOW64\\*","*\\Windows\\WinSxS\\*") AND (Filesystem.file_hash="d1e0c26774cb8beabaf64f119652719f673fb530368d5b2166178191ad5fcbea" OR Filesystem.file_path="*ScreenConnect Client (083e4d30c7ea44f7)*" OR Filesystem.file_path="*\\AppData\\Local\\Temp\\Lightshot\\*") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_hash
| `drop_dm_object_name(Filesystem)`
| convert ctime(firstTime) ctime(lastTime)
| sort - firstTime
```

**Defender KQL:**
```kql
let BadHash = "d1e0c26774cb8beabaf64f119652719f673fb530368d5b2166178191ad5fcbea";
union isfuzzy=true
  (DeviceImageLoadEvents
     | where Timestamp > ago(30d)
     | where FileName =~ "DWrite.dll"
     | where not(FolderPath startswith @"C:\Windows\")
     | where SHA256 == BadHash
        or InitiatingProcessFileName startswith "ScreenConnect."
        or FolderPath has "083e4d30c7ea44f7"
        or FolderPath has @"\AppData\Local\Temp\Lightshot\"
     | project Timestamp, DeviceName, Source="ImageLoad", FileName, FolderPath, SHA256,
               InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine),
  (DeviceFileEvents
     | where Timestamp > ago(30d)
     | where FileName =~ "DWrite.dll"
     | where SHA256 == BadHash
        or FolderPath has "083e4d30c7ea44f7"
        or FolderPath has @"\AppData\Local\Temp\Lightshot\"
     | project Timestamp, DeviceName, Source="FileWrite", FileName, FolderPath, SHA256,
               InitiatingProcessFileName, InitiatingProcessFolderPath=InitiatingProcessFolderPath, InitiatingProcessCommandLine)
| order by Timestamp desc
```

### [LLM] VS Code (Code.exe/node) drops payload to %TEMP%\Lightshot staging directory

`UC_567_17` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_name) as files values(Filesystem.file_hash) as hashes from datamodel=Endpoint.Filesystem where Filesystem.file_path="*\\AppData\\Local\\Temp\\Lightshot\\*" AND (Filesystem.process_name IN ("Code.exe","node.exe") OR Filesystem.file_hash IN ("e20b920c7af988aa215c95bbaa365d005dd673544ab7e3577b60fecf11dcdea2","d1e0c26774cb8beabaf64f119652719f673fb530368d5b2166178191ad5fcbea") OR Filesystem.file_name IN ("Code.exe","DWrite.dll","zoomupdate.msi")) by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path Filesystem.file_name Filesystem.file_hash
| `drop_dm_object_name(Filesystem)`
| convert ctime(firstTime) ctime(lastTime)
| sort - firstTime
```

**Defender KQL:**
```kql
let BadHashes = dynamic(["e20b920c7af988aa215c95bbaa365d005dd673544ab7e3577b60fecf11dcdea2","d1e0c26774cb8beabaf64f119652719f673fb530368d5b2166178191ad5fcbea"]);
let StagingDrops = DeviceFileEvents
    | where Timestamp > ago(30d)
    | where FolderPath has @"\AppData\Local\Temp\Lightshot\"
    | where InitiatingProcessFileName in~ ("Code.exe","node.exe")
         or SHA256 in (BadHashes)
         or FileName in~ ("Code.exe","DWrite.dll","zoomupdate.msi","ffmpeg.dll","libEGL.dll","v8_context_snapshot.bin")
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName;
let DetachedExec = DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FolderPath has @"\AppData\Local\Temp\Lightshot\"
         or InitiatingProcessFolderPath has @"\AppData\Local\Temp\Lightshot\"
    | project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine;
union StagingDrops, DetachedExec
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

### Crypto-wallet file/keystore access by non-wallet process

`UC_CRYPTO_WALLET` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\Ethereum\keystore\*"
        OR Filesystem.file_path="*\Bitcoin\wallet.dat"
        OR Filesystem.file_path="*\Exodus\exodus.wallet*"
        OR Filesystem.file_path="*\Electrum\wallets\*"
        OR Filesystem.file_path="*\MetaMask\*"
        OR Filesystem.file_path="*\Phantom\*"
        OR Filesystem.file_path="*\Atomic\Local Storage\*")
      AND NOT Filesystem.process_name IN ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where FolderPath has_any (@"\Ethereum\keystore\", @"\Bitcoin\", @"\Exodus\", @"\Electrum\wallets\", @"\MetaMask\", @"\Phantom\", @"\Atomic\Local Storage\")
| where InitiatingProcessFileName !in~ ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
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

### Article-specific behavioural hunt — Fake Clawdbot VS Code Extension Installs ScreenConnect RAT

`UC_567_13` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Fake Clawdbot VS Code Extension Installs ScreenConnect RAT ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("config.exe","config.dll","dwrite.dll","ffmpeg.dll","libegl.dll","msvcp140.dll","vcruntime140.dll","vcruntime140_1.dll","screenconnect.clientservice.exe","screenconnect.windowsbackstageshell.exe","screenconnect.windowsfilemanager.exe","zoomupdate.msi","lightshot.exe","lightshot.dll","node.js") OR Processes.process="*Net.WebClient*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("config.exe","config.dll","dwrite.dll","ffmpeg.dll","libegl.dll","msvcp140.dll","vcruntime140.dll","vcruntime140_1.dll","screenconnect.clientservice.exe","screenconnect.windowsbackstageshell.exe","screenconnect.windowsfilemanager.exe","zoomupdate.msi","lightshot.exe","lightshot.dll","node.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Fake Clawdbot VS Code Extension Installs ScreenConnect RAT
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("config.exe", "config.dll", "dwrite.dll", "ffmpeg.dll", "libegl.dll", "msvcp140.dll", "vcruntime140.dll", "vcruntime140_1.dll", "screenconnect.clientservice.exe", "screenconnect.windowsbackstageshell.exe", "screenconnect.windowsfilemanager.exe", "zoomupdate.msi", "lightshot.exe", "lightshot.dll", "node.js") or ProcessCommandLine has_any ("Net.WebClient"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("config.exe", "config.dll", "dwrite.dll", "ffmpeg.dll", "libegl.dll", "msvcp140.dll", "vcruntime140.dll", "vcruntime140_1.dll", "screenconnect.clientservice.exe", "screenconnect.windowsbackstageshell.exe", "screenconnect.windowsfilemanager.exe", "zoomupdate.msi", "lightshot.exe", "lightshot.dll", "node.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `178.16.54.253`, `179.43.176.32`, `clawdbot.getintwopc.site`, `darkgptprivate.com`, `meeting.bulletmailer.net`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `e20b920c7af988aa215c95bbaa365d005dd673544ab7e3577b60fecf11dcdea2`, `d1e0c26774cb8beabaf64f119652719f673fb530368d5b2166178191ad5fcbea`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 18 use case(s) fired, 29 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

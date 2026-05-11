# [CRIT] Hackers Use Weaponized JPEG File to Deploy Trojanized ScreenConnect Malware

**Source:** Cyber Security News
**Published:** 2026-05-11
**Article:** https://cybersecuritynews.com/hackers-use-weaponized-jpeg-file/

## Threat Profile

Home Cyber Security News 
Hackers Use Weaponized JPEG File to Deploy Trojanized ScreenConnect Malware 
By Tushar Subhra Dutta 
May 11, 2026 
A sophisticated new cyberattack campaign is targeting Windows systems using a fake image file to sneak dangerous malware past security defenses. The operation, named Operation SilentCanvas, tricks victims into running a malicious PowerShell script disguised as a harmless JPEG photo, ultimately handing attackers full and silent control of the infected machin…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `45.138.16.64`
- **Domain (defanged):** `legitserver.theworkpc.com`
- **SHA256:** `7adffc1c0b3fdcba46e8d0a81203c955976d4ef39893c98d0b2dbfbb8d6a8ec3`
- **SHA256:** `ecd5ed16975d556d1d17bc980f248f8a5262bed11df9d9cf999efd9c273c11df`
- **SHA256:** `ee3d776cdaf82335e4293e19ee313cc35eee49cde9963b96766a8f9c89d44a79`
- **SHA256:** `4d8ac85c5b98c69ba44146df61183e9bf613edd796aa516c3ae73611b7d77c06`
- **SHA256:** `A635F0C94C98B658AE799978994F0D0A292567CD97B8A19068A8423D1297652A`
- **MD5:** `7DD05336097E5A833F03A63D3221494F`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1005** — Data from Local System
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1219** — Remote Access Software
- **T1543.003** — Persistence (article-specific)
- **T1548.002** — Abuse Elevation Control Mechanism: Bypass User Account Control
- **T1112** — Modify Registry
- **T1027.004** — Obfuscated Files or Information: Compile After Delivery
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1074.001** — Data Staged: Local Data Staging
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1543.003** — Create or Modify System Process: Windows Service

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] ms-settings Shell hijack via uds.exe → ComputerDefaults.exe UAC bypass (Operation SilentCanvas)

`UC_15_12` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where Registry.registry_path IN ("*\\Software\\Classes\\ms-settings\\Shell\\Open\\command*","*\\software\\classes\\ms-settings\\shell\\open\\command*") AND (Registry.registry_value_data IN ("*uds.exe*","*C:\\Systems\\*","*\\Systems\\uds*") OR Registry.registry_value_name="DelegateExecute") by Registry.dest Registry.user Registry.registry_path Registry.registry_value_name Registry.registry_value_data Registry.process_name | `drop_dm_object_name(Registry)` | join type=inner dest [| tstats `summariesonly` count from datamodel=Endpoint.Processes where Processes.process_name="ComputerDefaults.exe" by Processes.dest Processes.process_name Processes.parent_process_name Processes.process_integrity_level | `drop_dm_object_name(Processes)`] | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let WindowMin = 5m;
let Hijack = DeviceRegistryEvents
    | where Timestamp > ago(7d)
    | where ActionType in ("RegistryValueSet","RegistryKeyCreated")
    | where RegistryKey has @"\Software\Classes\ms-settings\Shell\Open\command"
    | where (RegistryValueData has_any ("uds.exe", @"C:\Systems\", @"\Systems\uds"))
         or (RegistryValueName =~ "DelegateExecute" and isempty(RegistryValueData))
    | project HijackTime = Timestamp, DeviceId, DeviceName, RegistryKey, RegistryValueName, RegistryValueData,
              InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName;
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "ComputerDefaults.exe"
| where ProcessIntegrityLevel in~ ("High","System")
| join kind=inner Hijack on DeviceId
| where Timestamp between (HijackTime .. HijackTime + WindowMin)
| project HijackTime, ElevTime = Timestamp, DeviceName, InitiatingProcessAccountName,
          RegistryKey, RegistryValueData,
          ElevParent = InitiatingProcessFileName, ElevCmd = ProcessCommandLine, ProcessIntegrityLevel
| order by HijackTime desc
```

### [LLM] PowerShell-driven csc.exe compiling uds.exe to C:\Systems staging directory (Operation SilentCanvas)

`UC_15_13` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action="created" AND Filesystem.file_name="uds.exe" AND (Filesystem.file_path="C:\\Systems\\*" OR Filesystem.file_path="*\\Systems\\uds.exe") by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.file_hash Filesystem.process_name | `drop_dm_object_name(Filesystem)` | eval ioc_hash_match=if(file_hash IN ("7DD05336097E5A833F03A63D3221494F","A635F0C94C98B658AE799978994F0D0A292567CD97B8A19068A8423D1297652A"),1,0) | append [| tstats `summariesonly` count from datamodel=Endpoint.Processes where Processes.parent_process_name="powershell.exe" AND Processes.process_name="csc.exe" AND (Processes.process="*C:\\Systems*" OR Processes.process="*uds*" OR Processes.process="*\\AppData\\Local\\Temp\\*.cs*") by Processes.dest Processes.user Processes.parent_process Processes.process Processes.process_name | `drop_dm_object_name(Processes)`] | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let CscChain = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessFileName in~ ("powershell.exe","pwsh.exe")
    | where FileName =~ "csc.exe"
    | where ProcessCommandLine has_any (@"C:\Systems", "uds", @"\AppData\Local\Temp\")
    | project Timestamp, DeviceId, DeviceName, AccountName,
              CscCmd = ProcessCommandLine, PsCmd = InitiatingProcessCommandLine;
let FileDrop = DeviceFileEvents
    | where Timestamp > ago(7d)
    | where ActionType == "FileCreated"
    | where FileName =~ "uds.exe"
         or (InitiatingProcessFileName in~ ("csc.exe","cvtres.exe")
              and FolderPath has_any (@"C:\Systems\", @"\AppData\Local\Temp\"))
    | project Timestamp, DeviceId, DeviceName, FileName, FolderPath, SHA256, MD5,
              InitiatingProcessFileName, InitiatingProcessCommandLine
    | extend KnownDropper = iff(MD5 =~ "7DD05336097E5A833F03A63D3221494F"
                              or SHA256 =~ "A635F0C94C98B658AE799978994F0D0A292567CD97B8A19068A8423D1297652A", "YES","");
union CscChain, FileDrop
| order by Timestamp desc
```

### [LLM] Trojanized ScreenConnect C2 to legitserver.theworkpc.com:5443 / 45.138.16.64 + OneDriveServer persistence (Operation SilentCanvas)

`UC_15_14` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_host) as dest_hosts from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="45.138.16.64" OR All_Traffic.dest_host="legitserver.theworkpc.com" OR All_Traffic.dest_host="*.theworkpc.com") AND All_Traffic.dest_port=5443 by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app All_Traffic.user | `drop_dm_object_name(All_Traffic)` | append [| tstats `summariesonly` count from datamodel=Endpoint.Filesystem where Filesystem.file_path IN ("C:\\ProgramData\\OneDriveServer\\*","*\\OneDriveServer\\*") AND Filesystem.action="created" by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_name | `drop_dm_object_name(Filesystem)`] | append [| tstats `summariesonly` count from datamodel=Endpoint.Registry where Registry.registry_path="*\\Services\\OneDriveServers*" by Registry.dest Registry.registry_path Registry.registry_value_name Registry.registry_value_data Registry.process_name | `drop_dm_object_name(Registry)`] | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let C2_Net = DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where (RemoteIP == "45.138.16.64"
          or RemoteUrl has "theworkpc.com"
          or RemoteUrl =~ "legitserver.theworkpc.com")
    | where RemotePort == 5443 or RemoteIP == "45.138.16.64"
    | project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName,
              InitiatingProcessFileName, InitiatingProcessFolderPath,
              InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort;
let C2_File = DeviceFileEvents
    | where Timestamp > ago(7d)
    | where FolderPath has_any (@"C:\ProgramData\OneDriveServer\", @"\OneDriveServer\")
    | project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName,
              FileName, FolderPath, SHA256, InitiatingProcessFileName,
              InitiatingProcessCommandLine;
let C2_Svc = DeviceRegistryEvents
    | where Timestamp > ago(7d)
    | where RegistryKey has @"\Services\OneDriveServers"
    | project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName,
              RegistryKey, RegistryValueName, RegistryValueData,
              InitiatingProcessFileName, InitiatingProcessCommandLine;
union C2_Net, C2_File, C2_Svc
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

### Article-specific behavioural hunt — Hackers Use Weaponized JPEG File to Deploy Trojanized ScreenConnect Malware

`UC_15_11` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Hackers Use Weaponized JPEG File to Deploy Trojanized ScreenConnect Malware ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("csc.exe","uds.exe","computerdefaults.exe","cvtres.exe","node.js") OR Processes.process_path="*C:\ProgramData\OneDriveServer\*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*C:\ProgramData\OneDriveServer\*" OR Filesystem.file_name IN ("csc.exe","uds.exe","computerdefaults.exe","cvtres.exe","node.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Hackers Use Weaponized JPEG File to Deploy Trojanized ScreenConnect Malware
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("csc.exe", "uds.exe", "computerdefaults.exe", "cvtres.exe", "node.js") or FolderPath has_any ("C:\ProgramData\OneDriveServer\"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("C:\ProgramData\OneDriveServer\") or FileName in~ ("csc.exe", "uds.exe", "computerdefaults.exe", "cvtres.exe", "node.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `45.138.16.64`, `legitserver.theworkpc.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `7adffc1c0b3fdcba46e8d0a81203c955976d4ef39893c98d0b2dbfbb8d6a8ec3`, `ecd5ed16975d556d1d17bc980f248f8a5262bed11df9d9cf999efd9c273c11df`, `ee3d776cdaf82335e4293e19ee313cc35eee49cde9963b96766a8f9c89d44a79`, `4d8ac85c5b98c69ba44146df61183e9bf613edd796aa516c3ae73611b7d77c06`, `A635F0C94C98B658AE799978994F0D0A292567CD97B8A19068A8423D1297652A`, `7DD05336097E5A833F03A63D3221494F`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 15 use case(s) fired, 24 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

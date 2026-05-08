# [CRIT] Hackers Deploy Modular RAT With Credential Theft and Screenshot Capture Capabilities

**Source:** Cyber Security News
**Published:** 2026-05-08
**Article:** https://cybersecuritynews.com/hackers-deploy-modular-rat-with-credential-theft/

## Threat Profile

Home Cyber Security News 
Hackers Deploy Modular RAT With Credential Theft and Screenshot Capture Capabilities 
By Tushar Subhra Dutta 
May 8, 2026 




A newly identified malware campaign is targeting senior executives and government investigators across Southeast Asia, using a modular Remote Access Trojan capable of stealing credentials, capturing screenshots, and maintaining deep persistence on infected systems. 
The operation, dubbed Operation GriefLure, is running two simultaneous campa…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `38.54.122.188`
- **Domain (defanged):** `whatsappcenter.com`
- **SHA256:** `35af2cf5494181920b8624c7b719d39590e2a5ff5eaa1a2fa1ba86b2b5aa9b43`
- **SHA256:** `bc090d75f51c293d916c40d4b21094faaec191a42d97448c92d264875bf1f17b`
- **SHA256:** `197f11a7b0003aa7da58a3302cfa2a96a670de91d39ddebc7a51ac1d9404a7e6`
- **SHA256:** `f34f550147c2792c1ff2a003d15be89e5573f0896c5aa6126068baa4621ef416`
- **SHA256:** `bc83817c6d2bf8df1d58eac946a12b5e2566b2ffe15cf96f37c711c4b755512b`
- **SHA256:** `61e9d76f07334843df561fe4bac449fb6fdaed5e5eb91480bded225f3d265c5f`
- **SHA256:** `ee6330870087f66a237a7f7c115b65beb042299f12eae1e9004e016686d0c387`
- **SHA256:** `91a15554ec9e49c00c5ca301f276bd79d346968651d54204743a08a3ca8a5067`
- **SHA256:** `a49155df50963d2412534090bbd967749268bd013881ddb81d78b87f91cdc15b`
- **SHA256:** `7f80add94ee8107a79c87a9b4ccbd33e39eccd1596748a5b88629dd6ac11b86d`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
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
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1219** — Remote Access Software
- **T1027** — Obfuscated Files or Information
- **T1105** — Ingress Tool Transfer
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1027.013** — Obfuscated Files or Information: Encrypted/Encoded File
- **T1140** — Deobfuscate/Decode Files or Information
- **T1564.001** — Hide Artifacts: Hidden Files and Directories
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1583.001** — Acquire Infrastructure: Domains
- **T1584.004** — Compromise Infrastructure: Server

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Operation GriefLure: LNK-spawned ftp.exe with script-flag download

`UC_1_11` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process) as parent_cmd values(Processes.parent_process_name) as parent_name from datamodel=Endpoint.Processes where Processes.process_name="ftp.exe" (Processes.process="*-s:*" OR Processes.process="*/s:*" OR Processes.parent_process="*.lnk*") (Processes.parent_process_name="explorer.exe" OR Processes.parent_process_name="cmd.exe" OR Processes.parent_process_name="conhost.exe") by host Processes.user Processes.process Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "ftp.exe"
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("explorer.exe","cmd.exe","conhost.exe","wscript.exe","cscript.exe")
| where ProcessCommandLine has_any ("-s:","/s:") 
   or InitiatingProcessCommandLine has ".lnk"
   or InitiatingProcessCommandLine has @"\Users\Public\"
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd   = InitiatingProcessCommandLine,
          ChildImage  = FolderPath,
          ChildCmd    = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### [LLM] Operation GriefLure: chunked .doc payload assembly via cmd copy /b in C:\Users\Public

`UC_1_12` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where Processes.process_name="cmd.exe" Processes.process="*copy*/b*" (Processes.process="*\\Users\\Public\\*" OR Processes.process="*.doc+*" OR Processes.process="*.doc *.doc*") by host Processes.user Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | rex field=cmd "(?i)(?<frag_count>(\.doc[a-z]?\s*\+\s*){2,})" | where isnotnull(frag_count) OR like(cmd,"%\\Users\\Public\\%") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// Stage A: cmd.exe issuing binary-mode multi-fragment copy in Public
let AssemblyCmds = DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName =~ "cmd.exe"
    | where AccountName !endswith "$"
    | where ProcessCommandLine matches regex @"(?i)copy\s+/b"
    | where ProcessCommandLine has @"\Users\Public\"
        or ProcessCommandLine matches regex @"(?i)\.doc[a-z]?\s*\+\s*[^\s]+\.doc"
    | project AsmTime = Timestamp, DeviceId, DeviceName, AccountName,
              AssemblyCmd = ProcessCommandLine,
              InitiatingProcessFileName;
// Stage B: companion .doc drops from same process within 5 min before assembly
let DocDrops = DeviceFileEvents
    | where Timestamp > ago(30d)
    | where ActionType == "FileCreated"
    | where FolderPath has @"\Users\Public\"
    | where FileName endswith ".doc" or FileName endswith ".docx"
    | summarize FragCount = dcount(FileName),
                Fragments = make_set(FileName, 25),
                DropStart = min(Timestamp),
                DropEnd   = max(Timestamp)
        by DeviceId, InitiatingProcessFileName
    | where FragCount >= 3;
AssemblyCmds
| join kind=inner DocDrops on DeviceId
| where AsmTime between (DropStart .. DropEnd + 5m)
| project AsmTime, DeviceName, AccountName, AssemblyCmd,
          FragCount, Fragments, DropStart, DropEnd
| order by AsmTime desc
```

### [LLM] Operation GriefLure C2 + payload-hash sweep (whatsappcenter[.]com / 38.54.122.188)

`UC_1_13` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dest values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.app) as app from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="whatsappcenter.com" OR All_Traffic.dest="*.whatsappcenter.com" OR All_Traffic.dest_ip="38.54.122.188") by host All_Traffic.src All_Traffic.user | `drop_dm_object_name(All_Traffic)` | append [ | tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_name) as file values(Filesystem.file_path) as path from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("35af2cf5494181920b8624c7b719d39590e2a5ff5eaa1a2fa1ba86b2b5aa9b43","bc090d75f51c293d916c40d4b21094faaec191a42d97448c92d264875bf1f17b","197f11a7b0003aa7da58a3302cfa2a96a670de91d39ddebc7a51ac1d9404a7e6","f34f550147c2792c1ff2a003d15be89e5573f0896c5aa6126068baa4621ef416","bc83817c6d2bf8df1d58eac946a12b5e2566b2ffe15cf96f37c711c4b755512b","61e9d76f07334843df561fe4bac449fb6fdaed5e5eb91480bded225f3d265c5f","ee6330870087f66a237a7f7c115b65beb042299f12eae1e9004e016686d0c387","91a15554ec9e49c00c5ca301f276bd79d346968651d54204743a08a3ca8a5067","a49155df50963d2412534090bbd967749268bd013881ddb81d78b87f91cdc15b","7f80add94ee8107a79c87a9b4ccbd33e39eccd1596748a5b88629dd6ac11b86d") by host Filesystem.user Filesystem.file_name Filesystem.file_path | `drop_dm_object_name(Filesystem)` ] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let GriefLureC2Domains = dynamic(["whatsappcenter.com"]);
let GriefLureC2IPs = dynamic(["38.54.122.188"]);
let GriefLureSHA256 = dynamic([
    "35af2cf5494181920b8624c7b719d39590e2a5ff5eaa1a2fa1ba86b2b5aa9b43",
    "bc090d75f51c293d916c40d4b21094faaec191a42d97448c92d264875bf1f17b",
    "197f11a7b0003aa7da58a3302cfa2a96a670de91d39ddebc7a51ac1d9404a7e6",
    "f34f550147c2792c1ff2a003d15be89e5573f0896c5aa6126068baa4621ef416",
    "bc83817c6d2bf8df1d58eac946a12b5e2566b2ffe15cf96f37c711c4b755512b",
    "61e9d76f07334843df561fe4bac449fb6fdaed5e5eb91480bded225f3d265c5f",
    "ee6330870087f66a237a7f7c115b65beb042299f12eae1e9004e016686d0c387",
    "91a15554ec9e49c00c5ca301f276bd79d346968651d54204743a08a3ca8a5067",
    "a49155df50963d2412534090bbd967749268bd013881ddb81d78b87f91cdc15b",
    "7f80add94ee8107a79c87a9b4ccbd33e39eccd1596748a5b88629dd6ac11b86d"]);
union isfuzzy=true
  ( DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where (RemoteUrl has_any (GriefLureC2Domains))
         or (RemoteIP in (GriefLureC2IPs))
    | project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName,
              Hit = strcat("NET:", coalesce(RemoteUrl, RemoteIP)),
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              RemoteIP, RemotePort ),
  ( DeviceFileEvents
    | where Timestamp > ago(30d)
    | where SHA256 in (GriefLureSHA256)
    | project Timestamp, DeviceName,
              AccountName = InitiatingProcessAccountName,
              Hit = strcat("FILE:", FileName, " sha256=", SHA256),
              InitiatingProcessFileName,
              InitiatingProcessCommandLine = InitiatingProcessCommandLine,
              RemoteIP = "", RemotePort = int(null) ),
  ( DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where SHA256 in (GriefLureSHA256) or InitiatingProcessSHA256 in (GriefLureSHA256)
    | project Timestamp, DeviceName, AccountName,
              Hit = strcat("PROC:", FileName, " sha256=", SHA256),
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              RemoteIP = "", RemotePort = int(null) )
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

### Article-specific behavioural hunt — Hackers Deploy Modular RAT With Credential Theft and Screenshot Capture Capabili

`UC_1_10` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Hackers Deploy Modular RAT With Credential Theft and Screenshot Capture Capabili ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("360.8.dll","th5znehec.exe"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("360.8.dll","th5znehec.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Hackers Deploy Modular RAT With Credential Theft and Screenshot Capture Capabili
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("360.8.dll", "th5znehec.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("360.8.dll", "th5znehec.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `38.54.122.188`, `whatsappcenter.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `35af2cf5494181920b8624c7b719d39590e2a5ff5eaa1a2fa1ba86b2b5aa9b43`, `bc090d75f51c293d916c40d4b21094faaec191a42d97448c92d264875bf1f17b`, `197f11a7b0003aa7da58a3302cfa2a96a670de91d39ddebc7a51ac1d9404a7e6`, `f34f550147c2792c1ff2a003d15be89e5573f0896c5aa6126068baa4621ef416`, `bc83817c6d2bf8df1d58eac946a12b5e2566b2ffe15cf96f37c711c4b755512b`, `61e9d76f07334843df561fe4bac449fb6fdaed5e5eb91480bded225f3d265c5f`, `ee6330870087f66a237a7f7c115b65beb042299f12eae1e9004e016686d0c387`, `91a15554ec9e49c00c5ca301f276bd79d346968651d54204743a08a3ca8a5067` _(+2 more)_


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 14 use case(s) fired, 24 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

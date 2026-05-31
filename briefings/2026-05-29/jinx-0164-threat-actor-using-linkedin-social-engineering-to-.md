# [CRIT] JINX-0164 Threat Actor Using LinkedIn Social Engineering to Deploy Custom macOS Malware

**Source:** Cyber Security News
**Published:** 2026-05-29
**Article:** https://cybersecuritynews.com/jinx-0164-threat-actor-using-linkedin-social-engineering/

## Threat Profile

Home Cyber Security News 
JINX-0164 Threat Actor Using LinkedIn Social Engineering to Deploy Custom macOS Malware 
By Tushar Subhra Dutta 
May 29, 2026 
A new threat actor tracked as JINX-0164 has been running calculated attacks against cryptocurrency organizations, using LinkedIn profiles to lure developers into downloading custom macOS malware. 
Active since at least mid-2025, the group has combined social engineering, credential theft, and supply chain sabotage into a seamless operation that …

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `89.36.224.5`
- **IPv4 (defanged):** `185.100.85.250`
- **IPv4 (defanged):** `84.32.83.250`
- **IPv4 (defanged):** `153.92.126.84`
- **IPv4 (defanged):** `45.45.217.242`
- **IPv4 (defanged):** `163.172.53.20`
- **IPv4 (defanged):** `208.115.220.17`
- **IPv4 (defanged):** `185.175.59.85`
- **Domain (defanged):** `datahub.ink`
- **Domain (defanged):** `cloud-sync.online`
- **Domain (defanged):** `byte-io.us`
- **Domain (defanged):** `apple.driver-store.com`
- **Domain (defanged):** `apple.driver-update.io`
- **Domain (defanged):** `driver-updater.net`
- **Domain (defanged):** `driver-hub.net`
- **Domain (defanged):** `drvstore.com`
- **Domain (defanged):** `bitget-meeting.com`
- **Domain (defanged):** `teamicrosoft.com`
- **Domain (defanged):** `teams.cam`
- **Domain (defanged):** `live.us.org`
- **Domain (defanged):** `us03-slack.online`
- **Domain (defanged):** `live.ong`
- **SHA256:** `0a8ab3d16b12d3a453ee5a3208fe04744ad54514ef8ea27bb8fe32679efad270`
- **SHA256:** `0b028b781950641818800fee2b4bf68e4ef2bcee53fe71a21755275ba10875f5`
- **SHA256:** `a35d2b67fa478a7174e308b43ce30bf69b3bc6f44fa76197fdf95fc2fbc1cf7d`
- **SHA256:** `65cba741fe30fa4799fb9002ea8de6d96042a59159dd7c3419c766af24c7a8b4`
- **SHA256:** `0b1a36a31b952341a534fe24890f1ed2921ee259773cff46e4f6273b8c4d5e3a`
- **SHA256:** `e8ee6f5145c9d503c5130bfc6585567f6e19d409158c3c0ca0b259f1875b1a2f`
- **SHA256:** `3e3901519c2305fbe9d5483b7234c25c6d2b562512916481d96f26b849c7d4e1`
- **SHA256:** `9c2ce925133a3bf5a924063bbef8df49918d5b7258695c1894cd18c75970157a`
- **SHA256:** `402625ec79e3573a80b6de9b33fc1e503e3c7803603cd958ddd515fb0e4a3c91`
- **SHA256:** `b6cab0b3aa8e56e2427f486c74588d598ae58bb0cbc0eda6939fe171cb4f2d89`
- **SHA256:** `d4e863f9818bfb2f1dd932df6441dff204e6142c3bdb55b298cb08dc7b6a9f12`
- **SHA256:** `c6ef82d2864dfd26f117a1ef5602679153423f2742970a7949cec72722f0a0b3`
- **SHA256:** `2a10ffe0367bb1b26ba2c3bc600892c21074725c0b8c9dc9161e6ceb339f4d5c`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1566.004** — Phishing: Spearphishing Voice
- **T1566** — Phishing
- **T1219** — Remote Access Software
- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1543.001** — Persistence (article-specific)
- **T1543.001** — Create or Modify System Process: Launch Agent
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1573.001** — Encrypted Channel: Symmetric Cryptography
- **T1105** — Ingress Tool Transfer
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1566.002** — Phishing: Spearphishing Link
- **T1656** — Impersonation
- **T1552.004** — Unsecured Credentials: Private Keys
- **T1213.003** — Data from Information Repositories: Code Repositories
- **T1567** — Exfiltration Over Web Service

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] JINX-0164 AUDIOFIX/MINIRAT macOS LaunchAgent plist persistence

`UC_33_11` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_path="*/Library/LaunchAgents/*" Filesystem.file_name IN ("com.microsoft.teams.coreaudiod.plist","io.aircall.workspace.helper.plist","com.apple.Terminal.profiler.plist") by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has "/Library/LaunchAgents/"
| where FileName in~ ("com.microsoft.teams.coreaudiod.plist","io.aircall.workspace.helper.plist","com.apple.Terminal.profiler.plist")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessSHA256, SHA256, ActionType
| order by Timestamp desc
```

### [LLM] JINX-0164 C2 and payload delivery infrastructure callback

`UC_33_12` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest IN ("208.115.220.17","185.175.59.85","89.36.224.5","185.100.85.250","84.32.83.250","153.92.126.84","45.45.217.242","163.172.53.20") OR All_Traffic.dest_host IN ("datahub.ink","cloud-sync.online","byte-io.us","apple.driver-store.com","apple.driver-update.io","driver-updater.net","driver-hub.net","drvstore.com")) by All_Traffic.src All_Traffic.dest All_Traffic.dest_host All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let JinxDomains = dynamic(["datahub.ink","cloud-sync.online","byte-io.us","apple.driver-store.com","apple.driver-update.io","driver-updater.net","driver-hub.net","drvstore.com","bitget-meeting.com","teamicrosoft.com","teams.cam","live.us.org","us03-slack.online","live.ong"]);
let JinxIPs = dynamic(["208.115.220.17","185.175.59.85","89.36.224.5","185.100.85.250","84.32.83.250","153.92.126.84","45.45.217.242","163.172.53.20"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (JinxIPs) or RemoteUrl has_any (JinxDomains)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName, RemoteIP, RemoteUrl, RemotePort, Protocol, ActionType
| order by Timestamp desc
```

### [LLM] Trojanized npm @velora-dex/sdk v4.9.1 install or import

`UC_33_13` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("npm","yarn","pnpm","npx","node") (Processes.process="*@velora-dex/sdk@4.9.1*" OR Processes.process="*velora-dex/sdk*4.9.1*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
union isfuzzy=true
(DeviceProcessEvents
  | where Timestamp > ago(60d)
  | where FileName in~ ("npm","yarn","pnpm","npx","node","npm.exe","yarn.exe","pnpm.cmd")
  | where ProcessCommandLine has "@velora-dex/sdk" and ProcessCommandLine has "4.9.1"
  | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath),
(DeviceFileEvents
  | where Timestamp > ago(60d)
  | where FileName in~ ("package.json","package-lock.json","yarn.lock","pnpm-lock.yaml")
  | where InitiatingProcessCommandLine has "@velora-dex/sdk" and InitiatingProcessCommandLine has "4.9.1"
  | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, FileName, ProcessCommandLine=InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath)
| order by Timestamp desc
```

### [LLM] User access to JINX-0164 fake conferencing platform domains (Teams/Slack/Bitget spoofs)

`UC_33_14` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where Web.url IN ("*bitget-meeting.com*","*teamicrosoft.com*","*teams.cam*","*live.us.org*","*us03-slack.online*","*live.ong*") by Web.src Web.user Web.url Web.http_referrer Web.http_user_agent | `drop_dm_object_name(Web)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let SpoofDomains = dynamic(["bitget-meeting.com","teamicrosoft.com","teams.cam","live.us.org","us03-slack.online","live.ong"]);
let ClickHits = UrlClickEvents
    | where Timestamp > ago(30d)
    | where Url has_any (SpoofDomains)
    | project Timestamp, AccountUpn, Url, ActionType, IPAddress, NetworkMessageId, Source="UrlClickEvents";
let NetHits = DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteUrl has_any (SpoofDomains)
    | project Timestamp, AccountUpn=InitiatingProcessAccountUpn, Url=RemoteUrl, ActionType, IPAddress=RemoteIP, NetworkMessageId="", Source="DeviceNetworkEvents", DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine;
union isfuzzy=true ClickHits, NetHits
| order by Timestamp desc
```

### [LLM] nord-stream CI/CD secret-exfiltration tool execution

`UC_33_15` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="nord-stream" OR Processes.process_name="nord-stream.py" OR Processes.process="*nord-stream*" OR Processes.process="*nord_stream*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(90d)
| where FileName in~ ("nord-stream","nord-stream.py","nord_stream.py")
    or ProcessCommandLine has_any ("nord-stream","nord_stream")
    or InitiatingProcessCommandLine has_any ("nord-stream","nord_stream")
| where not(ProcessCommandLine has_any ("--help","-h "," -V","--version"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, SHA256
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

### Microsoft Teams external-tenant chat from unverified IT-helpdesk impersonator

`UC_TEAMS_VISHING` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`o365_management_activity`
  Workload=MicrosoftTeams Operation=MessageSent
  ExternalParticipants=*
| where match(SenderDisplayName, "(?i)(help.?desk|it.?support|service.?desk|tech.?support|admin)")
| stats count, earliest(_time) as firstTime, latest(_time) as lastTime
    by SenderUpn, SenderDisplayName, RecipientUpn, ChatId
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Microsoft Teams"
| where ActionType == "MessageSent"
| where RawEventData has "ExternalParticipants"
| extend SenderDisplayName = tostring(parse_json(RawEventData).SenderDisplayName)
| where SenderDisplayName matches regex @"(?i)(help.?desk|it.?support|service.?desk|tech.?support|admin)"
| project Timestamp, AccountDisplayName, IPAddress, ActivityType, SenderDisplayName, RawEventData
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

### Article-specific behavioural hunt — JINX-0164 Threat Actor Using LinkedIn Social Engineering to Deploy Custom macOS

`UC_33_10` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — JINX-0164 Threat Actor Using LinkedIn Social Engineering to Deploy Custom macOS ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/Library/LaunchAgents/com.microsoft.teams.coreaudiod.plist*" OR Filesystem.file_path="*/Library/LaunchAgents/io.aircall.workspace.helper.plist*" OR Filesystem.file_path="*/Library/LaunchAgents/com.apple.Terminal.profiler.plist*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — JINX-0164 Threat Actor Using LinkedIn Social Engineering to Deploy Custom macOS
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/Library/LaunchAgents/com.microsoft.teams.coreaudiod.plist", "/Library/LaunchAgents/io.aircall.workspace.helper.plist", "/Library/LaunchAgents/com.apple.Terminal.profiler.plist"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `89.36.224.5`, `185.100.85.250`, `84.32.83.250`, `153.92.126.84`, `45.45.217.242`, `163.172.53.20`, `208.115.220.17`, `185.175.59.85` _(+14 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `0a8ab3d16b12d3a453ee5a3208fe04744ad54514ef8ea27bb8fe32679efad270`, `0b028b781950641818800fee2b4bf68e4ef2bcee53fe71a21755275ba10875f5`, `a35d2b67fa478a7174e308b43ce30bf69b3bc6f44fa76197fdf95fc2fbc1cf7d`, `65cba741fe30fa4799fb9002ea8de6d96042a59159dd7c3419c766af24c7a8b4`, `0b1a36a31b952341a534fe24890f1ed2921ee259773cff46e4f6273b8c4d5e3a`, `e8ee6f5145c9d503c5130bfc6585567f6e19d409158c3c0ca0b259f1875b1a2f`, `3e3901519c2305fbe9d5483b7234c25c6d2b562512916481d96f26b849c7d4e1`, `9c2ce925133a3bf5a924063bbef8df49918d5b7258695c1894cd18c75970157a` _(+5 more)_


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 16 use case(s) fired, 30 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

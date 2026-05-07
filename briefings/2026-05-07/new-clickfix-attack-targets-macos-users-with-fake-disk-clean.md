# [CRIT] New ClickFix Attack Targets macOS Users With Fake Disk Cleanup and Utility Lures

**Source:** Cyber Security News
**Published:** 2026-05-07
**Article:** https://cybersecuritynews.com/new-clickfix-attack-targets-macos-users/

## Threat Profile

Home Cyber Security News 
New ClickFix Attack Targets macOS Users With Fake Disk Cleanup and Utility Lures 
By Tushar Subhra Dutta 
May 7, 2026 
A new wave of cyberattacks is putting macOS users in the crosshairs, and this time the bait looks almost too familiar. Attackers are disguising their malware as helpful disk cleanup tools and system utilities, tricking people into running dangerous commands directly on their own computers. 
The campaign, known as ClickFix, works by placing fake troubles…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `95.85.251.177`
- **IPv4 (defanged):** `138.124.93.32`
- **IPv4 (defanged):** `168.100.9.122`
- **IPv4 (defanged):** `199.217.98.33`
- **IPv4 (defanged):** `38.244.158.103`
- **IPv4 (defanged):** `45.94.47.204`
- **Domain (defanged):** `macclean.craft.me`
- **Domain (defanged):** `cleanmymacos.org`
- **Domain (defanged):** `mac-storage-guide.squarespace.com`
- **Domain (defanged):** `claudecodedoc.squarespace.com`
- **Domain (defanged):** `domenpozh.net`
- **Domain (defanged):** `rapidfilevault4.sbs`
- **Domain (defanged):** `coco-fun2.com`
- **Domain (defanged):** `nitlebuf.com`
- **Domain (defanged):** `yablochnisok.com`
- **Domain (defanged):** `mentaorb.com`
- **Domain (defanged):** `seagalnssteavens.com`
- **Domain (defanged):** `filefastdata.com`
- **Domain (defanged):** `metramon.com`
- **Domain (defanged):** `octopixeldate.com`
- **Domain (defanged):** `datasphere.us.com`
- **Domain (defanged):** `rapidfilevault5.sbs`
- **Domain (defanged):** `dialerformac.com`
- **Domain (defanged):** `swift-sh.com`
- **Domain (defanged):** `0x666.info`
- **Domain (defanged):** `honestly.ink`
- **Domain (defanged):** `pla7ina.cfd`
- **Domain (defanged):** `play67.cc`
- **Domain (defanged):** `cauterizespray.icu`
- **Domain (defanged):** `script.sh`
- **Domain (defanged):** `enslaveculprit.digital`
- **Domain (defanged):** `resilientlimb.icu`
- **Domain (defanged):** `t.me`
- **Domain (defanged):** `rvdownloads.com`
- **Domain (defanged):** `famiode.com`
- **Domain (defanged):** `contatoplus.com`
- **Domain (defanged):** `woupp.com`
- **Domain (defanged):** `octopox.com`
- **Domain (defanged):** `avipstudios.com`
- **Domain (defanged):** `joytion.com`
- **Domain (defanged):** `laislivon.com`
- **Domain (defanged):** `reachnv.com`
- **Domain (defanged):** `vagturk.com`
- **Domain (defanged):** `futampako.com`
- **Domain (defanged):** `joeyapple.com`
- **Domain (defanged):** `wusetail.com`
- **Domain (defanged):** `aforvm.com`
- **Domain (defanged):** `ouilov.com`
- **Domain (defanged):** `malext.com`
- **Domain (defanged):** `rebidy.com`
- **SHA256:** `9d2da07aa6e7db3fbc36b36f0cfd74f78d5815f5ba55d0f0405cdd668bd13767`
- **SHA256:** `7ca42f1f23dbdc9427c9f135815bb74708a7494ea78df1fbc0fc348ba2a161ae`
- **SHA256:** `241a50befcf5c1aa6dab79664e2ba9cb373cc351cb9de9c3699fd2ecb2afab05`
- **SHA256:** `522fdfaff44797b9180f36c654f77baf5cdeaab861bbf372ccfc1a5bd920d62e`

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
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1543.001** — Persistence (article-specific)
- **T1543.004** — Persistence (article-specific)
- **T1059.002** — Command and Scripting Interpreter: AppleScript
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1140** — Deobfuscate/Decode Files or Information
- **T1105** — Ingress Tool Transfer
- **T1543.001** — Create or Modify System Process: Launch Agent
- **T1547.011** — Plist File Modification
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1564.001** — Hide Artifacts: Hidden Files and Directories
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1102.002** — Web Service: Bidirectional Communication
- **T1567.002** — Exfiltration Over Web Service: Exfiltration to Cloud Storage
- **T1573** — Encrypted Channel

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] macOS ClickFix Terminal-pasted curl piped to base64/gunzip into osascript or shell

`UC_9_14` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.os="macOS" AND Processes.parent_process_name IN ("Terminal","bash","zsh","sh","dash","login") AND Processes.process="*curl*" AND (Processes.process="*base64*" OR Processes.process="*gunzip*" OR Processes.process="*gzip -d*") AND (Processes.process="*osascript*" OR Processes.process="*| sh*" OR Processes.process="*| bash*" OR Processes.process="*| zsh*" OR Processes.process="*|sh*" OR Processes.process="*|bash*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_hash | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// macOS ClickFix paste — curl piped to base64/gunzip into osascript or shell
let MacDevices = DeviceInfo | where OSPlatform =~ "macOS" | distinct DeviceId;
DeviceProcessEvents
| where Timestamp > ago(30d)
| where DeviceId in (MacDevices)
   or InitiatingProcessFileName in~ ("Terminal","bash","zsh","sh","dash","login")
| where InitiatingProcessFileName in~ ("Terminal","bash","zsh","sh","dash","login")
| where ProcessCommandLine has "curl"
| where ProcessCommandLine has_any ("base64", "gunzip", "gzip -d")
| where ProcessCommandLine has_any ("osascript", "| sh", "| bash", "| zsh", "|sh", "|bash", "|zsh")
| project Timestamp, DeviceName, AccountName,
          ParentProcess = InitiatingProcessFileName,
          ParentCmd     = InitiatingProcessCommandLine,
          ChildProcess  = FileName,
          ChildCmd      = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### [LLM] macOS ClickFix persistence: fake Google Keystone plist, /tmp/helper, .mainhelper backdoor

`UC_9_15` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action IN ("created","modified") AND ( (Filesystem.file_name="com.google.keystone.agent.plist" AND Filesystem.file_path="*LaunchAgents*") OR Filesystem.file_path="*GoogleUpdate.app/Contents/MacOS*" OR (Filesystem.file_path="/tmp/" AND Filesystem.file_name IN ("helper","starter")) OR Filesystem.file_name IN (".mainhelper",".agent") ) AND NOT Filesystem.process_name IN ("ksinstall","ksadmin","GoogleSoftwareUpdateAgent","installd","mdmclient","Install Google Software Update.app") by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.process_name Filesystem.process_path | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// macOS ClickFix persistence — Microsoft IOC paths / filenames
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where (FileName =~ "com.google.keystone.agent.plist" and FolderPath has "LaunchAgents")
   or FolderPath contains "GoogleUpdate.app/Contents/MacOS"
   or (FolderPath in ("/tmp/","/private/tmp/") and FileName in~ ("helper","starter"))
   or FileName in~ (".mainhelper",".agent")
   or (FolderPath has "LaunchAgents" and FileName matches regex @"(?i)^com\.[a-z0-9]{6,}\.plist$")
// strip legitimate Google Software Update installer noise
| where InitiatingProcessFileName !in~ ("ksinstall","ksadmin","GoogleSoftwareUpdateAgent","installd","mdmclient")
| project Timestamp, DeviceName, ActionType,
          FileName, FolderPath, SHA256,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### [LLM] macOS endpoint contacting ClickFix loader/script/helper C2, exfil endpoint or Telegram fallback bot

`UC_9_16` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest IN ("95.85.251.177","138.124.93.32","168.100.9.122","199.217.98.33","38.244.158.103","45.94.47.204") OR All_Traffic.dest_host IN ("rapidfilevault4.sbs","rapidfilevault5.sbs","coco-fun2.com","nitlebuf.com","yablochnisok.com","mentaorb.com","seagalnssteavens.com","filefastdata.com","metramon.com","octopixeldate.com","datasphere.us.com","dialerformac.com","swift-sh.com","0x666.info","honestly.ink","pla7ina.cfd","play67.cc","cleanmymacos.org","domenpozh.net","macclean.craft.me","macos-disk-space.medium.com","apple-mac-fix-hidden.medium.com","mac-storage-guide.squarespace.com","claudecodedoc.squarespace.com","cauterizespray.icu","enslaveculprit.digital","resilientlimb.icu","rvdownloads.com","famiode.com","contatoplus.com","woupp.com","octopox.com","avipstudios.com","joytion.com","laislivon.com","reachnv.com","vagturk.com","futampako.com","joeyapple.com","wusetail.com","aforvm.com","ouilov.com","malext.com","rebidy.com","t.me")) by All_Traffic.src All_Traffic.user All_Traffic.app All_Traffic.dest All_Traffic.dest_host All_Traffic.dest_port All_Traffic.url | `drop_dm_object_name(All_Traffic)` | search NOT (dest_host="t.me" AND NOT url="*ax03bot*") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// macOS ClickFix C2 / exfil IOC sweep
let ClickFixDomains = dynamic([
  "rapidfilevault4.sbs","rapidfilevault5.sbs","coco-fun2.com","nitlebuf.com",
  "yablochnisok.com","mentaorb.com","seagalnssteavens.com","filefastdata.com",
  "metramon.com","octopixeldate.com","datasphere.us.com","dialerformac.com",
  "swift-sh.com","0x666.info","honestly.ink","pla7ina.cfd","play67.cc",
  "cleanmymacos.org","domenpozh.net","macclean.craft.me",
  "macos-disk-space.medium.com","apple-mac-fix-hidden.medium.com",
  "mac-storage-guide.squarespace.com","claudecodedoc.squarespace.com",
  "cauterizespray.icu","enslaveculprit.digital","resilientlimb.icu",
  "rvdownloads.com","famiode.com","contatoplus.com","woupp.com","octopox.com",
  "avipstudios.com","joytion.com","laislivon.com",
  "reachnv.com","vagturk.com","futampako.com","joeyapple.com",
  "wusetail.com","aforvm.com","ouilov.com","malext.com","rebidy.com"
]);
let ClickFixIPs = dynamic([
  "95.85.251.177","138.124.93.32","168.100.9.122",
  "199.217.98.33","38.244.158.103","45.94.47.204"
]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (ClickFixIPs)
   or RemoteUrl has_any (ClickFixDomains)
   or RemoteUrl has "/ax03bot"          // Telegram fallback bot
   or (RemoteUrl endswith "/script.sh" and RemoteUrl has_any ("cauterizespray","enslaveculprit","resilientlimb"))
   or (RemoteUrl endswith "/contact" and RemoteIP in ("138.124.93.32","168.100.9.122","199.217.98.33","38.244.158.103"))
| project Timestamp, DeviceName, AccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          RemoteIP, RemotePort, RemoteUrl, Protocol
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

### Article-specific behavioural hunt — New ClickFix Attack Targets macOS Users With Fake Disk Cleanup and Utility Lures

`UC_9_13` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — New ClickFix Attack Targets macOS Users With Fake Disk Cleanup and Utility Lures ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/tmp/helper*" OR Filesystem.file_path="*/tmp/starter*" OR Filesystem.file_path="*/Library/Application*" OR Filesystem.file_path="*/Library/LaunchAgents/com.*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — New ClickFix Attack Targets macOS Users With Fake Disk Cleanup and Utility Lures
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/tmp/helper", "/tmp/starter", "/Library/Application", "/Library/LaunchAgents/com."))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `95.85.251.177`, `138.124.93.32`, `168.100.9.122`, `199.217.98.33`, `38.244.158.103`, `45.94.47.204`, `macclean.craft.me`, `cleanmymacos.org` _(+42 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `9d2da07aa6e7db3fbc36b36f0cfd74f78d5815f5ba55d0f0405cdd668bd13767`, `7ca42f1f23dbdc9427c9f135815bb74708a7494ea78df1fbc0fc348ba2a161ae`, `241a50befcf5c1aa6dab79664e2ba9cb373cc351cb9de9c3699fd2ecb2afab05`, `522fdfaff44797b9180f36c654f77baf5cdeaab861bbf372ccfc1a5bd920d62e`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 17 use case(s) fired, 35 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

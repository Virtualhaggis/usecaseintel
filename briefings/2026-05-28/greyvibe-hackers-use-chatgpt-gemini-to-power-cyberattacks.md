# [CRIT] GreyVibe hackers use ChatGPT, Gemini to power cyberattacks

**Source:** BleepingComputer
**Published:** 2026-05-28
**Article:** https://www.bleepingcomputer.com/news/security/greyvibe-hackers-use-chatgpt-gemini-to-power-cyberattacks/

## Threat Profile

GreyVibe hackers use ChatGPT, Gemini to power cyberattacks 
By Bill Toulas 
May 28, 2026
06:24 PM
0 
A likely Russian threat group tracked as GreyVibe has been using AI-generated lures and a rich set of custom malware tools to target entities in the military, government, civilian, and business sectors.
The cyberespionage campaign has been active since at least August 2025 and appears to align with Russian state interests, although researchers cannot confidently classify it as a nation-state oper…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

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
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1204.001** — Malicious Link
- **T1059.003** — Windows Command Shell
- **T1555.003** — Credentials from Web Browsers
- **T1119** — Automated Collection
- **T1005** — Data from Local System
- **T1021.001** — Remote Services: RDP
- **T1112** — Modify Registry
- **T1562.004** — Disable or Modify System Firewall
- **T1102** — Web Service
- **T1496** — Resource Hijacking

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] PhantomMail: Ukrainian-themed ZIP/RAR delivered via Google Drive or 4sync links

`UC_49_6` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Email.recipient) as recipient values(All_Email.subject) as subject values(All_Email.url) as url values(All_Email.file_name) as file_name from datamodel=Email where All_Email.src_user!="" (All_Email.file_name="*.zip" OR All_Email.file_name="*.rar" OR All_Email.url="*drive.google.com/*" OR All_Email.url="*4sync.com/*" OR All_Email.url="*4shared.com/*") by All_Email.src_user All_Email.recipient _time | `drop_dm_object_name(All_Email)` | search subject IN ("*Україн*","*ДСНС*","*Укртелеком*","*Нафтогаз*","*Укренерго*","*Ukrain*","*emergency*","*energy*","*charity*","*drone*","*FPV*","*UAV*")
```

**Defender KQL:**
```kql
let SuspectArchive = EmailAttachmentInfo | where Timestamp > ago(14d) | where FileName endswith ".zip" or FileName endswith ".rar" | project Timestamp, NetworkMessageId, FileName, SHA256, RecipientEmailAddress; let SuspectUrl = EmailUrlInfo | where Timestamp > ago(14d) | where UrlDomain in~ ("drive.google.com","4sync.com","4shared.com") | project Timestamp, NetworkMessageId, Url, UrlDomain; EmailEvents | where Timestamp > ago(14d) | where EmailDirection == "Inbound" | where Subject has_any ("Україн","ДСНС","Укртелеком","Нафтогаз","Укренерго","Ukrain","emergency","energy","charity","drone","FPV","UAV","СПО НЕБО","НЕБО") | join kind=inner (union SuspectArchive, SuspectUrl) on NetworkMessageId | project Timestamp, SenderFromAddress, SenderMailFromDomain, RecipientEmailAddress, Subject, FileName, SHA256, Url, UrlDomain, NetworkMessageId | order by Timestamp desc
```

### [LLM] PhantomClick: browser → mshta/powershell/cmd within 60s of fake Cloudflare/Zoom/LAPAS lure

`UC_49_7` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent values(Processes.process_name) as child from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe") Processes.process_name IN ("powershell.exe","pwsh.exe","mshta.exe","cmd.exe","wscript.exe","cscript.exe") by Processes.dest Processes.user Processes.process_id _time | `drop_dm_object_name(Processes)` | search cmdline IN ("*I am not a robot*","*Cloudflare*","*ray-id*","*verification*","*captcha*","*zoom*","*lapas*","*FromBase64String*","*iex*","*Invoke-Expression*","*curl*","*irm *","*mshta http*")
```

**Defender KQL:**
```kql
DeviceProcessEvents | where Timestamp > ago(7d) | where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe") | where FileName in~ ("powershell.exe","pwsh.exe","mshta.exe","cmd.exe","wscript.exe","cscript.exe") | where ProcessCommandLine has_any ("I am not a robot","Cloudflare","ray-id","verification","captcha","zoom","lapas","FromBase64String","IEX","Invoke-Expression","irm ","mshta http","curl http","Verify you are human") | where AccountName !endswith "$" | project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256 | order by Timestamp desc
```

### [LLM] LegionRelay browser credential theft from Chromium/Firefox Login Data by PowerShell

`UC_49_8` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.process_name) as process_name from datamodel=Endpoint.Filesystem where (Filesystem.file_name="Login Data" OR Filesystem.file_name="Local State" OR Filesystem.file_name="logins.json" OR Filesystem.file_name="key4.db" OR Filesystem.file_name="cookies.sqlite") Filesystem.process_name!="chrome.exe" Filesystem.process_name!="msedge.exe" Filesystem.process_name!="firefox.exe" Filesystem.process_name!="brave.exe" Filesystem.process_name!="opera.exe" by Filesystem.dest Filesystem.user Filesystem.process_name _time | `drop_dm_object_name(Filesystem)` | search process_name IN ("powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe")
```

**Defender KQL:**
```kql
DeviceFileEvents | where Timestamp > ago(14d) | where FileName in~ ("Login Data","Local State","logins.json","key4.db","cookies.sqlite","Cookies","Web Data") | where FolderPath has_any ("\\Google\\Chrome\\","\\Microsoft\\Edge\\","\\Mozilla\\Firefox\\","\\BraveSoftware\\","\\Opera Software\\") | where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","explorer.exe","searchprotocolhost.exe","backup.exe") | where InitiatingProcessFileName in~ ("powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe") | where InitiatingProcessAccountName !endswith "$" | project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName, ActionType | order by Timestamp desc
```

### [LLM] LegionRelay Telegram / WhatsApp messenger store exfiltration

`UC_49_9` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.process_name) as process_name from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\Telegram Desktop\\tdata\\*" OR Filesystem.file_path="*\\WhatsApp\\Local Storage\\*" OR Filesystem.file_path="*\\WhatsApp\\IndexedDB\\*" OR Filesystem.file_name="msgstore.db" OR Filesystem.file_name="key_datas") Filesystem.process_name!="Telegram.exe" Filesystem.process_name!="WhatsApp.exe" by Filesystem.dest Filesystem.user Filesystem.process_name _time | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents | where Timestamp > ago(14d) | where FolderPath has_any ("\\Telegram Desktop\\tdata\\","\\WhatsApp\\Local Storage\\","\\WhatsApp\\IndexedDB\\") or FileName in~ ("key_datas","msgstore.db","map0","map1") | where InitiatingProcessFileName !in~ ("telegram.exe","whatsapp.exe","updater.exe","explorer.exe") | where InitiatingProcessFileName in~ ("powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","7z.exe","winrar.exe") | where InitiatingProcessAccountName !endswith "$" | project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName, ActionType | order by Timestamp desc
```

### [LLM] GreyVibe: RDP enablement via fDenyTSConnections=0 + firewall by PowerShell RAT

`UC_49_10` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
(`wineventlog_security` EventCode=4688 (CommandLine="*fDenyTSConnections*" OR CommandLine="*Set-ItemProperty*Terminal Server*" OR CommandLine="*netsh advfirewall*RemoteDesktop*" OR CommandLine="*Enable-NetFirewallRule*RemoteDesktop*" OR CommandLine="*reg add*Terminal Server*/v fDenyTSConnections*" OR CommandLine="*UserAuthentication*0*")) OR (index=* sourcetype="WinRegistry" (object="*\\Terminal Server\\fDenyTSConnections" OR object="*\\WinStations\\RDP-Tcp\\UserAuthentication") data="0") | stats min(_time) as firstTime max(_time) as lastTime values(CommandLine) as cmdline values(object) as regkey by host user | where isnotnull(cmdline) OR isnotnull(regkey)
```

**Defender KQL:**
```kql
let RegFlip = DeviceRegistryEvents | where Timestamp > ago(14d) | where (RegistryKey has "\\Terminal Server" and RegistryValueName == "fDenyTSConnections" and RegistryValueData == "0") or (RegistryKey has "\\WinStations\\RDP-Tcp" and RegistryValueName == "UserAuthentication") | where InitiatingProcessFileName in~ ("powershell.exe","pwsh.exe","cmd.exe","reg.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe") | project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RegistryKey, RegistryValueName, RegistryValueData; let CmdFlip = DeviceProcessEvents | where Timestamp > ago(14d) | where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","netsh.exe","reg.exe") | where ProcessCommandLine has_any ("fDenyTSConnections","Set-ItemProperty","Enable-NetFirewallRule","netsh advfirewall") | where ProcessCommandLine has_any ("Terminal Server","RemoteDesktop","TermService","RDP-Tcp","UserAuthentication") | project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine; union RegFlip, CmdFlip | order by Timestamp desc
```

### [LLM] PowerShell.exe sustained beaconing to uncategorized web endpoint (LegionRelay/PhantomRelay C2)

`UC_49_11` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime dc(All_Traffic.dest) as dest_count values(All_Traffic.dest) as dest values(All_Traffic.dest_port) as dest_port from datamodel=Network_Traffic.All_Traffic where All_Traffic.app="powershell.exe" All_Traffic.dest_port IN (80,443,8080,8443) by All_Traffic.src All_Traffic.user span=10m | `drop_dm_object_name(All_Traffic)` | where count > 20 AND dest_count <= 2
```

**Defender KQL:**
```kql
DeviceNetworkEvents | where Timestamp > ago(7d) | where InitiatingProcessFileName in~ ("powershell.exe","pwsh.exe") | where RemotePort in (80,443,8080,8443) | where RemoteIPType == "Public" | summarize ConnectionCount = count(), DistinctRemoteIPs = dcount(RemoteIP), DistinctRemoteUrls = dcount(RemoteUrl), FirstSeen = min(Timestamp), LastSeen = max(Timestamp), SampleUrl = any(RemoteUrl), SampleCmd = any(InitiatingProcessCommandLine) by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 10m) | where ConnectionCount >= 20 and DistinctRemoteIPs <= 2 | order by ConnectionCount desc
```

### [LLM] GreyVibe cryptocurrency miner deployment via PowerShell RAT

`UC_49_12` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.process_name) as process_name values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where (Processes.process_name IN ("xmrig.exe","ethminer.exe","t-rex.exe","lolminer.exe","phoenixminer.exe","nbminer.exe","teamredminer.exe","srbminer.exe") OR Processes.process="*--algo*" OR Processes.process="*stratum+tcp://*" OR Processes.process="*--donate-level*" OR Processes.process="*-o stratum*" OR Processes.process="*xmrig*" OR Processes.process="*RandomX*") by Processes.dest Processes.user _time | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
let MinerProcess = DeviceProcessEvents | where Timestamp > ago(14d) | where FileName in~ ("xmrig.exe","ethminer.exe","t-rex.exe","lolminer.exe","phoenixminer.exe","nbminer.exe","teamredminer.exe","srbminer.exe") or ProcessCommandLine has_any ("stratum+tcp://","stratum+ssl://","--algo ","--donate-level","-o stratum","RandomX","--coin=monero","--cpu-priority") | project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256; let MinerNet = DeviceNetworkEvents | where Timestamp > ago(14d) | where RemotePort in (3333,4444,5555,7777,8333,14444,14433,45700) or RemoteUrl has_any ("pool.minexmr.com","xmrpool","nanopool","f2pool","supportxmr","moneroocean","hashvault","2miners") | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl; union MinerProcess, MinerNet | order by Timestamp desc
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


## Why this matters

Severity classified as **CRIT** based on: 13 use case(s) fired, 21 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

# [CRIT] Azerbaijani Energy Firm Hit by Repeated Microsoft Exchange Exploitation

**Source:** The Hacker News
**Published:** 2026-05-13
**Article:** https://thehackernews.com/2026/05/azerbaijani-energy-firm-hit-by-repeated.html

## Threat Profile

Azerbaijani Energy Firm Hit by Repeated Microsoft Exchange Exploitation 
 Ravie Lakshmanan  May 13, 2026 Cyber Espionage / Malware 
A threat actor with affiliations to China has been linked to a "multi-wave intrusion" targeting an unnamed Azerbaijani oil and gas company between late December 2025 and late February 2026, marking an expansion of its targeting.
The activity has been attributed by Bitdefender with moderate-to-high confidence to a hacking group known as FamousSparrow (aka UAT-9244)…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `sentinelonepro.com`

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
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1219** — Remote Access Software
- **T1195.002** — Compromise Software Supply Chain
- **T1190** — Exploit Public-Facing Application
- **T1133** — External Remote Services
- **T1505.003** — Web Shell
- **T1059.003** — Windows Command Shell
- **T1574.002** — DLL Side-Loading
- **T1036.005** — Match Legitimate Name or Location
- **T1027** — Obfuscated Files or Information
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1568** — Dynamic Resolution
- **T1036** — Masquerading

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] FamousSparrow ProxyNotShell exploitation pattern against Exchange Autodiscover endpoint

`UC_133_8` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.user_agent) as user_agent values(Web.status) as status from datamodel=Web where Web.url="*autodiscover.json*" AND (Web.url="*PowerShell*" OR Web.url="*Powershell*" OR Web.url="*powershell*") AND (Web.url="*@*" OR Web.http_cookie="*Email=autodiscover*") by Web.src Web.dest Web.url Web.status | `drop_dm_object_name(Web)` | where status=200 OR status=301 OR status=302 | sort - count
```

**Defender KQL:**
```kql
// IIS logs are not in Defender XDR — pivot on w3wp.exe egress, the most reliable post-exploit signal
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where InitiatingProcessFolderPath has @"\inetsrv\"
| where RemoteIPType == "Public"
| where not(RemoteUrl has_any ("microsoft.com","office.com","office365.com","windows.com","digicert.com"))
| project Timestamp, DeviceName, InitiatingProcessCommandLine, InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl, Protocol
| order by Timestamp desc
```

### [LLM] Exchange w3wp.exe spawning shell/script interpreter — FamousSparrow web shell foothold

`UC_133_9` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.process_path) as image values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.parent_process_name="w3wp.exe" AND Processes.parent_process_path="*\\inetsrv\\*" AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","powershell_ise.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","certutil.exe","bitsadmin.exe","curl.exe","net.exe","net1.exe","whoami.exe","systeminfo.exe","nltest.exe") by host Processes.parent_process_name Processes.process_name Processes.process_path Processes.user | `drop_dm_object_name(Processes)` | sort - firstTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where InitiatingProcessFolderPath has @"\inetsrv\"
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","powershell_ise.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","certutil.exe","bitsadmin.exe","curl.exe","net.exe","net1.exe","whoami.exe","systeminfo.exe","nltest.exe","ipconfig.exe")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### [LLM] FamousSparrow LogMeIn Hamachi DLL side-load chain (LMIGuardianSvc.exe from C:\TEMP)

`UC_133_10` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.process_hash) as sha256 values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where (Processes.process_name="LMIGuardianSvc.exe" OR Processes.process_name="lmiguardiansvc.exe") AND (Processes.process_path="*\\TEMP\\*" OR Processes.process_path="*\\Temp\\*" OR Processes.process_path="*\\tmp\\*" OR Processes.process_path="*\\AppData\\*" OR Processes.process_path="*\\ProgramData\\*" OR Processes.process_path="*\\Public\\*") AND NOT Processes.process_path="*\\LogMeIn Hamachi\\*" by host Processes.user Processes.process_path Processes.process_name | `drop_dm_object_name(Processes)` | append [| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path from datamodel=Endpoint.Filesystem where (Filesystem.file_name="lmiguardiandll.dll" OR Filesystem.file_name=".hamachi.lng" OR Filesystem.file_name="hamachi.lng") by host Filesystem.file_name | `drop_dm_object_name(Filesystem)`] | sort - firstTime
```

**Defender KQL:**
```kql
// Stage 1: Hamachi binary running from non-canonical path
let SideloadHost = DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName =~ "LMIGuardianSvc.exe"
    | where not(FolderPath has @"\LogMeIn Hamachi\")
    | where FolderPath has_any (@"\TEMP\", @"\Temp\", @"\tmp\", @"\AppData\", @"\ProgramData\", @"\Users\Public\", @"\Windows\Temp\")
    | project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine, SHA256, MD5, ProcessId;
// Stage 2: rogue DLL or encrypted shellcode dropped near the host binary
let SideloadArtifacts = DeviceFileEvents
    | where Timestamp > ago(30d)
    | where FileName in~ ("lmiguardiandll.dll", ".hamachi.lng", "hamachi.lng")
       or (FolderPath has_any (@"\TEMP\", @"\Temp\") and FileName =~ "lmiguardiandll.dll")
    | project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine;
// Stage 3: image-load confirmation — Hamachi process loading the rogue DLL
let RogueImageLoad = DeviceImageLoadEvents
    | where Timestamp > ago(30d)
    | where InitiatingProcessFileName =~ "LMIGuardianSvc.exe"
    | where FileName =~ "lmiguardiandll.dll"
    | where not(FolderPath has @"\LogMeIn Hamachi\")
    | project Timestamp, DeviceName, InitiatingProcessFolderPath, FileName, FolderPath, SHA256;
union SideloadHost, SideloadArtifacts, RogueImageLoad
| extend KnownBadMD5 = iff(MD5 =~ "0554f3b69d39d175dd110d765c11347a", "YES — LMIGuardianSvc dropper", "")
| order by Timestamp desc
```

### [LLM] FamousSparrow Deed RAT C2 beaconing to sentinelonepro.com / virusblocker.it.com

`UC_133_11` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(DNS.src) as src values(DNS.query) as query from datamodel=Network_Resolution where (DNS.query="sentinelonepro.com" OR DNS.query="*.sentinelonepro.com" OR DNS.query="virusblocker.it.com" OR DNS.query="*.virusblocker.it.com") by host DNS.query | `drop_dm_object_name(DNS)` | append [| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src) as src values(All_Traffic.dest) as dest values(All_Traffic.dest_port) as dest_port from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="sentinelonepro.com" OR All_Traffic.dest="virusblocker.it.com" OR All_Traffic.dest_url="*sentinelonepro.com*" OR All_Traffic.dest_url="*virusblocker.it.com*") by host All_Traffic.dest All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)`] | sort - firstTime
```

**Defender KQL:**
```kql
let FamousSparrowC2 = dynamic(["sentinelonepro.com","virusblocker.it.com"]);
let DnsHits = DeviceNetworkEvents
    | where Timestamp > ago(90d)
    | where RemoteUrl has_any (FamousSparrowC2) or RemoteUrl endswith ".sentinelonepro.com" or RemoteUrl endswith ".virusblocker.it.com"
    | project Timestamp, DeviceName, ActionType, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName;
let ProcessHits = DeviceProcessEvents
    | where Timestamp > ago(90d)
    | where ProcessCommandLine has_any (FamousSparrowC2)
    | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, FolderPath, SHA256;
union DnsHits, ProcessHits
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `sentinelonepro.com`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 12 use case(s) fired, 24 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

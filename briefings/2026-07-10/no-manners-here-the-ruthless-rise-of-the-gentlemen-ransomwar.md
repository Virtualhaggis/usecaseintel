# [CRIT] No Manners Here: The Ruthless Rise of The Gentlemen Ransomware

**Source:** Unit 42 (Palo Alto)
**Published:** 2026-07-10
**Article:** https://unit42.paloaltonetworks.com/the-gentlemen-ransomware/

## Threat Profile

Threat Research Center 
Insights 
Hospitality Hacks and Retail Reality Checks 
Hospitality Hacks and Retail Reality Checks 
No Manners Here: The Ruthless Rise of The Gentlemen Ransomware 
5 min read 
Related Products Unit 42 Incident Response 
By: Matt Brady 
Published: July 10, 2026 
Categories: Hospitality Hacks and Retail Reality Checks 
Insights 
Tags: Howling Scorpius 
RaaS 
Spikey Scorpius 
Executive Summary 
The Gentlemen (aka Storm-2697 ) is a Ransomware-as-a-Service (RaaS) program activ…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2024-55591`
- **CVE:** `CVE-2025-32433`
- **CVE:** `CVE-2025-33073`
- **CVE:** `CVE-2025-55182`
- **CVE:** `CVE-2025-7771`
- **CVE:** `CVE-2023-27532`
- **CVE:** `CVE-2024-37085`
- **IPv4 (defanged):** `193.233.202.17`
- **IPv4 (defanged):** `77.110.122.137`
- **IPv4 (defanged):** `45.86.230.112`
- **SHA256:** `22b38dad7da097ea03aa28d0614164cd25fafeb1383dbc15047e34c8050f6f67`
- **SHA256:** `51b9f246d6da85631131fcd1fabf0a67937d4bdde33625a44f7ee6a3a7baebd2`
- **SHA256:** `025fc0976c548fb5a880c83ea3eb21a5f23c5d53c4e51e862bb893c11adf712a`
- **SHA256:** `3ab9575225e00a83a4ac2b534da5a710bdcf6eb72884944c437b5fbe5c5c9235`
- **SHA1:** `8ae6bd18b129061f63642531f1b684cf0383c75d`
- **SHA1:** `d605994fc72a2bb59b5cfb1624a1b9170eca73a2`
- **SHA1:** `5aa3124e5c4921e5edfc60133b5d71da21b07da3`
- **SHA1:** `a5cf917ec4a7dfbdfa43621398604805d860c718`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
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
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1053.005** — Scheduled Task
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1219** — Remote Access Software
- **T1027** — Obfuscated Files or Information
- **T1053.005** — Persistence (article-specific)
- **T1068** — Exploitation for Privilege Escalation
- **T1211** — Exploitation for Defense Evasion
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1070.001** — Indicator Removal: Clear Windows Event Logs
- **T1046** — Network Service Discovery
- **T1018** — Remote System Discovery
- **T1090** — Proxy
- **T1572** — Protocol Tunneling
- **T1490** — Inhibit System Recovery

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### The Gentlemen: internet-facing assets exposed to the group's known-exploited edge/BYOVD CVEs

`UC_2_14` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Vulnerabilities.Vulnerabilities where Vulnerabilities.cve IN ("CVE-2024-55591","CVE-2025-32433","CVE-2025-33073","CVE-2025-55182","CVE-2025-7771") by Vulnerabilities.dest Vulnerabilities.cve Vulnerabilities.severity Vulnerabilities.signature | `drop_dm_object_name(Vulnerabilities)` | sort - count
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId in ("CVE-2024-55591","CVE-2025-32433","CVE-2025-33073","CVE-2025-55182","CVE-2025-7771")
| summarize arg_max(Timestamp, VulnerabilitySeverityLevel, SoftwareVendor, SoftwareName, SoftwareVersion, RecommendedSecurityUpdate) by DeviceId, DeviceName, CveId
| join kind=leftouter (DeviceInfo | where Timestamp > ago(1d) | summarize arg_max(Timestamp, IsInternetFacing) by DeviceId) on DeviceId
| project DeviceName, CveId, VulnerabilitySeverityLevel, SoftwareVendor, SoftwareName, SoftwareVersion, IsInternetFacing, RecommendedSecurityUpdate
| order by IsInternetFacing desc, CveId asc
```

### The Gentlemen 'gentlemen*' scheduled task creation/execution

`UC_2_15` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Endpoint.Processes.process_name=schtasks.exe Endpoint.Processes.process="*gentlemen*" by Endpoint.Processes.dest Endpoint.Processes.user Endpoint.Processes.process Endpoint.Processes.parent_process_name | `drop_dm_object_name(Endpoint.Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
union
 (DeviceProcessEvents
  | where Timestamp > ago(7d)
  | where FileName =~ "schtasks.exe"
  | where ProcessCommandLine has "gentlemen"
  | project Timestamp, DeviceName, AccountName, Evidence = ProcessCommandLine, Parent = InitiatingProcessFileName, ParentCmd = InitiatingProcessCommandLine),
 (DeviceFileEvents
  | where Timestamp > ago(7d)
  | where FolderPath has @"\System32\Tasks\"
  | where FileName startswith "gentlemen"
  | project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName, Evidence = FolderPath, Parent = InitiatingProcessFileName, ParentCmd = InitiatingProcessCommandLine)
| order by Timestamp desc
```

### The Gentlemen BYOVD: ThrottleStop.sys/ThrottleBlood.sys load & GentleKiller EDR-killer drivers (CVE-2025-7771)

`UC_2_16` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Endpoint.Filesystem.file_name IN ("ThrottleStop.sys","ThrottleBlood.sys","eb.sys","nseckrnl.sys","stpm_old.sys","stpm_new.sys","360netmon_wfp.sys","havoc.sys","googleApiUtil64.sys","dmx.sys")) by Endpoint.Filesystem.dest Endpoint.Filesystem.file_name Endpoint.Filesystem.file_path Endpoint.Filesystem.process_name | `drop_dm_object_name(Endpoint.Filesystem)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where FileName in~ ("ThrottleStop.sys","ThrottleBlood.sys","eb.sys","nseckrnl.sys","stpm_old.sys","stpm_new.sys","360netmon_wfp.sys","havoc.sys","googleApiUtil64.sys","dmx.sys")
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
| order by Timestamp desc
```

### The Gentlemen anti-forensics: wevtutil clearing Security/System event logs

`UC_2_17` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Endpoint.Processes.process_name=wevtutil.exe (Endpoint.Processes.process="*cl *" OR Endpoint.Processes.process="*clear-log*") (Endpoint.Processes.process="*Security*" OR Endpoint.Processes.process="*System*") by Endpoint.Processes.dest Endpoint.Processes.user Endpoint.Processes.process Endpoint.Processes.parent_process_name | `drop_dm_object_name(Endpoint.Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName =~ "wevtutil.exe"
| where ProcessCommandLine has_any ("cl ","clear-log")
| where ProcessCommandLine has_any ("Security","System")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### The Gentlemen internal recon via Advanced IP Scanner

`UC_2_18` · phase: **recon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Endpoint.Processes.process_name IN ("advanced_ip_scanner.exe","advanced_port_scanner.exe") OR Endpoint.Processes.original_file_name="advanced_ip_scanner.exe") by Endpoint.Processes.dest Endpoint.Processes.user Endpoint.Processes.process Endpoint.Processes.parent_process_name | `drop_dm_object_name(Endpoint.Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where AccountName !endswith "$"
| where FileName in~ ("advanced_ip_scanner.exe","advanced_port_scanner.exe")
    or ProcessVersionInfoProductName has "Advanced IP Scanner"
    or ProcessVersionInfoCompanyName has "Famatech"
    or ProcessVersionInfoOriginalFileName =~ "advanced_ip_scanner.exe"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, ProcessVersionInfoProductName, InitiatingProcessFileName
| order by Timestamp desc
```

### The Gentlemen C2: SystemBC / Go backdoor beacon to actor infrastructure

`UC_2_19` · phase: **c2** · confidence: **Low** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip IN ("193.233.202.17","77.110.122.137","45.86.230.112") by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name(All_Traffic)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in ("193.233.202.17","77.110.122.137","45.86.230.112")
| project Timestamp, DeviceName, RemoteIP, RemotePort, Protocol, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
| order by Timestamp desc
```

### The Gentlemen impact prep: Volume Shadow Copy deletion via vssadmin/wmic

`UC_2_20` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where ((Endpoint.Processes.process_name=vssadmin.exe AND Endpoint.Processes.process="*delete*" AND Endpoint.Processes.process="*shadow*") OR (Endpoint.Processes.process_name=wmic.exe AND Endpoint.Processes.process="*shadowcopy*" AND Endpoint.Processes.process="*delete*")) by Endpoint.Processes.dest Endpoint.Processes.user Endpoint.Processes.process Endpoint.Processes.parent_process_name | `drop_dm_object_name(Endpoint.Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where (FileName =~ "vssadmin.exe" and ProcessCommandLine has "delete" and ProcessCommandLine has "shadow")
    or (FileName =~ "wmic.exe" and ProcessCommandLine has_all ("shadowcopy","delete"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### The Gentlemen encryptor execution by known SHA256/SHA1 hash

`UC_2_21` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Endpoint.Processes.process_hash IN ("22b38dad7da097ea03aa28d0614164cd25fafeb1383dbc15047e34c8050f6f67","51b9f246d6da85631131fcd1fabf0a67937d4bdde33625a44f7ee6a3a7baebd2","025fc0976c548fb5a880c83ea3eb21a5f23c5d53c4e51e862bb893c11adf712a","3ab9575225e00a83a4ac2b534da5a710bdcf6eb72884944c437b5fbe5c5c9235","8ae6bd18b129061f63642531f1b684cf0383c75d","d605994fc72a2bb59b5cfb1624a1b9170eca73a2","5aa3124e5c4921e5edfc60133b5d71da21b07da3","a5cf917ec4a7dfbdfa43621398604805d860c718")) by Endpoint.Processes.dest Endpoint.Processes.user Endpoint.Processes.process_name Endpoint.Processes.process | `drop_dm_object_name(Endpoint.Processes)`
```

**Defender KQL:**
```kql
union
 (DeviceProcessEvents | where Timestamp > ago(30d)
   | where SHA256 in ("22b38dad7da097ea03aa28d0614164cd25fafeb1383dbc15047e34c8050f6f67","51b9f246d6da85631131fcd1fabf0a67937d4bdde33625a44f7ee6a3a7baebd2","025fc0976c548fb5a880c83ea3eb21a5f23c5d53c4e51e862bb893c11adf712a","3ab9575225e00a83a4ac2b534da5a710bdcf6eb72884944c437b5fbe5c5c9235")
      or SHA1 in ("8ae6bd18b129061f63642531f1b684cf0383c75d","d605994fc72a2bb59b5cfb1624a1b9170eca73a2","5aa3124e5c4921e5edfc60133b5d71da21b07da3","a5cf917ec4a7dfbdfa43621398604805d860c718")
   | project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, SHA1, ProcessCommandLine, Evt="ProcessExec"),
 (DeviceFileEvents | where Timestamp > ago(30d)
   | where SHA256 in ("22b38dad7da097ea03aa28d0614164cd25fafeb1383dbc15047e34c8050f6f67","51b9f246d6da85631131fcd1fabf0a67937d4bdde33625a44f7ee6a3a7baebd2","025fc0976c548fb5a880c83ea3eb21a5f23c5d53c4e51e862bb893c11adf712a","3ab9575225e00a83a4ac2b534da5a710bdcf6eb72884944c437b5fbe5c5c9235")
   | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, FileName, FolderPath, SHA256, SHA1, ProcessCommandLine=InitiatingProcessCommandLine, Evt="FileWrite")
| order by Timestamp desc
```

### The Gentlemen mass file encryption — .umc16h extension write/rename burst

`UC_2_22` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Endpoint.Filesystem.file_name="*.umc16h" by Endpoint.Filesystem.dest Endpoint.Filesystem.process_name _time span=5m | `drop_dm_object_name(Endpoint.Filesystem)` | where count > 50
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileRenamed","FileCreated","FileModified")
| where FileName endswith ".umc16h"
| summarize FileCount = dcount(FolderPath), FirstSeen = min(Timestamp), LastSeen = max(Timestamp), SampleProc = any(InitiatingProcessFileName), SamplePath = any(InitiatingProcessFolderPath), SampleCmd = any(InitiatingProcessCommandLine) by DeviceName, InitiatingProcessId, bin(Timestamp, 5m)
| where FileCount > 50   // 50 = bulk-encryption burst threshold in a 5m window
| order by FileCount desc
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

### Article-specific behavioural hunt — No Manners Here: The Ruthless Rise of The Gentlemen Ransomware

`UC_2_13` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — No Manners Here: The Ruthless Rise of The Gentlemen Ransomware ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("throttlestop.sys"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("throttlestop.sys"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — No Manners Here: The Ruthless Rise of The Gentlemen Ransomware
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("throttlestop.sys"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("throttlestop.sys"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `193.233.202.17`, `77.110.122.137`, `45.86.230.112`

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2024-55591`, `CVE-2025-32433`, `CVE-2025-33073`, `CVE-2025-55182`, `CVE-2025-7771`, `CVE-2023-27532`, `CVE-2024-37085`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `22b38dad7da097ea03aa28d0614164cd25fafeb1383dbc15047e34c8050f6f67`, `51b9f246d6da85631131fcd1fabf0a67937d4bdde33625a44f7ee6a3a7baebd2`, `025fc0976c548fb5a880c83ea3eb21a5f23c5d53c4e51e862bb893c11adf712a`, `3ab9575225e00a83a4ac2b534da5a710bdcf6eb72884944c437b5fbe5c5c9235`, `8ae6bd18b129061f63642531f1b684cf0383c75d`, `d605994fc72a2bb59b5cfb1624a1b9170eca73a2`, `5aa3124e5c4921e5edfc60133b5d71da21b07da3`, `a5cf917ec4a7dfbdfa43621398604805d860c718`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 23 use case(s) fired, 31 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

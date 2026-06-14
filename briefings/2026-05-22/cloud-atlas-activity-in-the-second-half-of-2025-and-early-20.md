# [CRIT] Cloud Atlas activity in the second half of 2025 and early 2026: new tools and a new payload

**Source:** Securelist (Kaspersky)
**Published:** 2026-05-22
**Article:** https://securelist.com/cloud-atlas-2026/119895/

## Threat Profile

Table of Contents
Technical details 
Initial infection 
Fixed.ps1 (loader) 
Fixed.ps1::Payload (VBCloud dropper) 
Fixed.ps1::Payload (PowerShower) 
PowerShower::Payload (credential grabber) 
Multi-user RDP by patching termsrv.dll 
Reverse SSH tunneling 
Patched OpenSSH 
RevSocks 
Tor tunneling 
PowerCloud 
Browser checker 
Victims 
Conclusion 
Indicators of compromise 
Domains and IPs 
File paths 
Authors
Kaspersky 
In 2025, we observed pervasive SSH tunnel activity, which has remained active in…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2018-0802`
- **IPv4 (defanged):** `194.102.104.207`
- **IPv4 (defanged):** `46.17.45.56`
- **IPv4 (defanged):** `46.17.45.49`
- **IPv4 (defanged):** `46.17.44.125`
- **IPv4 (defanged):** `46.17.44.212`
- **IPv4 (defanged):** `185.22.154.73`
- **IPv4 (defanged):** `194.87.196.163`
- **IPv4 (defanged):** `195.58.49.9`
- **IPv4 (defanged):** `93.125.114.193`
- **IPv4 (defanged):** `93.125.114.57`
- **IPv4 (defanged):** `45.87.219.116`
- **IPv4 (defanged):** `37.228.129.224`
- **IPv4 (defanged):** `185.53.179.136`
- **IPv4 (defanged):** `185.126.239.77`
- **IPv4 (defanged):** `5.181.21.75`
- **IPv4 (defanged):** `146.70.53.171`
- **IPv4 (defanged):** `45.15.65.134`
- **IPv4 (defanged):** `185.250.181.207`
- **IPv4 (defanged):** `81.30.105.71`
- **Domain (defanged):** `tenkoff.org`
- **Domain (defanged):** `cloudguide.in`
- **Domain (defanged):** `goverru.com`
- **Domain (defanged):** `kufar.org`
- **Domain (defanged):** `ultimatecore.net`
- **Domain (defanged):** `spbnews.net`
- **Domain (defanged):** `onedrivesupport.net`
- **Domain (defanged):** `amerikastaj.com`
- **Domain (defanged):** `bigbang.me`
- **Domain (defanged):** `paleturquoise-dragonfly-364512.hostingersite.com`
- **Domain (defanged):** `wizzifi.com`
- **Domain (defanged):** `totallegacy.org`
- **Domain (defanged):** `mamurjor.com`
- **Domain (defanged):** `landscapeuganda.com`
- **Domain (defanged):** `lafortunaitalian.co.uk`
- **Domain (defanged):** `kommando.live`
- **Domain (defanged):** `internationalcommoditiesllc.com`
- **Domain (defanged):** `humanitas.si`
- **Domain (defanged):** `fishingflytackle.com`
- **Domain (defanged):** `firsai.tipshub.net`
- **Domain (defanged):** `alnakhlah.com.sa`
- **Domain (defanged):** `allgoodsdirect.com.au`
- **Domain (defanged):** `agenciakharis.com.br`
- **Domain (defanged):** `istochnik.org`
- **Domain (defanged):** `znews.net`
- **Domain (defanged):** `investika-club.com`
- **MD5:** `1a11b26dd0261ef27a112ce8b361c247`
- **MD5:** `5329f7bff9d0d5db28821b86c26d628f`
- **MD5:** `7a95360b7e0eb5b107a3d231abbc541a`
- **MD5:** `c0d1eaa15a2cefbab9735787575c8d8e`
- **MD5:** `d5b38b252cf212a4a32763de36732d40`
- **MD5:** `3c75cedb1196df5eab91f31411ed4b33`
- **MD5:** `42ac350bfbc5b4eb0fedba16c81919c7`
- **MD5:** `493b901d1b33eb577db64aadd948f9ce`
- **MD5:** `2cabb721681455dae1b6a26709def453`
- **MD5:** `1b39e86eb772a0e40060b672b7f574f1`
- **MD5:** `1d401d6e6fc0b00aaa2c65a0ac0cfd6b`
- **MD5:** `40a562b8600f843b717bc5951b2e3c29`
- **MD5:** `f721a76deb28fd0b80d27fce6b8f5016`
- **MD5:** `d3c8afd22baa306ff659db1fac28574a`
- **MD5:** `6d7b2d1172bbdb7340972d844f6f0717`
- **MD5:** `9769f43b9de8d19e803263267fa6d62e`
- **MD5:** `63b6be9ae8d8024a40b200cccb438f1d`
- **MD5:** `6aa586bcc45ca2e92a4f0ef47e086fa1`
- **MD5:** `eba3bcdb19a7e256bf8e2cc5b9c1cca9`
- **MD5:** `b4e183627b7399006c1bc47b3711e419`
- **MD5:** `f56b31a4b47ad3365b18a7e922fba1a8`
- **MD5:** `f6f62456fb0fcc396fb654cbed339bc3`
- **MD5:** `25c8ed0511375dca57ef136ac3fa0cca`
- **MD5:** `2b4ba4facf8c299749771a3a4369782e`
- **MD5:** `ba9ce06641067742f2afc9691faff1dc`
- **MD5:** `fb0f8027acf1b1e47e07a63d8812ed50`
- **MD5:** `bbf1fa694122e07635deeac11ad712f8`
- **MD5:** `f301aa3d62b5095eec4d8e34201a4769`
- **MD5:** `f9c3bbe108566d1a6b070f9c5fb03160`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
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
- **T1027** — Obfuscated Files or Information
- **T1219** — Remote Access Software
- **T1053.005** — Persistence (article-specific)
- **T1547.001** — Persistence (article-specific)
- **T1070.004** — Indicator Removal: File Deletion
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1547.001** — Boot or Logon Autostart Execution: Registry Run Keys
- **T1564.001** — Hide Artifacts: Hidden Files and Directories
- **T1003.002** — OS Credential Dumping: Security Account Manager
- **T1003.004** — OS Credential Dumping: LSA Secrets
- **T1006** — Direct Volume Access
- **T1036.008** — Masquerading: Masquerade File Type
- **T1112** — Modify Registry
- **T1021.001** — Remote Services: Remote Desktop Protocol
- **T1547.014** — Boot or Logon Autostart Execution: Active Setup
- **T1572** — Protocol Tunneling
- **T1090.001** — Proxy: Internal Proxy
- **T1569.002** — System Services: Service Execution

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### PowerShell-parented taskkill of winrar.exe (Cloud Atlas LNK anti-forensic cleanup)

`UC_218_12` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=taskkill.exe Processes.process="*winrar.exe*" Processes.parent_process_name=powershell.exe by Processes.dest Processes.user Processes.process Processes.parent_process Processes.parent_process_name | `drop_dm_object_name(Processes)` | where match(process, "(?i)/F") OR match(process, "(?i)/IM") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "taskkill.exe"
| where ProcessCommandLine has "winrar.exe"
| where ProcessCommandLine has_any ("/F", "/IM")
| where InitiatingProcessFileName =~ "powershell.exe"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### PowerShower dropped to user Pictures folder as googleearth.ps1

`UC_218_13` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process="*Pictures*googleearth.ps1*" by Processes.dest Processes.user Processes.process Processes.process_name Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
union
(DeviceProcessEvents
  | where Timestamp > ago(14d)
  | where ProcessCommandLine has "googleearth.ps1"
  | where ProcessCommandLine has @"\Pictures\" or InitiatingProcessCommandLine has @"\Pictures\"
  | project Timestamp, DeviceName, AccountName, EventKind="Process", FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine),
(DeviceFileEvents
  | where Timestamp > ago(14d)
  | where FileName =~ "googleearth.ps1"
  | where FolderPath has @"\Pictures\"
  | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, EventKind="FileDrop", FileName, ProcessCommandLine=InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine)
| order by Timestamp desc
```

### SAM/SECURITY registry hives copied from VSS shadow to Public\Documents as .pdf

`UC_218_14` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process="*Public\\Documents*" Processes.process="*.pdf*" (Processes.process="*SAM*" OR Processes.process="*SECURITY*" OR Processes.process="*HarddiskVolumeShadowCopy*") by Processes.dest Processes.user Processes.process Processes.parent_process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where ProcessCommandLine has @"\Users\Public\Documents\" or InitiatingProcessCommandLine has @"\Users\Public\Documents\"
| where ProcessCommandLine has ".pdf" or InitiatingProcessCommandLine has ".pdf"
| where ProcessCommandLine has_any ("SAM", "SECURITY", "HarddiskVolumeShadowCopy", "Win32_ShadowCopy", "vssadmin")
   or InitiatingProcessCommandLine has_any ("SAM", "SECURITY", "HarddiskVolumeShadowCopy", "Win32_ShadowCopy", "vssadmin")
| where InitiatingProcessFileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe", "wmic.exe", "fodhelper.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### termsrv.dll patched (multi-RDP enabling) - takeown + binary write + TermService restart

`UC_218_15` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process="*termsrv.dll*" (Processes.process="*takeown*" OR Processes.process="*icacls*" OR Processes.process="*TermService*" OR Processes.process="*Restart-Service*" OR Processes.parent_process_name=powershell.exe) by Processes.dest Processes.user Processes.process Processes.parent_process Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
let TermsrvProc = DeviceProcessEvents
    | where Timestamp > ago(14d)
    | where ProcessCommandLine has "termsrv.dll"
    | where ProcessCommandLine has_any ("takeown", "icacls", "TermService", "Restart-Service", "Stop-Service", "net stop termservice", "sc ")
        or FileName in~ ("takeown.exe", "icacls.exe")
    | project Timestamp, DeviceName, AccountName, EventKind="Proc", FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine;
let TermsrvFileWrite = DeviceFileEvents
    | where Timestamp > ago(14d)
    | where FolderPath endswith @"\System32" and FileName =~ "termsrv.dll"
    | where ActionType in ("FileModified", "FileCreated", "FileRenamed")
    | where InitiatingProcessFileName !in~ ("TrustedInstaller.exe", "msiexec.exe", "TiWorker.exe")
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, EventKind="FileWrite", FileName, ProcessCommandLine=InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine;
union TermsrvProc, TermsrvFileWrite
| order by Timestamp desc
```

### OpenSSH reverse port-forward (-R) launched on a workstation - Cloud Atlas backup C2

`UC_218_16` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=ssh.exe Processes.process="* -R *" by Processes.dest Processes.user Processes.process Processes.parent_process Processes.parent_process_name | `drop_dm_object_name(Processes)` | where match(parent_process_name, "(?i)^(wscript|cscript|cmd|powershell|psexec|paexec|services)\.exe$") | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName =~ "ssh.exe"
| where ProcessCommandLine matches regex @"(?i)\s-R\s+\S+"
| where InitiatingProcessFileName in~ ("wscript.exe", "cscript.exe", "cmd.exe", "powershell.exe", "pwsh.exe", "psexec.exe", "psexec64.exe", "paexec.exe", "services.exe")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| join kind=leftouter (
    DeviceNetworkEvents
    | where Timestamp > ago(14d)
    | where InitiatingProcessFileName =~ "ssh.exe"
    | where RemotePort == 22 or RemotePort == 443
    | project NetTime=Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl
  ) on DeviceName
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

### Article-specific behavioural hunt — Cloud Atlas activity in the second half of 2025 and early 2026: new tools and a

`UC_218_11` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Cloud Atlas activity in the second half of 2025 and early 2026: new tools and a ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("fixed.ps1","termsrv.dll","winrar.exe","video.vbs","googleearth.ps1","fodhelper.exe","rdp_new.ps1","gen.vbs","writetoschedulergeneratekey.vbs","run.vbs","writetoschedulerrunssh.vbs","kill.vbs","writetoschedulerkillssh.vbs","libcrypto.dll","syruntime.dll") OR Processes.process_path="*C:\Users\Public\Documents\*" OR Processes.process_path="*C:\Windows\ime*" OR Processes.process_path="*C:\Windows\System32\ime*" OR Processes.process_path="*C:\Windows\pla*" OR Processes.process_path="*C:\Windows\inf*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*C:\Users\Public\Documents\*" OR Filesystem.file_path="*C:\Windows\ime*" OR Filesystem.file_path="*C:\Windows\System32\ime*" OR Filesystem.file_path="*C:\Windows\pla*" OR Filesystem.file_path="*C:\Windows\inf*" OR Filesystem.file_path="*C:\Windows\migration*" OR Filesystem.file_path="*C:\Windows\System32\timecontrolsvc*" OR Filesystem.file_path="*C:\Windows\SKB*" OR Filesystem.file_name IN ("fixed.ps1","termsrv.dll","winrar.exe","video.vbs","googleearth.ps1","fodhelper.exe","rdp_new.ps1","gen.vbs","writetoschedulergeneratekey.vbs","run.vbs","writetoschedulerrunssh.vbs","kill.vbs","writetoschedulerkillssh.vbs","libcrypto.dll","syruntime.dll"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Cloud Atlas activity in the second half of 2025 and early 2026: new tools and a
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("fixed.ps1", "termsrv.dll", "winrar.exe", "video.vbs", "googleearth.ps1", "fodhelper.exe", "rdp_new.ps1", "gen.vbs", "writetoschedulergeneratekey.vbs", "run.vbs", "writetoschedulerrunssh.vbs", "kill.vbs", "writetoschedulerkillssh.vbs", "libcrypto.dll", "syruntime.dll") or FolderPath has_any ("C:\Users\Public\Documents\", "C:\Windows\ime", "C:\Windows\System32\ime", "C:\Windows\pla", "C:\Windows\inf"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("C:\Users\Public\Documents\", "C:\Windows\ime", "C:\Windows\System32\ime", "C:\Windows\pla", "C:\Windows\inf", "C:\Windows\migration", "C:\Windows\System32\timecontrolsvc", "C:\Windows\SKB") or FileName in~ ("fixed.ps1", "termsrv.dll", "winrar.exe", "video.vbs", "googleearth.ps1", "fodhelper.exe", "rdp_new.ps1", "gen.vbs", "writetoschedulergeneratekey.vbs", "run.vbs", "writetoschedulerrunssh.vbs", "kill.vbs", "writetoschedulerkillssh.vbs", "libcrypto.dll", "syruntime.dll"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `194.102.104.207`, `46.17.45.56`, `46.17.45.49`, `46.17.44.125`, `46.17.44.212`, `185.22.154.73`, `194.87.196.163`, `195.58.49.9` _(+37 more)_

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2018-0802`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `1a11b26dd0261ef27a112ce8b361c247`, `5329f7bff9d0d5db28821b86c26d628f`, `7a95360b7e0eb5b107a3d231abbc541a`, `c0d1eaa15a2cefbab9735787575c8d8e`, `d5b38b252cf212a4a32763de36732d40`, `3c75cedb1196df5eab91f31411ed4b33`, `42ac350bfbc5b4eb0fedba16c81919c7`, `493b901d1b33eb577db64aadd948f9ce` _(+21 more)_


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 17 use case(s) fired, 33 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

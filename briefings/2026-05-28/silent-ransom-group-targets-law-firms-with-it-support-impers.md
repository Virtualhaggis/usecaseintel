# [CRIT] Silent Ransom Group Targets Law Firms With IT Support Impersonation Attacks

**Source:** Cyber Security News
**Published:** 2026-05-28
**Article:** https://cybersecuritynews.com/silent-ransom-group-targets-law-firms/

## Threat Profile

Home Cyber Security News 
Silent Ransom Group Targets Law Firms With IT Support Impersonation Attacks 
By Tushar Subhra Dutta 
May 28, 2026 
A threat group known as the Silent Ransom Group is actively targeting US-based law firms using a bold and deceptive social engineering playbook. 
Rather than deploying ransomware in the traditional sense, this group goes straight for the data and then turns it into a weapon against the very organizations it stole from. 
The Silent Ransom Group (SRG), also t…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `business-data-leaks.com`

## MITRE ATT&CK Techniques

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
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1071** — Application Layer Protocol
- **T1566.004** — Spearphishing Voice
- **T1567.002** — Exfiltration to Cloud Storage
- **T1036.005** — Match Legitimate Name or Location
- **T1048.002** — Exfiltration Over Asymmetric Encrypted Non-C2 Protocol
- **T1572** — Protocol Tunneling
- **T1657** — Financial Theft
- **T1071.001** — Application Layer Protocol: Web Protocols

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Silent Ransom Group / Luna Moth RMM Tool First-Time Execution

`UC_13_10` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where Processes.process_name IN ("msra.exe","quickassist.exe","AnyDesk.exe","RustDesk.exe","ZA_Connect.exe","ZA_Access.exe","Assist.exe","SplashtopStreamer.exe","SRClient.exe","SRManager.exe","AteraAgent.exe","AgentPackageRunCommandInteractive.exe","Kabuto.exe","Syncro.exe","SyncroLive.Agent.Service.exe") by Processes.dest Processes.user Processes.process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | join type=left dest process_name [| tstats summariesonly=true count as baseline_count from datamodel=Endpoint.Processes where earliest=-60d@d latest=-7d@d Processes.process_name IN ("msra.exe","quickassist.exe","AnyDesk.exe","RustDesk.exe","ZA_Connect.exe","ZA_Access.exe","Assist.exe","SplashtopStreamer.exe","SRClient.exe","SRManager.exe","AteraAgent.exe","AgentPackageRunCommandInteractive.exe","Kabuto.exe","Syncro.exe","SyncroLive.Agent.Service.exe") by Processes.dest Processes.process_name | `drop_dm_object_name(Processes)`] | where isnull(baseline_count)
```

**Defender KQL:**
```kql
let RmmBinaries = dynamic(["msra.exe","quickassist.exe","AnyDesk.exe","RustDesk.exe","ZA_Connect.exe","ZA_Access.exe","Assist.exe","SplashtopStreamer.exe","SRClient.exe","SRManager.exe","AteraAgent.exe","AgentPackageRunCommandInteractive.exe","Kabuto.exe","Syncro.exe","SyncroLive.Agent.Service.exe"]);
let Baseline = DeviceProcessEvents
    | where Timestamp between (ago(60d) .. ago(7d))
    | where FileName in~ (RmmBinaries)
    | summarize by DeviceName, FileName;
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ (RmmBinaries)
| where AccountName !endswith "$"
| join kind=leftanti Baseline on DeviceName, FileName
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName, SHA256
| order by Timestamp desc
```

### [LLM] Renamed Rclone Binary Identified by Exfil Cmdline Signature

`UC_13_11` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where Processes.process="*--config*" Processes.process="*--transfers*" (Processes.process="* copy *" OR Processes.process="* sync *" OR Processes.process="* move *" OR Processes.process="* lsd *" OR Processes.process="* lsf *") by Processes.dest Processes.user Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | where match(process, "(?i)\s\S+:\S*\s") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "--config"
     and ProcessCommandLine has "--transfers"
     and ProcessCommandLine has_any (" copy "," sync "," move "," lsd "," lsf "," check ")
| where ProcessCommandLine matches regex @"\s[A-Za-z0-9_-]+:[A-Za-z0-9/_\-\.]*"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName
| order by Timestamp desc
```

### [LLM] WinSCP / SFTP Outbound to Public IP on Port 22 from Endpoint

`UC_13_12` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count sum(All_Traffic.bytes_out) as bytes_out values(All_Traffic.app) as app from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port=22 (All_Traffic.app="winscp.exe" OR All_Traffic.process_name="winscp.exe") NOT (All_Traffic.dest IN ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16")) by All_Traffic.src All_Traffic.user All_Traffic.dest All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)` | where bytes_out > 1048576
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "WinSCP.exe"
| where RemotePort == 22
| where RemoteIPType == "Public"
| where InitiatingProcessAccountName !endswith "$"
| summarize ConnectionCount = count(),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            RemoteIPs = make_set(RemoteIP, 50)
            by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by LastSeen desc
```

### [LLM] DNS / Proxy Resolution of SRG Leak Site business-data-leaks[.]com

`UC_13_13` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(DNS.query) as queries from datamodel=Network_Resolution.DNS where DNS.query="*business-data-leaks.com*" OR DNS.query="*business-data-leaks*" by DNS.src DNS.dest DNS.query | `drop_dm_object_name(DNS)` | convert ctime(firstTime) ctime(lastTime) | append [| tstats summariesonly=true count from datamodel=Web.Web where Web.url="*business-data-leaks.com*" by Web.src Web.user Web.url | `drop_dm_object_name(Web)`]
```

**Defender KQL:**
```kql
union
  (DeviceNetworkEvents
    | where Timestamp > ago(90d)
    | where RemoteUrl has "business-data-leaks.com"
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, InitiatingProcessFileName, RemoteUrl, RemoteIP, Source="DeviceNetworkEvents"),
  (DeviceEvents
    | where Timestamp > ago(90d)
    | where ActionType == "DnsQueryResponse" and AdditionalFields has "business-data-leaks.com"
    | project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, RemoteUrl="business-data-leaks.com", AdditionalFields, Source="DeviceEvents")
| order by Timestamp desc
```

### [LLM] Rclone / WinSCP Beaconing to OneDrive or Google Drive (Cloud Exfil Chain)

`UC_13_14` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count sum(All_Traffic.bytes_out) as bytes_out from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_host="*onedrive.live.com" OR All_Traffic.dest_host="*drive.google.com" OR All_Traffic.dest_host="*docs.google.com") (All_Traffic.app IN ("rclone.exe","winscp.exe") OR All_Traffic.process_name IN ("rclone.exe","winscp.exe")) by All_Traffic.src All_Traffic.user All_Traffic.app All_Traffic.dest_host | `drop_dm_object_name(All_Traffic)` | where bytes_out > 10485760
```

**Defender KQL:**
```kql
let CloudHosts = dynamic(["onedrive.live.com","drive.google.com","docs.google.com","graph.microsoft.com"]);
let ExfilBinaries = dynamic(["rclone.exe","winscp.exe","WinSCP.com"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has_any (CloudHosts)
| where InitiatingProcessFileName in~ (ExfilBinaries)
     or InitiatingProcessCommandLine has_all ("--config","--transfers")
| where InitiatingProcessAccountName !endswith "$"
| summarize ConnectionCount = count(),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            Destinations = make_set(RemoteUrl, 20),
            SampleCmd = any(InitiatingProcessCommandLine)
            by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessParentFileName
| order by LastSeen desc
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `business-data-leaks.com`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 15 use case(s) fired, 24 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

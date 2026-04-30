# [CRIT] ESET APT Activity Report Q2 2025–Q3 2025

**Source:** ESET WeLiveSecurity
**Published:** 2025-11-06
**Article:** https://www.welivesecurity.com/en/eset-research/eset-apt-activity-report-q2-2025-q3-2025/

## Threat Profile

ESET APT Activity Report Q2 2025–Q3 2025 summarizes notable activities of selected advanced persistent threat (APT) groups that were documented by ESET researchers from April through September 2025. The highlighted operations are representative of the broader landscape of threats we investigated during this period. They illustrate the key trends and developments and contain only a small fraction of the cybersecurity intelligence data provided to customers of ESET APT reports.
During the monitore…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1219** — Remote Access Software
- **T1203** — Exploitation for Client Execution
- **T1547.001** — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- **T1564.004** — Hide Artifacts: NTFS File Attributes
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1021.001** — Remote Services: Remote Desktop Protocol
- **T1090.003** — Proxy: Multi-hop Proxy (Tor)

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] RomCom CVE-2025-8088 WinRAR ADS path-traversal drops payload into Startup

`UC_301_6` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_name) as file_name values(Filesystem.file_path) as file_path values(Filesystem.file_hash) as file_hash from datamodel=Endpoint.Filesystem where (Filesystem.process_name IN ("WinRAR.exe","Rar.exe","UnRAR.exe","7zFM.exe","WinRAR.SFX.exe") AND (Filesystem.file_path="*\\Start Menu\\Programs\\Startup\\*" OR Filesystem.file_path="*\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*") AND (Filesystem.file_name="*.lnk" OR Filesystem.file_name="*.exe" OR Filesystem.file_name="*.dll" OR Filesystem.file_name="*.cmd" OR Filesystem.file_name="*.bat")) OR Filesystem.file_name IN ("Adverse_Effect_Medical_Records_2025.rar","cv_submission.rar","JobDocs_July2025.rar","Recruitment_Dossier_July_2025.rar") OR Filesystem.file_hash IN ("371A5B8BA86FBCAB80D4E0087D2AA0D8FFDDC70B","D43F49E6A586658B5422EDC647075FFD405D6741") by Filesystem.dest Filesystem.user Filesystem.process_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let romcom_archives = dynamic(["Adverse_Effect_Medical_Records_2025.rar","cv_submission.rar","JobDocs_July2025.rar","Recruitment_Dossier_July_2025.rar"]);
let romcom_hashes = dynamic(["371a5b8ba86fbcab80d4e0087d2aa0d8ffddc70b","d43f49e6a586658b5422edc647075ffd405d6741"]);
let rar_procs = dynamic(["winrar.exe","rar.exe","unrar.exe","7zfm.exe","winrar.sfx.exe"]);
DeviceFileEvents
| where (InitiatingProcessFileName in~ (rar_procs)
         and FolderPath has @"\Start Menu\Programs\Startup\"
         and FileName endswith_cs ".lnk" or FileName endswith_cs ".exe" or FileName endswith_cs ".dll" or FileName endswith_cs ".cmd" or FileName endswith_cs ".bat")
   or FileName in~ (romcom_archives)
   or tolower(SHA1) in (romcom_hashes)
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, FolderPath, SHA1, SHA256, ActionType
```

### [LLM] InedibleOchotense fake-ESET installer beaconing to spoofed esetsmart/esetscanner/esetremover domains

`UC_301_7` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
(| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query IN ("esetsmart.com","esetscanner.com","esetremover.com","*.esetsmart.com","*.esetscanner.com","*.esetremover.com") by DNS.src DNS.query DNS.answer | `drop_dm_object_name(DNS)`) 
| append [| tstats `summariesonly` count from datamodel=Web.Web where Web.url IN ("*esetsmart.com*","*esetscanner.com*","*esetremover.com*") by Web.src Web.dest Web.url Web.user | `drop_dm_object_name(Web)`] 
| append [| tstats `summariesonly` count from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("ESETAVRemover.exe","ESETOnlineScanner.exe","esetsmart*.exe","esetscanner*.exe","esetremover*.exe") AND (Processes.process_name IN ("reg.exe","powershell.exe","cmd.exe","sc.exe","netsh.exe","ssh.exe","sshd.exe") OR Processes.process="*fDenyTSConnections*" OR Processes.process="*OpenSSH*" OR Processes.process="*Add-WindowsCapability*OpenSSH*" OR Processes.process="*Tor*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)`]
```

**Defender KQL:**
```kql
let spoofed = dynamic(["esetsmart.com","esetscanner.com","esetremover.com"]);
let net = DeviceNetworkEvents
| where RemoteUrl has_any (spoofed) or tolower(RemoteUrl) endswith "esetsmart.com" or tolower(RemoteUrl) endswith "esetscanner.com" or tolower(RemoteUrl) endswith "esetremover.com"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, ActionType;
let kalambur_post = DeviceProcessEvents
| where InitiatingProcessFileName matches regex @"(?i)^eset(smart|scanner|remover|avremover|onlinescanner).*\.exe$"
      or InitiatingProcessParentFileName matches regex @"(?i)^eset(smart|scanner|remover).*\.exe$"
| where ProcessCommandLine has_any ("fDenyTSConnections","Add-WindowsCapability","OpenSSH","sshd","netsh advfirewall firewall add rule","3389","Tor")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine;
let rdp_reg = DeviceRegistryEvents
| where RegistryKey has @"\CurrentControlSet\Control\Terminal Server" and RegistryValueName == "fDenyTSConnections" and RegistryValueData == "0"
| where InitiatingProcessFileName matches regex @"(?i)^eset(smart|scanner|remover).*\.exe$"
| project Timestamp, DeviceName, InitiatingProcessFileName, RegistryKey, RegistryValueName, RegistryValueData;
union net, kalambur_post, rdp_reg
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
| where FileName in~ ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
   or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:")
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
| where FileName in~ ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe")
   or FileName matches regex @"(?i)kaseya.*\.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```


## Why this matters

Severity classified as **CRIT** based on: 8 use case(s) fired, 17 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

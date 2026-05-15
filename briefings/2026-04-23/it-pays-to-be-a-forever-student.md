# [CRIT] It pays to be a forever student

**Source:** Cisco Talos
**Published:** 2026-04-23
**Article:** https://blog.talosintelligence.com/it-pays-to-be-a-forever-student/

## Threat Profile

It pays to be a forever student 
By 
Joe Marshall 
Thursday, April 23, 2026 14:00
Threat Source newsletter
Welcome to this week’s edition of the Threat Source newsletter. 
If I haven’t said it in a newsletter before, I'll say it now: If you want to be good at cybersecurity, be a forever student. Cultivating and feeding your desire to know how things work is one of the key ingredients to being a hacker. It’s not always about understanding the micro details, but the macro of how systems work. And …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-20333`
- **CVE:** `CVE-2025-20362`
- **SHA256:** `9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507`
- **SHA256:** `96fa6a7714670823c83099ea01d24d6d3ae8fef027f01a4ddac14f123b1c9974`
- **SHA256:** `90b1456cdbe6bc2779ea0b4736ed9a998a71ae37390331b6ba87e389a49d3d59`
- **SHA256:** `5e6060df7e8114cb7b412260870efd1dc05979454bd907d8750c669ae6fcbcfe`
- **SHA256:** `3c1dbc3f56e91cc79f0014850e773a7f12bbfef06680f08f883b2bf12873eccc`
- **MD5:** `2915b3f8b703eb744fc54c81f4a9c67f`
- **MD5:** `aac3165ece2959f39ff98334618d10d9`
- **MD5:** `c2efb2dcacba6d3ccc175b6ce1b7ed0a`
- **MD5:** `a2cf85d22a54e26794cbc7be16840bb1`
- **MD5:** `d749e0f8f2cd4e14178a787571534121`

## MITRE ATT&CK Techniques

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
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1219** — Remote Access Software
- **T1027** — Obfuscated Files or Information
- **T1566.002** — Phishing: Spearphishing Link
- **T1656** — Impersonation
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1083** — File and Directory Discovery
- **T1526** — Cloud Service Discovery
- **T1564.006** — Hide Artifacts: Run Virtual Instance

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Inbound email link to Softr-hosted credential harvesting page (UAT Q1 2026)

`UC_247_11` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Email.subject) as subject values(All_Email.src_user) as src_user values(All_Email.recipient) as recipient values(All_Email.url) as url from datamodel=Email where All_Email.direction="inbound" All_Email.action="delivered" (All_Email.url="*.softr.app*" OR All_Email.url="*softr.io*") by All_Email.message_id All_Email.recipient | `drop_dm_object_name(All_Email)` | join type=inner message_id [| tstats `summariesonly` count values(Web.user) as click_user values(Web.url) as clicked_url min(_time) as click_time from datamodel=Web where (Web.url="*.softr.app*" OR Web.url="*softr.io*") Web.action IN ("allowed","clickthrough") by Web.message_id | `drop_dm_object_name(Web)` | rename message_id as message_id]
```

**Defender KQL:**
```kql
let LookbackDays = 7d;
let SoftrEmails = EmailEvents
    | where Timestamp > ago(LookbackDays)
    | where EmailDirection == "Inbound"
    | where DeliveryAction in ("Delivered","DeliveredAsSpam")
    | join kind=inner (
        EmailUrlInfo
        | where Timestamp > ago(LookbackDays)
        | where UrlDomain endswith ".softr.app"
           or UrlDomain endswith "softr.io"
           or Url has_any ("softr.app","softr.io")
        | project NetworkMessageId, Url, UrlDomain
      ) on NetworkMessageId
    | project NetworkMessageId, EmailTime = Timestamp, SenderFromAddress,
              RecipientEmailAddress, Subject, Url, UrlDomain;
UrlClickEvents
| where Timestamp > ago(LookbackDays)
| where ActionType in ("ClickAllowed","ClickedThrough")
| where Url has_any ("softr.app","softr.io")
| join kind=leftouter SoftrEmails on NetworkMessageId
| project Timestamp, AccountUpn, ActionType, IsClickedThrough, Url,
          UrlDomain, SenderFromAddress, Subject, EmailTime, NetworkMessageId
| order by Timestamp desc
```

### [LLM] TruffleHog secret-scanning binary executed on endpoint by non-developer account

`UC_247_12` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process_name) as parent values(Processes.process_path) as path from datamodel=Endpoint.Processes where (Processes.process_name="trufflehog*" OR Processes.process="*trufflehog*" OR Processes.process IN ("*trufflehog git *","*trufflehog github *","*trufflehog gitlab *","*trufflehog s3 *","*trufflehog gcs *","*trufflehog filesystem *","*trufflehog docker *")) Processes.user!="*$" by host Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where AccountName !endswith "$"
| where AccountName !in~ ("system","local service","network service")
| where FileName =~ "trufflehog.exe"
   or FileName =~ "trufflehog"
   or ProcessCommandLine matches regex @"(?i)(^|[\s\\"/])trufflehog(\.exe)?(\s|$)"
   or ProcessCommandLine has_any (
       "trufflehog git ","trufflehog github","trufflehog gitlab",
       "trufflehog s3 ","trufflehog gcs ","trufflehog filesystem",
       "trufflehog docker","trufflehog circleci","trufflehog jenkins")
| project Timestamp, DeviceName, AccountName,
          FileName, FolderPath, SHA256,
          ProcessCommandLine,
          ParentFile = InitiatingProcessFileName,
          ParentCmd  = InitiatingProcessCommandLine,
          IsRemoteSession = InitiatingProcessTokenElevation
| order by Timestamp desc
```

### [LLM] QEMU machine emulator launched on user-class Windows endpoint (ransomware hidden-VM staging)

`UC_247_13` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.process_path) as path values(Processes.parent_process_name) as parent values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.process_name IN ("qemu-system-x86_64.exe","qemu-system-i386.exe","qemu-system-aarch64.exe","qemu-system-arm.exe","qemu-img.exe") OR Processes.process="*qemu-system-*" OR Processes.process IN ("* -hda *","* -drive file=*","* -netdev *")) Processes.user!="*$" by host Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | where match(process,"(?i)qemu")
```

**Defender KQL:**
```kql
let _vm_host_groups = dynamic(["VM-Hosts","DevWorkstations-Virt"]);
let _vm_hosts = DeviceInfo
    | where Timestamp > ago(1d)
    | where MachineGroup in (_vm_host_groups)
    | summarize by DeviceName;
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where DeviceName !in (_vm_hosts)
| where FileName matches regex @"(?i)^qemu-system-.*\.exe$"
   or FileName =~ "qemu-img.exe"
   or FileName =~ "qemu-ga.exe"
   or ProcessCommandLine has_any ("qemu-system-x86_64","qemu-system-i386",
                                  "qemu-system-aarch64","qemu-system-arm")
   or ProcessCommandLine matches regex @"(?i)\s-hda\s|\s-drive\s+file=|\s-netdev\s"
| project Timestamp, DeviceName, AccountName,
          FileName, FolderPath, SHA256,
          ProcessCommandLine,
          ParentFile = InitiatingProcessFileName,
          ParentCmd  = InitiatingProcessCommandLine,
          ParentSHA  = InitiatingProcessSHA256
| order by Timestamp desc
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

### Article-specific behavioural hunt — It pays to be a forever student

`UC_247_10` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — It pays to be a forever student ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("vid001.exe","d4aa3e7010220ad1b458fac17039c274_63_exe.exe","apq9305.dll","a2cf85d22a54e26794cbc7be16840bb1.exe","kitchencanvas_753447.exe"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("vid001.exe","d4aa3e7010220ad1b458fac17039c274_63_exe.exe","apq9305.dll","a2cf85d22a54e26794cbc7be16840bb1.exe","kitchencanvas_753447.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — It pays to be a forever student
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("vid001.exe", "d4aa3e7010220ad1b458fac17039c274_63_exe.exe", "apq9305.dll", "a2cf85d22a54e26794cbc7be16840bb1.exe", "kitchencanvas_753447.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("vid001.exe", "d4aa3e7010220ad1b458fac17039c274_63_exe.exe", "apq9305.dll", "a2cf85d22a54e26794cbc7be16840bb1.exe", "kitchencanvas_753447.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2025-20333`, `CVE-2025-20362`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507`, `96fa6a7714670823c83099ea01d24d6d3ae8fef027f01a4ddac14f123b1c9974`, `90b1456cdbe6bc2779ea0b4736ed9a998a71ae37390331b6ba87e389a49d3d59`, `5e6060df7e8114cb7b412260870efd1dc05979454bd907d8750c669ae6fcbcfe`, `3c1dbc3f56e91cc79f0014850e773a7f12bbfef06680f08f883b2bf12873eccc`, `2915b3f8b703eb744fc54c81f4a9c67f`, `aac3165ece2959f39ff98334618d10d9`, `c2efb2dcacba6d3ccc175b6ce1b7ed0a` _(+2 more)_


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 14 use case(s) fired, 22 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

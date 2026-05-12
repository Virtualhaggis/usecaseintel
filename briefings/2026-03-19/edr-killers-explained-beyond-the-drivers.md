# [CRIT] EDR killers explained: Beyond the drivers

**Source:** ESET WeLiveSecurity
**Published:** 2026-03-19
**Article:** https://www.welivesecurity.com/en/eset-research/edr-killers-explained-beyond-the-drivers/

## Threat Profile

EDR killers explained: Beyond the drivers 
ESET Research
EDR killers explained: Beyond the drivers ESET researchers dive deeper into the EDR killer ecosystem, disclosing how attackers abuse vulnerable drivers
Jakub Souček 
19 Mar 2026 
 •  
, 
24 min. read 
In recent years, EDR killers have become one of the most commonly seen tools in modern ransomware intrusions: an attacker acquires high privileges, deploys such a tool to disrupt protection, and only then launches the encryptor. Besides the d…

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
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1543.003** — Persistence (article-specific)
- **T1068** — Exploitation for Privilege Escalation
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1014** — Rootkit
- **T1562.004** — Impair Defenses: Disable or Modify System Firewall
- **T1055** — Process Injection

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] BYOVD: Genshin Impact mhyprot.sys driver dropped/loaded outside legitimate game install (Embargo evil-mhyprot-cli)

`UC_267_9` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action=created AND Filesystem.file_name IN ("mhyprot.sys","mhyprot2.sys") by host Filesystem.file_path Filesystem.file_name Filesystem.process_guid Filesystem.user | `drop_dm_object_name(Filesystem)` | search NOT (file_path="*\\Genshin Impact\\*" OR file_path="*\\miHoYo\\*" OR file_path="*\\HoYoPlay\\*") | append [| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where Registry.registry_path="*\\CurrentControlSet\\Services\\mhyprot*" by host Registry.registry_path Registry.registry_value_name Registry.registry_value_data Registry.process_guid | `drop_dm_object_name(Registry)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let _legit_paths = dynamic([@"\Genshin Impact\", @"\miHoYo\", @"\HoYoPlay\"]);
union
(
  DeviceFileEvents
  | where Timestamp > ago(30d)
  | where ActionType == "FileCreated"
  | where FileName in~ ("mhyprot.sys","mhyprot2.sys")
  | where not(FolderPath has_any (_legit_paths))
  | project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256,
            InitiatingProcessFileName, InitiatingProcessCommandLine,
            InitiatingProcessAccountName, Source="FileWrite"
),
(
  DeviceRegistryEvents
  | where Timestamp > ago(30d)
  | where ActionType in ("RegistryValueSet","RegistryKeyCreated")
  | where RegistryKey has @"\CurrentControlSet\Services\mhyprot"
      or (RegistryValueName =~ "ImagePath" and RegistryValueData has_any ("mhyprot.sys","mhyprot2.sys"))
  | project Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData,
            InitiatingProcessFileName, InitiatingProcessCommandLine,
            InitiatingProcessAccountName, Source="ServiceReg"
)
| order by Timestamp desc
```

### [LLM] EDRSilencer-style WFP filter blocking outbound traffic from named EDR binaries

`UC_267_10` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="EDRSilencer.exe" OR (Processes.process_name IN ("netsh.exe","powershell.exe","pwsh.exe") AND Processes.process IN ("*FwpmFilterAdd*","*Add-NetFirewallRule*MsSense*","*Add-NetFirewallRule*MsMpEng*","*New-NetFirewallRule*Block*Outbound*MsSense*","*FwpmEngineOpen*"))) by host Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | append [search source="WinEventLog:Security" EventCode=5157 (Application="*\\MsMpEng.exe" OR Application="*\\MsSense.exe" OR Application="*\\SentinelAgent.exe" OR Application="*\\CSFalconService.exe" OR Application="*\\ekrn.exe" OR Application="*\\elastic-agent.exe" OR Application="*\\xagt.exe" OR Application="*\\CarbonBlack*" OR Application="*\\bdservicehost.exe") | bin _time span=10m | stats count dc(Application) as edr_binaries values(Application) as Apps by host _time | where count>20 OR edr_binaries>=2] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let _edr_binaries = dynamic(["MsMpEng.exe","MsSense.exe","MsSenseS.exe","SenseIR.exe","SentinelAgent.exe","SentinelServiceHost.exe","CSFalconService.exe","CSFalconContainer.exe","ekrn.exe","egui.exe","elastic-agent.exe","xagt.exe","cb.exe","RepMgr.exe","bdservicehost.exe","cyserver.exe","cytray.exe","qualysagent.exe","TmListen.exe","PccNTMon.exe"]);
let _edr_binaries_lower = _edr_binaries | mv-apply b=_edr_binaries to typeof(string) on (project tolower(b));
union
(
  // Direct execution of the EDRSilencer tool / clones
  DeviceProcessEvents
  | where Timestamp > ago(7d)
  | where FileName =~ "EDRSilencer.exe"
     or ProcessCommandLine has_any ("FwpmFilterAdd0","FwpmEngineOpen0")
     or (FileName in~ ("powershell.exe","pwsh.exe") and ProcessCommandLine has_all ("New-NetFirewallRule","Block","Outbound") and ProcessCommandLine has_any (_edr_binaries))
     or (FileName =~ "netsh.exe" and ProcessCommandLine has "wfp" and ProcessCommandLine has "add")
  | project Timestamp, DeviceName, AccountName, FileName,
            ProcessCommandLine, InitiatingProcessFileName,
            InitiatingProcessCommandLine, Source="ToolExec"
),
(
  // Non-EDR processes loading the WFP user-mode client (FWPUCLNT.DLL) - rare outside Defender/firewall control panel
  DeviceImageLoadEvents
  | where Timestamp > ago(7d)
  | where FileName =~ "FWPUCLNT.DLL"
  | where InitiatingProcessFolderPath !startswith @"C:\Windows\"
      and InitiatingProcessFolderPath !startswith @"C:\Program Files\"
  | where InitiatingProcessFileName !in~ ("netsh.exe","MsMpEng.exe","svchost.exe","explorer.exe","mmc.exe","WerFault.exe")
  | project Timestamp, DeviceName, InitiatingProcessFileName,
            InitiatingProcessFolderPath, InitiatingProcessCommandLine,
            InitiatingProcessAccountName, Source="WfpDllLoad"
)
| order by Timestamp desc
```

### [LLM] EDR-Freeze: WerFaultSecure.exe abused to suspend AV/EDR processes via MiniDumpWriteDump race

`UC_267_11` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="WerFaultSecure.exe" AND NOT Processes.parent_process_name IN ("svchost.exe","wermgr.exe","WerFault.exe","services.exe","smss.exe","csrss.exe","taskhostw.exe") by host Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process Processes.process_id | `drop_dm_object_name(Processes)` | search (process="*/dump*" OR process="*-pid*" OR process="* /shared *" OR process="*MiniDumpWriteDump*") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let _trusted_wer_parents = dynamic(["svchost.exe","wermgr.exe","werfault.exe","services.exe","smss.exe","csrss.exe","taskhostw.exe","sihost.exe"]);
let WerFaultSpawn =
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName =~ "WerFaultSecure.exe"
    | where InitiatingProcessFileName !in~ (_trusted_wer_parents)
    | where AccountName !endswith "$"
    | project Timestamp, DeviceName, AccountName,
              ParentImage = InitiatingProcessFileName,
              ParentCmd = InitiatingProcessCommandLine,
              ParentFolder = InitiatingProcessFolderPath,
              ChildCmd = ProcessCommandLine,
              ChildPid = ProcessId, Signal="WerFaultSecure_unusual_parent";
let SuspendOnWer =
    DeviceEvents
    | where Timestamp > ago(7d)
    | where ActionType in ("OpenProcessApiCall","SuspendThread","ProcessPrimaryTokenModified")
    | where FileName =~ "WerFaultSecure.exe"      // target was WerFaultSecure
    | where InitiatingProcessFileName !in~ (_trusted_wer_parents)
    | where InitiatingProcessFolderPath !startswith @"C:\Windows\System32"
    | project Timestamp, DeviceName, ActionType,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              InitiatingProcessFolderPath, InitiatingProcessAccountName,
              Signal="Suspend_against_WerFaultSecure";
union WerFaultSpawn, SuspendOnWer
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

### Article-specific behavioural hunt — EDR killers explained: Beyond the drivers

`UC_267_8` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — EDR killers explained: Beyond the drivers ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("aswarpot.sys","k7rkscan.sys","bdapiutil.sys","tfsysmon.sys","hwrwdrv.sys","throttlestop.sys","truesight.sys","enportv.sys","2gk8.exe","smuot.sys","edr-freeze.exe","killer.exe","edrgay.exe","susanoo.exe","vmtools.exe"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("aswarpot.sys","k7rkscan.sys","bdapiutil.sys","tfsysmon.sys","hwrwdrv.sys","throttlestop.sys","truesight.sys","enportv.sys","2gk8.exe","smuot.sys","edr-freeze.exe","killer.exe","edrgay.exe","susanoo.exe","vmtools.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — EDR killers explained: Beyond the drivers
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("aswarpot.sys", "k7rkscan.sys", "bdapiutil.sys", "tfsysmon.sys", "hwrwdrv.sys", "throttlestop.sys", "truesight.sys", "enportv.sys", "2gk8.exe", "smuot.sys", "edr-freeze.exe", "killer.exe", "edrgay.exe", "susanoo.exe", "vmtools.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("aswarpot.sys", "k7rkscan.sys", "bdapiutil.sys", "tfsysmon.sys", "hwrwdrv.sys", "throttlestop.sys", "truesight.sys", "enportv.sys", "2gk8.exe", "smuot.sys", "edr-freeze.exe", "killer.exe", "edrgay.exe", "susanoo.exe", "vmtools.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **CRIT** based on: 12 use case(s) fired, 20 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

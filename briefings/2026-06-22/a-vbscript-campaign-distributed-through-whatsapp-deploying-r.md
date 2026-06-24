# [HIGH] A VBScript campaign distributed through WhatsApp deploying RMM software

**Source:** Securelist (Kaspersky)
**Published:** 2026-06-22
**Article:** https://securelist.com/whatsapp-vbs-rmm-campaign/120290/

## Threat Profile

Table of Contents
Social engineering through financial-themed file names 
Delivery of the initial VBScript file 
Technical analysis 
Stage 1: Initial VBScript execution 
Stage 2: Execution of secondary VBScript payloads 
VBS script 1: UAC configuration modification 
VBS script 2: ZIP download and script execution 
Stage 3: Installation of remote monitoring and management software 
Victimology and attribution 
Conclusion 
IOCs 
VBScript 
Domains 
Attacker-controlled UEMS server IP Address 
Author…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `202.61.160.208`
- **IPv4 (defanged):** `202.61.160.202`
- **IPv4 (defanged):** `202.61.160.201`
- **IPv4 (defanged):** `202.61.160.160`
- **IPv4 (defanged):** `202.61.160.137`
- **IPv4 (defanged):** `38.55.151.63`
- **Domain (defanged):** `temu.baskwms.top`
- **Domain (defanged):** `invoice.msopsa.top`
- **Domain (defanged):** `baoxis.cc`
- **Domain (defanged):** `sdcwww.oss-ap-southeast-1.aliyuncs.com`
- **MD5:** `c7f38cbb99c8b74fa0465293feeba700`
- **MD5:** `b7cd06c71465038b658a6dc1f273a507`
- **MD5:** `9f13c7b8ba391b2f597874e54d310648`
- **MD5:** `993f4c0cadbc769a4b0ed62a918db58d`
- **MD5:** `7f81c1bc8cfd588e8998968e2621456e`
- **MD5:** `7403cbcc5a9c32384d431856dc48fcc9`
- **MD5:** `68c16c46f8afb9e00bbaba0207fb0a46`
- **MD5:** `66442f2457eca8f47385b1fb2c6fcab8`
- **MD5:** `6359e6236471cbe434d0ef4c42b7f879`
- **MD5:** `5b6bbcc06cf08cc99e1afeda486d42fb`
- **MD5:** `5002eca748205d544618e3bd2dedc223`
- **MD5:** `4f0593e8e0e8fac49429e9b45ebf7fa1`
- **MD5:** `4044e4b6471c9de7b0a4ba37d9d9df9a`
- **MD5:** `20209b3a32769afc6a75694b8d8839dd`
- **MD5:** `0ba93109757776a44de9d8c88baa4963`
- **MD5:** `02bb20455cc592a69c080abac770ce90`
- **MD5:** `6c39900d77dcba158e1d27c7619cb06d`
- **MD5:** `dad708e050632a4280cabf98ac1376b7`
- **MD5:** `05d188f071d097f5b6bd8138749b4b14`
- **MD5:** `2c6f05f1f309d89b2236e6c8b59c88f9`
- **MD5:** `3b1aba44dd3d9b6339b6f56e2f42034b`
- **MD5:** `d43fdaa1f0ee09d7e5f0f94ee9df7b6c`
- **MD5:** `df4fa0369eaca5cec348be293890d4af`
- **MD5:** `63ac85195b73753333316a889cf5880f`
- **MD5:** `74fd9f91fc93b6288b4fc253ea5b3e20`
- **MD5:** `d06333c360b51456f427e616c3c5f8bd`
- **MD5:** `1d94fbe9cab21278cc3f104bea334d08`
- **MD5:** `9d9ac85765e4a818a3ccabe2cf4fef82`
- **MD5:** `6fb6a55424adfb61e31f06aef33273e5`
- **MD5:** `f90ed4b2d0b67114aa89ddfed658e5c0`
- **MD5:** `8c3322009b8982663c0cbecd9492e7eb`
- **MD5:** `66705384a7ad81d14c34fc6c054a0ecf`
- **MD5:** `8c6d9fc389ad3f20ccbc71d77eb39bfa`
- **MD5:** `1a3cc75466ffb1971482f7abf7aabc3f`
- **MD5:** `1c47c63e5ed25060d95359c57c77b107`
- **MD5:** `31037a42ca048e06e69a78f55bc2eff5`
- **MD5:** `7f16449cd0c4862d1eadf8a5742bf09a`
- **MD5:** `79ecd61b09b0f2d54b34586c916c4ec9`
- **MD5:** `7849061c536a3efb05a56d504694e7e7`
- **MD5:** `ddaffe9849f7f3c79f8804adb9a6b3d5`
- **MD5:** `d01cad98dd0d01b75e04e784953c5e2b`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.001** — PowerShell
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1027** — Obfuscated Files or Information
- **T1219** — Remote Access Software

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

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

### Article-specific behavioural hunt — A VBScript campaign distributed through WhatsApp deploying RMM software

`UC_40_7` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — A VBScript campaign distributed through WhatsApp deploying RMM software ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("reports.vbs","confirmation.vbs","list.vbs","statement.vbs","aus.vbs","bank.vbs","anda.vbs","whatsapp.root.exe","curl.exe","setup1.vbs","setup.bat","uemsagent.msi","form.vbs","applicationform1.vbs","sheet.vbs") OR Processes.process_path="*C:\Windows\System32\WScript.exe*" OR Processes.process_path="*\AppData\Local\Packages\5319275A.WhatsAppDesktop_cv1g1gvanyjgm\LocalState\Sessions\*" OR Processes.process_path="*C:\Users\Public\Documents\*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*C:\Windows\System32\WScript.exe*" OR Filesystem.file_path="*\AppData\Local\Packages\5319275A.WhatsAppDesktop_cv1g1gvanyjgm\LocalState\Sessions\*" OR Filesystem.file_path="*C:\Users\Public\Documents\*" OR Filesystem.file_name IN ("reports.vbs","confirmation.vbs","list.vbs","statement.vbs","aus.vbs","bank.vbs","anda.vbs","whatsapp.root.exe","curl.exe","setup1.vbs","setup.bat","uemsagent.msi","form.vbs","applicationform1.vbs","sheet.vbs"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
| append [
  | tstats `summariesonly` count
      from datamodel=Endpoint.Registry
      where Registry.action IN ("created","modified")
        AND (Registry.registry_path="*HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ConsentPromptBehaviorAdmin*")
      by Registry.dest, Registry.process_name, Registry.registry_path,
         Registry.registry_value_name, Registry.registry_value_data
  | `drop_dm_object_name(Registry)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — A VBScript campaign distributed through WhatsApp deploying RMM software
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("reports.vbs", "confirmation.vbs", "list.vbs", "statement.vbs", "aus.vbs", "bank.vbs", "anda.vbs", "whatsapp.root.exe", "curl.exe", "setup1.vbs", "setup.bat", "uemsagent.msi", "form.vbs", "applicationform1.vbs", "sheet.vbs") or FolderPath has_any ("C:\Windows\System32\WScript.exe", "\AppData\Local\Packages\5319275A.WhatsAppDesktop_cv1g1gvanyjgm\LocalState\Sessions\", "C:\Users\Public\Documents\"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("C:\Windows\System32\WScript.exe", "\AppData\Local\Packages\5319275A.WhatsAppDesktop_cv1g1gvanyjgm\LocalState\Sessions\", "C:\Users\Public\Documents\") or FileName in~ ("reports.vbs", "confirmation.vbs", "list.vbs", "statement.vbs", "aus.vbs", "bank.vbs", "anda.vbs", "whatsapp.root.exe", "curl.exe", "setup1.vbs", "setup.bat", "uemsagent.msi", "form.vbs", "applicationform1.vbs", "sheet.vbs"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc

// Registry persistence locations named in the article
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryKey has_any ("HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin")
| project Timestamp, DeviceName, AccountName, RegistryKey,
          RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `202.61.160.208`, `202.61.160.202`, `202.61.160.201`, `202.61.160.160`, `202.61.160.137`, `38.55.151.63`, `temu.baskwms.top`, `invoice.msopsa.top` _(+2 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `c7f38cbb99c8b74fa0465293feeba700`, `b7cd06c71465038b658a6dc1f273a507`, `9f13c7b8ba391b2f597874e54d310648`, `993f4c0cadbc769a4b0ed62a918db58d`, `7f81c1bc8cfd588e8998968e2621456e`, `7403cbcc5a9c32384d431856dc48fcc9`, `68c16c46f8afb9e00bbaba0207fb0a46`, `66442f2457eca8f47385b1fb2c6fcab8` _(+33 more)_


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 8 use case(s) fired, 10 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

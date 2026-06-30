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

- **IPv4 (defanged):** `202.61.160.202`
- **IPv4 (defanged):** `202.61.160.201`
- **IPv4 (defanged):** `202.61.160.137`
- **IPv4 (defanged):** `202.61.160.160`
- **IPv4 (defanged):** `202.61.160.208`
- **IPv4 (defanged):** `38.55.151.63`
- **Domain (defanged):** `temu.baskwms.top`
- **Domain (defanged):** `invoice.msopsa.top`
- **Domain (defanged):** `qse.shoppes.help`
- **Domain (defanged):** `shaaslong.one`
- **Domain (defanged):** `baoxis.cc`
- **Domain (defanged):** `baolongwes.oss-ap-southeast-1.aliyuncs.com`
- **Domain (defanged):** `sdcwww.oss-ap-southeast-1.aliyuncs.com`
- **Domain (defanged):** `caiwuascw.s3.us-east-005.backblazeb2.com`
- **Domain (defanged):** `facaia.s3.us-east-005.backblazeb2.com`
- **MD5:** `c7f38cbb99c8b74fa0465293feeba700`
- **MD5:** `b7cd06c71465038b658a6dc1f273a507`
- **MD5:** `9f13c7b8ba391b2f597874e54d310648`
- **MD5:** `993f4c0cadbc769a4b0ed62a918db58d`
- **MD5:** `7f81c1bc8cfd588e8998968e2621456e`

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
- **T1566** — Phishing
- **T1059.005** — Command and Scripting Interpreter: Visual Basic
- **T1564.001** — Hide Artifacts: Hidden Files and Directories
- **T1105** — Ingress Tool Transfer
- **T1036.003** — Masquerading: Rename System Utilities
- **T1548.002** — Abuse Elevation Control Mechanism: Bypass User Account Control
- **T1112** — Modify Registry
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1218.007** — System Binary Proxy Execution: Msiexec

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### WhatsApp Desktop spawning WScript executing VBS from attachment Transfers dir

`UC_101_8` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name=wscript.exe OR Processes.process_name=cscript.exe) AND (Processes.parent_process_name="WhatsApp.Root.exe" OR Processes.process="*\\Packages\\5319275A.WhatsAppDesktop_cv1g1gvanyjgm\\LocalState\\Sessions\\*") AND (Processes.process="*.vbs*" OR Processes.process="*.vbe*") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("wscript.exe","cscript.exe")
| where InitiatingProcessFileName =~ "WhatsApp.Root.exe"
    or ProcessCommandLine has @"\Packages\5319275A.WhatsAppDesktop_cv1g1gvanyjgm\LocalState\Sessions\"
| where ProcessCommandLine has_any (".vbs", ".vbe")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256, FolderPath
| order by Timestamp desc
```

### VBScript creating hidden working directory and VBS payloads under C:\Users\Public\Documents

`UC_101_9` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.process_name=wscript.exe OR Filesystem.process_name=cscript.exe) AND Filesystem.file_path="*\\Users\\Public\\Documents\\*" AND (Filesystem.file_path="*\\Temp_*" OR Filesystem.file_path="*\\MSUpdate_*" OR Filesystem.file_name="*.vbs" OR Filesystem.file_name="*.vbe") by Filesystem.dest Filesystem.process_name Filesystem.file_path Filesystem.file_name | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("wscript.exe","cscript.exe")
| where FolderPath has @"\Users\Public\Documents\"
| where FolderPath has_any (@"\Temp_", @"\MSUpdate_") or FileName endswith ".vbs" or FileName endswith ".vbe"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, ActionType, FolderPath, FileName, SHA256
| order by Timestamp desc
```

### Renamed curl.exe/bitsadmin.exe running from Public\Documents working directory

`UC_101_10` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.original_file_name=curl.exe OR Processes.original_file_name=bitsadmin.exe) AND NOT (Processes.process_name=curl.exe OR Processes.process_name=bitsadmin.exe) AND Processes.process_path="*\\Users\\Public\\Documents\\*" by Processes.dest Processes.user Processes.process_name Processes.original_file_name Processes.process_path Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessVersionInfoOriginalFileName in~ ("curl.exe","bitsadmin.exe")
| where FileName !in~ ("curl.exe","bitsadmin.exe")
| where FolderPath has @"\Users\Public\Documents\"
| project Timestamp, DeviceName, AccountName, FileName, ProcessVersionInfoOriginalFileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, SHA256
| order by Timestamp desc
```

### UAC ConsentPromptBehaviorAdmin disabled (set to 0) by Windows Script Host

`UC_101_11` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where Registry.registry_path="*\\Microsoft\\Windows\\CurrentVersion\\Policies\\System*" AND (Registry.registry_value_name=ConsentPromptBehaviorAdmin OR Registry.registry_value_name=EnableLUA) AND Registry.registry_value_data=0 by Registry.dest Registry.registry_path Registry.registry_value_name Registry.registry_value_data Registry.process_id | `drop_dm_object_name(Registry)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where RegistryKey has @"\Microsoft\Windows\CurrentVersion\Policies\System"
| where RegistryValueName in~ ("ConsentPromptBehaviorAdmin","EnableLUA")
| where RegistryValueData == "0"
| where InitiatingProcessFileName in~ ("wscript.exe","cscript.exe") or InitiatingProcessFolderPath has @"\Users\Public\Documents\"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RegistryKey, RegistryValueName, RegistryValueData
| order by Timestamp desc
```

### Beacon/download to WhatsApp-VBS campaign C2 infrastructure (202.61.160.0/24 + 38.55.151.63)

`UC_101_12` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_ip="202.61.160.208" OR All_Traffic.dest_ip="202.61.160.202" OR All_Traffic.dest_ip="202.61.160.201" OR All_Traffic.dest_ip="202.61.160.160" OR All_Traffic.dest_ip="202.61.160.137" OR All_Traffic.dest_ip="38.55.151.63") by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let c2ips = dynamic(["202.61.160.208","202.61.160.202","202.61.160.201","202.61.160.160","202.61.160.137","38.55.151.63"]);
let c2domains = dynamic(["temu.baskwms.top","invoice.msopsa.top","baoxis.cc","sdcwww.oss-ap-southeast-1.aliyuncs.com"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (c2ips) or RemoteUrl has_any (c2domains)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort
| order by Timestamp desc
```

### ManageEngine Endpoint Central (UEMS) agent silently installed as final RMM payload

`UC_101_13` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name=UEMSAgent.msi OR Filesystem.file_name=UEMSAgent.mst OR Filesystem.file_name=DCAgentServerInfo.json) AND (Filesystem.process_name=wscript.exe OR Filesystem.process_name=cscript.exe OR Filesystem.process_name=msiexec.exe OR Filesystem.file_path="*\\Users\\Public\\Documents\\*") by Filesystem.dest Filesystem.process_name Filesystem.file_path Filesystem.file_name | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName in~ ("UEMSAgent.msi","UEMSAgent.mst","DCAgentServerInfo.json")
| where InitiatingProcessFileName in~ ("wscript.exe","cscript.exe","msiexec.exe","curl.exe","bitsadmin.exe")
    or InitiatingProcessFolderPath has @"\Users\Public\Documents\"
    or FolderPath has @"\Users\Public\Documents\"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, ActionType, FolderPath, FileName, SHA256
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

`UC_101_7` · phase: **exploit** · confidence: **High**

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
  - IP / domain IOC(s): `202.61.160.202`, `202.61.160.201`, `202.61.160.137`, `202.61.160.160`, `202.61.160.208`, `38.55.151.63`, `temu.baskwms.top`, `invoice.msopsa.top` _(+7 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `c7f38cbb99c8b74fa0465293feeba700`, `b7cd06c71465038b658a6dc1f273a507`, `9f13c7b8ba391b2f597874e54d310648`, `993f4c0cadbc769a4b0ed62a918db58d`, `7f81c1bc8cfd588e8998968e2621456e`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 14 use case(s) fired, 19 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

# [CRIT] WhatsApp VBScript Campaign Uses Fake Documents to Install ManageEngine RMM Tool

**Source:** The Hacker News
**Published:** 2026-06-23
**Article:** https://thehackernews.com/2026/06/whatsapp-vbscript-campaign-uses-fake.html

## Threat Profile

WhatsApp VBScript Campaign Uses Fake Documents to Install ManageEngine RMM Tool 
 Ravie Lakshmanan  Jun 23, 2026 Malware / Social Engineering 
Direct messages sent via WhatsApp are being used to distribute malicious Visual Basic Script (VBScript) files that lead to the installation of legitimate Remote Monitoring and Management (RMM) software.
Per findings from Kaspersky, the active campaign is targeting users of WhatsApp Desktop and WhatsApp Web across Malaysia, Brazil, India, Mexico, Singapo…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-11645`
- **IPv4 (defanged):** `202.61.160.201`

## MITRE ATT&CK Techniques

- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1219** — Remote Access Software
- **T1071** — Application Layer Protocol
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Command and Scripting Interpreter: Visual Basic
- **T1105** — Ingress Tool Transfer
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1548.002** — Abuse Elevation Control Mechanism: Bypass User Account Control
- **T1112** — Modify Registry
- **T1218.007** — System Binary Proxy Execution: Msiexec
- **T1566.001** — Phishing: Spearphishing Attachment

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### WhatsApp Desktop (WhatsApp.Root.exe) spawning WScript/CScript

`UC_50_6` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name="WhatsApp.Root.exe" AND (Processes.process_name="wscript.exe" OR Processes.process_name="cscript.exe")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_path | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName =~ "WhatsApp.Root.exe"
| where FileName in~ ("wscript.exe","cscript.exe")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, FileName, ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### WScript/CScript C2 egress to WhatsApp-campaign download infrastructure

`UC_50_7` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_ip IN ("202.61.160.201","202.61.160.202","202.61.160.208","202.61.160.160","202.61.160.137","38.55.151.63")) by All_Traffic.src All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where (InitiatingProcessFileName in~ ("wscript.exe","cscript.exe","msiexec.exe") or isnotempty(RemoteUrl))
| where RemoteIP in ("202.61.160.201","202.61.160.202","202.61.160.208","202.61.160.160","202.61.160.137","38.55.151.63")
    or RemoteUrl has_any ("baskwms.top","msopsa.top","shoppes.help","baoxis.cc","baolongwes.oss-ap-southeast-1.aliyuncs.com")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort
| order by Timestamp desc
```

### UAC bypass via ConsentPromptBehaviorAdmin set to 0 by script host

`UC_50_8` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where (Registry.registry_value_name="ConsentPromptBehaviorAdmin" AND (Registry.registry_value_data="0" OR Registry.registry_value_data="0x00000000")) by Registry.dest Registry.registry_path Registry.registry_value_name Registry.registry_value_data Registry.process_guid | `drop_dm_object_name(Registry)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where RegistryKey has @"Policies\System"
| where RegistryValueName =~ "ConsentPromptBehaviorAdmin"
| where RegistryValueData in ("0","0x0","0x00000000")
| where InitiatingProcessFileName in~ ("wscript.exe","cscript.exe","cmd.exe","reg.exe","powershell.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RegistryKey, RegistryValueName, RegistryValueData
| order by Timestamp desc
```

### ManageEngine Endpoint Central (UEMSAgent.msi) silent install as RMM implant

`UC_50_9` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="msiexec.exe" AND Processes.process="*UEMSAgent*") by Processes.dest Processes.user Processes.parent_process_name Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "msiexec.exe"
| where ProcessCommandLine has "UEMSAgent" or ProcessCommandLine has_any ("DCAgentServerInfo","UEMSAgent.mst")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
| order by Timestamp desc
```

### Financial-lure .vbs written into WhatsApp Desktop session folder

`UC_50_10` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name="*.vbs" AND (Filesystem.file_path="*WhatsAppDesktop*" OR Filesystem.file_path="*5319275A.WhatsAppDesktop_cv1g1gvanyjgm*")) by Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.process_guid | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileRenamed")
| where FileName endswith ".vbs"
| where FolderPath has_any ("5319275A.WhatsAppDesktop_cv1g1gvanyjgm","WhatsAppDesktop")
    or FileName in~ ("Financial Reports.vbs","Account Statement.vbs","Debt confirmation.vbs","Statement of Debt(30K).vbs","Outstanding Payment List.vbs","Extrato de Conciliação.vbs","Penyata bank.vbs")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, FolderPath, SHA256
| order by Timestamp desc
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

### Article-specific behavioural hunt — WhatsApp VBScript Campaign Uses Fake Documents to Install ManageEngine RMM Tool

`UC_50_5` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — WhatsApp VBScript Campaign Uses Fake Documents to Install ManageEngine RMM Tool ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("reports.vbs","statement.vbs","whatsapp.root.exe"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("reports.vbs","statement.vbs","whatsapp.root.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — WhatsApp VBScript Campaign Uses Fake Documents to Install ManageEngine RMM Tool
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("reports.vbs", "statement.vbs", "whatsapp.root.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("reports.vbs", "statement.vbs", "whatsapp.root.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-11645`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `202.61.160.201`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 11 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

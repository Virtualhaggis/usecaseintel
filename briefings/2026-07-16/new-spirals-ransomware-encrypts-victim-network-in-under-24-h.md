# [HIGH] New Spirals ransomware encrypts victim network in under 24 hours

**Source:** BleepingComputer
**Published:** 2026-07-16
**Article:** https://www.bleepingcomputer.com/news/security/new-spirals-ransomware-encrypts-victim-network-in-under-24-hours/

## Threat Profile

New Spirals ransomware encrypts victim network in under 24 hours 
By Bill Toulas 
July 16, 2026
06:00 AM
0 


A new ransomware actor called Spirals completed a corporate intrusion, from initial access to data theft and encryption, in less than 24 hours.


The attack occurred in June and breached an IT services firm in South Asia after compromising an Internet Information Services (IIS) server exposed on the public web.


Researchers at Symantec's Threat Hunter Team say that the attacker mo…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1486** — Data Encrypted for Impact
- **T1219** — Remote Access Software
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1489** — Service Stop
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1490** — Inhibit System Recovery
- **T1572** — Protocol Tunneling
- **T1090** — Proxy
- **T1505.003** — Server Software Component: Web Shell
- **T1190** — Exploit Public-Facing Application
- **T1021.001** — Remote Services: Remote Desktop Protocol
- **T1112** — Modify Registry

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Spirals ransomware payload masquerading as bitsadmin.exe outside System32 / via PsExec

`UC_4_5` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=bitsadmin.exe by Processes.dest Processes.user Processes.process_name Processes.process_path Processes.parent_process_name Processes.process | `drop_dm_object_name(Processes)` | where NOT (match(process_path,"(?i)\\Windows\\System32\\") OR match(process_path,"(?i)\\Windows\\SysWOW64\\")) OR match(parent_process_name,"(?i)PSEXESVC\.exe") | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "bitsadmin.exe"
| where (FolderPath !startswith @"C:\Windows\System32" and FolderPath !startswith @"C:\Windows\SysWOW64")
     or InitiatingProcessFileName =~ "PSEXESVC.exe"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256,
          ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessIntegrityLevel
| order by Timestamp desc
```

### Spirals ransom note RECOVERY_SECTION.log dropped at drive root

`UC_4_6` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name=RECOVERY_SECTION.log by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_id | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where FileName =~ "RECOVERY_SECTION.log"
| project Timestamp, DeviceName, FolderPath, FileName, ActionType,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessAccountName, SHA256
| order by Timestamp desc
```

### PowerShell mass-stop of backup/DB/virtualization services + Defender tampering (Spirals pre-encryption)

`UC_4_7` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN (powershell.exe,pwsh.exe,cmd.exe,net.exe,sc.exe) by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | where (match(process,"(?i)(Veeam|VMware|vmms|MSSQL|SQLSERVERAGENT|OracleService|postgresql|vmcompute|MSExchange)") AND match(process,"(?i)(Stop-Service|net stop|sc stop|Set-Service)")) OR match(process,"(?i)(DisableRealtimeMonitoring|-RemoveDefinitions|Set-MpPreference)") | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","net.exe","sc.exe")
| where (ProcessCommandLine has_any ("Veeam","VMware","vmms","MSSQL","SQLSERVERAGENT","OracleService","postgresql","vmcompute","MSExchange")
         and ProcessCommandLine has_any ("Stop-Service","net stop","sc stop","Set-Service"))
   or ProcessCommandLine has_any ("DisableRealtimeMonitoring","-RemoveDefinitions","Set-MpPreference","MpCmdRun.exe -RemoveDefinitions")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Spirals redundant remote access via revsocks / Chisel / Cloudflare tunnel

`UC_4_8` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN (revsocks.exe,chisel.exe,cloudflared.exe) OR Processes.process="*trycloudflare.com*" OR Processes.process="*R:socks*" OR Processes.process="*tunnel run*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName has_any ("revsocks","chisel","cloudflared")
   or ProcessCommandLine has_any ("trycloudflare.com","R:socks","tunnel run","--url http")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256,
          ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### IIS worker process (w3wp.exe) spawning shell — Spirals ASP.NET web shell initial access

`UC_4_9` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name=w3wp.exe Processes.process_name IN (cmd.exe,powershell.exe,pwsh.exe,net.exe,net1.exe,whoami.exe,nltest.exe,bitsadmin.exe,certutil.exe,cscript.exe,wscript.exe,reg.exe) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","net.exe","net1.exe","whoami.exe","nltest.exe","bitsadmin.exe","certutil.exe","cscript.exe","wscript.exe","reg.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessCommandLine,
          FileName, ProcessCommandLine, SHA256, InitiatingProcessAccountName
| order by Timestamp desc
```

### Remote Desktop enabled via fDenyTSConnections registry flip (Spirals persistence)

`UC_4_10` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where Registry.registry_value_name=fDenyTSConnections Registry.registry_value_data=0 by Registry.dest Registry.registry_key_name Registry.registry_value_name Registry.registry_value_data Registry.process_id | `drop_dm_object_name(Registry)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where ActionType == "RegistryValueSet"
| where RegistryValueName =~ "fDenyTSConnections"
| where RegistryValueData == "0"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessIntegrityLevel
| order by Timestamp desc
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


## Why this matters

Severity classified as **HIGH** based on: 11 use case(s) fired, 18 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

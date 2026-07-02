# [CRIT] From cause to cash: a cross-border look at hacktivist activity

**Source:** Securelist (Kaspersky)
**Published:** 2026-06-08
**Article:** https://securelist.com/tr/hacktivists-broaden-attack-geography/120115/

## Threat Profile

Threat Response 
Table of Contents
Overlapping activity streams 
Technical details 
Vulnerable web servers and fd.aspx 
Scripts deployed 
Publicly available utilities 
C2 and communications 
Sliver 
Havoc 
Apollo 
Adaptix 
BlackSalt Backdoor 
EDR killers 
Connection to the ClearWater ransomware 
File encryption 
Additional functionality 
Updated Blackout Locker 
Rust dropper 
Blackout Locker 
Screen locker 
Attack geography 
Takeaways 
Detection by Kaspersky solutions 
Indicators of compromise 
…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2021-34473`
- **CVE:** `CVE-2021-34523`
- **CVE:** `CVE-2021-31207`
- **IPv4 (defanged):** `185.221.153.121`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1190** — Exploit Public-Facing Application
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1486** — Data Encrypted for Impact
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1219** — Remote Access Software
- **T1547.001** — Persistence (article-specific)
- **T1543.003** — Persistence (article-specific)
- **T1505.003** — Server Software Component: Web Shell
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1041** — Exfiltration Over C2 Channel
- **T1572** — Protocol Tunneling
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1543.003** — Create or Modify System Process: Windows Service
- **T1490** — Inhibit System Recovery

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### ProxyShell exploitation of on-prem Exchange (autodiscover SSRF → PowerShell backend)

`UC_237_9` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.http_method IN ("POST","GET")) (Web.url="*/autodiscover.json*" OR Web.url="*Email=autodiscover*" OR Web.url="*X-Rps-CAT*" OR Web.url="*X-BEResource*" OR Web.url="*/powershell*") by Web.src, Web.dest, Web.http_method, Web.url, Web.http_user_agent, Web.status | `drop_dm_object_name(Web)` | sort - lastTime
```

### fd.aspx modular web shell dropped into Exchange web directories

`UC_237_10` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Endpoint.Filesystem.file_name="fd.aspx" by Endpoint.Filesystem.dest, Endpoint.Filesystem.file_path, Endpoint.Filesystem.process_name, Endpoint.Filesystem.user | `drop_dm_object_name(Endpoint.Filesystem)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FileName =~ "fd.aspx"
   or (FileName endswith ".aspx" and InitiatingProcessFileName =~ "w3wp.exe" and FolderPath has_any (@"\FrontEnd\HttpProxy\", @"\ClientAccess\", @"\aspnet_client\", @"\inetpub\wwwroot\"))
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### IIS worker w3wp.exe spawning PowerShell/cmd (fd.aspx command execution)

`UC_237_11` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Endpoint.Processes.parent_process_name="w3wp.exe" (Endpoint.Processes.process_name="powershell.exe" OR Endpoint.Processes.process_name="pwsh.exe" OR Endpoint.Processes.process_name="cmd.exe") by Endpoint.Processes.dest, Endpoint.Processes.user, Endpoint.Processes.parent_process, Endpoint.Processes.process_name, Endpoint.Processes.process | `drop_dm_object_name(Endpoint.Processes)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe")
| where not (ProcessCommandLine has_any ("Microsoft.Exchange.","ExchangeHealth","ServerManager","CleanupWebServiceCache"))
| project Timestamp, DeviceName, AccountName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Host egress to shared hacktivist C2/exfil IP 185.221.153.121

`UC_237_12` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where All_Traffic.dest="185.221.153.121" by All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port, All_Traffic.app, All_Traffic.user, All_Traffic.process | `drop_dm_object_name(All_Traffic)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "185.221.153.121"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```

### Microsoft Dev Tunnels (devtunnel.exe) abused as ingress backdoor

`UC_237_13` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Endpoint.Processes.process_name="devtunnel.exe" OR Endpoint.Processes.process="*devtunnel*") (Endpoint.Processes.process="*host*" OR Endpoint.Processes.process="*port create*" OR Endpoint.Processes.process="*user login*") by Endpoint.Processes.dest, Endpoint.Processes.user, Endpoint.Processes.parent_process_name, Endpoint.Processes.process | `drop_dm_object_name(Endpoint.Processes)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "devtunnel.exe" or ProcessCommandLine has "devtunnel"
| where ProcessCommandLine has_any ("host","port create","user login")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
| order by Timestamp desc
```

### BYOVD EDR-killer: rentdrv2 vulnerable driver drop to disable Defender/MDE

`UC_237_14` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Endpoint.Filesystem.file_name="rentdrv2.sys" by Endpoint.Filesystem.dest, Endpoint.Filesystem.file_path, Endpoint.Filesystem.process_name, Endpoint.Filesystem.user | `drop_dm_object_name(Endpoint.Filesystem)` | sort - lastTime
```

**Defender KQL:**
```kql
union
(DeviceFileEvents
 | where Timestamp > ago(30d)
 | where FileName has "rentdrv2"
 | project Timestamp, DeviceName, Kind="FileWrite", Detail=FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName),
(DeviceRegistryEvents
 | where Timestamp > ago(30d)
 | where RegistryKey has @"\Services\rentdrv2"
 | project Timestamp, DeviceName, Kind="ServiceKey", Detail=RegistryKey, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName)
| order by Timestamp desc
```

### ClearWater ransomware payload execution from C:\ProgramData

`UC_237_15` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Endpoint.Processes.process_name="ClearWater_x64.exe" OR Endpoint.Processes.process_path="C:\\ProgramData\\ClearWater_x64.exe") by Endpoint.Processes.dest, Endpoint.Processes.user, Endpoint.Processes.parent_process_name, Endpoint.Processes.process, Endpoint.Processes.process_hash | `drop_dm_object_name(Endpoint.Processes)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "ClearWater_x64.exe" or FolderPath has @"\ProgramData\ClearWater_x64.exe"
| project Timestamp, DeviceName, AccountName, FolderPath, SHA256, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
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

### Article-specific behavioural hunt — From cause to cash: a cross-border look at hacktivist activity

`UC_237_8` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — From cause to cash: a cross-border look at hacktivist activity ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("anydesk.exe","upd.exe","winhost.exe","update1.exe","akolo.exe","install.bat","servicechecker.bat","backupsrv.exe","backupagnt.exe","windowsinternal.updatecomponent.dll","demon.x64.exe","windowsservicehelper.exe","svc.exe","kil.exe","killer.exe") OR Processes.process_path="*C:\Windows\System32\inetsrv\*" OR Processes.process_path="*C:\ProgramData\ClearWater_x64.exe*" OR Processes.process_path="*\AppData\Local\Microsoft\*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*C:\Windows\System32\inetsrv\*" OR Filesystem.file_path="*C:\ProgramData\ClearWater_x64.exe*" OR Filesystem.file_path="*\AppData\Local\Microsoft\*" OR Filesystem.file_name IN ("anydesk.exe","upd.exe","winhost.exe","update1.exe","akolo.exe","install.bat","servicechecker.bat","backupsrv.exe","backupagnt.exe","windowsinternal.updatecomponent.dll","demon.x64.exe","windowsservicehelper.exe","svc.exe","kil.exe","killer.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
| append [
  | tstats `summariesonly` count
      from datamodel=Endpoint.Registry
      where Registry.action IN ("created","modified")
        AND (Registry.registry_path="*HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run*" OR Registry.registry_path="*HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\PersonalizationCSP*")
      by Registry.dest, Registry.process_name, Registry.registry_path,
         Registry.registry_value_name, Registry.registry_value_data
  | `drop_dm_object_name(Registry)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — From cause to cash: a cross-border look at hacktivist activity
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("anydesk.exe", "upd.exe", "winhost.exe", "update1.exe", "akolo.exe", "install.bat", "servicechecker.bat", "backupsrv.exe", "backupagnt.exe", "windowsinternal.updatecomponent.dll", "demon.x64.exe", "windowsservicehelper.exe", "svc.exe", "kil.exe", "killer.exe") or FolderPath has_any ("C:\Windows\System32\inetsrv\", "C:\ProgramData\ClearWater_x64.exe", "\AppData\Local\Microsoft\"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("C:\Windows\System32\inetsrv\", "C:\ProgramData\ClearWater_x64.exe", "\AppData\Local\Microsoft\") or FileName in~ ("anydesk.exe", "upd.exe", "winhost.exe", "update1.exe", "akolo.exe", "install.bat", "servicechecker.bat", "backupsrv.exe", "backupagnt.exe", "windowsinternal.updatecomponent.dll", "demon.x64.exe", "windowsservicehelper.exe", "svc.exe", "kil.exe", "killer.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc

// Registry persistence locations named in the article
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryKey has_any ("HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP")
| project Timestamp, DeviceName, AccountName, RegistryKey,
          RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `185.221.153.121`

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2021-34473`, `CVE-2021-34523`, `CVE-2021-31207`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 16 use case(s) fired, 21 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

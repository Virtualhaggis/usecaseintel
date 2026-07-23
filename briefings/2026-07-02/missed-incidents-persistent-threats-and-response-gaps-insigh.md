# [CRIT] Missed incidents, persistent threats, and response gaps: Insights from compromise assessment projects

**Source:** Securelist (Kaspersky)
**Published:** 2026-07-02
**Article:** https://securelist.com/compromise-assessment-findings-2025/120542/

## Threat Profile

Table of Contents
Key trends observed during compromise assessment engagements 
About the Kaspersky Compromise Assessment service 
Detection logic families 
Reasons for requesting Kaspersky Compromise Assessment services 
Case study: Dormant threat uncovered only by a compromise assessment 
Missed long-term incidents 
Case study: Four-year-old crypto mining activity on domain controllers 
Unintentional malware preservation 
Legitimate, yet suspicious: LoLBins and remote management tools 
Impact …

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1053.005** — Scheduled Task
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1219** — Remote Access Software
- **T1053.005** — Persistence (article-specific)
- **T1546.003** — Persistence (article-specific)
- **T1218.007** — System Binary Proxy Execution: Msiexec
- **T1105** — Ingress Tool Transfer
- **T1027.011** — Fileless Storage
- **T1543.003** — Create or Modify System Process: Windows Service
- **T1014** — Rootkit
- **T1574.001** — Hijack Execution Flow: DLL Search Order Hijacking
- **T1505.003** — Server Software Component: Web Shell
- **T1496** — Resource Hijacking
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1140** — Deobfuscate/Decode Files or Information
- **T1047** — Windows Management Instrumentation
- **T1197** — BITS Jobs
- **T1190** — Exploit Public-Facing Application
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### PurpleFox fileless infection: remote MSI via msiexec + reflective PE injection

`UC_220_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name=msiexec.exe AND Processes.process="*http*" AND (Processes.process="*/q*" OR Processes.process="*/quiet*") AND (Processes.process="*.png*" OR Processes.process="*.jpg*" OR Processes.process="*.gif*" OR Processes.process="*.moe*" OR Processes.process="*.msi*")) by Processes.dest Processes.user Processes.parent_process_name Processes.process Processes.process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "msiexec.exe"
| where ProcessCommandLine has_any ("http://","https://")
| where ProcessCommandLine has_any ("/q","/quiet","-q")
| where ProcessCommandLine has_any (".png",".jpg",".gif",".moe",".msi")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### PurpleFox persistence via auto-generated AC0[0-9] Windows service

`UC_220_8` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Services where (Services.service_name IN ("AC00","AC01","AC02","AC03","AC04","AC05","AC06","AC07","AC08","AC09")) by Services.dest Services.service_name Services.service_path | `drop_dm_object_name(Services)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where ActionType == "RegistryKeyCreated"
| where RegistryKey has_any (@"\Services\AC00",@"\Services\AC01",@"\Services\AC02",@"\Services\AC03",@"\Services\AC04",@"\Services\AC05",@"\Services\AC06",@"\Services\AC07",@"\Services\AC08",@"\Services\AC09")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### LionTail backdoor: DLL search-order hijack via phantom System32 DLLs

`UC_220_9` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\System32\\*" AND Filesystem.file_name IN ("wlanapi.dll","wlbsctrl.dll","TSMSISrv.dll","TSVIPSrv.dll")) by Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)` | search process_name!="TiWorker.exe" process_name!="TrustedInstaller.exe" process_name!="msiexec.exe" process_name!="poqexec.exe" | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType == "FileCreated"
| where FolderPath has @"\Windows\System32\"
| where FileName in~ ("wlanapi.dll","wlbsctrl.dll","TSMSISrv.dll","TSVIPSrv.dll")
| where InitiatingProcessFileName !in~ ("msiexec.exe","tiworker.exe","trustedinstaller.exe","poqexec.exe","wuauclt.exe")
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### Dormant crypto-miner on servers: sustained stratum egress to mining pools

`UC_220_10` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_port IN (3333,4444,5555,7777,9999,14444,45560,45700) AND All_Traffic.direction=outbound) by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name(All_Traffic)` | where count > 5 | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIPType == "Public"
| where (RemotePort in (3333,4444,5555,7777,9999,14444,45560,45700)) or (RemoteUrl has_any ("xmr","monero","minexmr","supportxmr","nanopool","stratum","pool."))
| summarize ConnCount=count(), Ports=make_set(RemotePort), Urls=make_set(RemoteUrl), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath
| where ConnCount > 5   // sustained, not a single stray connection
| order by LastSeen desc
```

### LoLBin abuse: certutil decode/urlcache, bitsadmin transfer, wmic process-call-create

`UC_220_11` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where ((Processes.process_name=certutil.exe AND (Processes.process="*decode*" OR Processes.process="*urlcache*" OR Processes.process="*verifyctl*")) OR (Processes.process_name=bitsadmin.exe AND Processes.process="*/transfer*") OR (Processes.process_name=wmic.exe AND Processes.process="*process call create*")) by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where AccountName !endswith "$"
| where (FileName =~ "certutil.exe" and ProcessCommandLine has_any ("-decode","/decode","-urlcache","/urlcache","-verifyctl"))
    or (FileName =~ "bitsadmin.exe" and ProcessCommandLine has "/transfer")
    or (FileName =~ "wmic.exe" and ProcessCommandLine has "process call create")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### Web shell execution: web server process spawning command interpreters

`UC_220_12` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("w3wp.exe","httpd.exe","nginx.exe","php-cgi.exe","php.exe","tomcat.exe","java.exe") AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","net.exe","net1.exe","whoami.exe","cscript.exe","wscript.exe","certutil.exe","bitsadmin.exe","nltest.exe")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("w3wp.exe","httpd.exe","nginx.exe","php-cgi.exe","php.exe","tomcat.exe","java.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","net.exe","net1.exe","whoami.exe","cscript.exe","wscript.exe","certutil.exe","bitsadmin.exe","nltest.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
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

### Article-specific behavioural hunt — Missed incidents, persistent threats, and response gaps: Insights from compromis

`UC_220_6` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Missed incidents, persistent threats, and response gaps: Insights from compromis ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("nei.bat","dl1host.exe","bat.bat","cmd.bat","taskhost.exe","poab.bat","load.bat","loab.bat","mance.exe","eter.exe","puls.exe","eternalblue2.dll","doublepulsar2.dll","http.sys","scrcons.exe") OR Processes.process="*Invoke-Expression*" OR Processes.process_path="*C:\Windows\Fonts\Mysql*" OR Processes.process_path="*C:\Windows\System32\wbem*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*C:\Windows\Fonts\Mysql*" OR Filesystem.file_path="*C:\Windows\System32\wbem*" OR Filesystem.file_path="*/dev/null*" OR Filesystem.file_path="*/var/folders/*" OR Filesystem.file_name IN ("nei.bat","dl1host.exe","bat.bat","cmd.bat","taskhost.exe","poab.bat","load.bat","loab.bat","mance.exe","eter.exe","puls.exe","eternalblue2.dll","doublepulsar2.dll","http.sys","scrcons.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
| append [
  | tstats `summariesonly` count
      from datamodel=Endpoint.Registry
      where Registry.action IN ("created","modified")
        AND (Registry.registry_path="*HKU\\S-1-5-21-*" OR Registry.registry_path="*HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall*" OR Registry.registry_path="*HKLM\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall*")
      by Registry.dest, Registry.process_name, Registry.registry_path,
         Registry.registry_value_name, Registry.registry_value_data
  | `drop_dm_object_name(Registry)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Missed incidents, persistent threats, and response gaps: Insights from compromis
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("nei.bat", "dl1host.exe", "bat.bat", "cmd.bat", "taskhost.exe", "poab.bat", "load.bat", "loab.bat", "mance.exe", "eter.exe", "puls.exe", "eternalblue2.dll", "doublepulsar2.dll", "http.sys", "scrcons.exe") or ProcessCommandLine has_any ("Invoke-Expression") or FolderPath has_any ("C:\Windows\Fonts\Mysql", "C:\Windows\System32\wbem"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("C:\Windows\Fonts\Mysql", "C:\Windows\System32\wbem", "/dev/null", "/var/folders/") or FileName in~ ("nei.bat", "dl1host.exe", "bat.bat", "cmd.bat", "taskhost.exe", "poab.bat", "load.bat", "loab.bat", "mance.exe", "eter.exe", "puls.exe", "eternalblue2.dll", "doublepulsar2.dll", "http.sys", "scrcons.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc

// Registry persistence locations named in the article
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryKey has_any ("HKU\S-1-5-21-", "HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall")
| project Timestamp, DeviceName, AccountName, RegistryKey,
          RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **CRIT** based on: 13 use case(s) fired, 26 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

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
- **T1496** — Resource Hijacking
- **T1547.001** — Registry Run Keys / Startup Folder
- **T1218.007** — System Binary Proxy Execution: Msiexec
- **T1055** — Process Injection
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1574.002** — Hijack Execution Flow: DLL Side-Loading
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1505.003** — Server Software Component: Web Shell
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1484.001** — Domain Policy Modification: Group Policy Modification
- **T1570** — Lateral Tool Transfer

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Long-lived cryptomining C2 (stratum) from SYSTEM context on servers / domain controllers

`UC_111_7` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_port IN (3333,4444,5555,7777,14433,14444,45700,45560) OR All_Traffic.app IN ("stratum","stratum+tcp")) by All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port, All_Traffic.app | `drop_dm_object_name(All_Traffic)` | eval durDays=(lastTime-firstTime)/86400 | where durDays >= 7 | sort - durDays
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemotePort in (3333,4444,5555,7777,14433,14444,45700,45560)
     or RemoteUrl has_any ("stratum","xmr","monero","minexmr","nanopool","supportxmr","miningpool","pool.min")
| where InitiatingProcessAccountName in~ ("system","local service","network service") or InitiatingProcessAccountName endswith "$"
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Conns=count(), Ports=make_set(RemotePort), Dsts=make_set(RemoteIP) by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256
| where datetime_diff('day', LastSeen, FirstSeen) >= 7   // persistence beyond a week = the miner-on-DC pattern
| order by FirstSeen asc
```

### PurpleFox in-memory install: msiexec.exe fetching a remote MSI

`UC_111_8` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Endpoint.Processes.process_name="msiexec.exe" (Endpoint.Processes.process="*http://*" OR Endpoint.Processes.process="*https://*") by Endpoint.Processes.dest, Endpoint.Processes.user, Endpoint.Processes.parent_process_name, Endpoint.Processes.process | `drop_dm_object_name(Endpoint.Processes)` | sort - firstTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "msiexec.exe"
| where ProcessCommandLine has_any ("http://","https://")
| where ProcessCommandLine has_any (" /i"," -i","/q",".moe",".msi",".png")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### LionTail IIS backdoor: unexpected DLL written to / loaded by an IIS worker (w3wp)

`UC_111_9` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime from datamodel=Endpoint.Filesystem where (Endpoint.Filesystem.file_path="*\\inetpub\\*" OR Endpoint.Filesystem.file_path="*\\System32\\inetsrv\\*") Endpoint.Filesystem.file_name="*.dll" by Endpoint.Filesystem.dest, Endpoint.Filesystem.file_path, Endpoint.Filesystem.file_name, Endpoint.Filesystem.process_name | `drop_dm_object_name(Endpoint.Filesystem)` | where process_name!="msiexec.exe" AND process_name!="TrustedInstaller.exe" | sort - firstTime
```

**Defender KQL:**
```kql
DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where FileName endswith ".dll"
| where FolderPath !startswith @"C:\Windows\" and FolderPath !has @"\inetsrv\" and FolderPath !has @"\Microsoft.NET\" and FolderPath !has @"\assembly\" and FolderPath !has @"\Temporary ASP.NET Files\"
| project Timestamp, DeviceName, InitiatingProcessFolderPath, ModulePath=FolderPath, ModuleName=FileName, SHA256
| order by Timestamp desc
```

### Web-server process (w3wp/httpd) spawning a command shell or LOLBin

`UC_111_10` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime from datamodel=Endpoint.Processes where Endpoint.Processes.parent_process_name IN ("w3wp.exe","httpd.exe","nginx.exe","php-cgi.exe","tomcat.exe","tomcat9.exe") Endpoint.Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","net.exe","net1.exe","whoami.exe","cscript.exe","wscript.exe","rundll32.exe","systeminfo.exe") by Endpoint.Processes.dest, Endpoint.Processes.parent_process_name, Endpoint.Processes.process_name, Endpoint.Processes.process | `drop_dm_object_name(Endpoint.Processes)` | sort - firstTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("w3wp.exe","httpd.exe","nginx.exe","php-cgi.exe","tomcat.exe","tomcat9.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","net.exe","net1.exe","whoami.exe","cscript.exe","wscript.exe","rundll32.exe","systeminfo.exe")
| project Timestamp, DeviceName, AccountName, ParentProcess=InitiatingProcessFileName, ChildProcess=FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Mass execution of binaries from SYSVOL/NETLOGON (abused GPO software distribution)

`UC_111_11` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count values(Endpoint.Processes.dest) as hosts dc(Endpoint.Processes.dest) as host_count min(_time) as firstTime from datamodel=Endpoint.Processes where (Endpoint.Processes.process_path="*\\SYSVOL\\*" OR Endpoint.Processes.process="*\\SYSVOL\\*" OR Endpoint.Processes.process="*\\NETLOGON\\*") by Endpoint.Processes.process_name, Endpoint.Processes.process | `drop_dm_object_name(Endpoint.Processes)` | where host_count >= 5 | sort - host_count
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FolderPath has @"\SYSVOL\" or ProcessCommandLine has @"\SYSVOL\" or ProcessCommandLine has @"\NETLOGON\" or FolderPath has @"\NETLOGON\"
| where FileName endswith ".exe" or FileName in~ ("powershell.exe","cscript.exe","wscript.exe","cmd.exe")
| summarize Hosts=dcount(DeviceName), HostList=make_set(DeviceName, 25), FirstSeen=min(Timestamp), Cmds=make_set(ProcessCommandLine, 5) by FileName, SHA256, FolderPath
| where Hosts >= 5   // 5+ domain members running the same SYSVOL-sourced binary = mass GPO push
| order by Hosts desc
```

### Remote management tool executing from a non-install (temp/download) path

`UC_111_12` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime from datamodel=Endpoint.Processes where Endpoint.Processes.process_name IN ("anydesk.exe","teamviewer.exe","screenconnect.clientservice.exe","atera_agent.exe","ateraagent.exe","splashtop.exe","strwinclt.exe","rustdesk.exe","meshagent.exe","netsupport.exe","client32.exe","dwagent.exe","logmein.exe","gotoassist.exe","supremo.exe","syncro.exe") (Endpoint.Processes.process_path IN ("*\\Temp\\*","*\\Downloads\\*","*\\ProgramData\\*","*\\Users\\Public\\*","*\\AppData\\*")) by Endpoint.Processes.dest, Endpoint.Processes.user, Endpoint.Processes.process_name, Endpoint.Processes.process_path, Endpoint.Processes.process | `drop_dm_object_name(Endpoint.Processes)` | sort - firstTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("anydesk.exe","teamviewer.exe","screenconnect.clientservice.exe","atera_agent.exe","ateraagent.exe","splashtop.exe","strwinclt.exe","rustdesk.exe","meshagent.exe","netsupport.exe","client32.exe","dwagent.exe","logmein.exe","gotoassist.exe","supremo.exe","syncro.exe")
| where FolderPath has_any (@"\Temp\", @"\Downloads\", @"\ProgramData\", @"\Users\Public\", @"\AppData\")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, SHA256
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

`UC_111_6` · phase: **exploit** · confidence: **High**

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

Severity classified as **CRIT** based on: 13 use case(s) fired, 23 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

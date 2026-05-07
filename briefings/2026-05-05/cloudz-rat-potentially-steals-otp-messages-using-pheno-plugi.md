# [HIGH] CloudZ RAT potentially steals OTP messages using Pheno plugin

**Source:** Cisco Talos
**Published:** 2026-05-05
**Article:** https://blog.talosintelligence.com/cloudz-pheno-infostealer/

## Threat Profile

CloudZ RAT potentially steals OTP messages using Pheno plugin 
By 
Alex Karkins , 
Chetan Raghuprasad 
Tuesday, May 5, 2026 06:00
Threat Spotlight
RAT
Cisco Talos discovered an intrusion, active since at least January 2026, where an unknown attacker implanted a CloudZ remote access tool (RAT) and a previously undocumented plugin called “Pheno.”
According to the functionalities of the CloudZ RAT and Pheno plugin, this was with the intention of stealing victims’ credentials and potentially one-tim…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `185.196.10.136`
- **Domain (defanged):** `update.txt`
- **Domain (defanged):** `calm-wildflower-1349.hellohiall.workers.dev`
- **Domain (defanged):** `round-cherry-4418.hellohiall.workers.dev`
- **Domain (defanged):** `orange-cell-1353.hellohiall.workers.dev`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1053.005** — Scheduled Task
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1219** — Remote Access Software
- **T1053.005** — Persistence (article-specific)
- **T1218.009** — System Binary Proxy Execution: Regsvcs/Regasm
- **T1053.005** — Scheduled Task/Job: Scheduled Task
- **T1036.008** — Masquerading: Masquerade File Type
- **T1005** — Data from Local System
- **T1119** — Automated Collection
- **T1083** — File and Directory Discovery
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1102.002** — Web Service: Bidirectional Communication
- **T1571** — Non-Standard Port

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] CloudZ persistence: regasm.exe executing dropped .txt loader (update.txt/msupdate.txt)

`UC_61_6` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process) as parent_process values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.process_name="regasm.exe" OR Processes.process_path="*\\Microsoft.NET\\Framework64\\v4.0.30319\\regasm.exe") AND (Processes.process="*update.txt*" OR Processes.process="*msupdate.txt*" OR Processes.process="*\\ProgramData\\Microsoft\\Windo*Doc\\*") by Processes.dest Processes.user Processes.process Processes.parent_process Processes.process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName =~ "regasm.exe"
| where ProcessCommandLine has_any ("update.txt", "msupdate.txt")
   or ProcessCommandLine has @"\ProgramData\Microsoft\WindowsDoc\"
   or ProcessCommandLine has @"\ProgramData\Microsoft\windosDoc\"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          ParentImage = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          IsRemoteSession = InitiatingProcessParentFileName, SHA256
| order by Timestamp desc
```

### [LLM] Pheno plugin recon artefacts: phonelink-<HOST>.txt in Microsoft\feedback\cm staging

`UC_61_7` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.process_name) as process_name from datamodel=Endpoint.Filesystem where (Filesystem.file_name="pheno.exe" OR Filesystem.file_path="*\\Microsoft\\feedback\\cm\\phonelink-*.txt" OR (Filesystem.file_name="phonelink-*" AND Filesystem.file_path="*\\Microsoft\\feedback\\cm\\*")) by Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let pheno_files = DeviceFileEvents
    | where Timestamp > ago(7d)
    | where ActionType in ("FileCreated", "FileModified", "FileRenamed")
    | where (FileName =~ "pheno.exe")
         or (FileName startswith "phonelink-" and FileName endswith ".txt"
             and FolderPath has @"\Microsoft\feedback\cm\")
         or (FolderPath has @"\ProgramData\Microsoft\whealth\")
    | project Timestamp, DeviceName, ActionType, FileName, FolderPath,
              SHA256, Initiator = InitiatingProcessFileName,
              InitiatorCmd = InitiatingProcessCommandLine,
              Account = InitiatingProcessAccountName;
let phonelink_db_access = DeviceFileEvents
    | where Timestamp > ago(7d)
    | where FileName startswith "PhoneExperiences-" and FileName endswith ".db"
    | where InitiatingProcessFileName !in~ ("PhoneExperienceHost.exe","YourPhone.exe","PhoneLink.exe",
                                            "svchost.exe","explorer.exe","backgroundtaskhost.exe",
                                            "runtimebroker.exe","searchindexer.exe")
    | project Timestamp, DeviceName, ActionType, FileName, FolderPath,
              Initiator = InitiatingProcessFileName,
              InitiatorCmd = InitiatingProcessCommandLine,
              Account = InitiatingProcessAccountName;
union pheno_files, phonelink_db_access
| order by Timestamp desc
```

### [LLM] CloudZ C2/staging beacon: hellohiall.workers.dev or 185.196.10.136:8089

`UC_61_8` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as app values(All_Traffic.process_name) as process_name from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_ip="185.196.10.136" AND All_Traffic.dest_port=8089) OR All_Traffic.dest="*.hellohiall.workers.dev" by All_Traffic.src All_Traffic.user All_Traffic.dest All_Traffic.dest_ip All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where (RemoteIP == "185.196.10.136" and RemotePort == 8089)
     or (RemoteUrl endswith ".hellohiall.workers.dev")
     or (RemoteUrl in~ ("calm-wildflower-1349.hellohiall.workers.dev",
                        "round-cherry-4418.hellohiall.workers.dev",
                        "orange-cell-1353.hellohiall.workers.dev"))
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, Protocol,
          Initiator = InitiatingProcessFileName,
          InitiatorCmd = InitiatingProcessCommandLine,
          InitiatorPath = InitiatingProcessFolderPath,
          Account = InitiatingProcessAccountName, InitiatingProcessSHA256
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

### Article-specific behavioural hunt — CloudZ RAT potentially steals OTP messages using Pheno plugin

`UC_61_5` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — CloudZ RAT potentially steals OTP messages using Pheno plugin ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("systemupdates.exe","windows-interactive-update.exe","regasm.exe","pheno.exe") OR Processes.process_path="*C:\ProgramData\Microsoft\windosDoc\*" OR Processes.process_path="*C:\ProgramData\Microsoft\WindowsDoc\update*" OR Processes.process_path="*C:\WINDOWS\Microsoft.NET\Framework64\v4.0.30319\*" OR Processes.process_path="*C:\ProgramData\Microsoft\whealth\*" OR Processes.process_path="*C:\Windows\TEMP\pheno.exe*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*C:\ProgramData\Microsoft\windosDoc\*" OR Filesystem.file_path="*C:\ProgramData\Microsoft\WindowsDoc\update*" OR Filesystem.file_path="*C:\WINDOWS\Microsoft.NET\Framework64\v4.0.30319\*" OR Filesystem.file_path="*C:\ProgramData\Microsoft\whealth\*" OR Filesystem.file_path="*C:\Windows\TEMP\pheno.exe*" OR Filesystem.file_path="*C:\programdata\Microsoft\feedback\cm*" OR Filesystem.file_path="*%TEMP%\Microsoft\feedback\cm*" OR Filesystem.file_name IN ("systemupdates.exe","windows-interactive-update.exe","regasm.exe","pheno.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — CloudZ RAT potentially steals OTP messages using Pheno plugin
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("systemupdates.exe", "windows-interactive-update.exe", "regasm.exe", "pheno.exe") or FolderPath has_any ("C:\ProgramData\Microsoft\windosDoc\", "C:\ProgramData\Microsoft\WindowsDoc\update", "C:\WINDOWS\Microsoft.NET\Framework64\v4.0.30319\", "C:\ProgramData\Microsoft\whealth\", "C:\Windows\TEMP\pheno.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("C:\ProgramData\Microsoft\windosDoc\", "C:\ProgramData\Microsoft\WindowsDoc\update", "C:\WINDOWS\Microsoft.NET\Framework64\v4.0.30319\", "C:\ProgramData\Microsoft\whealth\", "C:\Windows\TEMP\pheno.exe", "C:\programdata\Microsoft\feedback\cm", "%TEMP%\Microsoft\feedback\cm") or FileName in~ ("systemupdates.exe", "windows-interactive-update.exe", "regasm.exe", "pheno.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `185.196.10.136`, `update.txt`, `calm-wildflower-1349.hellohiall.workers.dev`, `round-cherry-4418.hellohiall.workers.dev`, `orange-cell-1353.hellohiall.workers.dev`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 9 use case(s) fired, 17 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

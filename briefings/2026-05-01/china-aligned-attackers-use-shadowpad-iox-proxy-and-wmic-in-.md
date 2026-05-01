# [CRIT] China-Aligned Attackers Use ShadowPad, IOX Proxy, and WMIC in Multi-Stage Espionage Campaign

**Source:** Cyber Security News
**Published:** 2026-05-01
**Article:** https://cybersecuritynews.com/china-aligned-attackers-use-multi-stage-espionage-campaign/

## Threat Profile

Home Cyber Security News 
China-Aligned Attackers Use ShadowPad, IOX Proxy, and WMIC in Multi-Stage Espionage Campaign 
By Tushar Subhra Dutta 
May 1, 2026 
A China-aligned threat group has been carrying out a carefully planned espionage campaign against government agencies and critical infrastructure across Asia. 
The group, tracked under the temporary designation SHADOW-EARTH-053, has been active since at least December 2024, quietly targeting organizations in at least eight countries. 
The ca…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2021-26855`
- **CVE:** `CVE-2021-26857`
- **CVE:** `CVE-2021-26858`
- **CVE:** `CVE-2021-27065`

## MITRE ATT&CK Techniques

- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1190** — Exploit Public-Facing Application
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1053.005** — Scheduled Task
- **T1486** — Data Encrypted for Impact
- **T1219** — Remote Access Software
- **T1053.005** — Scheduled Task/Job: Scheduled Task
- **T1574.002** — Hijack Execution Flow: DLL Side-Loading
- **T1505.003** — Server Software Component: Web Shell
- **T1003.001** — OS Credential Dumping: LSASS Memory
- **T1112** — Modify Registry
- **T1047** — Windows Management Instrumentation
- **T1572** — Protocol Tunneling
- **T1090** — Proxy

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] SHADOW-EARTH-053 ShadowPad persistence: scheduled task 'M1onltor' running sideloaded binary every 5 min

`UC_8_6` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process) as parent_process from datamodel=Endpoint.Processes where (Processes.process_name IN ("schtasks.exe","powershell.exe","pwsh.exe","cmd.exe","wmic.exe") AND Processes.process="*M1onltor*") OR (Processes.process="*/Create*" AND Processes.process="*M1onltor*" AND Processes.process="*PT5M*") by Processes.dest Processes.user Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | append [| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Endpoint.Filesystem.file_path="*\\Windows\\System32\\Tasks\\M1onltor*" by Endpoint.Filesystem.dest Endpoint.Filesystem.file_path Endpoint.Filesystem.process_name | `drop_dm_object_name(Filesystem)`] | stats min(firstTime) as firstTime max(lastTime) as lastTime values(*) as * by dest
```

**Defender KQL:**
```kql
union
  (DeviceProcessEvents
   | where ProcessCommandLine has "M1onltor"
      or (FileName =~ "schtasks.exe" and ProcessCommandLine has_all ("/Create","/SC MINUTE","/MO 5"))
   | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine),
  (DeviceFileEvents
   | where FolderPath has @"\Windows\System32\Tasks\" and FileName has "M1onltor"
   | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine),
  (DeviceRegistryEvents
   | where RegistryKey has @"\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\" and (RegistryKey has "M1onltor" or RegistryValueData has "M1onltor")
   | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName)
| sort by Timestamp desc
```

### [LLM] Post-ProxyLogon: IIS w3wp.exe drops GODZILLA web shells or spawns Evil-CreateDump / Mimikatz

`UC_8_7` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.process_name) as child from datamodel=Endpoint.Processes where Processes.parent_process_name="w3wp.exe" AND (Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","rundll32.exe","wmic.exe","net.exe","net1.exe","whoami.exe","DomainMachines.exe","Sharp-SMBExec.exe","newdcsync.exe") OR Processes.process IN ("*Evil-CreateDump*","*createdump*-f *full*","*sekurlsa::logonpasswords*","*lsadump::dcsync*")) by Processes.dest Processes.user Processes.parent_process Processes.process | `drop_dm_object_name(Processes)` | append [| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Endpoint.Filesystem.file_path IN ("*\\inetpub\\wwwroot\\*","*\\Exchange Server\\*FrontEnd\\HttpProxy\\*") AND Endpoint.Filesystem.file_name IN ("error.aspx","warn.aspx","TimeinLogout.aspx","tunnel.ashx") by Endpoint.Filesystem.dest Endpoint.Filesystem.file_path Endpoint.Filesystem.process_name | `drop_dm_object_name(Filesystem)`] | stats min(firstTime) as firstTime max(lastTime) as lastTime values(*) as * by dest
```

**Defender KQL:**
```kql
let webshellNames = dynamic(["error.aspx","warn.aspx","TimeinLogout.aspx","tunnel.ashx"]);
union
  (DeviceProcessEvents
   | where InitiatingProcessFileName =~ "w3wp.exe"
   | where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","rundll32.exe","wmic.exe","net.exe","net1.exe","whoami.exe","nltest.exe","DomainMachines.exe","Sharp-SMBExec.exe","newdcsync.exe")
      or ProcessCommandLine has_any ("Evil-CreateDump","sekurlsa::logonpasswords","lsadump::dcsync","createdump.exe -f")
   | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine),
  (DeviceFileEvents
   | where FileName in~ (webshellNames)
   | where FolderPath has_any (@"\inetpub\wwwroot\", @"\Exchange Server\", @"\FrontEnd\HttpProxy\", @"\ClientAccess\Owa\")
   | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine)
| sort by Timestamp desc
```

### [LLM] SHADOW-EARTH-053 staging: LocalAccountTokenFilterPolicy=1 followed by IOX/GOST/Wstunnel from C:\Users\Public or C:\ProgramData

`UC_8_8` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where Endpoint.Registry.registry_path="*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System*" AND Endpoint.Registry.registry_value_name="LocalAccountTokenFilterPolicy" AND Endpoint.Registry.registry_value_data="0x00000001" by Endpoint.Registry.dest Endpoint.Registry.user Endpoint.Registry.process_name | `drop_dm_object_name(Registry)` | rename dest as host | join type=inner host [| tstats `summariesonly` count from datamodel=Endpoint.Processes where (Processes.process_path IN ("*\\Users\\Public\\*","*\\ProgramData\\*") AND (Processes.process IN ("*iox*","*gost*","*wstunnel*","*-socks5*","*-listen*","*fwd*","*proxy*")) ) OR (Processes.process_name="wmic.exe" AND Processes.process="*process call create*" AND Processes.process="*/node:*") by Processes.dest Processes.process Processes.parent_process_name _time | `drop_dm_object_name(Processes)` | rename dest as host | eval lateral_time=_time] | where lateral_time>=firstTime AND lateral_time<=firstTime+86400 | stats min(firstTime) as firstTime max(lastTime) as lastTime values(process) as suspicious_processes by host user
```

**Defender KQL:**
```kql
let regChange = DeviceRegistryEvents
  | where RegistryKey has @"\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
  | where RegistryValueName =~ "LocalAccountTokenFilterPolicy"
  | where RegistryValueData == "1"
  | project regTime=Timestamp, DeviceId, DeviceName, regProc=InitiatingProcessFileName, regCmd=InitiatingProcessCommandLine;
let stagingExec = DeviceProcessEvents
  | where (FolderPath has_any (@"\Users\Public\", @"\ProgramData\")
           and (FileName has_any ("iox","gost","wstunnel")
                or ProcessCommandLine has_any ("-socks5","-listen","fwd ","proxy ","wss://","wstunnel")))
     or (FileName =~ "wmic.exe" and ProcessCommandLine has "process call create" and ProcessCommandLine has "/node:")
  | project execTime=Timestamp, DeviceId, DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine;
regChange
| join kind=inner stagingExec on DeviceId
| where execTime between (regTime .. regTime + 1d)
| project regTime, execTime, DeviceName, regProc, regCmd, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName
| sort by execTime asc
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
| where FileName in~ ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
   or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
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
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has_any ("powershell","cmd.exe","rundll32","-enc","FromBase64","\Users\Public","\AppData\")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
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
| where ActionType in ("FileRenamed","FileModified")
| summarize files = dcount(FileName) by DeviceName, AccountName, bin(Timestamp, 1m)
| where files > 200
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
| where FileName in~ ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe")
   or FileName matches regex @"(?i)kaseya.*\.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2021-26855`, `CVE-2021-26857`, `CVE-2021-26858`, `CVE-2021-27065`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 9 use case(s) fired, 16 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

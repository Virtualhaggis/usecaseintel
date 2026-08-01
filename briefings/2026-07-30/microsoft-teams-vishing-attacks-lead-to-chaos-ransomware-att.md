# [CRIT] Microsoft Teams vishing attacks lead to Chaos ransomware attacks

**Source:** BleepingComputer
**Published:** 2026-07-30
**Article:** https://www.bleepingcomputer.com/news/security/microsoft-teams-vishing-attacks-lead-to-chaos-ransomware-attacks/

## Threat Profile

Microsoft Teams vishing attacks lead to Chaos ransomware attacks 
By Lawrence Abrams 
July 30, 2026
11:56 AM
0 
Threat actors are impersonating IT support staff in Microsoft Teams calls to gain remote access to corporate devices and deploy Chaos ransomware in attacks targeting North American organizations.
Sophos tracks the campaign as STAC4749 and says it targeted dozens of organizations between February and June 2026.
At least three of these intrusions led to the deployment of Chaos ransomware…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `sequrityupdate.top`
- **Domain (defanged):** `scan-security.top`
- **Domain (defanged):** `system-connect.top`
- **Domain (defanged):** `corp-connect.top`
- **Domain (defanged):** `supportsoft.top`

## MITRE ATT&CK Techniques

- **T1566.004** — Phishing: Spearphishing Voice
- **T1566** — Phishing
- **T1219** — Remote Access Software
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1071** — Application Layer Protocol
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1105** — Ingress Tool Transfer
- **T1547.001** — Registry Run Keys / Startup Folder
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1021.001** — Remote Services: Remote Desktop Protocol
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1490** — Inhibit System Recovery

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### STAC4749 Teams vishing: Quick Assist / RemSupp remote-support tool spawning a shell

`UC_43_7` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("quickassist.exe","remsupp.exe")) AND (Processes.process_name IN ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe","wscript.exe","cscript.exe","curl.exe")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("quickassist.exe","remsupp.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe","wscript.exe","cscript.exe","curl.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### STAC4749 PowerShell backdoor download into %AppData% (updater.exe / helper / msupdate.exe)

`UC_43_8` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime from datamodel=Endpoint.Processes where Processes.process_name IN ("powershell.exe","pwsh.exe") AND (Processes.process="*Invoke-WebRequest*" OR Processes.process="*Invoke-RestMethod*" OR Processes.process="*DownloadFile*" OR Processes.process="*DownloadString*" OR Processes.process="*Start-BitsTransfer*") AND (Processes.process="*AppData*" OR Processes.process="*Unblock-File*" OR Processes.process="*updater.exe*" OR Processes.process="*msupdate.exe*" OR Processes.process="*helper*") by Processes.dest Processes.user Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any ("Invoke-WebRequest","iwr ","Invoke-RestMethod","DownloadFile","DownloadString","Start-BitsTransfer")
| where ProcessCommandLine has_any ("AppData","Unblock-File","updater.exe","msupdate.exe","helper")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
| order by Timestamp desc
```

### STAC4749 Run-key persistence disguised as Realtek / WinAudio audio components

`UC_43_9` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime from datamodel=Endpoint.Registry where (Registry.registry_path="*\\CurrentVersion\\Run*") AND (Registry.registry_value_name IN ("Realtek HD Audio","Realtek Audio UHD","Realtek HD Audio Universal Service","Realtek Audio","WinAudio life2")) by Registry.dest Registry.registry_path Registry.registry_value_name Registry.registry_value_data | `drop_dm_object_name(Registry)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any (@"\CurrentVersion\Run", @"\CurrentVersion\RunOnce")
| where RegistryValueName in~ ("Realtek HD Audio","Realtek Audio UHD","Realtek HD Audio Universal Service","Realtek Audio","WinAudio life2")
| project Timestamp, DeviceName, InitiatingProcessAccountName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### STAC4749 backup-access RMM (DWAgent/AnyDesk) install + RDP enablement for lateral movement

`UC_43_10` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("dwagent.exe","anydesk.exe")) OR (Processes.process_name="reg.exe" AND Processes.process="*fDenyTSConnections*") OR (Processes.process_name="netsh.exe" AND Processes.process="*Remote Desktop*") by Processes.dest Processes.user Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where (FileName in~ ("dwagent.exe","anydesk.exe"))
    or (FileName =~ "reg.exe" and ProcessCommandLine has "fDenyTSConnections")
    or (FileName =~ "netsh.exe" and ProcessCommandLine has_all ("firewall","Remote Desktop"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### STAC4749 IT-themed .top C2 / lure domain contact (sequrityupdate.top et al.)

`UC_43_11` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where (DNS.query IN ("sequrityupdate.top","scan-security.top","system-connect.top","corp-connect.top","supportsoft.top") OR DNS.query="*.sequrityupdate.top" OR DNS.query="*.scan-security.top" OR DNS.query="*.system-connect.top" OR DNS.query="*.corp-connect.top" OR DNS.query="*.supportsoft.top") by DNS.src DNS.query | `drop_dm_object_name(DNS)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any ("sequrityupdate.top","scan-security.top","system-connect.top","corp-connect.top","supportsoft.top")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### STAC4749 Chaos ransomware note (readme.chaos.txt) creation across hosts

`UC_43_12` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime dc(Filesystem.file_path) as pathCount from datamodel=Endpoint.Filesystem where Filesystem.file_name="readme.chaos.txt" by Filesystem.dest Filesystem.process_id | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated"
| where FileName =~ "readme.chaos.txt"
| summarize NoteCount = count(), Folders = make_set(FolderPath, 25), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName
| order by FirstSeen desc
```

### Microsoft Teams external-tenant chat from unverified IT-helpdesk impersonator

`UC_TEAMS_VISHING` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`o365_management_activity`
  Workload=MicrosoftTeams Operation=MessageSent
  ExternalParticipants=*
| where match(SenderDisplayName, "(?i)(help.?desk|it.?support|service.?desk|tech.?support|admin)")
| stats count, earliest(_time) as firstTime, latest(_time) as lastTime
    by SenderUpn, SenderDisplayName, RecipientUpn, ChatId
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Microsoft Teams"
| where ActionType == "MessageSent"
| where RawEventData has "ExternalParticipants"
| extend SenderDisplayName = tostring(parse_json(RawEventData).SenderDisplayName)
| where SenderDisplayName matches regex @"(?i)(help.?desk|it.?support|service.?desk|tech.?support|admin)"
| project Timestamp, AccountDisplayName, IPAddress, ActivityType, SenderDisplayName, RawEventData
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `sequrityupdate.top`, `scan-security.top`, `system-connect.top`, `corp-connect.top`, `supportsoft.top`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 13 use case(s) fired, 18 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

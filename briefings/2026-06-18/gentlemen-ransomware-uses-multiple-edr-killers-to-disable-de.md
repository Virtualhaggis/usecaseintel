# [CRIT] Gentlemen ransomware uses multiple EDR killers to disable defenses

**Source:** BleepingComputer
**Published:** 2026-06-18
**Article:** https://www.bleepingcomputer.com/news/security/gentlemen-ransomware-uses-multiple-edr-killers-to-disable-defenses/

## Threat Profile

Gentlemen ransomware uses multiple EDR killers to disable defenses 
By Bill Toulas 
June 18, 2026
06:31 PM
0 
The Gentlemen ransomware-as-a-service (RaaS) is actively developing and maintaining a suite of endpoint detection and response (EDR) killers to help affiliates evade detection in attacks.
The gang employs a collection of EDR-killing tools, most notably a utility that researchers dubbed GentleKiller. The tool has at least eight variants and impersonates various legitimate security product…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2022-42045`
- **CVE:** `CVE-2025-26125`
- **SHA1:** `8AE6BD18B129061F63642531F1B684CF0383C75D`
- **SHA1:** `BA914FE77B177B45799403B16DD14765C510A074`
- **SHA1:** `D605994FC72A2BB59B5CFB1624A1B9170ECA73A2`
- **SHA1:** `B0B912A3FD1C05D72080848EC4C92880004021A1`
- **SHA1:** `5AA3124E5C4921E5EDFC60133B5D71DA21B07DA3`
- **SHA1:** `7556AE58C215B8245A43F764F0676C7A8F0FDD1A`
- **SHA1:** `331879F5EEC8892BBD896F90BDBB1BAD0BF63BD6`
- **SHA1:** `F11AEBCCB9A86A7E2E653F90BAEC697F233C255F`
- **SHA1:** `EF9CD06683159397F099CAA244E94E6EAAD96EBA`
- **SHA1:** `711EF221526997039E804A18DB9647C91680BBE2`
- **SHA1:** `68FEC379F2AE76C3D2CE913F7BE650CEA1D06990`
- **SHA1:** `A11EE9CDC59E5CAA59AEFD27B30D104F3AD68E62`
- **SHA1:** `96F0DBF52AED0AFD43E44500116B04B674F7358E`
- **SHA1:** `2F86898528C6CAB3540C486A9BFAA0C029B73950`
- **SHA1:** `9AD51AD97C01E97AB59214116740785E0F6320A8`
- **SHA1:** `A19117175DBC9BA4D23B5DCE8415E299A2E32192`
- **SHA1:** `12500F6C87CE62712A0ED6652C57468D15C14223`
- **SHA1:** `D29670E684E40DDC89B47010C37CBC96737035B6`
- **SHA1:** `56BEE9DF5833A637F5C54D5911DF98B0812FE643`
- **SHA1:** `CF4D74DF17A91B4A36A2911B22AFEC5D8FA93A01`
- **SHA1:** `EC296F9501AD71E430810CB5CDC38D954D4BA536`
- **SHA1:** `7131B377E96016DC1911020C9F95B1B4D042D7B4`
- **SHA1:** `82ED942A52CDCF120A8919730E00BA37619661A3`
- **SHA1:** `F0537CBB773AE12100B36731E7C39F5A9D852B14`
- **SHA1:** `1FA071303FB846308571E64727501FB98B1C2BE6`
- **SHA1:** `A5CF917EC4A7DFBDFA43621398604805D860C718`
- **SHA1:** `D4B19141102015D436321E6F26976E98183CFD27`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1027** — Obfuscated Files or Information
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1489** — Service Stop
- **T1068** — Exploitation for Privilege Escalation
- **T1014** — Rootkit
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1027.002** — Obfuscated Files or Information: Software Packing
- **T1553.002** — Subvert Trust Controls: Code Signing
- **T1543.003** — Create or Modify System Process: Windows Service
- **T1090.002** — Proxy: External Proxy
- **T1571** — Non-Standard Port

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Gentlemen EDR killer — mass termination of security vendor processes

`UC_2_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdlines values(Processes.process_name) as victims dc(Processes.process_name) as victim_count from datamodel=Endpoint.Processes where Processes.parent_process_name!="services.exe" Processes.process_name IN ("MsMpEng.exe","SenseIR.exe","MsSense.exe","NisSrv.exe","CSFalconService.exe","CSFalconController.exe","SentinelAgent.exe","SentinelServiceHost.exe","SentinelStaticEngine.exe","cyserver.exe","cytray.exe","CylanceSvc.exe","sophosFS.exe","SophosHealth.exe","SAVService.exe","ekrn.exe","egui.exe","bdservicehost.exe","vsserv.exe","avp.exe","kavfs.exe","tmccsf.exe","tmlisten.exe","mfemms.exe","mfetp.exe","masvc.exe","cortex.exe","Traps.exe","PanGPS.exe") (Processes.process="*taskkill*" OR Processes.process="*TerminateProcess*" OR Processes.process="*Stop-Process*" OR Processes.process="*sc * stop*") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | where victim_count >= 5 AND lastTime-firstTime < 300 | sort - lastTime
```

**Defender KQL:**
```kql
let WindowMin = 5m;
let AvProcs = dynamic(["msmpeng.exe","sensir.exe","mssense.exe","nissrv.exe","csfalconservice.exe","csfalconcontroller.exe","sentinelagent.exe","sentinelservicehost.exe","sentinelstaticengine.exe","cyserver.exe","cytray.exe","cylancesvc.exe","sophosfs.exe","sophoshealth.exe","savservice.exe","ekrn.exe","egui.exe","bdservicehost.exe","vsserv.exe","avp.exe","kavfs.exe","tmccsf.exe","tmlisten.exe","mfemms.exe","mfetp.exe","masvc.exe","cortex.exe","traps.exe","pangps.exe"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where (FileName =~ "taskkill.exe" and ProcessCommandLine has_any (AvProcs))
   or (FileName in~ ("powershell.exe","pwsh.exe") and ProcessCommandLine has "Stop-Process" and ProcessCommandLine has_any (AvProcs))
   or (FileName =~ "sc.exe" and ProcessCommandLine has "stop")
| summarize FirstKill = min(Timestamp), LastKill = max(Timestamp), Victims = make_set(ProcessCommandLine, 50), VictimCount = dcount(ProcessCommandLine) by DeviceName, DeviceId, AccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256, bin(Timestamp, WindowMin)
| where VictimCount >= 5
| order by LastKill desc
```

### BYOVD — vulnerable kernel driver loaded from user-writable path

`UC_2_6` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths values(Filesystem.process_name) as initiators from datamodel=Endpoint.Filesystem where Filesystem.action="created" Filesystem.file_name="*.sys" (Filesystem.file_path="*\\Temp\\*" OR Filesystem.file_path="*\\AppData\\*" OR Filesystem.file_path="*\\ProgramData\\*" OR Filesystem.file_path="*\\Users\\Public\\*" OR Filesystem.file_path="*\\Downloads\\*") by Filesystem.dest Filesystem.file_name Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | eval is_known_byovd=if(match(file_name,"(?i)(throttleblood|procexp152|dbutil|rtcore64|gdrv|aswarpot|truesight|viragt|hsbdrv)\.sys"),1,0) | sort - lastTime
```

**Defender KQL:**
```kql
let KnownByovd = dynamic(["throttleblood.sys","procexp152.sys","dbutil_2_3.sys","rtcore64.sys","gdrv.sys","aswarpot.sys","truesight.sys","viragt64.sys","hsbdrv.sys"]);
let WritableRoots = dynamic([@"\Temp\", @"\AppData\", @"\ProgramData\", @"\Users\Public\", @"\Downloads\"]);
let DrvDrops = DeviceFileEvents
  | where Timestamp > ago(7d)
  | where ActionType == "FileCreated"
  | where FileName endswith ".sys"
  | where FolderPath has_any (WritableRoots) or tolower(FileName) in (KnownByovd)
  | project DropTime = Timestamp, DeviceId, DeviceName, DroppedDriver = FileName, DroppedPath = FolderPath, DroppedSHA256 = SHA256, DropperProc = InitiatingProcessFileName, DropperCmd = InitiatingProcessCommandLine, DropperSHA256 = InitiatingProcessSHA256;
let DrvLoads = DeviceImageLoadEvents
  | where Timestamp > ago(7d)
  | where FileName endswith ".sys"
  | where FolderPath has_any (WritableRoots) or tolower(FileName) in (KnownByovd)
  | project LoadTime = Timestamp, DeviceId, DeviceName, LoadedDriver = FileName, LoadedPath = FolderPath, LoadedSHA256 = SHA256, LoaderProc = InitiatingProcessFileName;
DrvDrops
| join kind=inner DrvLoads on DeviceId
| where LoadTime between (DropTime .. DropTime + 1h)
| project DropTime, LoadTime, DeviceName, DroppedDriver, DroppedPath, DroppedSHA256, DropperProc, DropperCmd, LoaderProc, LoadedDriver, LoadedPath
| order by LoadTime desc
```

### GentleKiller impersonation binary — Kaspersky/Valorant/Javelin/WatchDog from non-vendor path

`UC_2_7` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.process_hash) as sha256 from datamodel=Endpoint.Processes where (Processes.process_name IN ("Kaspersky.exe","avp.exe","avpui.exe","VALORANT.exe","vgc.exe","vgtray.exe","Javelin.exe","WatchDog.exe","WatchDogAgent.exe") OR Processes.process_company IN ("Kaspersky Lab","Riot Games","Javelin Networks","WatchDog")) AND NOT (Processes.process_path="*\\Program Files*\\Kaspersky Lab\\*" OR Processes.process_path="*\\Riot Games\\VALORANT\\*" OR Processes.process_path="*\\Program Files*\\Javelin*" OR Processes.process_path="*\\Program Files*\\WatchDog*") by Processes.dest Processes.user Processes.process_name Processes.process_path Processes.parent_process_name | `drop_dm_object_name(Processes)` | sort - lastTime
```

**Defender KQL:**
```kql
let Masqueraders = dynamic(["kaspersky.exe","avp.exe","avpui.exe","valorant.exe","vgc.exe","vgtray.exe","javelin.exe","watchdog.exe","watchdogagent.exe"]);
let LegitVendors = dynamic(["Kaspersky Lab","AO Kaspersky Lab","Riot Games","Riot Games, Inc.","Javelin Networks","WatchDog"]);
let LegitRoots = dynamic([@"\Program Files\Kaspersky", @"\Program Files (x86)\Kaspersky", @"\Riot Games\", @"\Program Files\Riot Vanguard\", @"\Program Files\Javelin", @"\Program Files\WatchDog"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where AccountName !endswith "$"
| where tolower(FileName) in (Masqueraders) or ProcessVersionInfoCompanyName in~ (LegitVendors)
| where not (FolderPath has_any (LegitRoots))
| where FolderPath has_any (@"\Temp\", @"\AppData\", @"\ProgramData\", @"\Users\Public\", @"\Downloads\", @"\Windows\Tasks\")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, SHA256,
          ClaimedVendor = ProcessVersionInfoCompanyName, ClaimedProduct = ProcessVersionInfoProductName,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Vulnerable driver service installation via registry

`UC_2_8` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Registry.registry_value_data) as image_path values(Registry.process_name) as creator from datamodel=Endpoint.Registry where Registry.registry_path="*\\SYSTEM\\CurrentControlSet\\Services\\*\\ImagePath" Registry.registry_value_data="*.sys*" NOT (Registry.registry_value_data="*\\System32\\drivers\\*" OR Registry.registry_value_data="*\\SysWOW64\\drivers\\*" OR Registry.registry_value_data="\\??\\C:\\Windows\\*") by Registry.dest Registry.registry_key_name Registry.user | `drop_dm_object_name(Registry)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryKey has @"\SYSTEM\CurrentControlSet\Services\"
| where RegistryValueName =~ "ImagePath"
| where RegistryValueData has ".sys"
| where not (RegistryValueData has_any (@"\System32\drivers\", @"\SysWOW64\drivers\", @"\Windows\INF\"))
| extend ServiceName = tostring(split(RegistryKey, "\\")[-1])
| where InitiatingProcessAccountName !endswith "$"
   or InitiatingProcessFileName !in~ ("services.exe","msiexec.exe","trustedinstaller.exe")
| project Timestamp, DeviceName, ServiceName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessFolderPath
| order by Timestamp desc
```

### SystemBC SOCKS5 proxy beacon — persistent low-volume egress on non-standard high port

`UC_2_9` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime sum(All_Traffic.bytes) as bytes_total dc(All_Traffic.dest_ip) as dst_ip_count from datamodel=Network_Traffic.All_Traffic where All_Traffic.transport="tcp" All_Traffic.dest_port>1024 All_Traffic.dest_port!=443 All_Traffic.dest_port!=80 All_Traffic.dest_port!=8080 (NOT All_Traffic.dest_ip IN (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)) All_Traffic.app!="chrome.exe" All_Traffic.app!="msedge.exe" All_Traffic.app!="firefox.exe" by All_Traffic.src All_Traffic.app All_Traffic.dest_ip All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)` | eval duration_min=(lastTime-firstTime)/60 | where duration_min > 30 AND dst_ip_count = 1 AND bytes_total < 5000000 | sort - duration_min
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "ConnectionSuccess"
| where RemoteIPType == "Public"
| where Protocol == "Tcp"
| where RemotePort > 1024 and RemotePort !in (443, 80, 8080, 8443, 22, 3389, 5900)
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","iexplore.exe","svchost.exe","OneDrive.exe","Teams.exe","slack.exe","zoom.exe","outlook.exe")
| where InitiatingProcessAccountName !endswith "$"
| summarize ConnCount = count(), DistinctIPs = dcount(RemoteIP), FirstSeen = min(Timestamp), LastSeen = max(Timestamp), SampleIP = any(RemoteIP) by DeviceName, DeviceId, InitiatingProcessFileName, InitiatingProcessSHA256, InitiatingProcessFolderPath, RemotePort
| extend DurationMin = datetime_diff('minute', LastSeen, FirstSeen)
| where DurationMin > 30 and DistinctIPs <= 2 and ConnCount >= 6
| order by DurationMin desc
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

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2022-42045`, `CVE-2025-26125`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `8AE6BD18B129061F63642531F1B684CF0383C75D`, `BA914FE77B177B45799403B16DD14765C510A074`, `D605994FC72A2BB59B5CFB1624A1B9170ECA73A2`, `B0B912A3FD1C05D72080848EC4C92880004021A1`, `5AA3124E5C4921E5EDFC60133B5D71DA21B07DA3`, `7556AE58C215B8245A43F764F0676C7A8F0FDD1A`, `331879F5EEC8892BBD896F90BDBB1BAD0BF63BD6`, `F11AEBCCB9A86A7E2E653F90BAEC697F233C255F` _(+19 more)_


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 10 use case(s) fired, 17 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

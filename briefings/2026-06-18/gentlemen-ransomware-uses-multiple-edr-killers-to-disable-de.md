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
- **T1068** — Exploitation for Privilege Escalation
- **T1543.003** — Create or Modify System Process: Windows Service
- **T1036.005** — Masquerading: Match Legitimate Resource Name or Location
- **T1027.002** — Obfuscated Files or Information: Software Packing

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### GentleKiller / HexKiller / ThrottleBlood / HavocKiller binary hash hit

`UC_25_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where Processes.process_hash IN ("8AE6BD18B129061F63642531F1B684CF0383C75D","BA914FE77B177B45799403B16DD14765C510A074","D605994FC72A2BB59B5CFB1624A1B9170ECA73A2","B0B912A3FD1C05D72080848EC4C92880004021A1","5AA3124E5C4921E5EDFC60133B5D71DA21B07DA3","7556AE58C215B8245A43F764F0676C7A8F0FDD1A","331879F5EEC8892BBD896F90BDBB1BAD0BF63BD6","F11AEBCCB9A86A7E2E653F90BAEC697F233C255F","EF9CD06683159397F099CAA244E94E6EAAD96EBA","711EF221526997039E804A18DB9647C91680BBE2","68FEC379F2AE76C3D2CE913F7BE650CEA1D06990","A11EE9CDC59E5CAA59AEFD27B30D104F3AD68E62","96F0DBF52AED0AFD43E44500116B04B674F7358E","2F86898528C6CAB3540C486A9BFAA0C029B73950","9AD51AD97C01E97AB59214116740785E0F6320A8","A19117175DBC9BA4D23B5DCE8415E299A2E32192","12500F6C87CE62712A0ED6652C57468D15C14223","D29670E684E40DDC89B47010C37CBC96737035B6","56BEE9DF5833A637F5C54D5911DF98B0812FE643","CF4D74DF17A91B4A36A2911B22AFEC5D8FA93A01") by Processes.dest Processes.user Processes.process_name Processes.process_hash | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let GentlemenSHA1 = dynamic(["8AE6BD18B129061F63642531F1B684CF0383C75D","BA914FE77B177B45799403B16DD14765C510A074","D605994FC72A2BB59B5CFB1624A1B9170ECA73A2","B0B912A3FD1C05D72080848EC4C92880004021A1","5AA3124E5C4921E5EDFC60133B5D71DA21B07DA3","7556AE58C215B8245A43F764F0676C7A8F0FDD1A","331879F5EEC8892BBD896F90BDBB1BAD0BF63BD6","F11AEBCCB9A86A7E2E653F90BAEC697F233C255F","EF9CD06683159397F099CAA244E94E6EAAD96EBA","711EF221526997039E804A18DB9647C91680BBE2","68FEC379F2AE76C3D2CE913F7BE650CEA1D06990","A11EE9CDC59E5CAA59AEFD27B30D104F3AD68E62","96F0DBF52AED0AFD43E44500116B04B674F7358E","2F86898528C6CAB3540C486A9BFAA0C029B73950","9AD51AD97C01E97AB59214116740785E0F6320A8","A19117175DBC9BA4D23B5DCE8415E299A2E32192","12500F6C87CE62712A0ED6652C57468D15C14223","D29670E684E40DDC89B47010C37CBC96737035B6","56BEE9DF5833A637F5C54D5911DF98B0812FE643","CF4D74DF17A91B4A36A2911B22AFEC5D8FA93A01"]);
let ProcHits = DeviceProcessEvents
  | where Timestamp > ago(30d)
  | where SHA1 in~ (GentlemenSHA1) or InitiatingProcessSHA1 in~ (GentlemenSHA1)
  | project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA1, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine;
let FileHits = DeviceFileEvents
  | where Timestamp > ago(30d)
  | where SHA1 in~ (GentlemenSHA1) or InitiatingProcessSHA1 in~ (GentlemenSHA1)
  | project Timestamp, DeviceName, FileName=FileName, FolderPath, SHA1, ProcessCommandLine=InitiatingProcessCommandLine, InitiatingProcessFileName, AccountName=InitiatingProcessAccountName, InitiatingProcessCommandLine;
ProcHits | union FileHits | order by Timestamp desc
```

### BYOVD vulnerable-driver service install impersonating Kaspersky/Valorant/Javelin/WatchDog

`UC_25_6` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Registry.registry_value_data) as ImagePath values(Registry.process_name) as parent from datamodel=Endpoint.Registry where Registry.registry_path="*\\System\\CurrentControlSet\\Services\\*\\ImagePath" (Registry.registry_value_data="*kaspersky*" OR Registry.registry_value_data="*valorant*" OR Registry.registry_value_data="*vgk*" OR Registry.registry_value_data="*javelin*" OR Registry.registry_value_data="*watchdog*" OR Registry.registry_path="*\\Services\\kaspersky*" OR Registry.registry_path="*\\Services\\valorant*" OR Registry.registry_path="*\\Services\\vgk*" OR Registry.registry_path="*\\Services\\javelin*" OR Registry.registry_path="*\\Services\\watchdog*") by Registry.dest Registry.user Registry.registry_path Registry.registry_value_data | `drop_dm_object_name(Registry)` | where NOT match(ImagePath, "(?i)\\\\Program Files\\\\(Kaspersky Lab|Riot Vanguard|Valorant)\\\\") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryKey has @"\System\CurrentControlSet\Services\"
| where (RegistryValueName =~ "ImagePath" and RegistryValueData has_any ("kaspersky","valorant","vgk.sys","javelin","watchdog","wdog","wsdk"))
     or (RegistryKey has_any (@"\Services\kaspersky",@"\Services\valorant",@"\Services\vgk",@"\Services\javelin",@"\Services\watchdog",@"\Services\wdog") and RegistryValueName =~ "ImagePath")
| where not (RegistryValueData has_any (@"\Program Files\Kaspersky Lab\", @"\Program Files\Riot Vanguard\", @"\Program Files\Valorant\"))
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessSHA1
| order by Timestamp desc
```

### Themida/Enigma packed binary with security-vendor masquerade name from user-writable path

`UC_25_7` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent values(Processes.process_hash) as hash from datamodel=Endpoint.Processes where (Processes.process_name="kaspersky*" OR Processes.process_name="avp*" OR Processes.process_name="valorant*" OR Processes.process_name="vgc*" OR Processes.process_name="vgk*" OR Processes.process_name="javelin*" OR Processes.process_name="watchdog*" OR Processes.process_name="wdog*") (Processes.process_path="*\\Users\\*\\AppData\\Local\\Temp\\*" OR Processes.process_path="*\\ProgramData\\*" OR Processes.process_path="*\\Users\\Public\\*" OR Processes.process_path="*\\Users\\*\\Downloads\\*" OR Processes.process_path="*\\Windows\\Temp\\*" OR Processes.process_path="*\\Perflogs\\*") NOT (Processes.process_path="*\\Program Files\\Kaspersky Lab\\*" OR Processes.process_path="*\\Program Files\\Riot Vanguard\\*" OR Processes.process_path="*\\Program Files\\Valorant\\*") by Processes.dest Processes.user Processes.process_name Processes.process_path | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let MasqNames = dynamic(["kaspersky","avp","avpui","valorant","vgc","vgk","javelin","watchdog","wdog"]);
let SuspectPaths = dynamic([@"\Users\Public\", @"\ProgramData\", @"\Windows\Temp\", @"\PerfLogs\", @"\AppData\Local\Temp\", @"\Downloads\"]);
let LegitPaths = dynamic([@"\Program Files\Kaspersky Lab\", @"\Program Files\Riot Vanguard\", @"\Program Files\Valorant\", @"\Program Files (x86)\Kaspersky Lab\"]);
DeviceProcessEvents
| where Timestamp > ago(14d)
| where AccountName !endswith "$"
| extend FNameLow = tolower(FileName)
| where FNameLow has_any (MasqNames)
| where FolderPath has_any (SuspectPaths)
| where not (FolderPath has_any (LegitPaths))
| extend SignerSuspect = (ProcessVersionInfoCompanyName !has_any ("Kaspersky","Riot Games","Microsoft")) or isempty(ProcessVersionInfoCompanyName)
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, SHA1,
          ProcessCommandLine, ProcessVersionInfoCompanyName, ProcessVersionInfoProductName, ProcessVersionInfoOriginalFileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine, SignerSuspect
| order by Timestamp desc
```

### Mass termination of 48-vendor EDR/AV process set within short window

`UC_25_8` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count values(Processes.process_name) as killed_processes dc(Processes.process_name) as VendorProcCount min(_time) as firstKill max(_time) as lastKill from datamodel=Endpoint.Processes where Processes.action="terminated" (Processes.process_name IN ("MsMpEng.exe","NisSrv.exe","SenseIR.exe","SenseCncProxy.exe","MsSense.exe","CSFalconService.exe","CSFalconContainer.exe","SentinelAgent.exe","SentinelServiceHost.exe","SentinelStaticEngine.exe","cyserver.exe","cyveraservice.exe","CortexXDR.exe","SophosAgent.exe","SophosFS.exe","SophosHealth.exe","SophosClean.exe","tmlisten.exe","PccNTMon.exe","TmCCSF.exe","ekrn.exe","egui.exe","eelam.exe","bdagent.exe","vsserv.exe","epsecurityservice.exe","masvc.exe","mcshield.exe","mfemms.exe","FrameworkService.exe","avp.exe","avpui.exe","kavfs.exe","klnagent.exe")) by Processes.dest Processes.user _time span=5m | where VendorProcCount >= 10 | convert ctime(firstKill) ctime(lastKill)
```

**Defender KQL:**
```kql
let VendorProcs = dynamic(["MsMpEng.exe","NisSrv.exe","SenseIR.exe","SenseCncProxy.exe","MsSense.exe","CSFalconService.exe","CSFalconContainer.exe","SentinelAgent.exe","SentinelServiceHost.exe","SentinelStaticEngine.exe","cyserver.exe","cyveraservice.exe","CortexXDR.exe","SophosAgent.exe","SophosFS.exe","SophosHealth.exe","SophosClean.exe","tmlisten.exe","PccNTMon.exe","TmCCSF.exe","ekrn.exe","egui.exe","eelam.exe","bdagent.exe","vsserv.exe","epsecurityservice.exe","masvc.exe","mcshield.exe","mfemms.exe","FrameworkService.exe","avp.exe","avpui.exe","kavfs.exe","klnagent.exe"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ActionType == "ProcessTerminated" or ActionType == "ProcessCreated"
| where FileName in~ (VendorProcs)
| summarize TerminatedProcs = make_set(FileName), VendorProcCount = dcount(FileName), FirstKill = min(Timestamp), LastKill = max(Timestamp) by DeviceName, bin(Timestamp, 5m)
| where VendorProcCount >= 10
| order by FirstKill desc
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

Severity classified as **CRIT** based on: CVE present, IOCs present, 9 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

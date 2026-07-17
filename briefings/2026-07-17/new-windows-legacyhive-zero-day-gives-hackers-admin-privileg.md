# [HIGH] New Windows LegacyHive zero-day gives hackers admin privileges

**Source:** BleepingComputer
**Published:** 2026-07-17
**Article:** https://www.bleepingcomputer.com/news/security/new-windows-legacyhive-zero-day-exploit-grants-hackers-admin-access/

## Threat Profile

New Windows LegacyHive zero-day gives hackers admin privileges 
By Sergiu Gatlan 
July 17, 2026
07:05 AM
0 


A security researcher using the "Nightmare Eclipse" handle has released a Windows zero-day exploit dubbed LegacyHive that allows attackers to escalate privileges on up-to-date Windows systems.


Nightmare Eclipse published a proof-of-concept (PoC) exploit hours after Microsoft released its July 2026 Patch Tuesday updates, saying that it abuses a security vulnerability in the Windows …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-50656`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1078.003** — Valid Accounts: Local Accounts
- **T1078** — Valid Accounts
- **T1112** — Modify Registry
- **T1546.001** — Event Triggered Execution: Change Default File Association
- **T1068** — Exploitation for Privilege Escalation
- **T1074.001** — Data Staged: Local Data Staging

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### LegacyHive: standard-user secondary-logon (CreateProcessWithLogonW) spawning cross-SID suspended benign binary

`UC_0_1` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Authentication where Authentication.action=success Authentication.logon_type=2 by Authentication.dest, Authentication.src_user, Authentication.user, Authentication.app, Authentication.signature_id | `drop_dm_object_name(Authentication)` | where src_user!=user AND src_user!="-" AND user!="-" AND NOT match(user,"\$$") AND NOT match(src_user,"\$$") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where isnotempty(AccountSid) and isnotempty(InitiatingProcessAccountSid)
| where AccountSid != InitiatingProcessAccountSid
| where InitiatingProcessIntegrityLevel in ("Medium","Low")
| where InitiatingProcessAccountName !endswith "$"
| where InitiatingProcessAccountName !in~ ("system","local service","network service")
| where AccountName !endswith "$"
// benign 'host' binaries the LegacyHive PoC launches suspended under the target account
| where FileName in~ ("notepad.exe","calc.exe","calculator.exe","cmd.exe","rundll32.exe","conhost.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessAccountSid, InitiatingProcessFileName, InitiatingProcessIntegrityLevel, InitiatingProcessCommandLine, AccountName, AccountSid, FileName, FolderPath, ProcessCommandLine, ProcessIntegrityLevel
| order by Timestamp desc
```

### LegacyHive: non-elevated process tampering per-user Classes hive ProgID/CLSID handler

`UC_0_2` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where (Registry.registry_path="*\\Software\\Classes\\*" OR Registry.registry_path="*_Classes\\*") (Registry.registry_path="*\\shell\\open\\command*" OR Registry.registry_path="*InprocServer32*" OR Registry.registry_path="*LocalServer32*") by Registry.dest, Registry.user, Registry.registry_path, Registry.registry_value_name, Registry.registry_value_data, Registry.process_name | `drop_dm_object_name(Registry)` | where NOT match(user,"\$$") AND process_name!="msiexec.exe" AND process_name!="explorer.exe" AND process_name!="svchost.exe" | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any (@"\Software\Classes", "_Classes")
| where RegistryKey has_any (@"\shell\open\command", @"\shell\runas\command", "InprocServer32", "LocalServer32")
| where InitiatingProcessIntegrityLevel in ("Medium","Low")
| where InitiatingProcessAccountName !endswith "$"
| where InitiatingProcessFileName !in~ ("msiexec.exe","explorer.exe","svchost.exe","setup.exe","teams.exe","onedrive.exe","chrome.exe","msedge.exe","firefox.exe","acrobat.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessIntegrityLevel, InitiatingProcessFileName, InitiatingProcessCommandLine, RegistryKey, RegistryValueName, RegistryValueData
| order by Timestamp desc
```

### LegacyHive: UsrClass.dat/NTUSER.DAT copies staged outside the user profile directory

`UC_0_3` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name="usrclass.dat" OR Filesystem.file_name="ntuser.dat") by Filesystem.dest, Filesystem.user, Filesystem.file_path, Filesystem.file_name, Filesystem.process_name | `drop_dm_object_name(Filesystem)` | where NOT like(lower(file_path),"c:\\users\\%") AND NOT like(lower(file_path),"%\\appdata\\local\\microsoft\\windows\\%") AND NOT match(user,"\$$") AND process_name!="svchost.exe" | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where FileName in~ ("usrclass.dat","ntuser.dat")
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath !startswith @"C:\Users\"
| where FolderPath !has @"\AppData\Local\Microsoft\Windows\"
| where InitiatingProcessAccountName !endswith "$"
| where InitiatingProcessFileName !in~ ("svchost.exe","explorer.exe","backup.exe","veeam.backup.shell.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessIntegrityLevel, InitiatingProcessFileName, InitiatingProcessFolderPath, ActionType, FileName, FolderPath
| order by Timestamp desc
```

### LegacyHive: elevated child spawned by explorer.exe shortly after per-user Classes hive modification

`UC_0_4` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Endpoint.Registry where (Registry.registry_path="*\\Software\\Classes\\*" OR Registry.registry_path="*_Classes\\*") Registry.registry_path="*\\shell\\open\\command*" by Registry.dest, _time | `drop_dm_object_name(Registry)` | rename _time as mod_time | join type=inner dest [ | tstats `summariesonly` count from datamodel=Endpoint.Processes where Processes.parent_process_name="explorer.exe" (Processes.process_integrity_level="High" OR Processes.process_integrity_level="System") by Processes.dest, Processes.process_name, Processes.process, Processes.process_integrity_level, _time | `drop_dm_object_name(Processes)` | rename _time as proc_time ] | where proc_time>=mod_time AND proc_time<=(mod_time+3600) | eval delay_sec=proc_time-mod_time | table dest, mod_time, proc_time, delay_sec, process_name, process, process_integrity_level
```

**Defender KQL:**
```kql
let LookbackDays = 7d;
let ClassesMods = DeviceRegistryEvents
    | where Timestamp > ago(LookbackDays)
    | where ActionType == "RegistryValueSet"
    | where RegistryKey has_any (@"\Software\Classes", "_Classes")
    | where RegistryKey has @"\shell\open\command"
    | where InitiatingProcessIntegrityLevel in ("Medium","Low")
    | project ModTime = Timestamp, DeviceId, DeviceName, ModKey = RegistryKey, ModData = RegistryValueData, ModActor = InitiatingProcessAccountName;
DeviceProcessEvents
| where Timestamp > ago(LookbackDays)
| where InitiatingProcessFileName =~ "explorer.exe"
| where ProcessIntegrityLevel in ("High","System")
| where FileName !in~ ("consent.exe","runtimebroker.exe","dllhost.exe","sihost.exe","taskhostw.exe","explorer.exe","userinit.exe","ctfmon.exe","searchhost.exe","startmenuexperiencehost.exe")
| join kind=inner ClassesMods on DeviceId
| where Timestamp between (ModTime .. ModTime + 1h)
| extend DelaySec = datetime_diff('second', Timestamp, ModTime)
| project Timestamp, DeviceName, ModTime, DelaySec, AccountName, ProcessIntegrityLevel, FileName, FolderPath, ProcessCommandLine, ModActor, ModKey, ModData
| order by Timestamp desc
```

### LegacyHive PoC validation marker written to registry (LegacyHive_Admin2_Marker / ADMIN2_HIVE_CONFIRMED)

`UC_0_5` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where (Registry.registry_value_name="*LegacyHive*" OR Registry.registry_path="*LegacyHive*" OR Registry.registry_value_data="*ADMIN2_HIVE_CONFIRMED*") by Registry.dest, Registry.user, Registry.registry_path, Registry.registry_value_name, Registry.registry_value_data, Registry.process_name | `drop_dm_object_name(Registry)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where RegistryValueName has "LegacyHive"
    or RegistryKey has "LegacyHive"
    or RegistryValueData has "ADMIN2_HIVE_CONFIRMED"
| project Timestamp, DeviceName, ActionType, InitiatingProcessAccountName, InitiatingProcessIntegrityLevel, InitiatingProcessFileName, InitiatingProcessCommandLine, RegistryKey, RegistryValueName, RegistryValueData
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-50656`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 6 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

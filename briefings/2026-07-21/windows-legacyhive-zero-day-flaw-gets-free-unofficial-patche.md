# [HIGH] Windows LegacyHive zero-day flaw gets free, unofficial patches

**Source:** BleepingComputer
**Published:** 2026-07-21
**Article:** https://www.bleepingcomputer.com/news/security/windows-legacyhive-zero-day-flaw-gets-free-unofficial-patches/

## Threat Profile

Windows LegacyHive zero-day flaw gets free, unofficial patches 
By Sergiu Gatlan 
July 21, 2026
04:06 AM
0 
Free unofficial patches are available for a recently disclosed Windows zero-day flaw that allows attackers to escalate privileges on up-to-date Windows systems.
The vulnerability (dubbed LegacyHive and without a CVE ID for easy tracking) was found by a security researcher using the "Nightmare Eclipse" handle in the Windows User Profile Service.
Nightmare Eclipse disclosed it the day Micros…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-33825`
- **CVE:** `CVE-2026-41091`
- **CVE:** `CVE-2026-45498`
- **Domain (defanged):** `git.projectnightcrawler.dev`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1071** — Application Layer Protocol
- **T1547.001** — Registry Run Keys / Startup Folder
- **T1547.004** — Winlogon Helper DLL
- **T1112** — Modify Registry
- **T1068** — Exploitation for Privilege Escalation

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### LegacyHive: autorun value written into another user's registry hive by non-admin process

`UC_10_2` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where (Registry.registry_path="*\\CurrentVersion\\Run*" OR Registry.registry_path="*\\CurrentVersion\\RunOnce*" OR Registry.registry_path="*\\CurrentVersion\\Winlogon*") Registry.registry_path="*\\USER\\S-1-5-21*" Registry.action=modified NOT (Registry.user IN ("SYSTEM","LOCAL SERVICE","NETWORK SERVICE") OR Registry.user="*$") by Registry.dest Registry.user Registry.registry_path Registry.registry_value_name Registry.registry_value_data Registry.process_guid 
| `drop_dm_object_name(Registry)` 
| rex field=registry_path "USER\\\\(?<hive_sid>S-1-5-21-[0-9\-]+)" 
| convert ctime(firstTime) ctime(lastTime) 
| table firstTime lastTime dest user hive_sid registry_path registry_value_name registry_value_data process_guid count
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where ActionType == "RegistryValueSet"
| where RegistryKey startswith "HKEY_USERS\\"
| where RegistryKey has_any (@"\CurrentVersion\Run", @"\CurrentVersion\RunOnce", @"CurrentVersion\Winlogon")
| extend HiveSid = extract(@"HKEY_USERS\\(S-1-5-21-[0-9\-]+)", 1, RegistryKey)
| where isnotempty(HiveSid)
| where InitiatingProcessIntegrityLevel in~ ("Medium","Low")
| where isnotempty(InitiatingProcessAccountSid) and InitiatingProcessAccountSid != HiveSid   // writing into ANOTHER user's hive = LegacyHive payoff
| where InitiatingProcessAccountName !endswith "$"
| where InitiatingProcessAccountName !in~ ("system","local service","network service")
| where InitiatingProcessFileName !in~ ("svchost.exe","msiexec.exe","userinit.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessAccountSid, HiveSid, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessIntegrityLevel
| order by Timestamp desc
```

### LegacyHive: elevated process at admin logon executing from a user-writable path

`UC_10_3` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("userinit.exe","explorer.exe")) (Processes.process_path="*\\AppData\\*" OR Processes.process_path="*\\Users\\Public\\*" OR Processes.process_path="*\\ProgramData\\*" OR Processes.process_path="*\\Temp\\*" OR Processes.process_path="*\\Downloads\\*") Processes.process_integrity_level IN ("high","system") NOT Processes.user="*$" by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process_path Processes.process Processes.process_integrity_level 
| `drop_dm_object_name(Processes)` 
| convert ctime(firstTime) ctime(lastTime) 
| table firstTime lastTime dest user parent_process_name process_name process_path process_integrity_level process count
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("userinit.exe","explorer.exe")
| where ProcessIntegrityLevel in~ ("High","System")
| where AccountName !endswith "$"
| where FolderPath has_any (@"\AppData\", @"C:\Users\Public\", @"C:\ProgramData\", @"\Temp\", @"\Downloads\")
| where FolderPath !has @"\AppData\Local\Microsoft\OneDrive" and FolderPath !has @"\AppData\Local\Microsoft\Teams"
| project Timestamp, DeviceName, AccountName, ProcessIntegrityLevel, FileName, FolderPath, SHA256, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountName
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-33825`, `CVE-2026-41091`, `CVE-2026-45498`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `git.projectnightcrawler.dev`


## Why this matters

Severity classified as **HIGH** based on: CVE present, IOCs present, 4 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.

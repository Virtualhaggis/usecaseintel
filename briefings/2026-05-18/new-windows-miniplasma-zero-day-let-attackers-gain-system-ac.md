# [CRIT] New Windows ‘MiniPlasma’ Zero-Day Let Attackers Gain SYSTEM Access – PoC Released

**Source:** Cyber Security News
**Published:** 2026-05-18
**Article:** https://cybersecuritynews.com/windows-miniplasma-zero-day/

## Threat Profile

Home Cyber Security News 
New Windows ‘MiniPlasma’ Zero-Day Let Attackers Gain SYSTEM Access – PoC Released 
By Abinaya 
May 18, 2026 




A critical Windows privilege escalation zero-day vulnerability dubbed “MiniPlasma” has emerged with a public proof-of-concept exploit that allows attackers to achieve SYSTEM-level privileges on fully patched Windows systems.
Security researcher Nightmare-Eclipse released the weaponized exploit on GitHub on May 13, 2026, claiming that Microsoft either fail…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2020-17103`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1068** — Exploitation for Privilege Escalation
- **T1112** — Modify Registry
- **T1134.001** — Token Impersonation/Theft
- **T1059.003** — Windows Command Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] MiniPlasma CVE-2020-17103: Registry write to HKU\.DEFAULT hive by non-SYSTEM principal

`UC_2_6` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Registry.registry_value_name) as registry_value_name values(Registry.registry_value_data) as registry_value_data values(Registry.process_name) as process_name values(Registry.user) as user from datamodel=Endpoint.Registry where (Registry.registry_key_name="HKU\\.DEFAULT\\*" OR Registry.registry_key_name="HKEY_USERS\\.DEFAULT\\*" OR Registry.registry_key_name="\\REGISTRY\\USER\\.DEFAULT\\*") Registry.action IN (created,modified) NOT (Registry.user IN ("*SYSTEM","*LOCAL SERVICE","*NETWORK SERVICE")) by Registry.dest Registry.registry_key_name Registry.user Registry.process_name | `drop_dm_object_name(Registry)` | where NOT match(user, "\$$")
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where ActionType in ("RegistryKeyCreated", "RegistryValueSet")
| where RegistryKey startswith @"HKEY_USERS\.DEFAULT"
    or RegistryKey startswith @"HKU\.DEFAULT"
    or RegistryKey startswith @"\REGISTRY\USER\.DEFAULT"
| where InitiatingProcessAccountSid !in ("S-1-5-18", "S-1-5-19", "S-1-5-20")
| where InitiatingProcessAccountName !endswith "$"
| where InitiatingProcessIntegrityLevel !in~ ("System", "High")
| where InitiatingProcessFileName !in~ ("svchost.exe", "services.exe", "wuauclt.exe", "trustedinstaller.exe", "MoUsoCoreWorker.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessAccountSid,
          InitiatingProcessIntegrityLevel, InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessSHA256,
          RegistryKey, RegistryValueName, RegistryValueData, ActionType
| order by Timestamp desc
```

### [LLM] MiniPlasma CVE-2020-17103: SYSTEM-integrity shell spawned by standard-user parent

`UC_2_7` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process) as parent_cmdline values(Processes.parent_process_name) as parent_name values(Processes.user) as user values(Processes.process_integrity_level) as integrity values(Processes.parent_process_integrity_level) as parent_integrity from datamodel=Endpoint.Processes where Processes.process_integrity_level="system" Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe") Processes.parent_process_integrity_level IN ("medium","low") Processes.parent_process_name!="services.exe" Processes.parent_process_name!="wininit.exe" Processes.parent_process_name!="msiexec.exe" Processes.parent_process_name!="consent.exe" by Processes.dest Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | where NOT match(user, "(?i)(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|\$$)")
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessIntegrityLevel =~ "System"
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "conhost.exe")
| where InitiatingProcessIntegrityLevel in~ ("Medium", "Low")
| where InitiatingProcessAccountSid !in ("S-1-5-18", "S-1-5-19", "S-1-5-20")
| where InitiatingProcessAccountName !endswith "$"
| where InitiatingProcessFileName !in~ (
    "services.exe", "wininit.exe", "msiexec.exe", "consent.exe",
    "RuntimeBroker.exe", "sihost.exe", "smartscreen.exe", "TiWorker.exe")
| where InitiatingProcessFolderPath !startswith @"C:\Windows\System32\config"
| project Timestamp, DeviceName, AccountName, AccountSid,
          ChildProcess = FileName, ChildCmd = ProcessCommandLine,
          ChildIntegrity = ProcessIntegrityLevel,
          ChildSHA256 = SHA256,
          ParentProcess = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          ParentIntegrity = InitiatingProcessIntegrityLevel,
          ParentAccountName = InitiatingProcessAccountName,
          ParentAccountSid = InitiatingProcessAccountSid,
          ParentFolderPath = InitiatingProcessFolderPath
| order by Timestamp desc
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

### Trusted vendor binary / installer launching unusual children

`UC_SUPPLY_CHAIN` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("setup.exe","installer.exe","update.exe")
      AND Processes.process_name IN ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
    by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("setup.exe","installer.exe","update.exe")
| where FileName in~ ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### Article-specific behavioural hunt — New Windows ‘MiniPlasma’ Zero-Day Let Attackers Gain SYSTEM Access – PoC Release

`UC_2_5` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — New Windows ‘MiniPlasma’ Zero-Day Let Attackers Gain SYSTEM Access – PoC Release ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("cldflt.sys"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("cldflt.sys"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — New Windows ‘MiniPlasma’ Zero-Day Let Attackers Gain SYSTEM Access – PoC Release
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("cldflt.sys"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("cldflt.sys"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2020-17103`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 8 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
